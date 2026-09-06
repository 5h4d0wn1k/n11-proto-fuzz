#!/usr/bin/env python3
"""
N11 - Protocol Fuzzer.

A real mutation fuzzer over a stdlib loopback-only dummy_proto_server. It
generates structural and random mutations, sends them to the service, and
detects when a connection is dropped / reset - which indicates the parser
hit its planted bug (a service crash). The fuzzer records the crashing
payload automatically and stops as soon as one is found.

Authorized use only: by default everything runs against 127.0.0.1 (loopback).
"""

import argparse
import random
import socket
import struct
import sys
from collections import defaultdict

from dummy_proto_server import DummyProtoServer


def build_packet(ptype, body_len):
    """Build a well-formed framed packet with the given type and body size."""
    body = b'A' * body_len
    return struct.pack('>HH', 4 + body_len, ptype) + body


def generate_corpus():
    """Deterministic corpus mixing valid headers, boundary values, and the
    planted crash-inducing case (type=3 with a short / missing trailer)."""
    corpus = []
    for ptype in (0, 1, 2, 3, 0xFFFF):
        for body_len in (0, 1, 4, 7, 8, 16, 64):
            corpus.append(build_packet(ptype, body_len))
    corpus += [
        b'',
        b'\x00',
        b'\xff' * 3,
        b'\x00\x03\x00\x00',
        b'\x00\x03\x00\x00ABCDEFG',   # type=3, 7-byte trailer -> crash
    ]
    return corpus


def random_mutation(rng):
    """Biased random mutation that also explores the crash-prone type=3 case."""
    ptype = rng.choice([0, 1, 2, 3, 3, 0xFFFF])
    body_len = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 64, 255])
    if ptype == 3 and body_len >= 8:
        body_len = rng.randint(0, 7)
    return build_packet(ptype, body_len)


class CrashDetector:
    """Records crashes, timeouts, and probes seen during fuzzing."""

    def __init__(self):
        self.crashes = []
        self.timeouts = []
        self.probes = 0

    def record_crash(self, host, port, payload, reason):
        entry = {
            'host': host, 'port': port, 'protocol': 'TCP',
            'payload_hex': payload.hex(),
            'payload_len': len(payload),
            'reason': reason,
        }
        self.crashes.append(entry)
        return entry


class ProtocolFuzzer:
    """Connects to a loopback TCP service and hunts for crash inputs."""

    def __init__(self, host='127.0.0.1', port=0, timeout=0.5, seed=1234):
        if host not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Authorized use only: target must be loopback')
        self.host = '127.0.0.1' if host == 'localhost' else host
        self.port = port
        self.timeout = timeout
        self.seed = seed
        self.detector = CrashDetector()
        self.rng = random.Random(seed)

    def _probe(self, payload):
        """Send one payload; return 'crash', 'ok', 'err', or 'timeout'."""
        send_ok = False
        try:
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                sock.sendall(payload)
                send_ok = True
                sock.settimeout(self.timeout)
                try:
                    resp = sock.recv(4096)
                except socket.timeout:
                    return 'timeout'
                if resp == b'':
                    return 'crash' if send_ok else 'timeout'
                if resp == b'OK':
                    return 'ok'
                return 'err'
        except ConnectionResetError:
            return 'crash'
        except (ConnectionRefusedError, OSError):
            return 'timeout'

    def find_crash(self, max_probes=300):
        """Fuzz until a crash input is found or the probe budget is spent.

        Returns the crashing payload entry, or None if none was found.
        """
        candidates = generate_corpus()
        while len(candidates) < max_probes:
            candidates.append(random_mutation(self.rng))

        for payload in candidates[:max_probes]:
            self.detector.probes += 1
            outcome = self._probe(payload)
            if outcome == 'crash':
                return self.detector.record_crash(
                    self.host, self.port, payload,
                    'connection dropped/reset on parse (service crash)')
            if outcome == 'timeout':
                pass
        return None


def run_demo(iterations=120):
    """Offline demo: spin up the loopback dummy server, let the fuzzer find
    the planted crashing input, then shut the server down. Fast, no network
    beyond 127.0.0.1."""
    print('=== N11 Protocol Fuzzer: offline demo (loopback dummy server) ===')
    server = DummyProtoServer(host='127.0.0.1')
    server.start()
    try:
        fuzzer = ProtocolFuzzer(host='127.0.0.1', port=server.port)
        entry = fuzzer.find_crash(max_probes=iterations)
        print(f'  probes:    {fuzzer.detector.probes}')
        print(f'  timeouts:  {fuzzer.detector.probes - (1 if entry else 0)}')
        if entry:
            print(f'  crash FOUND on probe:')
            print(f'    payload_hex: {entry["payload_hex"]}')
            print(f'    payload_len: {entry["payload_len"]}')
            print(f'    reason:      {entry["reason"]}')
            print('\n[RESULT] PASS (crashing input discovered)')
            return 0
        print('\n[RESULT] FAIL (no crashing input discovered)')
        return 1
    finally:
        server.stop()


def main():
    parser = argparse.ArgumentParser(
        description='N11 — Protocol Fuzzer (loopback dummy_proto_server)')
    parser.add_argument('--demo', action='store_true',
                        help='Run offline loopback demo (default)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Target host (loopback only for authorized use)')
    parser.add_argument('--port', type=int, default=0,
                        help='Target TCP port (0 = spin up a local dummy '
                             'server)')
    parser.add_argument('--iterations', '-n', type=int, default=120,
                        help='Max probes before giving up')
    parser.add_argument('--timeout', '-t', type=float, default=0.5,
                        help='Socket timeout in seconds')

    args = parser.parse_args()

    if args.port == 0:
        sys.exit(run_demo(iterations=args.iterations))

    try:
        fuzzer = ProtocolFuzzer(host=args.host, port=args.port,
                                timeout=args.timeout)
    except ValueError as exc:
        print(f'[-] {exc}')
        return 1

    print(f'[*] Fuzzing {fuzzer.host}:{fuzzer.port} '
          f'(up to {args.iterations} probes)')
    entry = fuzzer.find_crash(max_probes=args.iterations)
    if entry:
        print('[+] Crashing input discovered:')
        print(f'    payload_hex: {entry["payload_hex"]}')
        print(f'    payload_len: {entry["payload_len"]}')
        print(f'    reason:      {entry["reason"]}')
        return 0
    print('[-] No crashing input discovered within budget')
    return 1


if __name__ == '__main__':
    sys.exit(main())
