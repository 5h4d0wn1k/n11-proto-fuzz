#!/usr/bin/env python3
"""
N11 - Protocol Fuzzer (network layer)
TCP/UDP protocol fuzzing with mutation engine, crash detection, and response analysis.
"""

import socket
import random
import struct
import sys
import time
import argparse
import traceback
from collections import defaultdict


class MutationEngine:
    """Generate mutated payloads for protocol fuzzing."""

    NULL_BYTE = b'\x00'
    MAX_PAYLOAD = 65535

    @staticmethod
    def random_bytes(length):
        return bytes(random.randint(0, 255) for _ in range(length))

    @staticmethod
    def boundary_values():
        return [
            b'', b'\x00', b'\xff' * 4, b'\xff' * 8,
            b'\xff' * 16, b'\xff' * 64, b'\xff' * 256,
            b'\x00' * 4, b'\x00' * 8, b'\x00' * 16, b'\x00' * 64,
            struct.pack('>H', 0), struct.pack('>H', 65535),
            struct.pack('>I', 0), struct.pack('>I', 0xFFFFFFFF),
            struct.pack('>I', 0x7FFFFFFF),
        ]

    @staticmethod
    def format_string_payloads():
        return [
            b'%s%s%s%s%s', b'%x%x%x%x%x', b'%n%n%n%n%n',
            b'%' + b'x' * 100, b'%99999s',
            b'${HOME}', b'`id`', b'$(id)',
            b'%08x.%08x.%08x',
        ]

    def mutate(self, base_payload=None, strategy='random', length=None):
        """Apply mutation strategy to generate fuzz payload."""
        if length is None:
            length = random.randint(4, 512)

        if strategy == 'random':
            return self._random_mutation(length)
        elif strategy == 'boundary':
            return random.choice(self.boundary_values())
        elif strategy == 'format':
            return random.choice(self.format_string_payloads())
        elif strategy == 'overflow':
            return self._overflow_mutation(length)
        elif strategy == 'bitflip':
            return self._bitflip_mutation(base_payload or self.random_bytes(length))
        elif strategy == 'insertion':
            return self._insertion_mutation(length)
        elif strategy == 'combo':
            return self._combo_mutation(length)
        else:
            return self._random_mutation(length)

    def _random_mutation(self, length):
        mutation_type = random.choice(['pure_random', 'repeat_char',
                                       'structured'])
        if mutation_type == 'pure_random':
            return self.random_bytes(length)
        elif mutation_type == 'repeat_char':
            char = bytes([random.randint(0, 255)])
            count = random.randint(2, min(length, 1024))
            return char * count
        else:
            header = self.random_bytes(random.randint(1, 8))
            body = self.random_bytes(max(1, length - 8))
            return header + body

    def _overflow_mutation(self, length):
        overflow_sizes = [256, 512, 1024, 2048, 4096, 8192, 16384,
                          32768, 65535]
        size = random.choice(overflow_sizes)
        return b'A' * min(size, self.MAX_PAYLOAD)

    def _bitflip_mutation(self, data):
        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 4))
        for _ in range(num_flips):
            if data:
                byte_idx = random.randint(0, len(data) - 1)
                bit = 1 << random.randint(0, 7)
                data[byte_idx] ^= bit
        return bytes(data)

    def _insertion_mutation(self, length):
        base = self.random_bytes(max(1, length // 2))
        marker = random.choice([b'\x00\x00', b'\xff\xff', b'\r\n\r\n',
                                b'../../../', b'<?xml', b'\x00\x01\x02'])
        insert_pos = random.randint(0, len(base))
        return base[:insert_pos] + marker + base[insert_pos:]

    def _combo_mutation(self, length):
        strategies = ['random', 'boundary', 'format', 'overflow', 'bitflip']
        payload = self.mutate(length=min(length, 64), strategy='random')
        for _ in range(random.randint(1, 3)):
            extra = self.mutate(length=random.randint(4, 32),
                                strategy=random.choice(strategies))
            payload += extra
        return payload[:self.MAX_PAYLOAD]


class CrashDetector:
    """Monitor for crashes, hangs, and anomalies during fuzzing."""

    def __init__(self):
        self.crashes = []
        self.timeouts = []
        self.anomalies = []
        self.stats = defaultdict(int)

    def record_crash(self, target, port, payload, error, proto):
        entry = {
            'target': target, 'port': port, 'protocol': proto,
            'payload_hex': payload.hex()[:200],
            'payload_len': len(payload),
            'error': str(error),
            'timestamp': time.time(),
        }
        self.crashes.append(entry)
        self.stats['crashes'] += 1
        return entry

    def record_timeout(self, target, port, payload, proto):
        entry = {
            'target': target, 'port': port, 'protocol': proto,
            'payload_hex': payload.hex()[:200],
            'payload_len': len(payload),
            'timestamp': time.time(),
        }
        self.timeouts.append(entry)
        self.stats['timeouts'] += 1
        return entry

    def record_anomaly(self, target, port, description, proto):
        entry = {
            'target': target, 'port': port, 'protocol': proto,
            'description': description,
            'timestamp': time.time(),
        }
        self.anomalies.append(entry)
        self.stats['anomalies'] += 1
        return entry

    def summary(self):
        print(f"\n{'='*50}")
        print(f"  CRASH DETECTOR SUMMARY")
        print(f"{'='*50}")
        print(f"  Total tests:   {self.stats.get('total', 0)}")
        print(f"  Crashes:       {self.stats.get('crashes', 0)}")
        print(f"  Timeouts:      {self.stats.get('timeouts', 0)}")
        print(f"  Anomalies:     {self.stats.get('anomalies', 0)}")
        print(f"  Connections:   {self.stats.get('connections', 0)}")

        if self.crashes:
            print(f"\n  CRASHES:")
            for c in self.crashes[:10]:
                print(f"    {c['target']}:{c['port']} "
                      f"({c['protocol']}) - {c['error']}")
                print(f"      Payload: {c['payload_hex'][:60]}...")

        if self.timeouts:
            print(f"\n  TIMEOUTS:")
            for t in self.timeouts[:5]:
                print(f"    {t['target']}:{t['port']} ({t['protocol']}) "
                      f"- len={t['payload_len']}")

        if self.anomalies:
            print(f"\n  ANOMALIES:")
            for a in self.anomalies[:5]:
                print(f"    {a['target']}:{a['port']}: {a['description']}")
        print(f"{'='*50}")


class ProtocolFuzzer:
    """TCP/UDP protocol fuzzer with mutation engine."""

    def __init__(self, target, timeout=2):
        self.target = target
        self.timeout = timeout
        self.mutator = MutationEngine()
        self.detector = CrashDetector()
        self.mutations_log = []

    def fuzz_tcp(self, port, iterations=100, strategies=None):
        """Fuzz a TCP service."""
        if strategies is None:
            strategies = ['random', 'boundary', 'overflow', 'bitflip',
                          'format', 'combo']

        print(f"\n[*] TCP Fuzzing {self.target}:{port}")
        print(f"    Iterations: {iterations}")
        print(f"    Strategies: {strategies}")

        for i in range(iterations):
            strategy = random.choice(strategies)
            payload = self.mutator.mutate(strategy=strategy)
            self.detector.stats['total'] += 1

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))
                self.detector.stats['connections'] += 1

                sock.send(payload)
                time.sleep(0.1)

                try:
                    response = sock.recv(4096)
                    if response:
                        if len(response) > 1024:
                            self.detector.record_anomaly(
                                self.target, port,
                                f'large response: {len(response)} bytes',
                                'TCP')
                except socket.timeout:
                    pass

                sock.close()

            except ConnectionResetError as e:
                self.detector.record_crash(
                    self.target, port, payload, e, 'TCP')
                if (i + 1) % 10 == 0:
                    print(f"    [{i+1}/{iterations}] "
                          f"RESET - {strategy}")
            except ConnectionRefusedError:
                self.detector.record_anomaly(
                    self.target, port, 'connection refused', 'TCP')
            except BrokenPipeError as e:
                self.detector.record_crash(
                    self.target, port, payload, e, 'TCP')
            except socket.timeout:
                self.detector.record_timeout(
                    self.target, port, payload, 'TCP')
            except OSError as e:
                self.detector.record_crash(
                    self.target, port, payload, e, 'TCP')

            self.mutations_log.append({
                'iteration': i + 1, 'strategy': strategy,
                'payload_len': len(payload),
                'payload_preview': payload[:20],
            })

            if (i + 1) % 25 == 0:
                print(f"    [{i+1}/{iterations}] completed")

        print(f"    TCP fuzzing complete")

    def fuzz_udp(self, port, iterations=100, strategies=None):
        """Fuzz a UDP service."""
        if strategies is None:
            strategies = ['random', 'boundary', 'overflow', 'format',
                          'combo']

        print(f"\n[*] UDP Fuzzing {self.target}:{port}")
        print(f"    Iterations: {iterations}")

        for i in range(iterations):
            strategy = random.choice(strategies)
            payload = self.mutator.mutate(strategy=strategy,
                                          length=random.randint(8, 1024))
            self.detector.stats['total'] += 1

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(payload, (self.target, port))
                self.detector.stats['connections'] += 1

                try:
                    response, addr = sock.recvfrom(4096)
                    if response:
                        if len(response) != len(payload):
                            self.detector.record_anomaly(
                                self.target, port,
                                f'size mismatch: sent {len(payload)} '
                                f'got {len(response)}', 'UDP')
                except socket.timeout:
                    pass

                sock.close()

            except ConnectionRefusedError:
                self.detector.record_anomaly(
                    self.target, port, 'ICMP unreachable', 'UDP')
            except OSError as e:
                self.detector.record_crash(
                    self.target, port, payload, e, 'UDP')

            if (i + 1) % 25 == 0:
                print(f"    [{i+1}/{iterations}] completed")

        print(f"    UDP fuzzing complete")

    def fuzz_multi_port(self, ports, iterations=50, protocol='TCP'):
        """Fuzz multiple ports."""
        print(f"\n[*] Multi-port {protocol} fuzzing: {ports}")

        for port in ports:
            if protocol.upper() == 'TCP':
                self.fuzz_tcp(port, iterations)
            elif protocol.upper() == 'UDP':
                self.fuzz_udp(port, iterations)
            else:
                self.fuzz_tcp(port, iterations // 2)
                self.fuzz_udp(port, iterations // 2)

    def save_results(self, filepath):
        """Save fuzzing results to file."""
        import json
        results = {
            'target': self.target,
            'detector': {
                'crashes': self.detector.crashes,
                'timeouts': self.detector.timeouts,
                'anomalies': self.detector.anomalies,
                'stats': dict(self.detector.stats),
            },
            'mutations_log': self.mutations_log,
        }
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] Results saved to {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description='N11 — Protocol Fuzzer')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--tcp-ports', help='TCP ports to fuzz (comma-sep)')
    parser.add_argument('--udp-ports', help='UDP ports to fuzz (comma-sep)')
    parser.add_argument('--iterations', '-n', type=int, default=100,
                        help='Iterations per port')
    parser.add_argument('--timeout', '-t', type=float, default=2,
                        help='Socket timeout')
    parser.add_argument('--strategies', help='Comma-separated strategies')
    parser.add_argument('--output', '-o', help='Save results to file')

    args = parser.parse_args()

    fuzzer = ProtocolFuzzer(args.target, args.timeout)

    print("╔═══════════════════════════════════════╗")
    print("║     N11 — Protocol Fuzzer             ║")
    print("╚═══════════════════════════════════════╝")
    print(f"Target: {args.target}")

    strategies = None
    if args.strategies:
        strategies = [s.strip() for s in args.strategies.split(',')]

    tcp_ports = None
    udp_ports = None

    if args.tcp_ports:
        tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(',')]

    if args.udp_ports:
        udp_ports = [int(p.strip()) for p in args.udp_ports.split(',')]

    if not tcp_ports and not udp_ports:
        print("[-] Specify --tcp-ports or --udp-ports")
        print("    Example: --tcp-ports 21,22,80,443 --udp-ports 53,161")
        sys.exit(1)

    try:
        if tcp_ports:
            fuzzer.fuzz_multi_port(tcp_ports, args.iterations, 'TCP')
        if udp_ports:
            fuzzer.fuzz_multi_port(udp_ports, args.iterations, 'UDP')
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    fuzzer.detector.summary()

    if args.output:
        fuzzer.save_results(args.output)


if __name__ == '__main__':
    main()
