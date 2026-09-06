#!/usr/bin/env python3
"""
N11 - Dummy protocol server (stdlib, loopback only).

A minimal TCP server on 127.0.0.1 running a small framed protocol. A bug is
planted in the parser: a message with type=3 that lacks its 8-byte signature
trailer raises ProtocolCrash, after which the server drops the connection.
The fuzzer's job is to find such an input automatically.
"""

import socket
import struct
import threading


class ProtocolCrash(Exception):
    """Raised by the parser on a planted-bug malformed packet."""


class MalformedPacket(Exception):
    """Raised on structurally invalid (but non-crashing) packets."""


def parse_packet(data):
    """Parse a framed packet: [2-byte len][2-byte type] body.

    Returns a tuple (kind, payload). Raises MalformedPacket for structurally
    invalid input and ProtocolCrash for the planted crash case (type=3 without
    the 8-byte signature trailer).
    """
    if len(data) < 4:
        raise MalformedPacket('packet shorter than 4-byte header')
    plen, ptype = struct.unpack('>HH', data[:4])
    body = data[4:]
    if ptype == 3:
        if len(body) < 8:
            raise ProtocolCrash('type=3 requires 8-byte signature trailer')
        return ('comment', body[8:])
    if ptype == 0:
        return ('ping', None)
    return ('data', body)


class DummyProtoServer:
    """Loopback-only TCP server running the framed protocol."""

    def __init__(self, host='127.0.0.1', port=0):
        self.host = host
        self.port = port
        self._server_sock = None
        self._thread = None
        self._stopped = False
        self.crash_count = 0

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET,
                                          socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(8)
        self.port = self._server_sock.getsockname()[1]
        self._stopped = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve_one(self, conn):
        conn.settimeout(1.0)
        try:
            data = conn.recv(65536)
            if not data:
                return
            try:
                parse_packet(data)
                conn.sendall(b'OK')
            except ProtocolCrash:
                self.crash_count += 1
                # Abrupt close simulates the service crashing.
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack('ii', 1, 0))
                conn.close()
                return
            except MalformedPacket:
                conn.sendall(b'ERR')
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve(self):
        while not self._stopped:
            try:
                conn, _ = self._server_sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve_one, args=(conn,),
                             daemon=True).start()

    def stop(self):
        self._stopped = True
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
