"""Tests for the N11 protocol fuzzer and its dummy_proto_server."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from dummy_proto_server import (DummyProtoServer, MalformedPacket,
                                ProtocolCrash, parse_packet)
from proto_fuzz import (ProtocolFuzzer, build_packet, generate_corpus,
                        random_mutation)


class ParsePacketTests(unittest.TestCase):

    def test_short_packet_is_malformed(self):
        with self.assertRaises(MalformedPacket):
            parse_packet(b'\x00\x01')

    def test_ping_type_parses(self):
        kind, payload = parse_packet(build_packet(0, 0))
        self.assertEqual(kind, 'ping')
        self.assertIsNone(payload)

    def test_data_type_parses(self):
        kind, payload = parse_packet(build_packet(1, 4))
        self.assertEqual(kind, 'data')
        self.assertEqual(payload, b'A' * 4)

    def test_type3_valid_trailer_parses(self):
        kind, payload = parse_packet(build_packet(3, 8))
        self.assertEqual(kind, 'comment')
        self.assertEqual(payload, b'')

    def test_type3_short_trailer_crashes(self):
        with self.assertRaises(ProtocolCrash):
            parse_packet(build_packet(3, 4))

    def test_planted_bug_exists_in_corpus(self):
        crashed = [p for p in generate_corpus()
                   if self._triggers_crash(p)]
        self.assertTrue(crashed, 'corpus should contain a crashing input')

    @staticmethod
    def _triggers_crash(payload):
        try:
            parse_packet(payload)
            return False
        except ProtocolCrash:
            return True
        except MalformedPacket:
            return False


class FuzzerDiscoveryTests(unittest.TestCase):

    def test_fuzzer_finds_crashing_input_automatically(self):
        server = DummyProtoServer(host='127.0.0.1').start()
        try:
            fuzzer = ProtocolFuzzer(host='127.0.0.1', port=server.port)
            entry = fuzzer.find_crash(max_probes=200)
            self.assertIsNotNone(entry, 'fuzzer must discover the crash')
            self.assertEqual(entry['host'], '127.0.0.1')
            self.assertEqual(entry['port'], server.port)
            self.assertLessEqual(entry['payload_len'], 65535)
            # The discovered payload must actually trigger the planted bug.
            from dummy_proto_server import ProtocolCrash as PC
            with self.assertRaises(PC):
                parse_packet(bytes.fromhex(entry['payload_hex']))
            # Server must have observed the crash too.
            self.assertGreater(server.crash_count, 0)
        finally:
            server.stop()

    def test_fuzzer_stops_and_records_single_crash(self):
        server = DummyProtoServer(host='127.0.0.1').start()
        try:
            fuzzer = ProtocolFuzzer(host='127.0.0.1', port=server.port)
            entry = fuzzer.find_crash(max_probes=100)
            self.assertIsNotNone(entry)
            self.assertEqual(len(fuzzer.detector.crashes), 1)
        finally:
            server.stop()

    def test_valid_packets_do_not_crash(self):
        server = DummyProtoServer(host='127.0.0.1').start()
        try:
            fuzzer = ProtocolFuzzer(host='127.0.0.1', port=server.port)
            for payload in (build_packet(0, 0), build_packet(1, 16),
                            build_packet(3, 8)):
                outcome = fuzzer._probe(payload)
                self.assertIn(outcome, ('ok', 'err'))
            self.assertEqual(len(fuzzer.detector.crashes), 0)
        finally:
            server.stop()

    def test_non_loopback_target_rejected(self):
        server = DummyProtoServer(host='127.0.0.1').start()
        try:
            with self.assertRaises(ValueError):
                ProtocolFuzzer(host='203.0.113.5', port=server.port)
        finally:
            server.stop()

    def test_random_mutation_shapes_are_valid(self):
        rng = __import__('random').Random(42)
        for _ in range(50):
            payload = random_mutation(rng)
            self.assertIsInstance(payload, bytes)
            self.assertLessEqual(len(payload), 65535)


class ServerLifecycleTests(unittest.TestCase):

    def test_start_and_stop(self):
        server = DummyProtoServer(host='127.0.0.1').start()
        port = server.port
        self.assertGreater(port, 0)
        server.stop()


if __name__ == '__main__':
    unittest.main()
