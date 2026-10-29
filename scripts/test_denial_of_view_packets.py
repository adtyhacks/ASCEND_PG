"""Deterministic packet-builder regression; no networking or runtime writes."""
import ipaddress
import struct
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from attacks import denial_of_view


def internet_checksum(data: bytes) -> int:
    """Validate network-order words independently of the builder's unpacking."""
    total = 0
    for index in range(0, len(data), 2):
        total += data[index] << 8
        if index + 1 < len(data):
            total += data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total ^ 0xFFFF


class DenialOfViewPacketTests(unittest.TestCase):
    SOURCE = "10.0.0.5"
    DESTINATION = "10.0.0.100"
    FC06 = bytes.fromhex("0001000000060106001904d2")

    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        for target in (
            "socket.socket", "socket.create_connection",
            "subprocess.Popen", "subprocess.run", "os.system",
            "builtins.open", "pathlib.Path.open",
            "attacks.denial_of_view.log_event",
        ):
            guards.enter_context(patch(
                target, side_effect=AssertionError(f"Forbidden external effect: {target}")
            ))

    def tcp_header(self, payload):
        return denial_of_view._build_tcp_header(
            12345, 502, 0x12345678, 0x87654321, 0x18, payload,
            src_ip=self.SOURCE, dst_ip=self.DESTINATION,
        )

    def pseudo_header(self, payload):
        return (
            ipaddress.IPv4Address(self.SOURCE).packed
            + ipaddress.IPv4Address(self.DESTINATION).packed
            + b"\x00\x06"
            + (20 + len(payload)).to_bytes(2, "big")
        )

    def test_fc06_payload_is_unchanged(self):
        payload = denial_of_view.build_forged_fc06_response(1, 1, 25, 1234)
        self.assertEqual(len(payload), 12)
        self.assertEqual(payload, self.FC06)

    def test_tcp_header_fields(self):
        header = self.tcp_header(self.FC06)
        self.assertEqual(len(header), 20)
        self.assertEqual(int.from_bytes(header[0:2], "big"), 12345)
        self.assertEqual(int.from_bytes(header[2:4], "big"), 502)
        self.assertEqual(int.from_bytes(header[4:8], "big"), 0x12345678)
        self.assertEqual(int.from_bytes(header[8:12], "big"), 0x87654321)
        self.assertEqual(header[12] >> 4, 5)
        self.assertEqual(header[12] & 0x0F, 0)
        self.assertEqual(header[13], 0x18)
        self.assertEqual(int.from_bytes(header[14:16], "big"), 65535)
        self.assertEqual(len(header[16:18]), 2)
        self.assertEqual(int.from_bytes(header[18:20], "big"), 0)

    def test_tcp_checksum_even_odd_and_empty_payloads(self):
        for payload in (self.FC06, self.FC06 + b"\x01", b""):
            with self.subTest(payload_length=len(payload)):
                header = self.tcp_header(payload)
                zero_checksum_header = header[:16] + b"\x00\x00" + header[18:]
                expected = internet_checksum(
                    self.pseudo_header(payload) + zero_checksum_header + payload
                )
                self.assertEqual(int.from_bytes(header[16:18], "big"), expected)
                self.assertEqual(internet_checksum(
                    self.pseudo_header(payload) + header + payload
                ), 0)

    def test_checksum_padding_is_conditional(self):
        for payload, padding in (
            (self.FC06, b""), (self.FC06 + b"\x01", b"\x00"), (b"", b""),
        ):
            with self.subTest(payload_length=len(payload)):
                with patch.object(denial_of_view.struct, "unpack", wraps=struct.unpack) as unpack:
                    header = self.tcp_header(payload)
                unpack.assert_called_once()
                format_string, checksum_buffer = unpack.call_args.args
                zero_checksum_header = header[:16] + b"\x00\x00" + header[18:]
                expected = self.pseudo_header(payload) + zero_checksum_header + payload + padding
                self.assertEqual(checksum_buffer, expected)
                self.assertEqual(len(checksum_buffer), 32 + len(payload) + len(padding))
                self.assertEqual(struct.calcsize(format_string), len(checksum_buffer))

    def test_ipv4_packet_fields_and_checksum(self):
        for payload in (self.FC06, self.FC06 + b"\x01", b""):
            with self.subTest(payload_length=len(payload)):
                tcp = self.tcp_header(payload)
                header = denial_of_view._build_ip_header(
                    self.SOURCE, self.DESTINATION, len(tcp) + len(payload)
                )
                packet = header + tcp + payload
                self.assertEqual(len(header), 20)
                self.assertEqual(header[0] >> 4, 4)
                self.assertEqual((header[0] & 0x0F) * 4, 20)
                self.assertEqual(int.from_bytes(header[2:4], "big"), len(packet))
                self.assertEqual(header[9], 6)
                self.assertEqual(header[12:16], ipaddress.IPv4Address(self.SOURCE).packed)
                self.assertEqual(header[16:20], ipaddress.IPv4Address(self.DESTINATION).packed)
                expected = internet_checksum(header[:10] + b"\x00\x00" + header[12:])
                self.assertEqual(int.from_bytes(header[10:12], "big"), expected)
                self.assertEqual(internet_checksum(header), 0)
                self.assertEqual(packet[40:], payload)


if __name__ == "__main__":
    unittest.main()
