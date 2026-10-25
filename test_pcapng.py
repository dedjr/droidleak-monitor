import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path


def block(endian, block_type, body):
    total = 12 + len(body)
    padding = (-total) % 4
    body += b"\x00" * padding
    total = 12 + len(body)
    return (
        struct.pack(endian + "II", block_type, total)
        + body
        + struct.pack(endian + "I", total)
    )


def make_pcapng():
    endian = "<"
    # Ethernet + IPv4 + UDP + DNS query example.com
    dns = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ip = (
        b"\x45\x00"
        + struct.pack("!H", 20 + len(udp))
        + b"\x00\x01\x00\x00\x40\x11\x00\x00"
        + bytes([192, 168, 1, 10, 8, 8, 8, 8])
    )
    frame = b"\x00" * 12 + b"\x08\x00" + ip + udp

    # Section Header Block: byte-order magic, version 1.0, section length -1
    shb = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack(endian + "I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack(endian + "HHqI", 1, 0, -1, 28)
    )
    # Interface Description Block: Ethernet link type
    idb = block(endian, 1, struct.pack(endian + "HHI", 1, 0, 65535))
    # Enhanced Packet Block: interface 0, timestamp 0, captured/original length
    pad = b"\x00" * ((-len(frame)) % 4)
    epb = block(
        endian, 6,
        struct.pack(endian + "IIIII", 0, 0, 0, len(frame), len(frame))
        + frame + pad
    )
    return shb + idb + epb


class PcapngTests(unittest.TestCase):
    def test_pcapng_dns_and_json(self):
        sample = Path("test_sample.pcapng")
        report_file = Path("test_pcapng_report.json")
        try:
            sample.write_bytes(make_pcapng())
            result = subprocess.run(
                [sys.executable, "droidleak.py", str(sample),
                 "--json", str(report_file)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(report_file.read_text())
            self.assertEqual(report["packets_seen"], 1)
            self.assertEqual(report["protocols"]["UDP"], 1)
            self.assertIn("example.com", report["dns_queries"])
        finally:
            sample.unlink(missing_ok=True)
            report_file.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
