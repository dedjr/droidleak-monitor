import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def dns_name(name):
    return b"".join(
        bytes([len(part)]) + part.encode()
        for part in name.split(".")
    ) + b"\x00"


def make_dns_response():
    question_name = dns_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + bytes([93, 184, 216, 34])
    )
    dns = (
        struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )

    udp = struct.pack("!HHHH", 53, 53000, 8 + len(dns), 0) + dns
    src = bytes([8, 8, 8, 8])
    dst = bytes([192, 168, 1, 10])
    total_len = 20 + len(udp)
    ip = (
        struct.pack("!BBHHHBBH4s4s",
                    0x45, 0, total_len, 1, 0, 64, 17, 0, src, dst)
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    frame = ethernet + ip + udp

    # Classic PCAP, little-endian, Ethernet link type.
    global_header = struct.pack(
        "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
    )
    packet_header = struct.pack("<IIII", 1, 0, len(frame), len(frame))
    return global_header + packet_header + frame


class TestDNSIntegration(unittest.TestCase):
    def test_dns_response_appears_in_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "dns_response.pcap"
            report = Path(tmp) / "report.json"
            pcap.write_bytes(make_dns_response())

            result = subprocess.run(
                [
                    sys.executable, "droidleak.py",
                    str(pcap), "--json", str(report),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode, 0,
                msg=f"CLI gagal:\n{result.stdout}\n{result.stderr}",
            )
            self.assertTrue(report.exists(), "File JSON tidak dibuat.")

            data = json.loads(report.read_text())
            answers = data.get("dns_answers", [])
            self.assertIn(
                {
                    "name": "example.com",
                    "type": "A",
                    "address": "93.184.216.34",
                },
                answers,
                msg=f"Jawaban DNS tidak ditemukan. dns_answers={answers!r}",
            )


if __name__ == "__main__":
    unittest.main()
