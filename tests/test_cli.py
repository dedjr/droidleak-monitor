import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, PcapWriter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = PROJECT_ROOT / "droidleak.py"
SYNTHETIC_ETHERNET = {
    "src": "02:00:00:00:00:01",
    "dst": "02:00:00:00:00:02",
}


def write_capture(path: Path, packets: list, pcapng: bool = False) -> None:
    if pcapng:
        writer = PcapNgWriter(str(path))
    else:
        writer = PcapWriter(str(path), linktype=1, sync=True)
    for packet in packets:
        writer.write(packet)
    writer.close()


class DroidLeakCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = Path(self.temp_dir.name)

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CLI_PATH), *arguments],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_help_output(self) -> None:
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--find-coordinates", result.stdout)
        self.assertIn("--json", result.stdout)
        self.assertIn("does not decrypt TLS", result.stdout)

    def test_invalid_input_file_is_reported_without_traceback(self) -> None:
        missing = self.work_dir / "missing.pcap"
        result = self.run_cli(str(missing))
        self.assertEqual(result.returncode, 2)
        self.assertIn("Input file not found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_json_report_generation(self) -> None:
        capture = self.work_dir / "synthetic.pcap"
        report_path = self.work_dir / "report.json"
        packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.25")
            / TCP(sport=51000, dport=8080)
            / Raw(load=b"position=37.7749,-122.4194")
        )
        write_capture(capture, [packet])

        result = self.run_cli(
            str(capture),
            "--find-coordinates",
            "--json",
            str(report_path),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["capture"]["packet_count"], 1)
        self.assertTrue(report["coordinate_scan_enabled"])
        self.assertEqual(len(report["coordinate_findings"]), 1)
        self.assertIn("JSON report written to", result.stdout)

    def test_valid_empty_capture_is_handled(self) -> None:
        capture = self.work_dir / "empty.pcap"
        write_capture(capture, [])

        result = self.run_cli(str(capture), "--summary")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Packets analyzed: 0", result.stdout)
        self.assertIn("none observed", result.stdout)

    def test_zero_byte_file_is_reported_cleanly(self) -> None:
        capture = self.work_dir / "zero-byte.pcap"
        capture.write_bytes(b"")

        result = self.run_cli(str(capture))

        self.assertEqual(result.returncode, 2)
        self.assertIn("input file is empty", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_coordinate_scan_reports_packet_and_context(self) -> None:
        capture = self.work_dir / "coordinates.pcap"
        packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.5", dst="198.51.100.8")
            / UDP(sport=53000, dport=9000)
            / Raw(
                load=(
                    b"location=37.7749,-122.4194;visible;"
                    b"password=coordinate-secret-value"
                )
            )
        )
        write_capture(capture, [packet])

        result = self.run_cli(str(capture), "--find-coordinates", "--json", str(self.work_dir / "coords.json"))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.work_dir / "coords.json").read_text(encoding="utf-8"))
        finding = report["coordinate_findings"][0]
        self.assertEqual(finding["packet_number"], 1)
        self.assertEqual(finding["latitude"], 37.7749)
        self.assertEqual(finding["longitude"], -122.4194)
        self.assertIn("location=", finding["context"])
        self.assertEqual(finding["finding_type"], "potential_coordinate_pattern")
        report_text = (self.work_dir / "coords.json").read_text(encoding="utf-8")
        self.assertNotIn("coordinate-secret-value", report_text)

    def test_https_payload_is_not_scanned(self) -> None:
        capture = self.work_dir / "tls-port.pcap"
        packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.5", dst="198.51.100.8")
            / TCP(sport=53000, dport=443)
            / Raw(load=b"location=37.7749,-122.4194")
        )
        write_capture(capture, [packet])

        result = self.run_cli(str(capture), "--find-coordinates", "--json", str(self.work_dir / "tls.json"))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.work_dir / "tls.json").read_text(encoding="utf-8"))
        self.assertEqual(report["coordinate_findings"], [])

    def test_protocol_and_ip_summary_generation(self) -> None:
        capture = self.work_dir / "summary.pcap"
        tcp_packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.25")
            / TCP(sport=50000, dport=443)
        )
        dns_packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test"))
        )
        write_capture(capture, [tcp_packet, dns_packet])

        result = self.run_cli(str(capture), "--json", str(self.work_dir / "summary.json"))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.work_dir / "summary.json").read_text(encoding="utf-8"))
        summary = report["summary"]
        self.assertEqual(summary["packet_count"], 2)
        self.assertEqual(summary["protocols"]["IP"], 2)
        self.assertEqual(summary["protocols"]["TCP"], 1)
        self.assertEqual(summary["protocols"]["UDP"], 1)
        self.assertEqual(summary["protocols"]["DNS"], 1)
        self.assertEqual(summary["source_ips"]["192.0.2.10"], 2)
        self.assertEqual(summary["destination_ips"]["198.51.100.25"], 1)
        self.assertEqual(summary["destination_ports"]["TCP/443"], 1)
        self.assertEqual(
            report["dns"]["queries"],
            [{"name": "example.test", "count": 1}],
        )

    def test_pcapng_capture_is_supported(self) -> None:
        capture = self.work_dir / "synthetic.pcapng"
        packet = (
            Ether(**SYNTHETIC_ETHERNET)
            / IP(src="192.0.2.1", dst="198.51.100.1")
            / UDP(dport=53)
        )
        write_capture(capture, [packet], pcapng=True)

        result = self.run_cli(str(capture), "--summary")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(pcapng)", result.stdout)
        self.assertIn("Packets analyzed: 1", result.stdout)

    def test_unsupported_file_is_reported_cleanly(self) -> None:
        unsupported = self.work_dir / "notes.txt"
        unsupported.write_text("not a packet capture", encoding="utf-8")

        result = self.run_cli(str(unsupported))

        self.assertEqual(result.returncode, 2)
        self.assertIn("Unsupported file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_capture_is_reported_cleanly(self) -> None:
        malformed = self.work_dir / "truncated.pcap"
        malformed.write_bytes(b"\xd4\xc3\xb2\xa1\x02")

        result = self.run_cli(str(malformed))

        self.assertEqual(result.returncode, 2)
        self.assertIn("Could not parse capture", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_json_output_cannot_overwrite_capture(self) -> None:
        capture = self.work_dir / "safe.pcap"
        write_capture(capture, [])

        result = self.run_cli(str(capture), "--json", str(capture))

        self.assertEqual(result.returncode, 2)
        self.assertIn("must not overwrite the capture file", result.stderr)
        self.assertTrue(capture.exists())


if __name__ == "__main__":
    unittest.main()
