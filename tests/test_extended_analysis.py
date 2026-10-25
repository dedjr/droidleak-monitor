import json
import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, PcapWriter

from droidleak import analyze_pcap, parse_dns_query
from droidleak_core import _extract_tls_sni


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = PROJECT_ROOT / "droidleak.py"
ETHERNET = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def write_capture(path: Path, packets: list, pcapng: bool = False) -> None:
    writer = (
        PcapNgWriter(str(path))
        if pcapng
        else PcapWriter(str(path), linktype=1, sync=True)
    )
    for packet in packets:
        writer.write(packet)
    writer.close()


class ExtendedAnalysisTests(unittest.TestCase):
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

    def test_version_output(self) -> None:
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("DroidLeak Monitor 2.0.0", result.stdout)

    def test_legacy_dns_parser_and_report_fields_remain_available(self) -> None:
        query_name = b"\x07example\x04test\x00"
        query = query_name + b"\x00\x01\x00\x01"
        answer = (
            b"\xc0\x0c"
            + b"\x00\x01\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + bytes((203, 0, 113, 8))
        )
        dns_payload = (
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + query
            + answer
        )

        parsed = parse_dns_query(dns_payload)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["is_response"])
        self.assertEqual(parsed["queries"], ["example.test"])
        self.assertEqual(
            parsed["answers"],
            [{"name": "example.test", "type": "A", "address": "203.0.113.8"}],
        )

        capture = self.work_dir / "legacy-report.pcap"
        packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test"))
        )
        write_capture(capture, [packet])
        report = analyze_pcap(capture)
        self.assertEqual(report["packets_seen"], 1)
        self.assertEqual(report["protocols"]["UDP"], 1)
        self.assertIn("example.test", report["dns_queries"])
        self.assertEqual(len(report["top_endpoints"]), 1)

    def test_dns_query_and_a_aaaa_answers_are_reported(self) -> None:
        capture = self.work_dir / "dns.pcap"
        query = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test"))
        )
        answer_a = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.53", dst="192.0.2.10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="example.test"),
                an=DNSRR(rrname="example.test", type="A", rdata="203.0.113.20"),
            )
        )
        answer_aaaa = (
            Ether(**ETHERNET)
            / IPv6(src="2001:db8::53", dst="2001:db8::10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=2,
                qr=1,
                qd=DNSQR(qname="example.test"),
                an=DNSRR(
                    rrname="example.test",
                    type="AAAA",
                    rdata="2001:db8::20",
                ),
            )
        )
        write_capture(capture, [query, answer_a, answer_aaaa])
        report_path = self.work_dir / "dns.json"

        result = self.run_cli(str(capture), "--json", str(report_path))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["dns"]["queries"], [{"name": "example.test", "count": 1}])
        self.assertEqual(report["summary"]["dns_answer_count"], 2)
        answer_types = {row["record_type"] for row in report["dns"]["answers"]}
        self.assertEqual(answer_types, {"A", "AAAA"})
        self.assertEqual(report["summary"]["protocols"]["DNS"], 3)
        self.assertEqual(report["summary"]["unique_ip_count"], 4)

    def test_plaintext_http_sensitive_indicators_are_masked(self) -> None:
        capture = self.work_dir / "http.pcap"
        sensitive = (
            b"POST /session HTTP/1.1\r\n"
            b"Host: api.example.test\r\n"
            b"Authorization: Bearer BearerSecret987\r\n"
            b"Cookie: sessionid=CookieSecret567; theme=light\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"email=demo@example.test&password=PlainPassword123&phone=%2B15551234567"
        )
        packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.22")
            / TCP(sport=51000, dport=80)
            / Raw(load=sensitive)
        )
        write_capture(capture, [packet])
        report_path = self.work_dir / "http.json"
        html_path = self.work_dir / "http.html"

        result = self.run_cli(
            str(capture),
            "--json",
            str(report_path),
            "--html",
            str(html_path),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
        self.assertEqual(report["summary"]["http_request_count"], 1)
        self.assertEqual(report["http"]["hosts"], ["api.example.test"])
        types = {finding["type"] for finding in report["findings"]}
        self.assertTrue(
            {
                "http_authorization_header",
                "http_cookie",
                "plaintext_sensitive_field",
                "context_labelled_email",
                "context_labelled_phone",
            }.issubset(types)
        )
        self.assertEqual(report["risk_assessment"]["category"], "confirmed_exposure")
        for raw_value in (
            "BearerSecret987",
            "CookieSecret567",
            "PlainPassword123",
            "demo@example.test",
            "+15551234567",
        ):
            self.assertNotIn(raw_value, report_text)
            self.assertNotIn(raw_value, result.stdout)
            self.assertNotIn(raw_value, html_path.read_text(encoding="utf-8"))
        self.assertIn("Sensitive-data indicators", result.stdout)
        self.assertEqual(
            sum(finding["type"] == "http_cookie" for finding in report["findings"]),
            1,
            "ordinary preference cookies should not be reported as session leaks",
        )

    def test_email_without_a_context_label_is_not_flagged(self) -> None:
        capture = self.work_dir / "ordinary-http.pcap"
        packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.22")
            / TCP(sport=51000, dport=8080)
            / Raw(load=b"GET /search?q=demo@example.test HTTP/1.1\r\nHost: example.test\r\n\r\n")
        )
        write_capture(capture, [packet])

        result = self.run_cli(str(capture), "--json", str(self.work_dir / "ordinary.json"))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.work_dir / "ordinary.json").read_text(encoding="utf-8"))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["risk_assessment"]["category"], "no_evidence_found")

    def test_plaintext_set_cookie_is_masked_and_not_called_device_exfiltration(self) -> None:
        capture = self.work_dir / "response.pcap"
        packet = (
            Ether(**ETHERNET)
            / IP(src="198.51.100.22", dst="192.0.2.10")
            / TCP(sport=80, dport=51000)
            / Raw(
                load=(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Set-Cookie: sessionid=SessionSecret789; Path=/\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            )
        )
        write_capture(capture, [packet])
        report_path = self.work_dir / "response.json"

        result = self.run_cli(str(capture), "--json", str(report_path))

        self.assertEqual(result.returncode, 0, result.stderr)
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
        self.assertNotIn("SessionSecret789", report_text)
        self.assertEqual(report["findings"][0]["type"], "http_cookie")
        self.assertEqual(
            report["findings"][0]["evidence_category"],
            "potential_exposure",
        )
        self.assertIn("does not show", report["findings"][0]["explanation"])

    def test_html_report_is_standalone_and_escapes_content(self) -> None:
        capture = self.work_dir / "http.pcap"
        packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.22")
            / TCP(sport=51000, dport=80)
            / Raw(
                load=(
                    b"GET / HTTP/1.1\r\n"
                    b"Host: api.example.test<script>alert(1)</script>\r\n\r\n"
                )
            )
        )
        write_capture(capture, [packet])
        html_path = self.work_dir / "reports" / "report.html"

        result = self.run_cli(str(capture), "--html", str(html_path))

        self.assertEqual(result.returncode, 0, result.stderr)
        html = html_path.read_text(encoding="utf-8")
        self.assertIn("DroidLeak Monitor", html)
        self.assertIn("viewport", html)
        self.assertNotIn("<script", html.lower())
        self.assertIn("&lt;script&gt;", html.lower())
        self.assertNotIn("https://", html.lower())

    def test_tls_clienthello_sni_is_metadata_only(self) -> None:
        server_name = b"api.example.test"
        name_entry = b"\x00" + len(server_name).to_bytes(2, "big") + server_name
        server_name_list = len(name_entry).to_bytes(2, "big") + name_entry
        sni_extension = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
        extensions = len(sni_extension).to_bytes(2, "big") + sni_extension
        hello_body = (
            b"\x03\x03"
            + bytes(32)
            + b"\x00"
            + b"\x00\x02\x13\x01"
            + b"\x01\x00"
            + extensions
        )
        handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
        client_hello = (
            b"\x16\x03\x03"
            + len(handshake).to_bytes(2, "big")
            + handshake
        )
        self.assertEqual(_extract_tls_sni(client_hello), "api.example.test")

        capture = self.work_dir / "tls.pcap"
        tls_packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.22")
            / TCP(sport=51000, dport=443)
            / Raw(load=client_hello)
        )
        write_capture(capture, [tls_packet])
        report_path = self.work_dir / "tls.json"
        result = self.run_cli(str(capture), "--json", str(report_path))

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["risk_assessment"]["category"], "encrypted_unknown")
        self.assertEqual(
            report["tls"]["client_hello_server_names"][0]["server_name"],
            "api.example.test",
        )
        self.assertEqual(report["findings"], [])

    def test_large_capture_is_counted_without_loading_all_packets(self) -> None:
        capture = self.work_dir / "many.pcap"
        packet = (
            Ether(**ETHERNET)
            / IP(src="192.0.2.10", dst="198.51.100.22")
            / UDP(sport=55000, dport=9000)
        )
        write_capture(capture, [packet] * 300, pcapng=True)

        result = self.run_cli(str(capture), "--summary")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Packets analyzed: 300", result.stdout)

    def test_report_outputs_cannot_overwrite_each_other_or_capture(self) -> None:
        capture = self.work_dir / "capture.pcap"
        write_capture(capture, [])
        result = self.run_cli(str(capture), "--json", str(capture))
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not overwrite", result.stderr)

        result = self.run_cli(
            str(capture),
            "--json",
            str(self.work_dir / "same.out"),
            "--html",
            str(self.work_dir / "same.out"),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("different output paths", result.stderr)

    def test_analyzer_does_not_import_network_upload_clients(self) -> None:
        forbidden = {
            "requests",
            "httpx",
            "socket",
            "urllib.request",
            "http.client",
            "ftplib",
        }
        for filename in ("droidleak.py", "droidleak_core.py", "droidleak_html.py"):
            tree = ast.parse((PROJECT_ROOT / filename).read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            self.assertFalse(
                forbidden.intersection(imported),
                f"{filename} imports a network client",
            )


if __name__ == "__main__":
    unittest.main()
