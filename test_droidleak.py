import json
import subprocess
import sys
import unittest
from pathlib import Path


class DroidLeakTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "droidleak.py", *args],
            capture_output=True,
            text=True,
        )

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())

    def test_valid_pcap_and_json(self):
        result = self.run_cli("test_dns.pcap", "--json", "test_report.json")
        self.assertEqual(result.returncode, 0, result.stderr)

        report = json.loads(Path("test_report.json").read_text())
        self.assertEqual(report["packets_seen"], 1)
        self.assertEqual(report["protocols"]["UDP"], 1)
        self.assertIn("example.com", report["dns_queries"])

    def test_broken_pcap_rejected(self):
        Path("broken_test.pcap").write_text("not a pcap")
        result = self.run_cli("broken_test.pcap")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_file_rejected(self):
        result = self.run_cli("file-yang-tidak-ada.pcap")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
