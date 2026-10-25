#!/usr/bin/env python3
"""Command-line interface for DroidLeak Monitor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from droidleak_core import (
    TOOL_NAME,
    TOOL_VERSION,
    CaptureError,
    analyze_capture,
    parse_dns_payload,
)
from droidleak_html import render_html_report


def parse_dns_query(payload: bytes) -> dict[str, Any] | None:
    """Backward-compatible DNS payload parser."""
    return parse_dns_payload(payload)


def analyze_pcap(filename: str | Path) -> dict[str, Any]:
    """Backward-compatible entry point for programmatic callers."""
    return analyze_capture(Path(filename))


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none observed"
    return ", ".join(f"{key}: {value}" for key, value in counts.items())


def _duration(value: Any) -> str:
    if value is None:
        return "not available"
    return f"{value:.3f} seconds"


def render_report(report: dict[str, Any], summary_only: bool = False) -> str:
    """Render a concise, masked terminal report."""
    capture = report["capture"]
    summary = report["summary"]
    assessment = report["risk_assessment"]
    lines = [
        f"{TOOL_NAME} {report['tool_version']} — local capture analysis",
        f"Capture: {capture['name']} ({capture['format']}) · "
        f"{capture['file_size_bytes']:,} bytes",
        f"Duration: {_duration(capture['duration_seconds'])}",
        f"Packets analyzed: {summary['packet_count']:,}",
        f"Unique domains: {summary['unique_domain_count']:,} | "
        f"IP addresses: {summary['unique_ip_count']:,} | "
        f"Connections: {summary['connection_count']:,}",
        f"Visible HTTP requests: {summary['http_request_count']:,} | "
        f"Encrypted/unknown packets: {summary['encrypted_or_unknown_packet_count']:,}",
        f"Protocol layers (counts can overlap): {_format_counts(summary['protocols'])}",
        "Source IPs: " + _format_counts(summary["source_ips"]),
        "Destination IPs: " + _format_counts(summary["destination_ips"]),
        "Destination ports: " + _format_counts(summary["destination_ports"]),
    ]

    if not summary_only:
        queries = report["dns"]["queries"]
        answers = report["dns"]["answers"]
        lines.append(
            "DNS queries: "
            + (
                ", ".join(f"{item['name']} ({item['count']})" for item in queries[:8])
                if queries
                else "none observed"
            )
        )
        lines.append(
            "DNS A/AAAA answers: "
            + (
                ", ".join(
                    f"{item['name']} {item['record_type']}={item['address']}"
                    for item in answers[:8]
                )
                if answers
                else "none observed"
            )
        )

        request_entries = report["http"]["requests"]
        if request_entries:
            lines.append("Visible HTTP requests:")
            for request in request_entries[:5]:
                host = request["host"] or "host not present"
                lines.append(
                    f"  packet {request['packet_number']}: "
                    f"{request['method']} {host} "
                    f"({request['source']} -> {request['destination']})"
                )
        else:
            lines.append("Visible HTTP requests: none observed")

        tls_names = report["tls"]["client_hello_server_names"]
        if tls_names:
            names = ", ".join(
                f"{item['server_name']} (packet {item['packet_number']})"
                for item in tls_names[:8]
            )
            lines.append("TLS ClientHello server-name metadata (not decrypted): " + names)

        findings = report["findings"]
        if findings:
            lines.append(
                f"Sensitive-data indicators: {summary['finding_count']} "
                "(values masked; inspect each as evidence, not proof of harm)"
            )
            for finding in findings[:8]:
                lines.append(
                    f"  {finding['severity'].upper()} {finding['evidence_category']}: "
                    f"{finding['type']} at packet {finding['packet_number']} "
                    f"({finding['evidence_excerpt']})"
                )
            if report["findings_truncated"]:
                lines.append("  Additional findings were counted but omitted from the report.")
        else:
            lines.append("Sensitive-data indicators: none found in inspected bytes")

        if report["coordinate_scan_enabled"]:
            coordinate_count = len(report["coordinate_findings"])
            lines.append(
                f"Potential coordinate patterns (not confirmed leaks): {coordinate_count}"
            )
            for finding in report["coordinate_findings"][:5]:
                lines.append(
                    f"  packet {finding['packet_number']}: "
                    f"{finding['latitude']}, {finding['longitude']} "
                    f"({finding['protocol']} to {finding.get('destination') or 'unknown'}) "
                    f"context: {finding['context']!r}"
                )
        else:
            lines.append(
                "Coordinate scan: not requested; use --find-coordinates to scan "
                "accessible, non-encrypted packet payloads."
            )

        lines.extend(
            [
                f"Assessment: {assessment['headline']} "
                f"[{assessment['category']}; severity: {assessment['severity']}]",
                f"  {assessment['reasoning']}",
                "Limitations:",
            ]
        )
        lines.extend(f"  - {limitation}" for limitation in report["limitations"][:6])

    lines.append(
        "Privacy: analysis stays local. TLS/HTTPS/QUIC/VPN payloads are not decrypted. "
        "A clean result does not prove the device is free of leaks."
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a user-provided PCAP/PCAPNG file locally. "
            "This is not a live traffic monitor and does not decrypt TLS."
        ),
        epilog=(
            "Use only captures you are authorized to inspect. "
            "No capture or report data is uploaded."
        ),
    )
    parser.add_argument(
        "capture",
        type=Path,
        nargs="?",
        help="PCAP or PCAPNG file to analyze",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        metavar="REPORT.json",
        help="write a machine-readable JSON report to this path",
    )
    parser.add_argument(
        "--html",
        dest="html_path",
        type=Path,
        metavar="REPORT.html",
        help="write a standalone, phone-friendly HTML report to this path",
    )
    parser.add_argument(
        "--find-coordinates",
        action="store_true",
        help="scan accessible, non-encrypted payload bytes for potential coordinate pairs",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="print only capture and network metadata in the terminal",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    return parser


def _output_paths(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, Path]:
    outputs: dict[str, Path] = {}
    for name in ("json_path", "html_path"):
        path = getattr(args, name)
        if path is not None:
            outputs[name] = path.expanduser().resolve()
    capture_path = args.capture.expanduser().resolve()
    if capture_path in outputs.values():
        parser.error("report output path must not overwrite the capture file")
    if len(set(outputs.values())) != len(outputs):
        parser.error("JSON and HTML reports must use different output paths")
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.capture is None:
        parser.print_help()
        return 0
    outputs = _output_paths(args, parser)

    try:
        report = analyze_capture(args.capture, find_coordinates=args.find_coordinates)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        if "json_path" in outputs:
            json_path = outputs["json_path"]
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        if "html_path" in outputs:
            html_path = outputs["html_path"]
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(render_html_report(report), encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write report: {exc}", file=sys.stderr)
        return 2

    print(render_report(report, summary_only=args.summary))
    if "json_path" in outputs:
        print(f"JSON report written to: {outputs['json_path']}")
    if "html_path" in outputs:
        print(f"HTML report written to: {outputs['html_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
