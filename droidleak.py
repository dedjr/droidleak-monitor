#!/usr/bin/env python3
"""Inspect user-provided PCAP/PCAPNG files locally for visible network metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.utils import PcapReader
except ImportError as exc:  # pragma: no cover - covered by the installation instructions
    raise SystemExit(
        "Scapy is required. Install it with: python -m pip install -r requirements.txt"
    ) from exc


TOOL_NAME = "DroidLeak Monitor"
TLS_PORTS = {443, 853, 8443, 9443}
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap",
    b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}
COORDINATE_PATTERN = re.compile(
    rb"(?<![\d.])"
    rb"(?P<latitude>[+-]?\d{1,2}(?:\.\d{1,8})?)"
    rb"\s*(?:,|;|\|)\s*"
    rb"(?P<longitude>[+-]?\d{1,3}(?:\.\d{1,8})?)"
    rb"(?![\d.])"
)
KNOWN_PROTOCOL_LAYERS = {
    "ARP",
    "DNS",
    "IP",
    "IPv6",
    "TCP",
    "UDP",
    "ICMP",
}


class CaptureError(Exception):
    """An input file could not be safely read as a packet capture."""


def _detect_capture_format(path: Path) -> str:
    try:
        with path.open("rb") as capture_file:
            magic = capture_file.read(4)
    except OSError as exc:
        raise CaptureError(f"Cannot read {path}: {exc.strerror or exc}") from exc

    if not magic:
        raise CaptureError("The input file is empty; it has no PCAP or PCAPNG header.")
    capture_format = PCAP_MAGICS.get(magic)
    if capture_format is None:
        raise CaptureError("Unsupported file: expected a PCAP or PCAPNG capture.")
    return capture_format


def _iter_packet_layers(packet: Any) -> Iterator[Any]:
    current = packet
    visited: set[int] = set()
    while current is not None and current.__class__.__name__ != "NoPayload":
        identity = id(current)
        if identity in visited:
            break
        visited.add(identity)
        yield current
        current = getattr(current, "payload", None)


def _packet_protocol_names(packet: Any) -> set[str]:
    names: set[str] = set()
    for layer in packet.layers():
        name = getattr(layer, "__name__", str(layer))
        if name in KNOWN_PROTOCOL_LAYERS:
            names.add(name)
        elif name.startswith("ICMPv6"):
            names.add("ICMPv6")
    if not names:
        names.add("Other")
    return names


def _dns_query_names(packet: Any) -> list[str]:
    dns_packet = packet.getlayer(DNS)
    if dns_packet is None or getattr(dns_packet, "qr", 1) != 0:
        return []

    query_names: list[str] = []
    queries = getattr(dns_packet, "qd", None)
    if isinstance(queries, DNSQR):
        queries = [queries]
    if not isinstance(queries, (list, tuple)):
        return query_names

    for query in queries:
        if not isinstance(query, DNSQR):
            continue
        raw_name = getattr(query, "qname", b"")
        if isinstance(raw_name, bytes):
            name = raw_name.decode("utf-8", errors="replace")
        else:
            name = str(raw_name)
        name = name.rstrip(".")
        if name:
            query_names.append(name)
    return query_names


def _transport_layer(packet: Any) -> Any | None:
    for layer in _iter_packet_layers(packet):
        if isinstance(layer, (TCP, UDP)):
            return layer
    return None


def _is_tls_or_encrypted(packet: Any, transport: Any, payload: bytes) -> bool:
    for layer in _iter_packet_layers(packet):
        if layer.__class__.__name__.startswith("TLS"):
            return True

    source_port = getattr(transport, "sport", None)
    destination_port = getattr(transport, "dport", None)
    if source_port in TLS_PORTS or destination_port in TLS_PORTS:
        return True

    # A TLS record commonly starts with content type 0x14-0x17 and version 0x03xx.
    # This is a conservative signature check for non-standard TLS ports.
    return (
        len(payload) >= 3
        and payload[0] in {0x14, 0x15, 0x16, 0x17}
        and payload[1] == 0x03
        and payload[2] <= 0x04
    )


def _short_context(payload: bytes, start: int, end: int) -> str:
    before = payload[max(0, start - 32) : start].decode("utf-8", errors="replace")
    matched = payload[start:end].decode("ascii", errors="replace")
    after = payload[end : end + 32].decode("utf-8", errors="replace")

    def clean(value: str) -> str:
        return " ".join(
            "".join(
                character if character.isprintable() else " "
                for character in value
            ).split()
        )

    parts = [clean(part) for part in (before, matched, after)]
    snippet = " ".join(part for part in parts if part)
    if start > 32:
        snippet = "… " + snippet
    if end + 32 < len(payload):
        snippet += " …"
    return snippet[:100]


def _coordinate_findings(packet: Any, packet_number: int) -> list[dict[str, Any]]:
    transport = _transport_layer(packet)
    if transport is None:
        return []

    try:
        payload = bytes(transport.payload)
    except Exception:
        return []
    if not payload or _is_tls_or_encrypted(packet, transport, payload):
        return []

    source_ip = destination_ip = None
    for layer in _iter_packet_layers(packet):
        if isinstance(layer, (IP, IPv6)):
            source_ip = source_ip or getattr(layer, "src", None)
            destination_ip = destination_ip or getattr(layer, "dst", None)

    if isinstance(transport, TCP):
        protocol = "TCP"
    else:
        protocol = "UDP"
    destination_port = getattr(transport, "dport", None)

    findings: list[dict[str, Any]] = []
    for match in COORDINATE_PATTERN.finditer(payload):
        try:
            latitude = float(match.group("latitude"))
            longitude = float(match.group("longitude"))
        except ValueError:
            continue
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            continue
        findings.append(
            {
                "packet_number": packet_number,
                "latitude": latitude,
                "longitude": longitude,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "destination_port": destination_port,
                "context": _short_context(payload, match.start(), match.end()),
                "finding_type": "potential_coordinate_pattern",
            }
        )
    return findings


def analyze_capture(path: Path, find_coordinates: bool = False) -> dict[str, Any]:
    """Analyze a PCAP or PCAPNG file without retaining or transmitting payloads."""
    path = path.expanduser()
    if not path.exists():
        raise CaptureError(f"Input file not found: {path}")
    if not path.is_file():
        raise CaptureError(f"Input path is not a regular file: {path}")

    capture_format = _detect_capture_format(path)
    protocol_counts: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    destination_ports: Counter[str] = Counter()
    dns_query_counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    packet_count = 0

    try:
        with PcapReader(str(path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                packet_count = packet_number
                layers = list(_iter_packet_layers(packet))
                for protocol_name in _packet_protocol_names(packet):
                    protocol_counts[protocol_name] += 1

                for layer in layers:
                    if isinstance(layer, (IP, IPv6)):
                        source_ip = getattr(layer, "src", None)
                        destination_ip = getattr(layer, "dst", None)
                        if source_ip:
                            source_ips[str(source_ip)] += 1
                        if destination_ip:
                            destination_ips[str(destination_ip)] += 1

                transport = _transport_layer(packet)
                if transport is not None:
                    destination_port = getattr(transport, "dport", None)
                    if destination_port is not None:
                        transport_name = "TCP" if isinstance(transport, TCP) else "UDP"
                        destination_ports[f"{transport_name}/{destination_port}"] += 1

                for query_name in _dns_query_names(packet):
                    dns_query_counts[query_name] += 1

                if find_coordinates:
                    findings.extend(_coordinate_findings(packet, packet_number))
    except Exception as exc:
        raise CaptureError(f"Could not parse capture {path.name}: {exc}") from exc

    return {
        "tool": TOOL_NAME,
        "schema_version": "1.0",
        "capture": {
            "name": path.name,
            "format": capture_format,
            "packet_count": packet_count,
        },
        "summary": {
            "packet_count": packet_count,
            "protocols": dict(sorted(protocol_counts.items())),
            "source_ips": dict(sorted(source_ips.items())),
            "destination_ips": dict(sorted(destination_ips.items())),
            "destination_ports": dict(sorted(destination_ports.items())),
        },
        "dns_queries": [
            {"name": name, "count": count}
            for name, count in sorted(dns_query_counts.items())
        ],
        "coordinate_scan_enabled": find_coordinates,
        "coordinate_findings": findings,
        "limitations": [
            "Only this user-supplied capture file was analyzed; this tool does not capture live traffic.",
            "HTTPS/TLS-encrypted payloads are not readable and are excluded from coordinate scanning.",
            "Network metadata and pattern matches are observations, not proof of a privacy leak.",
            "The tool does not identify which installed app generated a packet.",
        ],
    }


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none observed"
    return ", ".join(f"{key}: {value}" for key, value in counts.items())


def render_report(report: dict[str, Any], summary_only: bool = False) -> str:
    summary = report["summary"]
    capture = report["capture"]
    lines = [
        f"{TOOL_NAME} — local capture analysis",
        f"Capture: {capture['name']} ({capture['format']})",
        f"Packets analyzed: {summary['packet_count']}",
        "Protocol layers (counts can overlap): "
        + _format_counts(summary["protocols"]),
        "Source IPs: " + _format_counts(summary["source_ips"]),
        "Destination IPs: " + _format_counts(summary["destination_ips"]),
        "Destination ports: " + _format_counts(summary["destination_ports"]),
    ]

    if not summary_only:
        if report["dns_queries"]:
            rendered_queries = ", ".join(
                f"{entry['name']} ({entry['count']})"
                for entry in report["dns_queries"]
            )
            lines.append("Visible DNS query names: " + rendered_queries)
        else:
            lines.append("Visible DNS query names: none observed")

        if not report["coordinate_scan_enabled"]:
            lines.append(
                "Coordinate scan: not requested; use --find-coordinates to scan "
                "accessible payload bytes."
            )
        elif not report["coordinate_findings"]:
            lines.append("Potential coordinate patterns: none found")
        else:
            lines.append(
                "Potential coordinate patterns (not confirmed leaks):"
            )
            for finding in report["coordinate_findings"]:
                endpoint = " -> ".join(
                    value or "unknown"
                    for value in (
                        finding["source_ip"],
                        finding["destination_ip"],
                    )
                )
                port = finding["destination_port"]
                port_label = f"/{port}" if port is not None else ""
                lines.append(
                    f"  packet {finding['packet_number']}: "
                    f"{finding['latitude']}, {finding['longitude']} "
                    f"({finding['protocol']}{port_label}; {endpoint}) "
                    f"context: {finding['context']!r}"
                )

    lines.append(
        "Note: TLS-encrypted payloads are unreadable here; metadata and matches "
        "do not prove a privacy leak or identify an installed app."
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
    parser.add_argument("capture", type=Path, help="PCAP or PCAPNG file to analyze")
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        metavar="REPORT.json",
        help="write a machine-readable JSON report to this path",
    )
    parser.add_argument(
        "--find-coordinates",
        action="store_true",
        help="scan accessible, non-TLS payload bytes for potential coordinate pairs",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="print only packet and network metadata in the terminal",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = analyze_capture(args.capture, find_coordinates=args.find_coordinates)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_path is not None:
        try:
            capture_path = args.capture.expanduser().resolve()
            report_path = args.json_path.expanduser().resolve()
            if capture_path == report_path:
                print(
                    "error: the JSON report path must not overwrite the capture file",
                    file=sys.stderr,
                )
                return 2
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"error: cannot write JSON report: {exc}", file=sys.stderr)
            return 2

    print(render_report(report, summary_only=args.summary))
    if args.json_path is not None:
        print(f"JSON report written to: {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
