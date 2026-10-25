"""Streaming analysis helpers for user-provided PCAP and PCAPNG files."""

from __future__ import annotations

import re
from collections import Counter
from math import isfinite
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote_plus

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader
except ImportError as exc:  # pragma: no cover - covered by installation instructions
    raise SystemExit(
        "Scapy is required. Install it with: python -m pip install -r requirements.txt"
    ) from exc


TOOL_NAME = "DroidLeak Monitor"
TOOL_VERSION = "2.0.0"
SCHEMA_VERSION = "2.0"
TLS_PORTS = {443, 853, 8443, 9443}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
MAX_INSPECTABLE_PAYLOAD_BYTES = 64 * 1024
MAX_RETAINED_FINDINGS = 1000
MAX_RETAINED_HTTP_REQUESTS = 1000
MAX_RETAINED_TLS_HANDSHAKES = 1000

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
HTTP_REQUEST_LINE = re.compile(
    rb"^(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|CONNECT)"
    rb"\s+\S+\s+HTTP/(?P<version>1\.[01])(?:\r?\n|$)",
    re.IGNORECASE,
)
EMAIL_FIELD_PATTERN = re.compile(
    r"""(?ix)
    \b(?:email|e[-_]?mail|user[-_]?email|contact[-_]?email)\b
    \s*["']?\s*[:=]\s*["']?
    (?P<value>[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})
    """
)
PHONE_FIELD_PATTERN = re.compile(
    r"""(?ix)
    \b(?:phone|phone[-_]?number|mobile|msisdn)\b
    \s*["']?\s*[:=]\s*["']?
    (?P<value>\+?[0-9][0-9 ()-]{5,}[0-9])
    """
)
SECRET_FIELD_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<key>password|passwd|passcode|access[-_]?token|refresh[-_]?token|
    auth[-_]?token|api[-_]?key|client[-_]?secret|secret|session[-_]?token)\b
    \s*["']?\s*[:=]\s*["']?
    ["']?(?P<value>[^"'&,\s;}]+)
    """
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?im)^authorization\s*:\s*(?P<scheme>[a-z][a-z0-9_-]*)\s+(?P<value>[^\r\n]+)"
)
COOKIE_PATTERN = re.compile(r"(?im)^cookie\s*:\s*(?P<value>[^\r\n]+)")
SET_COOKIE_PATTERN = re.compile(
    r"(?im)^set-cookie\s*:\s*(?P<name>[^=;\r\n]+)\s*=\s*(?P<value>[^;\r\n]+)"
)
SESSION_COOKIE_NAME = re.compile(
    r"(?i)(?:session|sessid|auth|token|sid|jwt|access|refresh|login)"
)
HOST_PATTERN = re.compile(r"(?im)^host\s*:\s*(?P<value>[^\r\n]+)")

KNOWN_PROTOCOL_LAYERS = {"ARP", "DNS", "IP", "IPv6", "TCP", "UDP", "ICMP"}


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


def _iter_dns_records(records: Any, record_type: type) -> Iterator[Any]:
    if isinstance(records, (list, tuple)):
        for record in records:
            if isinstance(record, record_type):
                yield record
        return

    current = records
    visited: set[int] = set()
    while current is not None and current.__class__.__name__ != "NoPayload":
        identity = id(current)
        if identity in visited:
            return
        visited.add(identity)
        if isinstance(current, record_type):
            yield current
        current = getattr(current, "payload", None)


def _dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".").lower()
    return str(value or "").rstrip(".").lower()


def parse_dns_payload(payload: bytes) -> dict[str, Any] | None:
    """Compatibility helper for callers that previously parsed raw DNS payloads."""
    if len(payload) < 12:
        return None
    try:
        dns_packet = DNS(payload)
        queries = [
            _dns_name(getattr(record, "qname", b""))
            for record in _iter_dns_records(getattr(dns_packet, "qd", None), DNSQR)
            if int(getattr(record, "qclass", 0)) == 1
        ]
        answers = []
        if getattr(dns_packet, "qr", 0):
            for record in _iter_dns_records(getattr(dns_packet, "an", None), DNSRR):
                record_type = int(getattr(record, "type", 0))
                if int(getattr(record, "rclass", 0)) != 1 or record_type not in {1, 28}:
                    continue
                name = _dns_name(getattr(record, "rrname", b""))
                address = str(getattr(record, "rdata", ""))
                if name and address:
                    answers.append(
                        {
                            "name": name,
                            "type": "A" if record_type == 1 else "AAAA",
                            "address": address,
                        }
                    )
        return {
            "queries": [name for name in queries if name],
            "answers": answers,
            "is_response": bool(getattr(dns_packet, "qr", 0)),
        }
    except Exception:
        return None


def _packet_protocol_names(packet: Any) -> set[str]:
    names: set[str] = set()
    try:
        packet_layers = packet.layers()
    except Exception:
        packet_layers = []
    for layer in packet_layers:
        name = getattr(layer, "__name__", str(layer))
        if name in KNOWN_PROTOCOL_LAYERS:
            names.add(name)
        elif name.startswith("ICMPv6"):
            names.add("ICMPv6")
    if not names:
        names.add("Other")
    return names


def _first_ip_endpoints(packet: Any) -> tuple[str | None, str | None]:
    for layer in _iter_packet_layers(packet):
        if isinstance(layer, (IP, IPv6)):
            return (
                str(getattr(layer, "src", "")) or None,
                str(getattr(layer, "dst", "")) or None,
            )
    return None, None


def _transport_layer(packet: Any) -> Any | None:
    for layer in _iter_packet_layers(packet):
        if isinstance(layer, (TCP, UDP)):
            return layer
    return None


def _endpoint(ip_address: str | None, port: Any) -> str | None:
    if ip_address is None:
        return None
    if port is None:
        return ip_address
    if ":" in ip_address:
        return f"[{ip_address}]:{port}"
    return f"{ip_address}:{port}"


def _payload_bytes(transport: Any) -> bytes:
    try:
        return bytes(transport.payload)[:MAX_INSPECTABLE_PAYLOAD_BYTES]
    except Exception:
        return b""


def _has_tls_record(payload: bytes) -> bool:
    return (
        len(payload) >= 3
        and payload[0] in {0x14, 0x15, 0x16, 0x17}
        and payload[1] == 0x03
        and payload[2] <= 0x04
    )


def _is_encrypted_or_unknown(packet: Any, transport: Any, payload: bytes) -> bool:
    if any(layer.__class__.__name__.startswith("TLS") for layer in _iter_packet_layers(packet)):
        return True
    ports = {
        getattr(transport, "sport", None),
        getattr(transport, "dport", None),
    }
    if ports.intersection(TLS_PORTS):
        return True
    if isinstance(transport, UDP) and 443 in ports:  # QUIC traffic is encrypted.
        return True
    return _has_tls_record(payload)


def _extract_tls_sni(payload: bytes) -> str | None:
    """Read an unencrypted ClientHello SNI extension without decrypting traffic."""
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    if record_length + 5 > len(payload) or payload[5] != 0x01:
        return None
    handshake_length = int.from_bytes(payload[6:9], "big")
    handshake_end = min(9 + handshake_length, 5 + record_length)
    if handshake_end > len(payload):
        return None

    offset = 9
    if offset + 34 > handshake_end:  # legacy_version + random
        return None
    offset += 34
    if offset >= handshake_end:
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length
    if offset + 2 > handshake_end:
        return None
    cipher_suites_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2 + cipher_suites_length
    if offset >= handshake_end:
        return None
    compression_length = payload[offset]
    offset += 1 + compression_length
    if offset + 2 > handshake_end:
        return None
    extensions_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    extensions_end = min(offset + extensions_length, handshake_end)

    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(payload[offset : offset + 2], "big")
        extension_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        extension_start = offset + 4
        extension_end = extension_start + extension_length
        if extension_end > extensions_end:
            return None
        if extension_type == 0 and extension_length >= 5:
            names_start = extension_start + 2
            names_end = min(
                names_start + int.from_bytes(payload[extension_start : extension_start + 2], "big"),
                extension_end,
            )
            cursor = names_start
            while cursor + 3 <= names_end:
                name_type = payload[cursor]
                name_length = int.from_bytes(payload[cursor + 1 : cursor + 3], "big")
                name_start = cursor + 3
                name_end = name_start + name_length
                if name_end > names_end:
                    return None
                if name_type == 0:
                    try:
                        return payload[name_start:name_end].decode("idna")
                    except UnicodeError:
                        return None
                cursor = name_end
        offset = extension_end
    return None


def _http_request(payload: bytes) -> dict[str, str] | None:
    match = HTTP_REQUEST_LINE.match(payload)
    if match is None:
        return None
    text = payload.decode("utf-8", errors="replace")
    if text.count("\ufffd") > max(1, len(text) // 100):
        return None
    method = match.group("method").decode("ascii").upper()
    version = match.group("version").decode("ascii")
    host_match = HOST_PATTERN.search(text)
    host = host_match.group("value").strip() if host_match else ""
    host = host.split(",", 1)[0].strip().lower()
    if len(host) > 253 or any(ord(char) < 32 for char in host):
        host = ""
    return {"method": method, "version": version, "host": host}


def _is_http_response(payload: bytes) -> bool:
    return re.match(rb"^HTTP/1\.[01]\s+[1-5][0-9][0-9](?:\s|$)", payload) is not None


def _mask_secret(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    if not value:
        return "[redacted]"
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        if local:
            return f"{local[0]}***@{domain}"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}…{value[-2:]}"


def _finding(
    *,
    finding_type: str,
    evidence_category: str,
    packet_number: int,
    source: str | None,
    destination: str | None,
    protocol: str,
    excerpt: str,
    severity: str,
    confidence: str,
    explanation: str,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "evidence_category": evidence_category,
        "packet_number": packet_number,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "encryption_status": "plaintext_http",
        "severity": severity,
        "confidence": confidence,
        "evidence_excerpt": excerpt[:120],
        "explanation": explanation,
        "limitations": (
            "This finding shows bytes visible in one captured packet. The analyzer "
            "does not reassemble TCP streams or establish who controlled either endpoint."
        ),
    }


def _http_findings(
    payload: bytes,
    packet_number: int,
    source: str | None,
    destination: str | None,
) -> list[dict[str, Any]]:
    text = payload.decode("utf-8", errors="replace")
    headers, separator, body = text.partition("\r\n\r\n")
    if not separator:
        headers, separator, body = text.partition("\n\n")
    if separator:
        text = headers + separator + unquote_plus(body)
    findings: list[dict[str, Any]] = []

    for match in AUTHORIZATION_PATTERN.finditer(text):
        scheme = match.group("scheme").capitalize()
        findings.append(
            _finding(
                finding_type="http_authorization_header",
                evidence_category="confirmed_exposure",
                packet_number=packet_number,
                source=source,
                destination=destination,
                protocol="HTTP",
                excerpt=f"Authorization: {scheme} {_mask_secret(match.group('value'))}",
                severity="high",
                confidence="high",
                explanation=(
                    "An HTTP authorization value is visible in a plaintext request. "
                    "The value is masked in this report."
                ),
            )
        )

    for match in COOKIE_PATTERN.finditer(text):
        cookie_pairs = []
        for pair in match.group("value").split(";"):
            name, separator, value = pair.strip().partition("=")
            if separator and name and SESSION_COOKIE_NAME.search(name):
                cookie_pairs.append(f"{name}={_mask_secret(value)}")
        if cookie_pairs:
            findings.append(
                _finding(
                    finding_type="http_cookie",
                    evidence_category="confirmed_exposure",
                    packet_number=packet_number,
                    source=source,
                    destination=destination,
                    protocol="HTTP",
                    excerpt="Cookie: " + "; ".join(cookie_pairs[:4]),
                    severity="high",
                    confidence="high",
                    explanation=(
                        "A session- or authentication-like cookie value is visible in a "
                        "plaintext HTTP request. The value is masked in this report."
                    ),
                )
            )

    for match in SET_COOKIE_PATTERN.finditer(text):
        name = match.group("name").strip()
        if SESSION_COOKIE_NAME.search(name):
            findings.append(
                _finding(
                    finding_type="http_cookie",
                    evidence_category="confirmed_exposure",
                    packet_number=packet_number,
                    source=source,
                    destination=destination,
                    protocol="HTTP",
                    excerpt=f"Set-Cookie: {name}={_mask_secret(match.group('value'))}",
                    severity="high",
                    confidence="high",
                    explanation=(
                        "A session- or authentication-like cookie value is visible in "
                        "plaintext HTTP. The value is masked in this report."
                    ),
                )
            )

    for match in SECRET_FIELD_PATTERN.finditer(text):
        key = match.group("key")
        findings.append(
            _finding(
                finding_type="plaintext_sensitive_field",
                evidence_category="confirmed_exposure",
                packet_number=packet_number,
                source=source,
                destination=destination,
                protocol="HTTP",
                excerpt=f"{key}={_mask_secret(match.group('value'))}",
                severity="high",
                confidence="medium",
                explanation=(
                    "A field with a credential or token-like name and a non-empty "
                    "value is visible in a plaintext HTTP request."
                ),
            )
        )

    for match in EMAIL_FIELD_PATTERN.finditer(text):
        findings.append(
            _finding(
                finding_type="context_labelled_email",
                evidence_category="potential_exposure",
                packet_number=packet_number,
                source=source,
                destination=destination,
                protocol="HTTP",
                excerpt=f"email={_mask_secret(match.group('value'))}",
                severity="medium",
                confidence="medium",
                explanation=(
                    "An email-like value appears next to an email field label in a "
                    "plaintext HTTP request; the analyzer cannot verify whose address it is."
                ),
            )
        )

    for match in PHONE_FIELD_PATTERN.finditer(text):
        findings.append(
            _finding(
                finding_type="context_labelled_phone",
                evidence_category="potential_exposure",
                packet_number=packet_number,
                source=source,
                destination=destination,
                protocol="HTTP",
                excerpt=f"phone={_mask_secret(match.group('value'))}",
                severity="medium",
                confidence="low",
                explanation=(
                    "A phone-like value appears next to a phone field label in a "
                    "plaintext HTTP request; format matching can produce false positives."
                ),
            )
        )
    return findings


def _coordinate_findings(
    payload: bytes,
    packet_number: int,
    source: str | None,
    destination: str | None,
    protocol: str,
    destination_port: int | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in COORDINATE_PATTERN.finditer(payload):
        try:
            latitude = float(match.group("latitude"))
            longitude = float(match.group("longitude"))
        except ValueError:
            continue
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            continue
        text = payload.decode("utf-8", errors="replace")
        start = max(0, match.start() - 32)
        end = min(len(payload), match.end() + 32)
        context = " ".join(text[start:end].replace("\r", " ").replace("\n", " ").split())
        context = re.sub(
            r"(?i)(password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^&\s,;]+",
            r"\1=[redacted]",
            context,
        )
        context = re.sub(
            r"(?i)\b(?:authorization|cookie|set-cookie)\s*:\s*[^\r\n]*",
            "[redacted-header]",
            context,
        )
        context = re.sub(
            r"(?i)\b(?:email|e[-_]?mail|phone(?:[-_]?number)?|mobile|msisdn)"
            r"\s*[:=]\s*[^&\s,;]+",
            "[redacted-personal-field]",
            context,
        )
        context = re.sub(
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            "[masked-email]",
            context,
            flags=re.IGNORECASE,
        )
        findings.append(
            {
                "type": "potential_coordinate_pattern",
                "finding_type": "potential_coordinate_pattern",
                "evidence_category": "potential_exposure",
                "packet_number": packet_number,
                "latitude": latitude,
                "longitude": longitude,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "destination_port": destination_port,
                "encryption_status": "not_observed_in_packet",
                "severity": "medium",
                "confidence": "low",
                "evidence_excerpt": f"…{latitude}, {longitude}…",
                "context": context[:100],
                "explanation": (
                    "A coordinate-shaped numeric pair was found in accessible payload "
                    "bytes. This pattern alone does not confirm that it is a real location "
                    "or that it was leaked."
                ),
                "limitations": (
                    "Pattern matching can produce false positives. The scan does not "
                    "inspect TLS, QUIC, VPN, or other encrypted payloads."
                ),
            }
        )
    return findings


def _flow_key(
    protocol: str,
    source: str | None,
    source_port: Any,
    destination: str | None,
    destination_port: Any,
) -> tuple[str, str, str]:
    first = _endpoint(source, source_port) or "unknown"
    second = _endpoint(destination, destination_port) or "unknown"
    low, high = sorted((first, second))
    return protocol, low, high


def _risk_assessment(
    findings: list[dict[str, Any]],
    packet_count: int,
    encrypted_packets: int,
    all_categories: set[str] | None = None,
    highest_severity_seen: str | None = None,
) -> dict[str, str]:
    categories = {item["evidence_category"] for item in findings}
    if all_categories:
        categories.update(all_categories)
    severity_order = {"high": 3, "medium": 2, "low": 1, "informational": 0}
    highest = max(
        [item["severity"] for item in findings]
        + ([highest_severity_seen] if highest_severity_seen else []),
        key=lambda severity: severity_order.get(severity, 0),
        default="none",
    )
    if "confirmed_exposure" in categories:
        category = "confirmed_exposure"
        headline = "Sensitive-looking content is visible in plaintext HTTP."
        reasoning = (
            "At least one inspectable HTTP request contained a credential-like field, "
            "authorization header, or cookie. Values are masked; this does not prove "
            "the remote endpoint's identity or subsequent use."
        )
    elif "potential_exposure" in categories:
        category = "potential_exposure"
        headline = "Potential sensitive-data indicators were found."
        reasoning = (
            "A context-labelled personal-data value or opt-in coordinate pattern was "
            "visible, but the capture alone does not establish personal ownership or harm."
        )
    elif packet_count == 0:
        category = "insufficient_data"
        headline = "The capture contains no packets to assess."
        reasoning = "An empty capture cannot support a privacy assessment."
    elif encrypted_packets:
        category = "encrypted_unknown"
        headline = "Some traffic was encrypted or could not be inspected."
        reasoning = (
            "No qualifying plaintext finding was identified, but encrypted or ambiguous "
            "traffic and capture coverage remain unknown."
        )
    else:
        category = "no_evidence_found"
        headline = "No qualifying sensitive-data indicator was found."
        reasoning = (
            "This describes only the inspected bytes and metadata. It does not prove that "
            "the device or application is free of leaks."
        )
    return {
        "category": category,
        "severity": highest,
        "headline": headline,
        "reasoning": reasoning,
    }


def analyze_capture(path: Path, find_coordinates: bool = False) -> dict[str, Any]:
    """Analyze a supplied capture, retaining metadata but not raw payloads."""
    path = path.expanduser()
    if not path.exists():
        raise CaptureError(f"Input file not found: {path}")
    if not path.is_file():
        raise CaptureError(f"Input path is not a regular file: {path}")

    capture_format = _detect_capture_format(path)
    try:
        file_size_bytes = path.stat().st_size
    except OSError as exc:
        raise CaptureError(f"Cannot inspect {path}: {exc.strerror or exc}") from exc

    protocol_counts: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    destination_ports: Counter[str] = Counter()
    endpoint_flow_counts: Counter[str] = Counter()
    dns_query_counts: Counter[str] = Counter()
    dns_answer_counts: Counter[tuple[str, str, str]] = Counter()
    connection_stats: dict[tuple[str, str, str], dict[str, Any]] = {}
    http_requests: list[dict[str, Any]] = []
    http_hosts: set[str] = set()
    tls_handshakes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    finding_categories: set[str] = set()
    highest_severity_seen: str | None = None
    finding_count = 0
    http_request_count = 0
    tls_or_unknown_packet_count = 0
    packet_count = 0
    timestamp_min: float | None = None
    timestamp_max: float | None = None
    timestamp_count = 0
    parsing_warning_count = 0

    def retain_finding(finding: dict[str, Any]) -> None:
        nonlocal finding_count, highest_severity_seen
        finding_count += 1
        finding_categories.add(finding["evidence_category"])
        severity_order = {"high": 3, "medium": 2, "low": 1, "informational": 0}
        if (
            highest_severity_seen is None
            or severity_order.get(finding["severity"], 0)
            > severity_order.get(highest_severity_seen, 0)
        ):
            highest_severity_seen = finding["severity"]
        if len(findings) < MAX_RETAINED_FINDINGS:
            findings.append(finding)

    try:
        with PcapReader(str(path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                packet_count = packet_number
                try:
                    for protocol_name in _packet_protocol_names(packet):
                        protocol_counts[protocol_name] += 1

                    source_ip, destination_ip = _first_ip_endpoints(packet)
                    if source_ip:
                        source_ips[source_ip] += 1
                    if destination_ip:
                        destination_ips[destination_ip] += 1

                    try:
                        timestamp = float(packet.time)
                        if isfinite(timestamp):
                            timestamp_count += 1
                            timestamp_min = (
                                timestamp if timestamp_min is None else min(timestamp_min, timestamp)
                            )
                            timestamp_max = (
                                timestamp if timestamp_max is None else max(timestamp_max, timestamp)
                            )
                    except (AttributeError, TypeError, ValueError, OverflowError):
                        pass

                    dns_packet = packet.getlayer(DNS)
                    if dns_packet is not None:
                        if getattr(dns_packet, "qr", 1) == 0:
                            for query in _iter_dns_records(getattr(dns_packet, "qd", None), DNSQR):
                                name = _dns_name(getattr(query, "qname", b""))
                                if name:
                                    dns_query_counts[name] += 1
                        else:
                            for answer in _iter_dns_records(getattr(dns_packet, "an", None), DNSRR):
                                record_type = int(getattr(answer, "type", 0))
                                if record_type not in {1, 28}:
                                    continue
                                name = _dns_name(getattr(answer, "rrname", b""))
                                address = str(getattr(answer, "rdata", ""))
                                if name and address:
                                    type_name = "A" if record_type == 1 else "AAAA"
                                    dns_answer_counts[(name, type_name, address)] += 1

                    transport = _transport_layer(packet)
                    if transport is None:
                        continue
                    protocol = "TCP" if isinstance(transport, TCP) else "UDP"
                    source_port = getattr(transport, "sport", None)
                    destination_port = getattr(transport, "dport", None)
                    if destination_port is not None:
                        destination_ports[f"{protocol}/{destination_port}"] += 1

                    source_endpoint = _endpoint(source_ip, source_port)
                    destination_endpoint = _endpoint(destination_ip, destination_port)
                    endpoint_flow_counts[
                        f"{source_endpoint or 'unknown'} -> {destination_endpoint or 'unknown'}"
                    ] += 1
                    flow = _flow_key(
                        protocol,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                    )
                    if flow not in connection_stats:
                        connection_stats[flow] = {
                            "protocol": protocol,
                            "source": source_endpoint,
                            "destination": destination_endpoint,
                            "packets": 0,
                        }
                    connection_stats[flow]["packets"] += 1

                    payload = _payload_bytes(transport)
                    encrypted_or_unknown = _is_encrypted_or_unknown(packet, transport, payload)
                    if encrypted_or_unknown:
                        tls_or_unknown_packet_count += 1
                        server_name = _extract_tls_sni(payload)
                        if server_name and len(tls_handshakes) < MAX_RETAINED_TLS_HANDSHAKES:
                            tls_handshakes.append(
                                {
                                    "packet_number": packet_number,
                                    "server_name": server_name,
                                    "metadata_only": True,
                                }
                            )
                    elif isinstance(transport, TCP) and payload:
                        request = _http_request(payload)
                        if request is not None:
                            http_request_count += 1
                            if request["host"]:
                                http_hosts.add(request["host"])
                            if len(http_requests) < MAX_RETAINED_HTTP_REQUESTS:
                                http_requests.append(
                                    {
                                        "packet_number": packet_number,
                                        "method": request["method"],
                                        "host": request["host"] or None,
                                        "http_version": request["version"],
                                        "source": source_endpoint,
                                        "destination": destination_endpoint,
                                    }
                                )
                            retain_finding_batch = _http_findings(
                                payload,
                                packet_number,
                                source_endpoint,
                                destination_endpoint,
                            )
                            for finding in retain_finding_batch:
                                retain_finding(finding)
                        elif _is_http_response(payload):
                            # Response data is not described as an outgoing request;
                            # the current detectors only inspect headers/body for
                            # fields with explicit sensitive labels.
                            for finding in _http_findings(
                                payload,
                                packet_number,
                                source_endpoint,
                                destination_endpoint,
                            ):
                                finding["evidence_category"] = "potential_exposure"
                                finding["severity"] = "medium"
                                finding["explanation"] = (
                                    "A labelled sensitive value is visible in a "
                                    "plaintext HTTP response; this does not show that "
                                    "the device sent it to a third party."
                                )
                                retain_finding(finding)

                    if find_coordinates and payload and not encrypted_or_unknown:
                        for finding in _coordinate_findings(
                            payload,
                            packet_number,
                            source_endpoint,
                            destination_endpoint,
                            protocol,
                            destination_port,
                        ):
                            retain_finding(finding)
                except Exception:
                    # A malformed or unusual packet must not prevent the rest of
                    # the user-supplied capture from being summarized.
                    parsing_warning_count += 1
    except CaptureError:
        raise
    except Exception as exc:
        raise CaptureError(f"Could not parse capture {path.name}: {exc}") from exc

    dns_queries = [
        {"name": name, "count": count}
        for name, count in sorted(dns_query_counts.items())
    ]
    dns_answers = [
        {
            "name": name,
            "record_type": record_type,
            "address": address,
            "count": count,
        }
        for (name, record_type, address), count in sorted(dns_answer_counts.items())
    ]
    observed_domains = (
        set(dns_query_counts)
        | {name for name, _, _ in dns_answer_counts}
        | http_hosts
    )
    unique_ip_addresses = set(source_ips) | set(destination_ips)
    duration_seconds = (
        timestamp_max - timestamp_min
        if timestamp_min is not None and timestamp_max is not None and timestamp_count >= 2
        else (0.0 if timestamp_count == 1 else None)
    )
    connections = [
        connection_stats[key]
        for key in sorted(connection_stats)
    ]
    coordinate_findings = [
        finding for finding in findings
        if finding["type"] == "potential_coordinate_pattern"
    ]
    risk_assessment = _risk_assessment(
        findings,
        packet_count,
        tls_or_unknown_packet_count,
        finding_categories,
        highest_severity_seen,
    )

    limitations = [
        "Only the user-supplied capture was analyzed. This tool does not capture live traffic or identify installed Android apps.",
        "HTTPS, TLS, QUIC, VPN, and encrypted DNS payloads are not decrypted or inspected.",
        "DNS-over-HTTPS and DNS-over-TLS can hide query names; only DNS records present in the capture are shown.",
        "HTTP inspection is limited to recognizable request data in individual packets; TCP streams and fragmented requests are not reassembled.",
        f"At most {MAX_INSPECTABLE_PAYLOAD_BYTES} bytes per packet are inspected, and report finding/request lists are capped.",
        "Sensitive indicators are heuristics. A clean result does not prove that a device or app is free of data leaks.",
        "No tracker reputation list is bundled; domain tracking classifications are not attempted.",
        "All analysis is local. Captures and report contents are not uploaded or sent to external services.",
    ]
    if parsing_warning_count:
        limitations.append(
            f"{parsing_warning_count} packet(s) could not be fully summarized because of malformed or unsupported packet data."
        )
    if finding_count > len(findings):
        limitations.append(
            f"Only the first {MAX_RETAINED_FINDINGS} findings are included; additional findings were counted but not retained."
        )
    if http_request_count > len(http_requests):
        limitations.append(
            f"Only the first {MAX_RETAINED_HTTP_REQUESTS} HTTP requests are included in the report."
        )
    if len(tls_handshakes) == MAX_RETAINED_TLS_HANDSHAKES:
        limitations.append(
            f"TLS server-name metadata is capped at {MAX_RETAINED_TLS_HANDSHAKES} entries."
        )

    protocols = dict(sorted(protocol_counts.items()))
    source_ip_counts = dict(sorted(source_ips.items()))
    destination_ip_counts = dict(sorted(destination_ips.items()))
    destination_port_counts = dict(sorted(destination_ports.items()))
    summary = {
        "packet_count": packet_count,
        "capture_duration_seconds": duration_seconds,
        "unique_domain_count": len(observed_domains),
        "unique_ip_count": len(unique_ip_addresses),
        "connection_count": len(connections),
        "dns_query_count": sum(dns_query_counts.values()),
        "dns_answer_count": sum(dns_answer_counts.values()),
        "http_request_count": http_request_count,
        "encrypted_or_unknown_packet_count": tls_or_unknown_packet_count,
        "finding_count": finding_count,
        "protocols": protocols,
        "source_ips": source_ip_counts,
        "destination_ips": destination_ip_counts,
        "destination_ports": destination_port_counts,
    }

    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "capture": {
            "name": path.name,
            "format": capture_format,
            "file_size_bytes": file_size_bytes,
            "packet_count": packet_count,
            "duration_seconds": duration_seconds,
        },
        "summary": summary,
        # Compatibility aliases for the original 0.x report shape.
        "packets_seen": packet_count,
        "protocols": protocols,
        "top_endpoints": [
            {"endpoint": endpoint, "packets": count}
            for endpoint, count in endpoint_flow_counts.most_common(30)
        ],
        "dns": {"queries": dns_queries, "answers": dns_answers},
        # Legacy callers used DNS query names and answer records without counts.
        "dns_queries": [item["name"] for item in dns_queries],
        "dns_answers": [
            {
                "name": item["name"],
                "type": item["record_type"],
                "address": item["address"],
            }
            for item in dns_answers
        ],
        "connections": connections,
        "http": {
            "requests": http_requests,
            "hosts": sorted(http_hosts),
        },
        "tls": {
            "or_unknown_packet_count": tls_or_unknown_packet_count,
            "client_hello_server_names": tls_handshakes,
        },
        "findings": findings,
        "finding_count": finding_count,
        "findings_truncated": finding_count > len(findings),
        "coordinate_scan_enabled": find_coordinates,
        "coordinate_findings": coordinate_findings,
        "risk_assessment": risk_assessment,
        "coverage": {
            "capture_has_timestamps": timestamp_count > 0,
            "packet_payload_limit_bytes": MAX_INSPECTABLE_PAYLOAD_BYTES,
            "packet_stream_reassembly": False,
            "tls_decryption": False,
            "parsing_warning_count": parsing_warning_count,
        },
        "limitations": limitations,
    }
