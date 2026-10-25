# JSON report schema

Current report schema: **2.0**. The `schema_version` field changes when the
report shape or meaning changes incompatibly. The report is UTF-8 JSON and
contains only summaries and sanitized findings; raw packet payloads are never
copied into it.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | Product name. |
| `tool_version` | string | Analyzer version. |
| `schema_version` | string | Stable report schema version. |
| `capture` | object | File name, detected format, file size, packet count, and duration. |
| `summary` | object | Counts for packets, domains, IPs, connections, DNS, HTTP, encrypted/unknown packets, and findings; also protocol, IP, and destination-port counters. |
| `dns` | object | Aggregated visible DNS questions and A/AAAA answers. |
| `packets_seen` | integer | Compatibility alias for `capture.packet_count`. |
| `protocols` | object | Compatibility alias for `summary.protocols`. |
| `top_endpoints` | array | Directional endpoint counts retained for compatibility with older reports. |
| `dns_queries` | array of strings | Compatibility list of visible DNS question names. |
| `dns_answers` | array | Compatibility records with `name`, `type`, and `address`. |
| `connections` | array | TCP/UDP endpoint pairs and packet counts. The source/destination shown are from the first observed packet in each conversation. |
| `http` | object | Recognizable plaintext HTTP request metadata and host names. Paths and query strings are omitted. |
| `tls` | object | Count of encrypted/unknown packets and parseable ClientHello server names. No TLS payload is decrypted. |
| `findings` | array | Sanitized HTTP indicators and, when requested, coordinate-pattern findings. |
| `finding_count` | integer | Number of findings observed before the report-list cap. |
| `findings_truncated` | boolean | Whether additional findings were counted but not retained. |
| `coordinate_scan_enabled` | boolean | Whether coordinate scanning was explicitly requested. |
| `coordinate_findings` | array | Compatibility/convenience subset of coordinate findings from `findings`. |
| `risk_assessment` | object | Overall category, severity, headline, and reasoning. |
| `coverage` | object | Timestamp availability, payload-size cap, stream reassembly/decryption flags, and packet warnings. |
| `limitations` | array of strings | Material limits and privacy notes for this run. |

## Findings

Each finding contains:

- `type`: stable indicator identifier, such as `http_authorization_header`,
  `http_cookie`, `plaintext_sensitive_field`, `context_labelled_email`,
  `context_labelled_phone`, or `potential_coordinate_pattern`.
- `evidence_category`: `confirmed_exposure` or `potential_exposure`.
- `packet_number`, `source`, `destination`, and `protocol` when available.
- `encryption_status`: `plaintext_http` for inspectable HTTP findings, or
  `not_observed_in_packet` for optional coordinate matches. This is limited to
  the observed packet, not a complete flow assessment.
- `severity`, `confidence`, `evidence_excerpt`, `explanation`, and `limitations`.
- Coordinate findings also include `latitude`, `longitude`, `destination_port`,
  and a short `context` excerpt.

Credentials, cookies, and token values are masked before being written. The
report does not include the complete HTTP body, request path, or query string.
DNS/IP/host metadata and coordinate values can still be sensitive; sanitize
reports before sharing them.

## Risk assessment categories

`risk_assessment.category` is one of:

- `confirmed_exposure`
- `potential_exposure`
- `encrypted_unknown`
- `no_evidence_found`
- `insufficient_data`

There is no `tracking_indicator` result because no domain classification list
is bundled. `no_evidence_found` applies only to inspected data and is not a
guarantee of safety.

## Counters and caps

`summary.protocols` counts observed protocol layers; a packet can contribute
to more than one layer. HTTP requests, TLS server names, and findings have
bounded retained lists to limit memory use; total counts are preserved where
available. The analyzer streams packets through Scapy and does not retain the
capture or payloads.

The top-level compatibility fields support consumers of earlier 0.x reports.
New consumers should use the richer `summary`, `dns`, `connections`, and
`http` objects.
