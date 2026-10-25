"""Self-contained HTML report rendering with no scripts or remote assets."""

from __future__ import annotations

from html import escape
from typing import Any


def _cell(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return escape(str(value))


def _table(headers: list[str], rows: list[list[Any]], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{_cell(value)}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=\"table-wrap\"><table><thead><tr>{header_html}</tr></thead><tbody>{body_html}</tbody></table></div>"


def render_html_report(report: dict[str, Any]) -> str:
    """Render the sanitized report as responsive standalone HTML."""
    capture = report["capture"]
    summary = report["summary"]
    assessment = report["risk_assessment"]
    finding_rows = [
        [
            finding.get("severity"),
            finding.get("evidence_category"),
            finding.get("type"),
            f"packet {finding.get('packet_number')}",
            finding.get("evidence_excerpt"),
            finding.get("explanation"),
        ]
        for finding in report.get("findings", [])
    ]
    dns_rows = [
        [item.get("name"), item.get("count")]
        for item in report.get("dns", {}).get("queries", [])
    ]
    dns_answer_rows = [
        [
            item.get("name"),
            item.get("record_type"),
            item.get("address"),
            item.get("count"),
        ]
        for item in report.get("dns", {}).get("answers", [])
    ]
    http_rows = [
        [
            item.get("method"),
            item.get("host"),
            item.get("source"),
            item.get("destination"),
            f"packet {item.get('packet_number')}",
        ]
        for item in report.get("http", {}).get("requests", [])
    ]
    tls_rows = [
        [item.get("server_name"), f"packet {item.get('packet_number')}"]
        for item in report.get("tls", {}).get("client_hello_server_names", [])
    ]
    connection_rows = [
        [item.get("protocol"), item.get("source"), item.get("destination"), item.get("packets")]
        for item in report.get("connections", [])
    ]
    duration = capture.get("duration_seconds")
    duration_text = f"{duration:.3f} s" if isinstance(duration, (int, float)) else "not available"
    size_text = f"{capture.get('file_size_bytes', 0):,} bytes"
    risk_class = escape(str(assessment.get("category", "unknown")).replace("_", "-"))
    limitations = "".join(
        f"<li>{escape(str(limitation))}</li>"
        for limitation in report.get("limitations", [])
    )

    sections = [
        f'<section><h2>Findings</h2>{_table(["Severity", "Category", "Indicator", "Packet", "Masked evidence", "Explanation"], finding_rows, "No qualifying findings.")}</section>',
        f'<section><h2>DNS questions</h2>{_table(["Domain", "Count"], dns_rows, "No visible DNS questions.")}</section>',
        f'<section><h2>DNS answers</h2>{_table(["Name", "Type", "Address", "Count"], dns_answer_rows, "No visible A or AAAA answers.")}</section>',
        f'<section><h2>Visible HTTP requests</h2>{_table(["Method", "Host", "Source", "Destination", "Packet"], http_rows, "No recognizable plaintext HTTP requests.")}</section>',
        f'<section><h2>TLS server-name metadata</h2>{_table(["Server name (SNI)", "Packet"], tls_rows, "No complete TLS ClientHello server-name entries were decoded.")}<p class="muted">This metadata is visible in some TLS handshakes; it is not decrypted content.</p></section>',
        f'<section><h2>Connections</h2>{_table(["Protocol", "First observed source", "First observed destination", "Packets"], connection_rows, "No TCP or UDP connections were observed.")}</section>',
        f'<section><h2>Limitations</h2><ul>{limitations}</ul></section>',
    ]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>DroidLeak Monitor report — {_cell(capture.get("name"))}</title>
  <style>
    :root {{ color-scheme: light; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #17212b; background: #f3f6f8; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; }}
    main {{ max-width: 1080px; margin: auto; padding: 24px 16px 48px; }}
    header, section, .assessment {{ background: white; border: 1px solid #dce3e8; border-radius: 12px; margin: 0 0 16px; padding: 20px; }}
    h1 {{ font-size: clamp(1.5rem, 5vw, 2rem); margin: 0 0 4px; }}
    h2 {{ font-size: 1.15rem; margin: 0 0 14px; }}
    p {{ margin: 6px 0; }}
    .muted {{ color: #52616d; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 10px; margin-top: 18px; }}
    .stat {{ background: #f1f5f7; border-radius: 8px; padding: 12px; overflow-wrap: anywhere; }}
    .stat strong {{ display: block; font-size: 1.2rem; }}
    .assessment {{ border-left: 5px solid #26734d; }}
    .assessment.potential-exposure {{ border-left-color: #a76b00; }}
    .assessment.confirmed-exposure {{ border-left-color: #a52828; }}
    .assessment.encrypted-unknown, .assessment.insufficient-data {{ border-left-color: #536c8d; }}
    .badge {{ display: inline-block; background: #edf1f4; border-radius: 999px; padding: 3px 9px; font-size: .85rem; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 560px; }}
    th, td {{ text-align: left; vertical-align: top; padding: 9px; border-bottom: 1px solid #e5eaee; overflow-wrap: anywhere; }}
    th {{ color: #33434f; background: #f6f8f9; }}
    li {{ margin: 6px 0; }}
    footer {{ font-size: .88rem; color: #52616d; }}
    @media (max-width: 560px) {{ main {{ padding: 12px 10px 28px; }} header, section, .assessment {{ padding: 15px; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>DroidLeak Monitor</h1>
      <p class="muted">Local analysis of a user-provided capture. This is not a live device monitor.</p>
      <p><strong>Capture:</strong> {_cell(capture.get("name"))} <span class="badge">{_cell(capture.get("format"))}</span></p>
      <p><strong>Size:</strong> {escape(size_text)} · <strong>Duration:</strong> {escape(duration_text)}</p>
      <div class="stats">
        <div class="stat"><strong>{summary.get("packet_count", 0):,}</strong>packets</div>
        <div class="stat"><strong>{summary.get("unique_domain_count", 0):,}</strong>domains observed</div>
        <div class="stat"><strong>{summary.get("unique_ip_count", 0):,}</strong>IP addresses</div>
        <div class="stat"><strong>{summary.get("connection_count", 0):,}</strong>connections</div>
        <div class="stat"><strong>{summary.get("http_request_count", 0):,}</strong>HTTP requests</div>
        <div class="stat"><strong>{summary.get("finding_count", 0):,}</strong>findings</div>
      </div>
    </header>
    <div class="assessment {risk_class}">
      <span class="badge">{_cell(assessment.get("category"))}</span>
      <h2>{_cell(assessment.get("headline"))}</h2>
      <p>{_cell(assessment.get("reasoning"))}</p>
      <p><strong>Severity:</strong> {_cell(assessment.get("severity"))}</p>
    </div>
    {''.join(sections)}
    <footer>
      Report schema {_cell(report.get("schema_version"))}. Sensitive values are masked.
      A clean result does not prove a device or app is free of leaks. Analysis is local;
      captures and report contents are not uploaded.
    </footer>
  </main>
</body>
</html>
"""
