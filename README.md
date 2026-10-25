# DroidLeak Monitor

DroidLeak Monitor is a local Python command-line analyzer for **PCAP and PCAPNG
files that you explicitly provide**. It summarizes observable network metadata,
visible DNS and HTTP information, and conservative indicators in recognizable
plaintext HTTP requests. Coordinate-pattern scanning is optional.

It is an analyzer, not a traffic-capture app. Android without root generally
cannot capture arbitrary traffic from every installed app. DroidLeak Monitor does
not decrypt HTTPS/TLS, QUIC, VPN, or encrypted DNS; bypass encryption; execute
captured data; upload captures; or identify which installed app generated a
packet. A visible indicator is evidence in the captured bytes, not by itself
proof of harm, intent, or app attribution.

## Quick start: Android Termux

Install Termux from a trusted distribution source, open it, then run:

```sh
pkg update
pkg install python git -y
git clone https://github.com/dedjr/droidleak-monitor.git
cd droidleak-monitor
pip install -r requirements.txt
python droidleak.py --help
```

Or, after cloning, run the included installer:

```sh
sh install.sh
```

Python 3.11 or newer is required. No root access, paid API, or cloud server is
needed.

### Access a capture stored on Android

If your capture is in shared Android storage, grant Termux access once:

```sh
termux-setup-storage
```

Approve Android's permission prompt. Shared storage is usually available under
`~/storage/shared/`; a file in Downloads can typically be analyzed with:

```sh
python droidleak.py ~/storage/shared/Download/capture.pcap
```

### Getting a capture

Capture collection and analysis are separate steps. To create a capture from
your own device, use a capture method that you are authorized to use, such as a
local VPN-based Android capture app that supports PCAP export, then export the
file and analyze it with DroidLeak Monitor. Android permits only one active VPN
service at a time, and capture apps vary in what they can see. Follow the
capture app's documentation and Android's permission prompts. Do not capture
other people's traffic without their authorization.

## Usage

Analyze a capture and print the default summary:

```sh
python droidleak.py capture.pcap
```

Write a machine-readable JSON report:

```sh
python droidleak.py capture.pcap --json report.json
```

Write a standalone, phone-friendly HTML report:

```sh
python droidleak.py capture.pcap --html report.html
```

Both report formats can be generated at once:

```sh
python droidleak.py capture.pcap --json report.json --html report.html
```

Print metadata only:

```sh
python droidleak.py capture.pcap --summary
```

Opt in to searching readable, non-encrypted TCP/UDP packet payloads for
latitude/longitude-shaped pairs:

```sh
python droidleak.py capture.pcap --find-coordinates --json report.json
```

Show help or the installed tool version:

```sh
python droidleak.py --help
python droidleak.py --version
```

Paths with spaces should be quoted, for example:

```sh
python droidleak.py "~/storage/shared/Download/my capture.pcap"
```

The tool returns exit code `2` for invalid input, malformed captures, or report
write errors. It refuses to overwrite the capture file with a report.

## What the analyzer reports

- Capture format, file size, packet count, and duration when timestamps are
  available.
- Protocol-layer counts, observed IPv4/IPv6 addresses, destination ports, and
  observed TCP/UDP connections.
- Visible DNS question names and A/AAAA answers. DNS-over-HTTPS and
  DNS-over-TLS queries are not visible as ordinary DNS records.
- Recognizable plaintext HTTP request methods and host names. Request paths and
  query strings are deliberately omitted from reports.
- TLS ClientHello server-name metadata (SNI) when a complete, parseable
  handshake is contained in one packet. SNI is metadata, not decrypted content.
- Sensitive-data indicators from recognizable plaintext HTTP requests:
  authorization headers, cookies, credential/token-like fields, and email or
  phone values next to corresponding field labels. Sensitive values are masked
  in terminal, JSON, and HTML output.
- Optional coordinate-pattern matches, including packet number, endpoints, and
  a short context excerpt. These are labeled potential findings, not confirmed
  leaks.
- An assessment category, severity, reasoning, and explicit coverage
  limitations.

The HTTP analyzer does not reassemble TCP streams, and it may miss requests
split between packets, unusual encodings, binary formats, or non-HTTP
protocols. It inspects at most 64 KiB of payload per packet. Phone detection is
context-labelled and heuristic. Ordinary IP addresses and unlabelled email-like
strings are not treated as sensitive-data findings.

No tracker/reputation list is included, so the tool does not classify domains
as trackers or suspicious. A DNS name, IP address, or visible TLS server name
is metadata, not proof of exfiltration or app identity.

## Assessment categories

- **Confirmed exposure**: a credential-like field, authorization header, or
  cookie is visibly present in a plaintext HTTP request. This confirms
  visibility in the capture, not malicious intent or what the remote endpoint
  did with it.
- **Potential exposure**: a context-labelled personal-data value or an
  opt-in coordinate-shaped pattern was found, but ownership or real-world
  meaning is not established.
- **Encrypted / unknown**: traffic could not be inspected or the capture did
  not contain enough visible content to assess it.
- **No evidence found**: no qualifying indicator was found in the inspected
  bytes. This does **not** mean the device or app is guaranteed safe.
- **Insufficient data**: the capture contained no packets.

Tracker indicators are not produced because no classification list is bundled.
Every report also describes unknowns and limitations.

## Reports and privacy

The JSON schema is documented in
[`docs/report-schema.md`](docs/report-schema.md). A clearly synthetic example
report is in [`examples/synthetic-report.json`](examples/synthetic-report.json).

Sensitive values detected in HTTP are masked, but reports still include
observable DNS names, IP addresses, HTTP hosts, and optional coordinate
findings. Review and sanitize a report before sharing it. The tool does not
transmit captures or reports to any service and does not retain raw payloads.
HTML reports contain inline CSS only; they have no JavaScript or remote assets.

## Tests

Tests construct synthetic captures with reserved documentation IP ranges and
`.test` domains. They do not use real captures or personal data.

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Download or contribute

The public source repository is
[github.com/dedjr/droidleak-monitor](https://github.com/dedjr/droidleak-monitor).
On GitHub, use **Code → Download ZIP**, or clone it with the commands above.
The source files can also be downloaded from the Replit file tree using its
**Download as zip** option.

Before sharing or committing changes, check that no personal capture or report
has been added. `.gitignore` excludes `.pcap`, `.pcapng`, and the default
`report.json` filename.

## License

MIT. See [LICENSE](LICENSE).
