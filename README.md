# DroidLeak Monitor

DroidLeak Monitor is a small, local command-line tool for reviewing **PCAP and
PCAPNG files that you provide**. It summarizes visible network metadata, lists
DNS query names when present, and can look for possible latitude/longitude
pairs in accessible, non-encrypted payload bytes.

It is not a live traffic monitor. Android without root generally cannot capture
arbitrary traffic from every installed app. This tool does not decrypt HTTPS or
TLS, bypass encryption, execute captured data, upload files, or determine which
installed app created a packet. Network metadata and pattern matches are
observations—not proof that information was leaked.

## Requirements

- Python 3.11 or newer
- Scapy (installed from `requirements.txt`)
- A PCAP or PCAPNG file that you are authorized to inspect

No root access, paid API, or cloud service is required. Captures and reports
stay on your device unless you choose to share them.

## Install on Android with Termux

Install Termux from a trusted distribution source, open it, then run:

```sh
pkg update
pkg install python git -y
git clone https://github.com/dedjr/droidleak-monitor.git
cd droidleak-monitor
pip install -r requirements.txt
python droidleak.py --help
```

The included installer runs the package and Python-version checks for you:

```sh
sh install.sh
```

If `pip` reports that it is unavailable, update Termux and install Python with
`pkg install python -y`, then retry. Python 3.11 or newer is required.

### Access a capture stored on Android

To let Termux access shared device storage, run this once and approve Android's
permission prompt:

```sh
termux-setup-storage
```

Shared storage is then available under `~/storage/shared/`. For example, a file
in Android's Downloads folder can usually be analyzed with:

```sh
python droidleak.py ~/storage/shared/Download/sample.pcap
```

You can also copy an authorized capture into the repository directory and use
its filename. DroidLeak Monitor analyzes only the file path you provide; it
does not capture traffic itself.

## Usage

Print packet, protocol, IP, port, and available DNS summaries:

```sh
python droidleak.py sample.pcap
```

Print a concise metadata-only summary:

```sh
python droidleak.py sample.pcap --summary
```

Write a JSON report:

```sh
python droidleak.py sample.pcap --json report.json
```

Explicitly scan accessible payload bytes for possible coordinate pairs:

```sh
python droidleak.py sample.pcap --find-coordinates
```

Combine coordinate scanning with a JSON report:

```sh
python droidleak.py sample.pcap --find-coordinates --json report.json
```

Coordinate results are labeled **potential** findings. The report includes the
packet number, matched values, endpoint metadata, and a short context window; it
does not dump complete packet payloads. TLS on common ports and payloads
identified by a TLS record signature are excluded from coordinate scanning.

## What the report can and cannot show

- Counts captured packets and summarizes observed protocol layers, IP
  addresses, and destination ports.
- Extracts visible DNS question names when the capture contains them.
- Optionally searches readable, non-TLS TCP/UDP payload bytes for numeric
  coordinate-like pairs.
- Does not reveal the contents of encrypted HTTPS/TLS payloads. Without
  authorized decryption outside this tool, those bytes remain unreadable.
- Does not identify the installed Android app behind a packet. A capture may
  contain no app attribution at all.
- Does not establish that a match was intentionally transmitted, received by a
  particular party, or leaked.
- Does not sniff, intercept, execute, or upload traffic.

## Tests

Tests use synthetic packet data only; they do not include real captures or
personal information.

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## GitHub and downloads

The intended public repository is
[github.com/dedjr/droidleak-monitor](https://github.com/dedjr/droidleak-monitor).
This source tree is prepared for that repository, but no GitHub push is implied.
To publish it, open **Tools → Git** in Replit, connect the intended repository,
review the staged changes, then commit and push (or enable auto-sync). The
workspace may contain other Replit files, so review what will be shared; copy
only this CLI's files if the GitHub repository should contain no other project
content. To make an offline copy, use the three-dot menu above the Replit file
tree and select **Download as zip**.

Before committing, review the files you plan to share. `.gitignore` excludes
PCAP/PCAPNG captures and the default report filename so personal traffic data
is less likely to be committed accidentally.

## License

MIT. See [LICENSE](LICENSE).
