DroidLeak Monitor

A lightweight command-line tool for analyzing user-provided PCAP network captures locally on Android using Termux and Python.

Current Features

- Read classic PCAP files with Ethernet link-layer packets.
- Count supported network protocols.
- List observed IPv4 endpoints and ports for TCP and UDP.
- Extract visible DNS query names from supported UDP packets.
- Export analysis reports to JSON.
- Run automated tests with Python's built-in unittest.

Requirements

- Python 3.10 or newer
- Termux on Android, or another Python environment

No paid API or external Python package is required.

Usage

Show help:

python droidleak.py --help

Analyze a capture:

python droidleak.py capture.pcap

Save a JSON report:

python droidleak.py capture.pcap --json report.json

Run tests:

python -m unittest -v test_droidleak.py

Limitations

This initial version supports classic PCAP files and basic Ethernet/IPv4 parsing. PCAPNG, deep IPv6 analysis, and many other link-layer formats are not yet supported.

Encrypted HTTPS/TLS payloads are not decrypted. DNS extraction only works for supported, visible DNS queries. Findings are observations, not proof that a data leak occurred.

The tool analyzes capture files supplied by the user; it does not automatically capture all Android application traffic.

Privacy

Analysis runs locally. Capture files may contain sensitive information, so only analyze files you are authorized to inspect and protect any reports that contain private data.

License

MIT License. See "LICENSE".
