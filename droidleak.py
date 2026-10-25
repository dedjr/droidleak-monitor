#!/usr/bin/env python3
"""DroidLeak Monitor - analisis dasar file PCAP/PCAPNG lokal."""

import argparse
import json
import socket
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def analyze_pcap(filename):
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f"File tidak ditemukan: {path}")

    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("File terlalu pendek untuk menjadi PCAP.")

    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }

    if magic in formats:
        endian, nano = formats[magic]
        snaplen = struct.unpack(endian + "I", data[16:20])[0]
        linktype = struct.unpack(endian + "I", data[20:24])[0]
        offset = 24
        packets = 0
        protocols = Counter()
        endpoints = Counter()
        dns_queries = set()

        while offset + 16 <= len(data):
            _, _, incl_len, _ = struct.unpack(
                endian + "IIII", data[offset:offset + 16]
            )
            offset += 16
            if incl_len > len(data) - offset:
                break

            frame = data[offset:offset + incl_len]
            offset += incl_len
            packets += 1

            # Link type 1 = Ethernet
            if linktype != 1 or len(frame) < 14:
                continue

            ethertype = struct.unpack("!H", frame[12:14])[0]
            pos = 14

            # IPv4
            if ethertype == 0x0800 and len(frame) >= pos + 20:
                ihl = (frame[pos] & 15) * 4
                if ihl < 20 or len(frame) < pos + ihl:
                    continue
                proto = frame[pos + 9]
                src = socket.inet_ntoa(frame[pos + 12:pos + 16])
                dst = socket.inet_ntoa(frame[pos + 16:pos + 20])
                pos += ihl

                if proto == 6:
                    protocols["TCP"] += 1
                    if len(frame) >= pos + 4:
                        sport, dport = struct.unpack(
                            "!HH", frame[pos:pos + 4]
                        )
                        endpoints[f"{src}:{sport} -> {dst}:{dport}"] += 1
                elif proto == 17:
                    protocols["UDP"] += 1
                    if len(frame) >= pos + 8:
                        sport, dport, length, _ = struct.unpack(
                            "!HHHH", frame[pos:pos + 8]
                        )
                        endpoints[f"{src}:{sport} -> {dst}:{dport}"] += 1
                        if dport == 53 and len(frame) >= pos + 12:
                            payload = frame[pos + 8:]
                            query = parse_dns_query(payload)
                            if query:
                                dns_queries.add(query)
                elif proto == 1:
                    protocols["ICMP"] += 1
                else:
                    protocols[f"IPv4 protocol {proto}"] += 1

            elif ethertype == 0x86DD:
                protocols["IPv6 (not deeply parsed)"] += 1
            else:
                protocols["Other Ethernet"] += 1

        return {
            "file": path.name,
            "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
            "packets_seen": packets,
            "capture_link_type": linktype,
            "protocols": dict(protocols.most_common()),
            "top_endpoints": [
                {"endpoint": k, "packets": v}
                for k, v in endpoints.most_common(30)
            ],
            "dns_queries": sorted(dns_queries),
            "notes": [
                "Analisis lokal terhadap file capture yang diberikan.",
                "Parser awal ini mendukung PCAP klasik dan Ethernet/IPv4.",
                "Tidak semua paket atau protokol didukung.",
                "PCAPNG dan IPv6 belum dianalisis secara mendalam.",
                "Tidak mendekripsi HTTPS/TLS atau membuktikan kebocoran data.",
            ],
        }

    raise ValueError(
        "Format belum didukung. Versi awal ini memerlukan PCAP klasik."
    )


def parse_dns_query(payload):
    if len(payload) < 17:
        return None
    try:
        flags = struct.unpack("!H", payload[2:4])[0]
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if flags & 0x8000 or qdcount < 1:
            return None
        pos = 12
        labels = []
        while pos < len(payload):
            length = payload[pos]
            pos += 1
            if length == 0:
                break
            if length > 63 or pos + length > len(payload):
                return None
            labels.append(payload[pos:pos + length].decode("ascii", "replace"))
            pos += length
        if not labels or pos + 4 > len(payload):
            return None
        return ".".join(labels)
    except (IndexError, struct.error):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="DroidLeak Monitor: analisis dasar PCAP secara lokal."
    )
    parser.add_argument("pcap", nargs="?", help="Path file PCAP")
    parser.add_argument("--json", help="Simpan laporan ke file JSON")
    parser.add_argument("--version", action="version", version="DroidLeak Monitor 0.1.0")
    args = parser.parse_args()

    if not args.pcap:
        parser.print_help()
        return

    try:
        report = analyze_pcap(args.pcap)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nLaporan disimpan ke: {args.json}")


if __name__ == "__main__":
    main()
