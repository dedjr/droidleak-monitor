#!/usr/bin/env python3
"""DroidLeak Monitor: analisis lokal PCAP dan PCAPNG."""

import argparse
import json
import socket
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read_capture(data):
    """Return (packets, linktypes), dengan packets berupa (frame, linktype)."""
    packets = []
    linktypes = []

    # PCAP klasik
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }

    if data[:4] in formats:
        endian = formats[data[:4]]
        if len(data) < 24:
            raise ValueError("Header PCAP tidak lengkap.")

        linktype = struct.unpack(endian + "I", data[20:24])[0]
        offset = 24

        while offset < len(data):
            if len(data) - offset < 16:
                raise ValueError("Header paket PCAP tidak lengkap.")
            _, _, caplen, _ = struct.unpack(
                endian + "IIII", data[offset:offset + 16]
            )
            offset += 16
            if caplen > len(data) - offset:
                raise ValueError("Data paket PCAP terpotong.")
            packets.append((data[offset:offset + caplen], linktype))
            offset += caplen

        return packets, [linktype]

    # PCAPNG
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Format tidak dikenal. Gunakan PCAP atau PCAPNG.")

    offset = 0
    endian = None
    interfaces = []

    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("Blok PCAPNG tidak lengkap.")

        # Section Header Block menentukan byte order untuk section.
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("Byte-order magic PCAPNG tidak valid.")
            interfaces = []
            block_type = 0x0A0D0D0A
        else:
            if endian is None:
                raise ValueError("PCAPNG tidak memiliki Section Header.")
            block_type = struct.unpack(
                endian + "I", data[offset:offset + 4]
            )[0]

        block_len = struct.unpack(
            endian + "I", data[offset + 4:offset + 8]
        )[0]

        if (block_len < 12 or block_len % 4 != 0
                or block_len > len(data) - offset):
            raise ValueError("Panjang blok PCAPNG tidak valid.")

        trailer = struct.unpack(
            endian + "I", data[offset + block_len - 4:offset + block_len]
        )[0]
        if trailer != block_len:
            raise ValueError("Panjang blok PCAPNG tidak cocok.")

        start = offset + 8
        end = offset + block_len - 4

        if block_type == 1:  # Interface Description Block
            if end - start < 8:
                raise ValueError("Interface Description Block tidak lengkap.")
            linktype = struct.unpack(endian + "H", data[start:start + 2])[0]
            interfaces.append(linktype)
            if linktype not in linktypes:
                linktypes.append(linktype)

        elif block_type == 6:  # Enhanced Packet Block
            if end - start < 20:
                raise ValueError("Enhanced Packet Block tidak lengkap.")
            interface_id, _, _, caplen, _ = struct.unpack(
                endian + "IIIII", data[start:start + 20]
            )
            packet_start = start + 20
            if caplen > end - packet_start:
                raise ValueError("Data paket PCAPNG terpotong.")
            if interface_id >= len(interfaces):
                raise ValueError("ID interface PCAPNG tidak valid.")
            packets.append((
                data[packet_start:packet_start + caplen],
                interfaces[interface_id],
            ))

        elif block_type == 3:  # Simple Packet Block, interface 0
            if end - start < 4:
                raise ValueError("Simple Packet Block tidak lengkap.")
            if not interfaces:
                raise ValueError("PCAPNG belum mendefinisikan interface.")
            origlen = struct.unpack(endian + "I", data[start:start + 4])[0]
            packet_start = start + 4
            caplen = min(origlen, end - packet_start)
            packets.append((
                data[packet_start:packet_start + caplen], interfaces[0]
            ))

        offset += block_len

    if not linktypes:
        raise ValueError("PCAPNG tidak memiliki interface jaringan.")
    return packets, linktypes


def parse_dns_query(payload):
    if len(payload) < 12:
        return None

    try:
        flags, qdcount, ancount = struct.unpack("!HHH", payload[2:8])
        is_response = bool(flags & 0x8000)
        pos = 12
        queries = []
        answers = []

        def read_name(data, offset):
            labels = []
            jumped = False
            next_offset = offset
            steps = 0

            while offset < len(data):
                steps += 1
                if steps > 128:
                    return None, next_offset

                length = data[offset]

                if length & 0xC0 == 0xC0:
                    if offset + 1 >= len(data):
                        return None, next_offset
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    if pointer >= len(data):
                        return None, next_offset
                    if not jumped:
                        next_offset = offset + 2
                    offset = pointer
                    jumped = True
                    continue

                if length & 0xC0:
                    return None, next_offset

                offset += 1
                if length == 0:
                    if not jumped:
                        next_offset = offset
                    return ".".join(labels), next_offset

                if length > 63 or offset + length > len(data):
                    return None, next_offset

                labels.append(data[offset:offset + length].decode("ascii", "replace"))
                offset += length

            return None, next_offset

        for _ in range(qdcount):
            name, next_pos = read_name(payload, pos)
            if name is None or next_pos + 4 > len(payload):
                return None

            _, qclass = struct.unpack("!HH", payload[next_pos:next_pos + 4])
            if qclass == 1 and name:
                queries.append(name)
            pos = next_pos + 4

        if is_response:
            for _ in range(ancount):
                name, next_pos = read_name(payload, pos)
                if name is None or next_pos + 10 > len(payload):
                    break

                rtype, rclass, _, rdlength = struct.unpack(
                    "!HHIH", payload[next_pos:next_pos + 10]
                )
                rstart = next_pos + 10
                rend = rstart + rdlength

                if rend > len(payload):
                    break

                if rclass == 1 and rtype == 1 and rdlength == 4:
                    answers.append({
                        "name": name,
                        "type": "A",
                        "address": socket.inet_ntop(socket.AF_INET, payload[rstart:rend]),
                    })
                elif rclass == 1 and rtype == 28 and rdlength == 16:
                    answers.append({
                        "name": name,
                        "type": "AAAA",
                        "address": socket.inet_ntop(socket.AF_INET6, payload[rstart:rend]),
                    })

                pos = rend

        return {
            "queries": queries,
            "answers": answers,
            "is_response": is_response,
        }
    except (IndexError, struct.error, ValueError):
        return None


def analyze_pcap(filename):
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f"File tidak ditemukan: {path}")

    data = path.read_bytes()
    packets, linktypes = read_capture(data)

    protocols = Counter()
    endpoints = Counter()
    dns_queries = set()
    dns_answers = set()

    for frame, linktype in packets:
        # Link type 1 = Ethernet
        if linktype != 1 or len(frame) < 14:
            continue

        ethertype = struct.unpack("!H", frame[12:14])[0]
        pos = 14

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
                    sport, dport = struct.unpack("!HH", frame[pos:pos + 4])
                    endpoints[f"{src}:{sport} -> {dst}:{dport}"] += 1

            elif proto == 17:
                protocols["UDP"] += 1
                if len(frame) >= pos + 8:
                    sport, dport, length, _ = struct.unpack(
                        "!HHHH", frame[pos:pos + 8]
                    )
                    endpoints[f"{src}:{sport} -> {dst}:{dport}"] += 1
                    if (sport == 53 or dport == 53) and len(frame) >= pos + 8:
                        payload = frame[pos + 8:]
                        dns_result = parse_dns_query(payload)
                        if dns_result:
                            dns_queries.update(dns_result["queries"])
                            for answer in dns_result["answers"]:
                                dns_answers.add(
                                    (answer["name"], answer["type"], answer["address"])
                                )

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
        "packets_seen": len(packets),
        "capture_link_type": linktypes[0] if len(linktypes) == 1 else linktypes,
        "protocols": dict(protocols.most_common()),
        "top_endpoints": [
            {"endpoint": k, "packets": v}
            for k, v in endpoints.most_common(30)
        ],
        "dns_queries": sorted(dns_queries),
        "dns_answers": [
            {"name": name, "type": record_type, "address": address}
            for name, record_type, address in sorted(dns_answers)
        ],
        "notes": [
            "Analisis lokal terhadap file capture yang diberikan.",
            "PCAP klasik dan blok PCAPNG EPB/SPB didukung.",
            "Analisis paket mendalam saat ini terbatas pada Ethernet/IPv4.",
            "IPv6 hanya dihitung, tidak dianalisis secara mendalam.",
            "Tidak mendekripsi HTTPS/TLS atau membuktikan kebocoran data.",
            "PCAPNG dengan format blok atau link-layer lain mungkin belum didukung.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="DroidLeak Monitor: analisis PCAP/PCAPNG secara lokal."
    )
    parser.add_argument("pcap", nargs="?", help="Path file PCAP atau PCAPNG")
    parser.add_argument("--json", help="Simpan laporan ke file JSON")
    parser.add_argument(
        "--version", action="version", version="DroidLeak Monitor 0.2.0"
    )
    args = parser.parse_args()

    if not args.pcap:
        parser.print_help()
        return

    try:
        report = analyze_pcap(args.pcap)
    except (ValueError, OSError, struct.error) as exc:
        parser.error(str(exc))

    output = json.dumps(report, indent=2, ensure_ascii=False)
    print(output)
    if args.json:
        Path(args.json).write_text(output, encoding="utf-8")
        print(f"\nLaporan disimpan ke: {args.json}")


if __name__ == "__main__":
    main()
