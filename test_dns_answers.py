import socket
import struct
import unittest

from droidleak import parse_dns_query


def make_dns_response(record_type, address):
    # Domain example.com
    question_name = b"\x07example\x03com\x00"

    question = question_name + struct.pack("!HH", record_type, 1)

    if record_type == 1:
        packed_address = socket.inet_pton(socket.AF_INET, address)
    elif record_type == 28:
        packed_address = socket.inet_pton(socket.AF_INET6, address)
    else:
        raise ValueError("Tipe DNS tidak didukung tes ini")

    # Pointer C00C menunjuk nama domain pada bagian question.
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", record_type, 1, 60, len(packed_address))
        + packed_address
    )

    header = struct.pack(
        "!HHHHHH",
        0x1234,  # transaction ID
        0x8180,  # response sukses
        1,       # satu question
        1,       # satu answer
        0,
        0,
    )

    return header + question + answer


class DNSAnswerTests(unittest.TestCase):
    def test_ipv4_a_answer(self):
        payload = make_dns_response(1, "93.184.216.34")
        result = parse_dns_query(payload)

        self.assertIsNotNone(result)
        self.assertTrue(result["is_response"])
        self.assertIn("example.com", result["queries"])
        self.assertIn(
            {
                "name": "example.com",
                "type": "A",
                "address": "93.184.216.34",
            },
            result["answers"],
        )

    def test_ipv6_aaaa_answer(self):
        payload = make_dns_response(28, "2001:db8::1")
        result = parse_dns_query(payload)

        self.assertIsNotNone(result)
        self.assertTrue(result["is_response"])
        self.assertIn(
            {
                "name": "example.com",
                "type": "AAAA",
                "address": "2001:db8::1",
            },
            result["answers"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
