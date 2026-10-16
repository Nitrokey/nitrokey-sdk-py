import unittest

from nitrokey.trussed._utils import Iso7816Apdu

# Expected encodings follow ISO/IEC 7816-4, section 5.1

CLA = 0x00
INS = 0xA4
P1 = 0x01
P2 = 0x02
HEADER = bytes([CLA, INS, P1, P2])


def encode(data: bytes = b"", le: int | None = None) -> bytes:
    return Iso7816Apdu(CLA, INS, P1, P2, data, le=le).to_bytes()


class TestIso7816Apdu(unittest.TestCase):
    def test_case_1_no_data_no_le(self) -> None:
        self.assertEqual(encode(), HEADER)

    def test_case_2s_le_only(self) -> None:
        self.assertEqual(encode(le=5), HEADER + bytes([0x05]))

    def test_case_2s_le_256(self) -> None:
        # A short Le of 0x00 already means 256, so this stays in the short form
        self.assertEqual(encode(le=256), HEADER + bytes([0x00]))

    def test_case_3s_data_only(self) -> None:
        self.assertEqual(encode(b"\x01\x02"), HEADER + bytes([0x02, 0x01, 0x02]))

    def test_case_4s_data_and_le(self) -> None:
        self.assertEqual(encode(b"\x01\x02", 5), HEADER + bytes([0x02, 0x01, 0x02, 0x05]))

    def test_case_2e_extended_le(self) -> None:
        self.assertEqual(encode(le=300), HEADER + bytes([0x00, 0x01, 0x2C]))

    def test_case_3e_extended_data(self) -> None:
        data = b"\xaa" * 300
        self.assertEqual(encode(data), HEADER + bytes([0x00, 0x01, 0x2C]) + data)

    def test_case_4e_extended_data_and_le(self) -> None:
        data = b"\xaa" * 300
        expected = HEADER + bytes([0x00, 0x01, 0x2C]) + data + bytes([0x00, 0x05])
        self.assertEqual(encode(data, 5), expected)

    def test_case_4s_le_0(self) -> None:
        self.assertEqual(encode(b"\x01\x02", 0), HEADER + bytes([0x02, 0x01, 0x02, 0x00]))

    def test_case_4e_le_0(self) -> None:
        data = b"\xaa" * 300
        expected = HEADER + bytes([0x00, 0x01, 0x2C]) + data + bytes([0x00, 0x00])
        self.assertEqual(encode(data, 0), expected)

    def test_short_form_boundary(self) -> None:
        data = b"\xaa" * 255
        self.assertEqual(encode(data, 255), HEADER + bytes([0xFF]) + data + bytes([0xFF]))

    def test_extended_form_boundary(self) -> None:
        data = b"\xaa" * 256
        expected = HEADER + bytes([0x00, 0x01, 0x00]) + data + bytes([0x00, 0x01])
        self.assertEqual(encode(data, 1), expected)

    def test_get_response(self) -> None:
        apdu = Iso7816Apdu(0x00, 0xC0, 0, 0, None, 0x10).to_bytes()
        self.assertEqual(apdu, bytes([0x00, 0xC0, 0x00, 0x00, 0x10]))

    def test_get_response_256_bytes(self) -> None:
        apdu = Iso7816Apdu(0x00, 0xC0, 0, 0, None, 0x00).to_bytes()
        self.assertEqual(apdu, bytes([0x00, 0xC0, 0x00, 0x00, 0x00]))

    def test_data_too_long(self) -> None:
        with self.assertRaises(ValueError):
            encode(b"\x00" * 0x10000)

    def test_le_too_large(self) -> None:
        with self.assertRaises(ValueError):
            encode(le=0x10000)

    def test_le_negative(self) -> None:
        with self.assertRaises(ValueError):
            encode(le=-1)


class TestIso7816ApduMixedForms(unittest.TestCase):
    def test_short_lc_is_not_combined_with_extended_le(self) -> None:
        apdu = encode(b"\xaa", 256)
        self.assertEqual(apdu, HEADER + bytes([0x01, 0xAA, 0x00]))

    def test_extended_lc_is_not_combined_with_short_le(self) -> None:
        data = b"\xaa" * 300
        apdu = encode(data, 5)
        self.assertEqual(apdu, HEADER + bytes([0x00, 0x01, 0x2C]) + data + bytes([0x00, 0x05]))

    def test_extended_le_does_not_repeat_the_leading_zero(self) -> None:
        data = b"\xaa" * 300
        apdu = encode(data, 65535)
        self.assertEqual(apdu, HEADER + bytes([0x00, 0x01, 0x2C]) + data + bytes([0xFF, 0xFF]))
