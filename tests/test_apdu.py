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
