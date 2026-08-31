import datetime
import unittest
from types import SimpleNamespace
from typing import Any


class TestPivTlv(unittest.TestCase):
    def test_build_parse_roundtrip(self) -> None:
        from nitrokey.nk3.piv_app import Tlv, find_by_id

        items = [(0x80, b"hello"), (0x81, b""), (0x7F49, bytes(300))]
        encoded = Tlv.build(items)
        parsed = Tlv.parse(encoded)
        self.assertEqual(parsed, items)
        self.assertEqual(find_by_id(0x80, parsed), b"hello")
        self.assertIsNone(find_by_id(0x99, parsed))

    def test_length_encoding_boundaries(self) -> None:
        from nitrokey.nk3.piv_app import Tlv

        for size in (0, 127, 128, 255, 256, 65535):
            ((tag, value),) = Tlv.parse(Tlv.build([(0x53, bytes(size))]))
            self.assertEqual(tag, 0x53)
            self.assertEqual(len(value), size)


class TestPivTlvRobustness(unittest.TestCase):
    def test_truncated_input_raises(self) -> None:
        from nitrokey.nk3.piv_app import PivError, Tlv

        for encoded in ("5381", "538201", "5381ff", "530a4142"):
            with self.assertRaises(PivError):
                Tlv.parse(bytes.fromhex(encoded))

    def test_long_form_lengths(self) -> None:
        from nitrokey.nk3.piv_app import Tlv

        ((tag, value),) = Tlv.parse(bytes.fromhex("53830001 00") + b"A" * 256)
        self.assertEqual(tag, 0x53)
        self.assertEqual(len(value), 256)

    def test_indefinite_length_rejected(self) -> None:
        from nitrokey.nk3.piv_app import PivError, Tlv

        with self.assertRaises(PivError):
            Tlv.parse(bytes.fromhex("5380"))

    def test_oversized_value_rejected(self) -> None:
        from nitrokey.nk3.piv_app import PivError, Tlv

        with self.assertRaises(PivError):
            Tlv.build([(0x53, bytes(0x10000))])


class TestPivPkcs1(unittest.TestCase):
    def test_prepare_pkcs1v15_sizes(self) -> None:
        from nitrokey.nk3.piv_app import _prepare_pkcs1v15_sha256

        for bits in (2048, 3072, 4096):
            block = _prepare_pkcs1v15_sha256(b"data", bits // 8)
            self.assertEqual(len(block), bits // 8)
            self.assertTrue(block.startswith(b"\x00\x01\xff"))
            # DigestInfo prefix for SHA-256 precedes the 32-byte hash
            self.assertIn(bytes.fromhex("3031300d060960864801650304020105000420"), block)

    def test_key_too_small_rejected(self) -> None:
        from nitrokey.nk3.piv_app import PivError, _prepare_pkcs1v15_sha256

        # Fewer than 8 padding bytes would violate PKCS#1 v1.5
        with self.assertRaises(PivError):
            _prepare_pkcs1v15_sha256(b"data", 55)


class TestPivPin(unittest.TestCase):
    def test_encode_pin_padding(self) -> None:
        from nitrokey.nk3.piv_app import _encode_pin

        self.assertEqual(_encode_pin("123456"), b"123456\xff\xff")
        self.assertEqual(_encode_pin("12345678"), b"12345678")

    def test_encode_pin_too_long(self) -> None:
        from nitrokey.nk3.piv_app import _encode_pin

        with self.assertRaises(ValueError):
            _encode_pin("123456789")


class TestPivError(unittest.TestCase):
    def test_status_decoding(self) -> None:
        from nitrokey.nk3.piv_app import PivError

        not_found = PivError(0x6A82)
        self.assertEqual(not_found.sw1, 0x6A)
        self.assertEqual(not_found.sw2, 0x82)
        self.assertTrue(not_found.is_not_found)
        self.assertFalse(not_found.is_wrong_pin)

        wrong_pin = PivError(0x63C2)
        self.assertTrue(wrong_pin.is_wrong_pin)
        self.assertEqual(wrong_pin.pin_retries, 2)


class TestPivSignRsa(unittest.TestCase):
    def test_unsupported_bits(self) -> None:
        from nitrokey.nk3.piv_app import PivApp, PivError

        app = PivApp.__new__(PivApp)
        with self.assertRaises(PivError):
            app.sign_rsa(b"data", 0x9A, 1024)


class TestPivCertInfo(unittest.TestCase):
    def test_from_der(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        from nitrokey.nk3.piv_app import PivCertInfo

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CN")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0x1234)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(key, hashes.SHA256())
        )

        info = PivCertInfo.from_der(cert.public_bytes(Encoding.DER))
        self.assertEqual(info.subject, "Test CN")
        self.assertEqual(info.issuer, "Test CN")
        self.assertEqual(info.serial, "1234")
        self.assertEqual(info.not_before, "2020-01-01")
        self.assertEqual(info.not_after, "2030-01-01")


def _device(transport: object) -> Any:
    """Stands in for an NK3 opened with the given transport"""
    return SimpleNamespace(transport=transport)


class TestPivTransport(unittest.TestCase):
    def test_rejects_non_ccid_transport(self) -> None:
        from nitrokey.nk3.piv_app import PivApp, PivError
        from nitrokey.trussed._connection import Transport

        device = _device(Transport.CTAPHID)
        with self.assertRaises(PivError) as ctx:
            PivApp(device)
        self.assertIn("CCID", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
