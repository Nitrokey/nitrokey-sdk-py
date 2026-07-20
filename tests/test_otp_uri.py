import unittest

from nitrokey.nk3.secrets_app import Algorithm, Kind, OTP_Uri

# Test URIs generated with https://devutl.com/hmac-based-one-time-password-tester/


class TestOTPUri(unittest.TestCase):
    def test_totp(self) -> None:
        totp_uri = "otpauth://totp/demo:test%40nitrokey.com?secret=BAUGXGAJZXWBVSBGYMFGNBXC4KV6KPB7&algorithm=SHA1&digits=6&period=30&issuer=demo"
        totp = OTP_Uri.from_uri(totp_uri)

        self.assertEqual(totp.label, "demo:test@nitrokey.com")
        self.assertEqual(totp.secret, b"\x08(k\x98\t\xcd\xec\x1a\xc8&\xc3\nf\x86\xe2\xe2\xab\xe5<?")
        self.assertEqual(totp.issuer, "demo")
        self.assertEqual(totp.algorithm, Algorithm.Sha1)
        self.assertEqual(totp.type_, Kind.Totp)
        self.assertEqual(totp.digits, 6)
        self.assertEqual(totp.period, 30)

    def test_hotp(self) -> None:
        hotp_uri = "otpauth://hotp/demoapp:test%40nitrokey.com?secret=AREPMG7CXJCXLPJQRTFWDACEDFNLCEED&issuer=demoapp&algorithm=SHA1&digits=6&counter=4"
        hotp = OTP_Uri.from_uri(hotp_uri)

        self.assertEqual(hotp.label, "demoapp:test@nitrokey.com")
        self.assertEqual(
            hotp.secret, b"\x04H\xf6\x1b\xe2\xbaEu\xbd0\x8c\xcba\x80D\x19Z\xb1\x10\x83"
        )
        self.assertEqual(hotp.issuer, "demoapp")
        self.assertEqual(hotp.algorithm, Algorithm.Sha1)
        self.assertEqual(hotp.type_, Kind.Hotp)
        self.assertEqual(hotp.digits, 6)
        self.assertEqual(hotp.counter, 4)
