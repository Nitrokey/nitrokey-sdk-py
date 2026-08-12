import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from nitrokey.trussed._bootloader.nrf52 import SignatureKey, parse_firmware_image
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing
from nitrokey.trussed.nrfutils import keygen, pkg_gen, pubview


class NrfTest(unittest.TestCase):
    def test_nrftests(self) -> None:
        path = "./tests/data/firmware-nk3am-nrf52-v1.8.3.hex"
        with tempfile.TemporaryDirectory() as testpath:
            privkeyfile = os.path.join(testpath, "privkey.pem")
            keygen(privkeyfile)
            self.assertTrue(os.path.exists(privkeyfile))
            # print(open(privkeyfile).read())

            pubkeycode = os.path.join(testpath, "pubkey.c")
            pubview("code", Signing.get_key_from_file(privkeyfile), pubkeycode)
            self.assertTrue(os.path.exists(pubkeycode))
            # print(open(pubkeycode).read())

            pubkeypem = os.path.join(testpath, "pubkey.pem")
            pubview("pem", Signing.get_key_from_file(privkeyfile), pubkeypem)
            self.assertTrue(os.path.exists(pubkeypem))
            # print(open(pubkeypem).read())

            signedfirmware = os.path.join(testpath, "firmware.zip")
            pkg_gen(
                hw_version=1,
                sd_req="0xFFFE",
                key_file=Signing.get_key_from_file(privkeyfile),
                out_path=signedfirmware,
                app_version=1,
                application=path,
                ecdsa_validation=True,
            )
            self.assertTrue(os.path.exists(signedfirmware))
            # print(open(signedfirmware, "rb").read())

            with open(pubkeypem, "rb") as pubpem:
                pubkey = pubpem.read()
            der = (
                serialization.load_pem_public_key(pubkey)
                .public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .hex()
            )
            key_name = "Test key"
            signaturekey = SignatureKey(name=key_name, is_official=False, der=der)

            with open(signedfirmware, "rb") as sf:
                firmware_bytes = sf.read()
            metadata = parse_firmware_image(firmware_bytes, keys=[signaturekey])

            self.assertEqual(metadata.signed_by, key_name)
