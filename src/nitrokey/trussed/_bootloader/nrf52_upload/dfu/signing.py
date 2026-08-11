#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Copyright (c) 2015 Nordic Semiconductor. All Rights Reserved.
#
# The information contained herein is property of Nordic Semiconductor ASA.
# Terms and conditions of usage are described in detail in NORDIC
# SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
#
# Licensees are granted free, non-transferable use of the information. NO
# WARRANTY of ANY KIND is provided. This heading must NOT be removed from
# the file.


# Modified the original code to use cryptography library instead of ECDSA.
# Is modification to the license text needed?

import datetime
from typing import Optional, cast

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
except Exception:
    print("Failed to import cryptography, cannot do signing")


keys_default_pem = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGvsrpXh8m/E9bj1dq/0o1aBPQVAFJQ6Pzusx685URE0oAoGCCqGSM49
AwEHoUQDQgAEaHYrUu/oFKIXN457GH+8IOuv6OIPBRLqoHjaEKM0wIzJZ0lhfO/A
53hKGjKEjYT3VNTQ3Zq1YB3o5QSQMP/LRg==
-----END EC PRIVATE KEY-----"""


class Signing:
    """
    Class for singing of hex-files
    """

    sk: Optional[ec.EllipticCurvePrivateKey]

    def __init__(self, sk: Optional[ec.EllipticCurvePrivateKey] = None) -> None:
        self.sk = sk

    def gen_key(self, filename: str) -> None:
        """
        Generate a new Signing key using NIST P-256 curve
        """
        self.sk = ec.generate_private_key(ec.SECP256R1())

        with open(filename, "wb") as sk_file:
            sk_file.write(
                self.sk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    @staticmethod
    def get_key_from_file(filename: str) -> ec.EllipticCurvePrivateKey:
        with open(filename, "r") as sk_file:
            sk_pem = sk_file.read()

        loaded_sk = serialization.load_pem_private_key(sk_pem.encode(), password=None)
        if not isinstance(loaded_sk, ec.EllipticCurvePrivateKey):
            raise TypeError("Loaded key is not an EC private key")
        return loaded_sk

    def load_key(self, filename: str) -> None:
        self.sk = Signing.get_key_from_file(filename)

    def sign_der(self, init_packet_data: bytes) -> bytes:
        if self.sk is None:
            raise AssertionError("Can't sign. No key created/loaded")

        # Sign the init-packet (returns a DER-encoded signature)
        der_signature = self.sk.sign(init_packet_data, ec.ECDSA(hashes.SHA256()))
        return der_signature

    def sign(self, init_packet_data: bytes) -> bytes:
        """
        Create signature for init package using P-256 curve and SHA-256 as hashing algorithm
        Returns R and S keys combined in a 64 byte array
        """
        der_signature = self.sign_der(init_packet_data)
        # Add assertion of init_packet
        r, s = decode_dss_signature(der_signature)

        signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

        return signature[31::-1] + signature[63:31:-1]

    def get_vk(self, output_type: Optional[str], dbg: bool) -> str:
        """
        Get public key (as hex, code or pem)
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        if output_type is None:
            raise ValueError("Invalid output type for public key.")
        elif output_type == "hex":
            return self.get_vk_hex()
        elif output_type == "code":
            return self.get_vk_code(dbg)
        elif output_type == "pem":
            return self.get_vk_pem()
        else:
            raise ValueError("Invalid argument. Can't get key")

    def get_pub_numbers(self) -> EllipticCurvePublicNumbers:
        if self.sk is None:
            raise AssertionError("Can't get pubkey. No key created/loaded")

        pem_data = self.get_vk_pem()

        if isinstance(pem_data, str):
            pem_data_bytes = pem_data.encode()

        public_key = serialization.load_pem_public_key(pem_data_bytes, backend=default_backend())
        ec_key = cast(EllipticCurvePublicKey, public_key)
        return ec_key.public_numbers()

    def get_vk_hex(self) -> str:
        """
        Get the verification key as hex
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        # Reverse the two halves of key for display. This
        # emulates a memory dump of the key interpreted as two
        # 256bit little endian integers.
        pub_numbers = self.get_pub_numbers()
        key = pub_numbers.x.to_bytes(32, byteorder="big") + pub_numbers.y.to_bytes(
            32, byteorder="big"
        )
        displayed_key = (key[:32][::-1] + key[32:][::-1]).hex()

        return f"Public (verification) key pk:\n{displayed_key}"

    def wrap_code(self, key_code: str, dbg: bool) -> str:
        header = """
/* This file was automatically generated by nrfutil on {0} */

#include "stdint.h"
#include "compiler_abstraction.h"
""".format(datetime.datetime.now().strftime("%Y-%m-%d (YY-MM-DD) at %H:%M:%S"))

        dbg_header = """
/* This file was generated with a throwaway private key, that is only intended for a debug version of the DFU project.
  Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate a valid public key. */

#ifdef NRF_DFU_DEBUG_VERSION
"""
        dbg_footer = """
#else
#error "Debug public key not valid for production. Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate it"
#endif
"""
        if dbg:
            code = header + dbg_header + key_code + dbg_footer
        else:
            code = header + key_code
        return code

    def get_vk_code(self, dbg: bool) -> str:
        """
        Get the verification key as code
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        def to_two_digit_hex_with_0x(b: int) -> str:
            return "0x{:02x}".format(b)

        pub_numbers = self.get_pub_numbers()
        key = pub_numbers.x.to_bytes(32, byteorder="big") + pub_numbers.y.to_bytes(
            32, byteorder="big"
        )
        vk_x_separated = ", ".join(map(to_two_digit_hex_with_0x, key[:32][::-1]))
        vk_y_separated = ", ".join(map(to_two_digit_hex_with_0x, key[32:][::-1]))

        key_code = """
/** @brief Public key used to verify DFU images */
__ALIGN(4) const uint8_t pk[64] =
{{
    {0},
    {1}
}};
"""
        key_code = key_code.format(vk_x_separated, vk_y_separated)
        vk_code = self.wrap_code(key_code, dbg)

        return vk_code

    def get_vk_pem(self) -> str:
        """
        Get the verification key as PEM
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        vk = self.sk.public_key()
        vk_pem = vk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Return pem as str to conform in type with the other cases.
        return vk_pem.decode()
