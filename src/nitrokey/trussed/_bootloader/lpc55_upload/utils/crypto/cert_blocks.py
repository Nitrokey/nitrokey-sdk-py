#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling Certificate block."""

import re
from struct import calcsize, unpack_from
from typing import TYPE_CHECKING, List, Optional, Union

from ...crypto.certificate import Certificate
from ...exceptions import SPSDKError
from ...utils.abstract import BaseClass
from ...utils.crypto.rkht import RKHTv1
from ...utils.misc import Endianness, align

if TYPE_CHECKING:
    from typing_extensions import Self


class CertBlock(BaseClass):
    """Common general class for various CertBlocks."""

    @property
    def rkth(self) -> bytes:
        """Root Key Table Hash 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return bytes()


########################################################################################################################
# Certificate Block Header Class
########################################################################################################################
class CertBlockHeader(BaseClass):
    """Certificate block header."""

    FORMAT = "<4s2H6I"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(
        self, version: str = "1.0", flags: int = 0, build_number: int = 0
    ) -> None:
        """Constructor.

        :param version: Version of the certificate in format n.n
        :param flags: Flags for the Certificate Header
        :param build_number: of the certificate
        :raises SPSDKError: When there is invalid version
        """
        if not re.match(r"[0-9]+\.[0-9]+", version):  # check format of the version: N.N
            raise SPSDKError("Invalid version")
        self.version = version
        self.flags = flags
        self.build_number = build_number
        self.image_length = 0
        self.cert_count = 0
        self.cert_table_length = 0

    def __repr__(self) -> str:
        nfo = f"CertBlockHeader: V={self.version}, F={self.flags}, BN={self.build_number}, IL={self.image_length}, "
        nfo += f"CC={self.cert_count}, CTL={self.cert_table_length}"
        return nfo

    def __str__(self) -> str:
        """Info of the certificate header in text form."""
        nfo = str()
        nfo += f" CB Version:           {self.version}\n"
        nfo += f" CB Flags:             {self.flags}\n"
        nfo += f" CB Build Number:      {self.build_number}\n"
        nfo += f" CB Image Length:      {self.image_length}\n"
        nfo += f" CB Cert. Count:       {self.cert_count}\n"
        nfo += f" CB Cert. Length:      {self.cert_table_length}\n"
        return nfo

    @classmethod
    def parse(cls, data: bytes) -> "Self":
        """Deserialize object from bytes array.

        :param data: Input data as bytes
        :return: Certificate Header instance
        :raises SPSDKError: Unexpected size or signature of data
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Incorrect size")
        (
            signature,
            major_version,
            minor_version,
            length,
            flags,
            build_number,
            image_length,
            cert_count,
            cert_table_length,
        ) = unpack_from(cls.FORMAT, data)
        if signature != cls.SIGNATURE:
            raise SPSDKError("Incorrect signature")
        if length != cls.SIZE:
            raise SPSDKError("Incorrect length")
        obj = cls(
            version=f"{major_version}.{minor_version}",
            flags=flags,
            build_number=build_number,
        )
        obj.image_length = image_length
        obj.cert_count = cert_count
        obj.cert_table_length = cert_table_length
        return obj


########################################################################################################################
# Certificate Block Class
########################################################################################################################
class CertBlockV1(CertBlock):
    """Certificate block.

    Shared for SB file 2.1 and for MasterBootImage using RSA keys.
    """

    # default size alignment
    DEFAULT_ALIGNMENT = 16

    @property
    def header(self) -> CertBlockHeader:
        """Certificate block header."""
        return self._header

    @property
    def rkh(self) -> List[bytes]:
        """List of root keys hashes (SHA-256), each hash as 32 bytes."""
        return self._rkht.rkh_list

    @property
    def rkth(self) -> bytes:
        """Root Key Table Hash 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return self._rkht.rkth()

    @property
    def rkth_fuses(self) -> List[int]:
        """List of RKHT fuses, ordered from highest bit to lowest.

        Note: Returned values are in format that should be passed for blhost
        """
        result = []
        rkht = self.rkth
        while rkht:
            fuse = int.from_bytes(rkht[:4], byteorder=Endianness.LITTLE.value)
            result.append(fuse)
            rkht = rkht[4:]
        return result

    @property
    def certificates(self) -> List[Certificate]:
        """List of certificates in header.

        First certificate is root certificate and followed by optional chain certificates
        """
        return self._cert

    @property
    def signature_size(self) -> int:
        """Size of the signature in bytes."""
        return len(
            self.certificates[0].signature
        )  # The certificate is self signed, return size of its signature

    @property
    def rkh_index(self) -> Optional[int]:
        """Index of the Root Key Hash that matches the certificate; None if does not match."""
        if self._cert:
            rkh = self._cert[0].public_key_hash()
            for index, value in enumerate(self.rkh):
                if rkh == value:
                    return index
        return None

    @property
    def alignment(self) -> int:
        """Alignment of the binary output, by default it is DEFAULT_ALIGNMENT but can be customized."""
        return self._alignment

    @alignment.setter
    def alignment(self, value: int) -> None:
        """Setter.

        :param value: new alignment
        :raises SPSDKError: When there is invalid alignment
        """
        if value <= 0:
            raise SPSDKError("Invalid alignment")
        self._alignment = value

    @property
    def raw_size(self) -> int:
        """Aligned size of the certificate block."""
        size = CertBlockHeader.SIZE
        size += self._header.cert_table_length
        size += self._rkht.RKH_SIZE * self._rkht.RKHT_SIZE
        return align(size, self.alignment)

    @property
    def expected_size(self) -> int:
        """Expected size of binary block."""
        return self.raw_size

    @property
    def image_length(self) -> int:
        """Image length in bytes."""
        return self._header.image_length

    @image_length.setter
    def image_length(self, value: int) -> None:
        """Setter.

        :param value: new image length
        :raises SPSDKError: When there is invalid image length
        """
        if value <= 0:
            raise SPSDKError("Invalid image length")
        self._header.image_length = value

    def __init__(
        self, version: str = "1.0", flags: int = 0, build_number: int = 0
    ) -> None:
        """Constructor.

        :param version: of the certificate in format n.n
        :param flags: Flags for the Certificate Block Header
        :param build_number: of the certificate
        """
        self._header = CertBlockHeader(version, flags, build_number)
        self._rkht: RKHTv1 = RKHTv1([])
        self._cert: List[Certificate] = []
        self._alignment = self.DEFAULT_ALIGNMENT

    def __len__(self) -> int:
        return len(self._cert)

    def add_certificate(self, cert: Union[bytes, Certificate]) -> None:
        """Add certificate.

        First call adds root certificate. Additional calls add chain certificates.

        :param cert: The certificate itself in DER format
        :raises SPSDKError: If certificate cannot be added
        """
        if isinstance(cert, bytes):
            cert_obj = Certificate.parse(cert)
        elif isinstance(cert, Certificate):
            cert_obj = cert
        else:
            raise SPSDKError("Invalid parameter type (cert)")
        if cert_obj.version.name != "v3":
            raise SPSDKError(
                "Expected certificate v3 but received: " + cert_obj.version.name
            )
        if self._cert:  # chain certificate?
            last_cert = self._cert[-1]  # verify that it is signed by parent key
            if not cert_obj.validate(last_cert):
                raise SPSDKError(
                    "Chain certificate cannot be verified using parent public key"
                )
        else:  # root certificate
            if not cert_obj.self_signed:
                raise SPSDKError(
                    f"Root certificate must be self-signed.\n{str(cert_obj)}"
                )
        self._cert.append(cert_obj)
        self._header.cert_count += 1
        self._header.cert_table_length += cert_obj.raw_size + 4

    def __repr__(self) -> str:
        return str(self._header)

    def __str__(self) -> str:
        """Text info about certificate block."""
        nfo = str(self.header)
        nfo += " Public Root Keys Hash e.g. RKH (SHA256):\n"
        rkh_index = self.rkh_index
        for index, root_key in enumerate(self._rkht.rkh_list):
            nfo += f"  {index}) {root_key.hex().upper()} {'<- Used' if index == rkh_index else ''}\n"
        rkth = self.rkth
        nfo += f" RKTH (SHA256): {rkth.hex().upper()}\n"
        for index, fuse in enumerate(self.rkth_fuses):
            bit_ofs = (len(rkth) - 4 * index) * 8
            nfo += f"  - RKTH fuse [{bit_ofs:03}:{bit_ofs - 31:03}]: {fuse:08X}\n"
        for index, cert in enumerate(self._cert):
            nfo += " Root Certificate:\n" if index == 0 else f" Certificate {index}:\n"
            nfo += str(cert)
        return nfo

    def verify_data(self, signature: bytes, data: bytes) -> bool:
        """Signature verification.

        :param signature: to be verified
        :param data: that has been signed
        :return: True if the data signature can be confirmed using the certificate; False otherwise
        """
        cert = self._cert[-1]
        pub_key = cert.get_public_key()
        return pub_key.verify_signature(signature=signature, data=data)

    @classmethod
    def parse(cls, data: bytes) -> "Self":
        """Deserialize CertBlockV1 from binary file.

        :param data: Binary data
        :return: Certificate Block instance
        :raises SPSDKError: Length of the data doesn't match Certificate Block length
        """
        header = CertBlockHeader.parse(data)
        offset = CertBlockHeader.SIZE
        if len(data) < (
            header.cert_table_length + (RKHTv1.RKHT_SIZE * RKHTv1.RKH_SIZE)
        ):
            raise SPSDKError(
                "Length of the data doesn't match Certificate Block length"
            )
        obj = cls(
            version=header.version, flags=header.flags, build_number=header.build_number
        )
        for _ in range(header.cert_count):
            cert_len = unpack_from("<I", data, offset)[0]
            offset += 4
            cert_obj = Certificate.parse(data[offset : offset + cert_len])
            obj.add_certificate(cert_obj)
            offset += cert_len
        obj._rkht = RKHTv1.parse(
            data[offset : offset + (RKHTv1.RKH_SIZE * RKHTv1.RKHT_SIZE)]
        )
        return obj
