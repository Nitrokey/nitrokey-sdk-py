#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for certificate management (generating certificate, validating certificate, chains)."""

from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from ..crypto.hash import EnumHashAlgorithm
from ..crypto.keys import PublicKey, PublicKeyRsa
from ..crypto.types import (
    SPSDKEncoding,
    SPSDKExtensionOID,
    SPSDKExtensions,
    SPSDKName,
    SPSDKVersion,
)
from ..exceptions import SPSDKError, SPSDKValueError
from ..utils.abstract import BaseClass
from ..utils.misc import align_block


class Certificate(BaseClass):
    """SPSDK Certificate representation."""

    def __init__(self, certificate: x509.Certificate) -> None:
        """Constructor of SPSDK Certificate.

        :param certificate: Cryptography Certificate representation.
        """
        assert isinstance(certificate, x509.Certificate)
        self.cert = certificate

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Convert certificates into bytes.

        :param encoding: encoding type
        :return: certificate in bytes form
        """
        if encoding == SPSDKEncoding.NXP:
            return align_block(self.export(SPSDKEncoding.DER), 4, "zeros")

        return self.cert.public_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding)
        )

    def get_public_key(self) -> PublicKey:
        """Get public keys from certificate.

        :return: RSA public key
        """
        pub_key = self.cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            return PublicKeyRsa(pub_key)

        raise SPSDKError(f"Unsupported Certificate public key: {type(pub_key)}")

    @property
    def version(self) -> SPSDKVersion:
        """Returns the certificate version."""
        return self.cert.version

    @property
    def signature(self) -> bytes:
        """Returns the signature bytes."""
        return self.cert.signature

    @property
    def tbs_certificate_bytes(self) -> bytes:
        """Returns the tbsCertificate payload bytes as defined in RFC 5280."""
        return self.cert.tbs_certificate_bytes

    @property
    def signature_hash_algorithm(
        self,
    ) -> Optional[hashes.HashAlgorithm]:
        """Returns a HashAlgorithm corresponding to the type of the digest signed in the certificate."""
        return self.cert.signature_hash_algorithm

    @property
    def extensions(self) -> SPSDKExtensions:
        """Returns an Extensions object."""
        return self.cert.extensions

    @property
    def issuer(self) -> SPSDKName:
        """Returns the issuer name object."""
        return self.cert.issuer

    @property
    def serial_number(self) -> int:
        """Returns certificate serial number."""
        return self.cert.serial_number

    @property
    def subject(self) -> SPSDKName:
        """Returns the subject name object."""
        return self.cert.subject

    def validate(self, issuer_certificate: "Certificate") -> bool:
        """Validate certificate.

        :param issuer_certificate: Issuer's certificate
        :raises SPSDKError: Unsupported key type in Certificate
        :return: true/false whether certificate is valid or not
        """
        assert self.signature_hash_algorithm
        return issuer_certificate.get_public_key().verify_signature(
            self.signature,
            self.tbs_certificate_bytes,
            EnumHashAlgorithm.from_label(self.signature_hash_algorithm.name),
        )

    @property
    def ca(self) -> bool:
        """Check if CA flag is set in certificate.

        :return: true/false depending whether ca flag is set or not
        """
        extension = self.extensions.get_extension_for_oid(
            SPSDKExtensionOID.BASIC_CONSTRAINTS
        )
        return extension.value.ca  # type: ignore # mypy can not handle property definition in cryptography

    @property
    def self_signed(self) -> bool:
        """Indication whether the Certificate is self-signed."""
        return self.validate(self)

    @property
    def raw_size(self) -> int:
        """Raw size of the certificate."""
        return len(self.export())

    def public_key_hash(
        self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256
    ) -> bytes:
        """Get key hash.

        :param algorithm: Used hash algorithm, defaults to sha256
        :return: Key Hash
        """
        return self.get_public_key().key_hash(algorithm)

    def __repr__(self) -> str:
        """Text short representation about the Certificate."""
        return f"Certificate, SN:{hex(self.cert.serial_number)}"

    def __str__(self) -> str:
        """Text information about the Certificate."""
        not_valid_before = self.cert.not_valid_before.strftime("%d.%m.%Y (%H:%M:%S)")
        not_valid_after = self.cert.not_valid_after.strftime("%d.%m.%Y (%H:%M:%S)")
        nfo = ""
        nfo += f"  Certification Authority:    {'YES' if self.ca else 'NO'}\n"
        nfo += f"  Serial Number:              {hex(self.cert.serial_number)}\n"
        nfo += f"  Validity Range:             {not_valid_before} - {not_valid_after}\n"
        if self.signature_hash_algorithm:
            nfo += (
                f"  Signature Algorithm:        {self.signature_hash_algorithm.name}\n"
            )
        nfo += f"  Self Issued:                {'YES' if self.self_signed else 'NO'}\n"

        return nfo

    @classmethod
    def parse(cls, data: bytes) -> "Certificate":
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :returns: Recreated certificate
        """

        def load_der_certificate(data: bytes) -> x509.Certificate:
            """Load the DER certificate from bytes.

            This function is designed to eliminate cryptography exception
            when the padded data is provided.

            :param data: Data with DER certificate
            :return: Certificate (from cryptography library)
            :raises SPSDKError: Unsupported certificate to load
            """
            while True:
                try:
                    return x509.load_der_x509_certificate(data)
                except ValueError as exc:
                    if (
                        len(exc.args)
                        and "kind: ExtraData" in exc.args[0]
                        and data[-1:] == b"\00"
                    ):
                        data = data[:-1]
                    else:
                        raise SPSDKValueError(str(exc)) from exc

        try:
            encoding = SPSDKEncoding.get_file_encodings(data)
            if encoding != SPSDKEncoding.DER:
                raise ValueError("Unsupported encoding: {encoding}")
            return Certificate(load_der_certificate(data))
        except ValueError as exc:
            raise SPSDKError(f"Cannot load certificate: ({str(exc)})") from exc
