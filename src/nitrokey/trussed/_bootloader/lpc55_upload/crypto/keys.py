#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for key generation and saving keys to file."""

import abc
import math
from abc import abstractmethod
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import PublicFormat

from ..utils.misc import Endianness
from .hash import EnumHashAlgorithm, get_hash, get_hash_algorithm
from .types import SPSDKEncoding


class PublicKey(abc.ABC):
    """SPSDK Public Key."""

    key: Any

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Size of signature data."""

    @property
    @abc.abstractmethod
    def public_numbers(self) -> Any:
        """Public numbers."""

    @abc.abstractmethod
    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
    ) -> bool:
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        """

    @abc.abstractmethod
    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export key into bytes to requested format.

        :param encoding: encoding type, default is NXP
        :return: Byte representation of key
        """

    def key_hash(
        self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256
    ) -> bytes:
        """Get key hash.

        :param algorithm: Used hash algorithm, defaults to sha256
        :return: Key Hash
        """
        return get_hash(self.export(), algorithm)

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return (
            isinstance(obj, self.__class__)
            and self.public_numbers == obj.public_numbers
        )

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @abstractmethod
    def __repr__(self) -> str:
        """Object representation in string format."""

    @abstractmethod
    def __str__(self) -> str:
        """Object description in string format."""


# ===================================================================================================
# ===================================================================================================
#
#                                      RSA Keys
#
# ===================================================================================================
# ===================================================================================================


class PublicKeyRsa(PublicKey):
    """SPSDK Public Key."""

    SUPPORTED_KEY_SIZES = [2048, 3072, 4096]

    key: rsa.RSAPublicKey

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: SPSDK Public Key data or file path
        """
        self.key = key

    @property
    def signature_size(self) -> int:
        """Size of signature data."""
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key Size
        """
        return self.key.key_size

    @property
    def public_numbers(self) -> rsa.RSAPublicNumbers:
        """Public numbers of key.

        :return: Public numbers
        """
        return self.key.public_numbers()

    @property
    def e(self) -> int:
        """Public number E.

        :return: E
        """
        return self.public_numbers.e

    @property
    def n(self) -> int:
        """Public number N.

        :return: N
        """
        return self.public_numbers.n

    def export(
        self,
        encoding: SPSDKEncoding = SPSDKEncoding.NXP,
        exp_length: Optional[int] = None,
        modulus_length: Optional[int] = None,
    ) -> bytes:
        """Save the public key to the bytes in NXP or DER format.

        :param encoding: encoding type, default is NXP
        :param exp_length: Optional specific exponent length in bytes
        :param modulus_length: Optional specific modulus length in bytes
        :returns: Public key in bytes
        """
        if encoding == SPSDKEncoding.NXP:
            exp_rotk = self.e
            mod_rotk = self.n
            exp_length = exp_length or math.ceil(exp_rotk.bit_length() / 8)
            modulus_length = modulus_length or math.ceil(mod_rotk.bit_length() / 8)
            exp_rotk_bytes = exp_rotk.to_bytes(exp_length, Endianness.BIG.value)
            mod_rotk_bytes = mod_rotk.to_bytes(modulus_length, Endianness.BIG.value)
            return mod_rotk_bytes + exp_rotk_bytes

        return self.key.public_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding), PublicFormat.PKCS1
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
    ) -> bool:
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        """
        try:
            self.key.verify(
                signature=signature,
                data=data,
                padding=padding.PKCS1v15(),
                algorithm=get_hash_algorithm(algorithm),
            )
        except InvalidSignature:
            return False

        return True

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return (
            isinstance(obj, self.__class__)
            and self.public_numbers == obj.public_numbers
        )

    def __repr__(self) -> str:
        return f"RSA{self.key_size} Public Key"

    def __str__(self) -> str:
        """Object description in string format."""
        ret = f"RSA{self.key_size} Public key: \ne({hex(self.e)}) \nn({hex(self.n)})"
        return ret
