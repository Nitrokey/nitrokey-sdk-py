#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for symmetric key encryption."""


# Used security modules
from typing import Optional

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..utils.misc import Endianness


class Counter:
    """AES counter with specified counter byte ordering and customizable increment."""

    @property
    def value(self) -> bytes:
        """Initial vector for AES encryption."""
        return self._nonce + self._ctr.to_bytes(4, self._ctr_byteorder_encoding.value)

    def __init__(
        self,
        nonce: bytes,
        ctr_value: Optional[int] = None,
        ctr_byteorder_encoding: Endianness = Endianness.LITTLE,
    ):
        """Constructor.

        :param nonce: last four bytes are used as initial value for counter
        :param ctr_value: counter initial value; it is added to counter value retrieved from nonce
        :param ctr_byteorder_encoding: way how the counter is encoded into output value
        :raises SPSDKError: When invalid byteorder is provided
        """
        assert isinstance(nonce, bytes) and len(nonce) == 16
        self._nonce = nonce[:-4]
        self._ctr_byteorder_encoding = ctr_byteorder_encoding
        self._ctr = int.from_bytes(nonce[-4:], ctr_byteorder_encoding.value)
        if ctr_value is not None:
            self._ctr += ctr_value

    def increment(self, value: int = 1) -> None:
        """Increment counter by specified value.

        :param value: to add to counter
        """
        self._ctr += value


def aes_key_unwrap(kek: bytes, wrapped_key: bytes) -> bytes:
    """Unwraps a key using a key-encrypting key (KEK).

    :param kek: The key-encrypting key
    :param wrapped_key: Encrypted data
    :return: Un-wrapped key
    """
    return keywrap.aes_key_unwrap(kek, wrapped_key)


def aes_ctr_decrypt(key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
    """Decrypt encrypted data with AES in CTR mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param nonce: Nonce data with counter value
    :return: Decrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()
