#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for Root Key Hash table."""

from abc import abstractmethod
from typing import TYPE_CHECKING, List

from ...crypto.hash import EnumHashAlgorithm, get_hash
from ...exceptions import SPSDKError

if TYPE_CHECKING:
    from typing_extensions import Self


class RKHT:
    """Root Key Hash Table class."""

    def __init__(self, rkh_list: List[bytes]) -> None:
        """Initialization of Root Key Hash Table class.

        :param rkh_list: List of Root Key Hashes
        """
        if len(rkh_list) > 4:
            raise SPSDKError("Number of Root Key Hashes can not be larger than 4.")
        self.rkh_list = rkh_list

    @abstractmethod
    def rkth(self) -> bytes:
        """Root Key Table Hash.

        :return: Hash of hashes of public keys.
        """

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Used hash algorithm name."""
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorighm name. No root key hashes.")
        return EnumHashAlgorithm.from_label(f"sha{self.hash_algorithm_size}")

    @property
    def hash_algorithm_size(self) -> int:
        """Used hash algorithm size in bites."""
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorithm size. No public keys provided.")
        return len(self.rkh_list[0]) * 8


class RKHTv1(RKHT):
    """Root Key Hash Table class for cert block v1."""

    RKHT_SIZE = 4
    RKH_SIZE = 32

    def __init__(
        self,
        rkh_list: List[bytes],
    ) -> None:
        """Initialization of Root Key Hash Table class.

        :param rkh_list: List of Root Key Hashes
        """
        for key_hash in rkh_list:
            if len(key_hash) != self.RKH_SIZE:
                raise SPSDKError(f"Invalid key hash size: {len(key_hash)}")
        super().__init__(rkh_list)

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Used Hash algorithm name."""
        return EnumHashAlgorithm.SHA256

    def export(self) -> bytes:
        """Export RKHT as bytes."""
        rotk_table = b""
        for i in range(self.RKHT_SIZE):
            if i < len(self.rkh_list) and self.rkh_list[i]:
                rotk_table += self.rkh_list[i]
            else:
                rotk_table += bytes(self.RKH_SIZE)
        if len(rotk_table) != self.RKH_SIZE * self.RKHT_SIZE:
            raise SPSDKError("Invalid length of data.")
        return rotk_table

    @classmethod
    def parse(cls, rkht: bytes) -> "Self":
        """Parse Root Key Hash Table into RKHTv1 object.

        :param rkht: Valid RKHT table
        """
        rotkh_len = len(rkht) // cls.RKHT_SIZE
        offset = 0
        key_hashes = []
        for _ in range(cls.RKHT_SIZE):
            key_hashes.append(rkht[offset : offset + rotkh_len])
            offset += rotkh_len
        return cls(key_hashes)

    def rkth(self) -> bytes:
        """Root Key Table Hash.

        :return: Hash of Hashes of public key.
        """
        rotkh = get_hash(self.export(), self.hash_algorithm)
        return rotkh
