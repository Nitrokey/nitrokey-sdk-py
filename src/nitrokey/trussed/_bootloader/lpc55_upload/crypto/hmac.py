#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for HMAC packet authentication."""

# Used security modules
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as hmac_cls


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return a HMAC from data with specified key and algorithm.

    :param key: The key in bytes format
    :param data: Input data in bytes format
    :return: HMAC bytes
    """
    hmac_obj = hmac_cls.HMAC(key, hashes.SHA256())
    hmac_obj.update(data)
    return hmac_obj.finalize()
