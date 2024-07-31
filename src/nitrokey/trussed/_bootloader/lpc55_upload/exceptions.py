#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Base for SPSDK exceptions."""
from typing import Optional

#######################################################################
# # Secure Provisioning SDK Exceptions
#######################################################################


class SPSDKError(Exception):
    """Secure Provisioning SDK Base Exception."""

    fmt = "SPSDK: {description}"

    def __init__(self, desc: Optional[str] = None) -> None:
        """Initialize the base SPSDK Exception."""
        super().__init__()
        self.description = desc

    def __str__(self) -> str:
        return self.fmt.format(description=self.description or "Unknown Error")


class SPSDKKeyError(SPSDKError, KeyError):
    """SPSDK standard key error."""


class SPSDKValueError(SPSDKError, ValueError):
    """SPSDK standard value error."""


class SPSDKTypeError(SPSDKError, TypeError):
    """SPSDK standard type error."""


class SPSDKAttributeError(SPSDKError, AttributeError):
    """SPSDK standard attribute error."""


class SPSDKConnectionError(SPSDKError, ConnectionError):
    """SPSDK standard connection error."""
