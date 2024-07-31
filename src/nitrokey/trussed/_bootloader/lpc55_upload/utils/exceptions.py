#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for SPSDK utilities."""
from ..exceptions import SPSDKError


class SPSDKTimeoutError(TimeoutError, SPSDKError):
    """SPSDK Timeout."""
