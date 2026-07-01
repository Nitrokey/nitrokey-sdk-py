# Copyright 2022-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import typing
from dataclasses import dataclass


class TrussedException(Exception):
    pass


class ConnectionError(TrussedException):
    """
    Raised if the connection to the device is lost while executing a command.
    """

    def __init__(self) -> None:
        super().__init__("Lost the connection to the device while executing a command")


@dataclass(frozen=True)
class CcidErrorCode:
    sw1: int
    sw2: int

    def __str__(self) -> str:
        return f"CCID error code 0x{bytes([self.sw1, self.sw2]).hex()}"


@dataclass(frozen=True)
class CtapErrorCode:
    error: int

    def __str__(self) -> str:
        from fido2.ctap import CtapError

        try:
            error = str(CtapError.ERR(self.error))
        except ValueError:
            error = str(CtapError.UNKNOWN_ERR(self.error))
        return f"CTAP error code {error}"


class DeviceError(TrussedException):
    """
    An error code returned by the device.
    """

    code: CcidErrorCode | CtapErrorCode

    def __init__(self, code: CcidErrorCode | CtapErrorCode) -> None:
        super().__init__(f"The device return an error code: {code}")

        self.code = code

    def is_code(self, ccid: CcidErrorCode, ctap: CtapErrorCode) -> bool:
        if isinstance(self.code, CcidErrorCode):
            return self.code == ccid
        if isinstance(self.code, CtapErrorCode):
            return self.code == ctap
        typing.assert_never(self.code)


class TimeoutException(TrussedException):
    def __init__(self) -> None:
        super().__init__("The user confirmation request timed out")
