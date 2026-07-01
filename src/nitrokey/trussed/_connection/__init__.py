import enum
import importlib.util
import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from fido2.hid import CtapHidDevice

HAS_CCID_SUPPORT = importlib.util.find_spec("smartcard") is not None


@enum.unique
class Transport(Enum):
    CCID = "ccid"
    CTAPHID = "ctaphid"

    @staticmethod
    def from_str(s: str) -> "Transport":
        for transport in Transport:
            if transport.value == s:
                return transport
        raise ValueError(f"Unknown transport '{s}'")


@enum.unique
class App(Enum):
    """Vendor-specific CTAPHID commands for Trussed apps."""

    SECRETS = 0x70
    PROVISIONER = 0x71
    ADMIN = 0x72

    def aid(self) -> bytes:
        if self == App.SECRETS:
            return bytes.fromhex("A000000527 2101")
        elif self == App.ADMIN:
            return bytes.fromhex("A00000084700000001")
        elif self == App.PROVISIONER:
            return bytes.fromhex("A00000084700000001")
        else:
            typing.assert_never(self)


@dataclass(kw_only=True, frozen=True)
class VidPid:
    vid: int
    pid: int


class Connection(ABC):
    def path(self) -> Optional[str]:
        return None

    @abstractmethod
    def transport(self) -> Transport: ...

    @abstractmethod
    def logger_name(self) -> str: ...

    def vid_pid(self) -> Optional[VidPid]:
        return None

    @abstractmethod
    def close(self) -> None: ...

    def ctaphid_device(self) -> CtapHidDevice | None:
        return None

    @abstractmethod
    def wink(self) -> None: ...

    @abstractmethod
    def call_admin_app_legacy(
        self, command: int, data: bytes, response_len: Optional[int]
    ) -> bytes: ...

    @abstractmethod
    def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes: ...

    def set_secrets_pin_cache(self) -> None:
        return
