import enum
import importlib.util
import typing
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TypeAlias

from fido2.hid import CtapHidDevice

from .._utils import VidPid

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
class CcidConnectionInfo:
    reader: str
    atr: bytes


@dataclass(kw_only=True, frozen=True)
class CtapHidConnectionInfo:
    path: str
    vid_pid: VidPid


DeviceConnectionInfo: TypeAlias = CcidConnectionInfo | CtapHidConnectionInfo


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


def open_connection(info: DeviceConnectionInfo) -> AbstractContextManager[Connection]:
    if isinstance(info, CcidConnectionInfo):
        from .ccid import open_ccid

        return open_ccid(info=info, exclusive=True)

    if isinstance(info, CtapHidConnectionInfo):
        from .ctaphid import open_ctaphid

        return open_ctaphid(info=info)

    typing.assert_never(info)
