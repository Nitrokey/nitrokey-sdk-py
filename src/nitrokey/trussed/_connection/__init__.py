import enum
import importlib.util
from enum import Enum
from typing import Optional, Protocol

HAS_CCID_SUPPORT = importlib.util.find_spec("smartcard") is not None


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


class Connection(Protocol):
    def path(self) -> Optional[str]: ...
    def logger_name(self) -> str: ...
    def vid_pid(self) -> Optional[tuple[int, int]]: ...
    def close(self) -> None: ...
    def wink(self) -> None: ...
    def call_admin_app_legacy(
        self, command: int, data: bytes, response_len: Optional[int]
    ) -> bytes: ...
    def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes: ...
