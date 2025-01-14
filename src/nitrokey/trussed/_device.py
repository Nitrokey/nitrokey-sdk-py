# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import logging
import platform
import sys
from abc import abstractmethod
from enum import Enum
from typing import List, Optional, Sequence, TypeVar, Union

from fido2.hid import CtapHidDevice, open_device

from ._base import TrussedBase
from ._utils import Fido2Certs, Uuid

T = TypeVar("T", bound="TrussedDevice")

logger = logging.getLogger(__name__)


@enum.unique
class App(Enum):
    """Vendor-specific CTAPHID commands for Trussed apps."""

    SECRETS = 0x70
    PROVISIONER = 0x71
    ADMIN = 0x72


class TrussedDevice(TrussedBase):
    def __init__(
        self, device: CtapHidDevice, fido2_certs: Sequence[Fido2Certs]
    ) -> None:
        self._validate_vid_pid(device.descriptor.vid, device.descriptor.pid)

        self.device = device
        self.fido2_certs = fido2_certs
        self._path = _device_path_to_str(device.descriptor.path)
        self._logger = logger.getChild(self._path)

        from .admin_app import AdminApp

        self.admin = AdminApp(self)
        self.admin.status()

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        self.device.close()

    def reboot(self) -> bool:
        from .admin_app import BootMode

        return self.admin.reboot(BootMode.FIRMWARE)

    def uuid(self) -> Optional[Uuid]:
        return self.admin.uuid()

    def wink(self) -> None:
        self.device.wink()

    def _call(
        self,
        command: int,
        command_name: str,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> bytes:
        response = self.device.call(command, data=data)
        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {command_name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    def _call_app(
        self,
        app: App,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> bytes:
        return self._call(app.value, app.name, response_len, data)

    @classmethod
    @abstractmethod
    def from_device(cls: type[T], device: CtapHidDevice) -> T: ...

    @classmethod
    def open(cls: type[T], path: str) -> Optional[T]:
        try:
            if platform.system() == "Windows":
                device = open_device(bytes(path, "utf-8"))
            else:
                device = open_device(path)
        except Exception:
            logger.warn(f"No CTAPHID device at path {path}", exc_info=sys.exc_info())
            return None
        try:
            return cls.from_device(device)
        except ValueError:
            logger.warn(f"No Nitrokey device at path {path}", exc_info=sys.exc_info())
            return None

    @classmethod
    @abstractmethod
    def list(cls: type[T]) -> List[T]: ...


def _device_path_to_str(path: Union[bytes, str]) -> str:
    """
    Converts a device path as returned by the fido2 library to a string.

    Typically, the path already is a string.  Only on Windows, a bytes object
    using an ANSI encoding is used instead.  We use the ISO 8859-1 encoding to
    decode the string which should work for all systems.
    """
    if isinstance(path, bytes):
        return path.decode("iso-8859-1", errors="ignore")
    else:
        return path
