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

from fido2.hid import CtapHidDevice, list_descriptors, open_device
from smartcard.Exceptions import NoCardException
from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
from smartcard.System import readers

from ._base import TrussedBase
from ._utils import Fido2Certs, Iso7816Apdu, Uuid

T = TypeVar("T", bound="TrussedDevice")

logger = logging.getLogger(__name__)


class PcscError(Exception):
    def __init__(self, sw1: int, sw2: int) -> None:
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f"Got error code {bytes([sw1, sw2]).hex()}")


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


class TrussedDevice(TrussedBase):
    def __init__(
        self,
        device: CtapHidDevice | ExclusiveConnectCardConnection,
        fido2_certs: Sequence[Fido2Certs],
    ) -> None:
        self._path = None
        if isinstance(device, CtapHidDevice):
            self._validate_vid_pid(device.descriptor.vid, device.descriptor.pid)
            self._path = _device_path_to_str(device.descriptor.path)
            self._logger = logger.getChild(self._path)
        else:
            self._logger = logger.getChild(str(device.getReader()))

        self.device = device
        self.fido2_certs = fido2_certs

        from .admin_app import AdminApp

        self.admin = AdminApp(self)
        self.admin.status()

    @property
    def path(self) -> Optional[str]:
        return self._path

    def close(self) -> None:
        if isinstance(self.device, CtapHidDevice):
            self.device.close()
        else:
            self.device.disconnect()
            self.device.release()

    def reboot(self) -> bool:
        from .admin_app import BootMode

        return self.admin.reboot(BootMode.FIRMWARE)

    def uuid(self) -> Optional[Uuid]:
        return self.admin.uuid()

    def wink(self) -> None:
        if isinstance(self.device, CtapHidDevice):
            self.device.wink()

    def _call_admin_legacy(
        self, command: int, command_name: str, response_len: Optional[int] = None, data: bytes = b""
    ) -> bytes:
        response: bytes = bytes()
        if isinstance(self.device, CtapHidDevice):
            response = self.device.call(command, data=data)
        else:
            response = self._call_admin_ccid_legacy(command, data)

        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {command_name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    def _call_admin_ccid_legacy(
        self, command: int, data: bytes, response_len: Optional[int] = None
    ) -> bytes:
        assert not isinstance(self.device, CtapHidDevice)
        app = App.ADMIN
        select = bytes([0x00, 0xA4, 0x04, 0x00, len(app.aid())]) + app.aid()
        _, sw1, sw2 = self.device.transmit(list(select))
        while True:
            if sw1 == 0x61:
                _, sw1, sw2 = self.device.transmit(
                    list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                )
                continue
            break
        if sw1 != 0x90 or sw2 != 0x00:
            raise PcscError(sw1, sw2)
        p1 = 0
        if len(data) >= 1:
            p1 = data[0]
        apdu = Iso7816Apdu(0x00, command, 0, p1, data, le=response_len)
        data, sw1, sw2 = self.device.transmit(list(apdu.to_bytes()))
        accumulator = bytes(data)
        while True:
            if sw1 == 0x61:
                data, sw1, sw2 = self.device.transmit(
                    list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                )
                accumulator += bytes(data)
                continue
            break
        if sw1 != 0x90 or sw2 != 0x00:
            raise PcscError(sw1, sw2)

        return accumulator

    def _call_ccid(self, app: App, response_len: Optional[int] = None, data: bytes = b"") -> bytes:
        assert not isinstance(self.device, CtapHidDevice)
        select = bytes([0x00, 0xA4, 0x04, 0x00, len(app.aid())]) + app.aid()
        _, sw1, sw2 = self.device.transmit(list(select))
        while True:
            if sw1 == 0x61:
                _, sw1, sw2 = self.device.transmit(
                    list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                )
                continue
            break
        if sw1 != 0x90 or sw2 != 0x00:
            raise PcscError(sw1, sw2)

        command = None
        if app == App.ADMIN or app == App.PROVISIONER:
            command = list(Iso7816Apdu(0x00, data[0], 0, 0, data[1:], le=response_len).to_bytes())
        elif app == App.SECRETS:
            command = list(data)

        data, sw1, sw2 = self.device.transmit(command)
        accumulator = bytes(data)
        while True:
            if sw1 == 0x61:
                data, sw1, sw2 = self.device.transmit(
                    list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                )
                accumulator += bytes(data)
                continue
            break

        if app == App.SECRETS:
            accumulator = bytes([sw1, sw2]) + accumulator
            # Let the secret app handle the error
            return accumulator

        if sw1 != 0x90 or sw2 != 0x00:
            raise PcscError(sw1, sw2)

        return accumulator

    def _call_app(self, app: App, response_len: Optional[int] = None, data: bytes = b"") -> bytes:
        response: bytes = bytes()
        if isinstance(self.device, CtapHidDevice):
            response = self.device.call(app.value, data=data)
        else:
            response = self._call_ccid(app, response_len, data)

        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {app.name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    @classmethod
    @abstractmethod
    def from_device(cls: type[T], device: CtapHidDevice | ExclusiveConnectCardConnection) -> T: ...

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
    def list_ccid(cls: type[T]) -> List[T]: ...

    @classmethod
    @abstractmethod
    def list_ctaphid(cls: type[T]) -> List[T]: ...

    @classmethod
    def _list_vid_pid(cls: type[T], vid: int, pid: int) -> List[T]:
        descriptors = [
            desc
            for desc in list_descriptors()  # type: ignore
            if desc.vid == vid and desc.pid == pid
        ]
        return [cls.from_device(open_device(desc.path)) for desc in descriptors]

    @classmethod
    def _list_pcsc_atr(cls: type[T], atr: List[int]) -> List[T]:
        devices = []
        for r in readers():
            connection = ExclusiveConnectCardConnection(r.createConnection())
            try:
                connection.connect()
            except NoCardException:
                continue
            if atr != connection.getATR():
                connection.disconnect()
                connection.release()
                continue
            devices.append(cls.from_device(connection))

        return devices


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
