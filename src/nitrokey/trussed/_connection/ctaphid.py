# Copyright (C) Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 or MIT

import logging
import platform
from typing import Optional

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, get_descriptor, list_descriptors, open_connection
from fido2.hid.base import HidDescriptor

from .._exceptions import ConnectionError, CtapErrorCode, DeviceError
from . import App, Connection, Transport, VidPid, close_all

logger = logging.getLogger(__name__)


class CtapHidConnection(Connection):
    def __init__(self, device: CtapHidDevice) -> None:
        self.device = device
        self._path = _device_path_to_str(device.descriptor.path)
        self._logger = logger.getChild(self._path)

    def transport(self) -> Transport:
        return Transport.CTAPHID

    def path(self) -> Optional[str]:
        return self._path

    def logger_name(self) -> str:
        return self._path

    def vid_pid(self) -> Optional[VidPid]:
        d = self.device.descriptor
        return VidPid(vid=d.vid, pid=d.pid)

    def ctaphid_device(self) -> CtapHidDevice:
        return self.device

    def close(self) -> None:
        self._logger.debug("Closing CTAPHID connection")
        self.device.close()

    def wink(self) -> None:
        self.device.wink()

    def _call(self, command: int, data: bytes) -> bytes:
        self._logger.debug(f"Sending CTAPHID command {command:02x} (data: {len(data)} bytes)")
        try:
            response = self.device.call(command, data=data)
        except CtapError as e:
            self._logger.debug(f"CTAPHID command {command:02x} failed: {e}")
            raise DeviceError(CtapErrorCode(error=e.code.value)) from e
        except OSError as e:
            self._logger.debug(f"CTAPHID command {command:02x} lost the connection: {e}")
            raise ConnectionError() from e
        self._logger.debug(
            f"Received CTAPHID response for {command:02x} (data: {len(response)} bytes)"
        )
        return response

    def call_admin_app_legacy(
        self, command: int, data: bytes, response_len: Optional[int]
    ) -> bytes:
        return self._call(command, data)

    def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes:
        return self._call(app.value, data)


def _device_path_to_str(path: bytes | str) -> str:
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


def _str_to_device_path(path: str) -> bytes | str:
    """
    Converts a device path string to the representation used by the fido2 library.

    This is the inverse of _device_path_to_str so that a path returned by a list
    function can be used to open the same device again.
    """
    if platform.system() == "Windows":
        return path.encode("iso-8859-1")
    else:
        return path


def open_ctaphid(path: str, vid: int, pid: int) -> Optional[CtapHidConnection]:
    """
    Opens the CTAPHID device at the given path if it has the given VID and PID.

    The descriptor is read before opening the device so that devices from other
    vendors are never opened.  Returns None if the VID or PID does not match.
    """
    logger.debug(f"Opening CTAPHID device at path {path}")
    descriptor = get_descriptor(_str_to_device_path(path))  # type: ignore
    if (descriptor.vid, descriptor.pid) != (vid, pid):
        logger.debug(
            f"Ignoring CTAPHID device at path {path} with VID:PID "
            f"{descriptor.vid:04x}:{descriptor.pid:04x} (expected: {vid:04x}:{pid:04x})"
        )
        return None
    return CtapHidConnection(_open_descriptor(descriptor))


def _open_descriptor(descriptor: HidDescriptor) -> CtapHidDevice:
    """
    Opens the device with the given descriptor.

    If the CTAPHID initialization fails, the device is closed again so that we don't
    leave a stale channel behind.
    """
    hid_connection = open_connection(descriptor)  # type: ignore
    try:
        return CtapHidDevice(descriptor, hid_connection)
    except BaseException:
        hid_connection.close()
        raise


def list_ctaphid(vid: int, pid: int) -> list[CtapHidConnection]:
    descriptors = [
        desc
        for desc in list_descriptors()  # type: ignore
        if desc.vid == vid and desc.pid == pid
    ]
    logger.debug(f"Found {len(descriptors)} CTAPHID device(s) with VID:PID {vid:04x}:{pid:04x}")
    connections = []
    try:
        for desc in descriptors:
            connections.append(CtapHidConnection(_open_descriptor(desc)))
    except BaseException:
        close_all(connections)
        raise
    return connections
