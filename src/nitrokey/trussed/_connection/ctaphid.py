import platform
from typing import Optional

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, list_descriptors, open_device

from .._exceptions import ConnectionError, CtapErrorCode, DeviceError
from . import App, Connection, Transport, VidPid


class CtapHidConnection(Connection):
    def __init__(self, device: CtapHidDevice) -> None:
        self.device = device
        self._path = _device_path_to_str(device.descriptor.path)

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
        self.device.close()

    def wink(self) -> None:
        self.device.wink()

    def _call(self, command: int, data: bytes) -> bytes:
        try:
            return self.device.call(command, data=data)
        except CtapError as e:
            raise DeviceError(CtapErrorCode(error=e.code.value)) from e
        except OSError as e:
            raise ConnectionError() from e

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


def open_ctaphid(path: str) -> CtapHidConnection:
    if platform.system() == "Windows":
        device = open_device(bytes(path, "utf-8"))
    else:
        device = open_device(path)
    return CtapHidConnection(device)


def list_ctaphid(vid: int, pid: int) -> list[CtapHidConnection]:
    descriptors = [
        desc
        for desc in list_descriptors()  # type: ignore
        if desc.vid == vid and desc.pid == pid
    ]
    return [CtapHidConnection(open_device(desc.path)) for desc in descriptors]
