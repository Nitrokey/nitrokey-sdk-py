import platform
from contextlib import contextmanager
from typing import Iterator, Optional

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, list_descriptors, open_device

from .._exceptions import ConnectionError, CtapErrorCode, DeviceError
from . import App, Connection, CtapHidConnectionInfo, Transport, VidPid


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


@contextmanager
def open_ctaphid(info: CtapHidConnectionInfo) -> Iterator[CtapHidConnection]:
    if platform.system() == "Windows":
        device = open_device(bytes(info.path, "utf-8"))
    else:
        device = open_device(info.path)
    try:
        vid = device.descriptor.vid
        pid = device.descriptor.pid
        if vid != info.vid or pid != info.pid:
            raise Exception(
                "Failed to open CTAPHID device at '{info.path}': expected VID/PID {info.vid:02x}/{info.pid:02x}, got {vid:02x}/{pid:02x}"
            )
        yield CtapHidConnection(device)
    finally:
        device.close()


def list_ctaphid(*, filter: VidPid | None) -> list[CtapHidConnectionInfo]:
    infos = []
    for desc in list_descriptors():  # type: ignore
        if filter is not None:
            if desc.vid != filter.vid or desc.pid != filter.pid:
                continue
        path = _device_path_to_str(desc.path)
        infos.append(CtapHidConnectionInfo(vid=desc.vid, pid=desc.pid, path=path))
    return infos
