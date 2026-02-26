import platform
from typing import TYPE_CHECKING, Optional

from fido2.hid import CtapHidDevice, list_descriptors, open_device

from . import App, Connection


class CtapHidConnection:
    def __init__(self, device: CtapHidDevice) -> None:
        self.device = device
        self._path = _device_path_to_str(device.descriptor.path)

    def path(self) -> Optional[str]:
        return self._path

    def logger_name(self) -> str:
        return self._path

    def vid_pid(self) -> Optional[tuple[int, int]]:
        d = self.device.descriptor
        return (d.vid, d.pid)

    def close(self) -> None:
        self.device.close()

    def wink(self) -> None:
        self.device.wink()

    def call_admin_app_legacy(
        self, command: int, data: bytes, response_len: Optional[int]
    ) -> bytes:
        return self.device.call(command, data=data)

    def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes:
        return self.device.call(app.value, data=data)


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


if TYPE_CHECKING:
    _: type[Connection] = CtapHidConnection
