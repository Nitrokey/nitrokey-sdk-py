"""
MIT License

Copyright (c) 2016 gwangyi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import ctypes
from typing import Any, Optional, Union

_ole32 = ctypes.WinDLL("ole32")  # type: ignore[attr-defined]


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __init__(
        self,
        guid: Union[
            str, "ctypesInternalGUID"
        ] = "{00000000-0000-0000-0000-000000000000}",
    ) -> None:
        super().__init__()
        if isinstance(guid, str):
            ret = _ole32.CLSIDFromString(
                ctypes.create_unicode_buffer(guid), ctypes.byref(self)
            )
            if ret < 0:
                err_no = ctypes.GetLastError()  # type: ignore[attr-defined]
                raise WindowsError(err_no, ctypes.FormatError(err_no), guid)  # type: ignore[attr-defined,name-defined]
        else:
            ctypes.memmove(ctypes.byref(self), bytes(guid), ctypes.sizeof(self))

    def __str__(self) -> str:
        s = ctypes.c_wchar_p()
        ret = _ole32.StringFromCLSID(ctypes.byref(self), ctypes.byref(s))
        if ret < 0:
            err_no = ctypes.GetLastError()  # type: ignore[attr-defined]
            raise WindowsError(err_no, ctypes.FormatError(err_no))  # type: ignore[attr-defined,name-defined]
        value = str(s.value)
        _ole32.CoTaskMemFree(s)
        return value

    def __repr__(self) -> str:
        return "<GUID: {}>".format(str(self))


assert ctypes.sizeof(_GUID) == 16


class GUID:
    def __init__(
        self,
        guid: Union[
            str, "ctypesInternalGUID"
        ] = "{00000000-0000-0000-0000-000000000000}",
    ) -> None:
        self._guid = _GUID(guid)

    def __bytes__(self) -> bytes:
        return bytes(self._guid)

    def __str__(self) -> str:
        return str(self._guid)

    def __repr__(self) -> str:
        return repr(self._guid)


class DevicePropertyKey(ctypes.Structure):
    # noinspection SpellCheckingInspection
    _fields_ = [("fmtid", _GUID), ("pid", ctypes.c_ulong)]

    def __init__(self, guid: str, pid: int, name: Optional[str] = None) -> None:
        super().__init__()
        self.fmtid.__init__(guid)
        self.pid = pid
        self.name = name
        self.__doc__ = str(self)

    def __repr__(self) -> str:
        return "<DevPropKey: {}>".format(str(self))

    def __str__(self) -> str:
        if not hasattr(self, "name") or self.name is None:
            # noinspection SpellCheckingInspection
            return "{} {}".format(self.fmtid, self.pid)
        else:
            # noinspection SpellCheckingInspection
            return "{}, {} {}".format(self.name, self.fmtid, self.pid)

    def __eq__(self, key: object) -> bool:
        if not isinstance(key, DevicePropertyKey):
            return False
        return bytes(self) == bytes(key)


class DeviceInfoData(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("ClassGuid", _GUID),
        ("DevInst", ctypes.c_ulong),
        ("Reserved", ctypes.c_void_p),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.cbSize = ctypes.sizeof(self)

    def __str__(self) -> str:
        return "ClassGuid:{} DevInst:{}".format(self.ClassGuid, self.DevInst)


class ctypesInternalGUID:
    def __init__(self, bytes: ctypes.Array[ctypes.c_wchar]) -> None:
        self._internal = bytes

    def __bytes__(self) -> bytes:
        return bytes(self._internal)


def ValidHandle(value: int, func: Any, arguments: Any) -> int:
    if value == 0:
        raise ctypes.WinError()  # type: ignore[attr-defined]
    return value


DeviceInfoData.size = DeviceInfoData.cbSize  # type: ignore[attr-defined]
DeviceInfoData.dev_inst = DeviceInfoData.DevInst  # type: ignore[attr-defined]
DeviceInfoData.class_guid = DeviceInfoData.ClassGuid  # type: ignore[attr-defined]
# noinspection SpellCheckingInspection
SP_DEVINFO_DATA = DeviceInfoData
# noinspection SpellCheckingInspection
DEVPROPKEY = DevicePropertyKey
