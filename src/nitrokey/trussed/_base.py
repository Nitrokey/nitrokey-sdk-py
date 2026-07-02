# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import typing
from abc import ABC, abstractmethod
from enum import Enum
from typing import Self

from nitrokey import _VID_NITROKEY

from ._utils import Uuid, VidPid


class Model(Enum):
    NK3 = "Nitrokey 3"
    NKPK = "Nitrokey Passkey"

    def __str__(self) -> str:
        return self.value

    @property
    def name(self) -> str:
        return self.value

    @property
    def _device_vid_pid(self) -> VidPid:
        if self == Model.NK3:
            from nitrokey.nk3 import _PID_NK3_DEVICE

            pid = _PID_NK3_DEVICE
        elif self == Model.NKPK:
            from nitrokey.nkpk import _PID_NKPK_DEVICE

            pid = _PID_NKPK_DEVICE
        else:
            typing.assert_never(self)

        return VidPid(vid=_VID_NITROKEY, pid=pid)

    @property
    def _device_atr(self) -> bytes:
        return bytes.fromhex("3B8F01805D4E6974726F6B657900000000006A")

    @classmethod
    def from_str(cls, s: str) -> "Model":
        for model in cls:
            if model.value == s:
                return model
        raise ValueError(f"Unknown model {s}")

    @classmethod
    def all(cls) -> list[Self]:
        return list(cls)


class TrussedBase(ABC):
    """
    Base class for Nitrokey devices using the Trussed framework and running
    the firmware or the bootloader.
    """

    def _validate_vid_pid(self, vid: int, pid: int) -> None:
        if (vid, pid) != (self.vid, self.pid):
            raise ValueError(
                f"Not a {self.name} device: expected VID:PID "
                f"{self.vid:x}:{self.pid:x}, got {vid:x}:{pid:x}"
            )

    @property
    @abstractmethod
    def model(self) -> Model: ...

    @property
    def vid(self) -> int:
        return _VID_NITROKEY

    @property
    @abstractmethod
    def pid(self) -> int: ...

    @property
    @abstractmethod
    def path(self) -> str | None: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def reboot(self) -> bool: ...

    @abstractmethod
    def uuid(self) -> Uuid | None: ...

    @staticmethod
    @abstractmethod
    def _model() -> Model: ...
