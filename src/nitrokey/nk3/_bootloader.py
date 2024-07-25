# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Sequence

from nitrokey import _VID_NITROKEY
from nitrokey.trussed._bootloader import NitrokeyTrussedBootloader
from nitrokey.trussed._bootloader.lpc55 import NitrokeyTrussedBootloaderLpc55
from nitrokey.trussed._bootloader.nrf52 import (
    NitrokeyTrussedBootloaderNrf52,
    SignatureKey,
)


class Nitrokey3Bootloader(NitrokeyTrussedBootloader):
    @staticmethod
    def list() -> List["Nitrokey3Bootloader"]:
        devices: List[Nitrokey3Bootloader] = []
        devices.extend(Nitrokey3BootloaderLpc55._list())
        devices.extend(Nitrokey3BootloaderNrf52._list())
        return devices

    @staticmethod
    def open(path: str) -> Optional["Nitrokey3Bootloader"]:
        lpc55 = Nitrokey3BootloaderLpc55._open(path)
        if lpc55:
            return lpc55

        nrf52 = Nitrokey3BootloaderNrf52._open(path)
        if nrf52:
            return nrf52

        return None


class Nitrokey3BootloaderLpc55(NitrokeyTrussedBootloaderLpc55, Nitrokey3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (LPC55)"

    @property
    def pid(self) -> int:
        from . import _PID_NITROKEY3_LPC55_BOOTLOADER

        return _PID_NITROKEY3_LPC55_BOOTLOADER

    @classmethod
    def _list(cls) -> List["Nitrokey3BootloaderLpc55"]:
        from . import _PID_NITROKEY3_LPC55_BOOTLOADER

        return cls.list_vid_pid(_VID_NITROKEY, _PID_NITROKEY3_LPC55_BOOTLOADER)


class Nitrokey3BootloaderNrf52(NitrokeyTrussedBootloaderNrf52, Nitrokey3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (NRF52)"

    @property
    def pid(self) -> int:
        from . import _PID_NITROKEY3_NRF52_BOOTLOADER

        return _PID_NITROKEY3_NRF52_BOOTLOADER

    @classmethod
    def _list(cls) -> List["Nitrokey3BootloaderNrf52"]:
        from . import _PID_NITROKEY3_NRF52_BOOTLOADER

        return cls.list_vid_pid(_VID_NITROKEY, _PID_NITROKEY3_NRF52_BOOTLOADER)

    @classmethod
    def _open(cls, path: str) -> Optional["Nitrokey3BootloaderNrf52"]:
        from . import _PID_NITROKEY3_NRF52_BOOTLOADER

        return cls.open_vid_pid(_VID_NITROKEY, _PID_NITROKEY3_NRF52_BOOTLOADER, path)

    @property
    def signature_keys(self) -> Sequence[SignatureKey]:
        from . import NK3_DATA

        return NK3_DATA.nrf52_signature_keys
