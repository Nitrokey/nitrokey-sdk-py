# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Sequence

from nitrokey import _VID_NITROKEY
from nitrokey.trussed._base import Model
from nitrokey.trussed._bootloader import TrussedBootloader
from nitrokey.trussed._bootloader.lpc55 import TrussedBootloaderLpc55
from nitrokey.trussed._bootloader.nrf52 import SignatureKey, TrussedBootloaderNrf52


class NK3Bootloader(TrussedBootloader):
    @property
    def model(self) -> Model:
        return Model.NK3

    @staticmethod
    def list() -> List["NK3Bootloader"]:
        devices: List[NK3Bootloader] = []
        devices.extend(NK3BootloaderLpc55._list())
        devices.extend(NK3BootloaderNrf52._list())
        return devices

    @staticmethod
    def open(path: str) -> Optional["NK3Bootloader"]:
        lpc55 = NK3BootloaderLpc55._open(path)
        if lpc55:
            return lpc55

        nrf52 = NK3BootloaderNrf52._open(path)
        if nrf52:
            return nrf52

        return None


class NK3BootloaderLpc55(TrussedBootloaderLpc55, NK3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (LPC55)"

    @property
    def pid(self) -> int:
        from . import _PID_NK3_LPC55_BOOTLOADER

        return _PID_NK3_LPC55_BOOTLOADER

    @classmethod
    def _list(cls) -> List["NK3BootloaderLpc55"]:
        from . import _PID_NK3_LPC55_BOOTLOADER

        return cls._list_vid_pid(_VID_NITROKEY, _PID_NK3_LPC55_BOOTLOADER)


class NK3BootloaderNrf52(TrussedBootloaderNrf52, NK3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (NRF52)"

    @property
    def pid(self) -> int:
        from . import _PID_NK3_NRF52_BOOTLOADER

        return _PID_NK3_NRF52_BOOTLOADER

    @classmethod
    def _list(cls) -> List["NK3BootloaderNrf52"]:
        from . import _PID_NK3_NRF52_BOOTLOADER

        return cls._list_vid_pid(_VID_NITROKEY, _PID_NK3_NRF52_BOOTLOADER)

    @classmethod
    def _open(cls, path: str) -> Optional["NK3BootloaderNrf52"]:
        from . import _PID_NK3_NRF52_BOOTLOADER

        return cls._open_vid_pid(_VID_NITROKEY, _PID_NK3_NRF52_BOOTLOADER, path)

    @property
    def _signature_keys(self) -> Sequence[SignatureKey]:
        from . import _NK3_DATA

        return _NK3_DATA.nrf52_signature_keys
