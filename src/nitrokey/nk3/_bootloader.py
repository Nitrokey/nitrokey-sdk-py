# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import typing
from collections.abc import Sequence
from contextlib import AbstractContextManager

from nitrokey import _VID_NITROKEY
from nitrokey.trussed._base import Model
from nitrokey.trussed._bootloader import BootloaderInfo, TrussedBootloader, Variant
from nitrokey.trussed._bootloader.lpc55 import TrussedBootloaderLpc55
from nitrokey.trussed._bootloader.lpc55_upload.utils.interfaces.device.usb_device import UsbDevice
from nitrokey.trussed._bootloader.nrf52 import SignatureKey, TrussedBootloaderNrf52
from nitrokey.trussed._utils import VidPid


class NK3Bootloader(TrussedBootloader):
    @property
    def model(self) -> Model:
        return Model.NK3

    @staticmethod
    def _model() -> Model:
        return Model.NK3


class NK3BootloaderLpc55(TrussedBootloaderLpc55, NK3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (LPC55)"

    @property
    def pid(self) -> int:
        from . import _PID_NK3_LPC55_BOOTLOADER

        return _PID_NK3_LPC55_BOOTLOADER

    @staticmethod
    def _expected_vid_pid() -> VidPid:
        from . import _PID_NK3_LPC55_BOOTLOADER

        return VidPid(vid=_VID_NITROKEY, pid=_PID_NK3_LPC55_BOOTLOADER)

    @classmethod
    def _from_device(cls, device: UsbDevice) -> "NK3BootloaderLpc55":
        return NK3BootloaderLpc55(device)


class NK3BootloaderNrf52(TrussedBootloaderNrf52, NK3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (NRF52)"

    @property
    def pid(self) -> int:
        from . import _PID_NK3_NRF52_BOOTLOADER

        return _PID_NK3_NRF52_BOOTLOADER

    @property
    def _signature_keys(self) -> Sequence[SignatureKey]:
        from . import _NK3_DATA

        return _NK3_DATA.nrf52_signature_keys

    @staticmethod
    def _expected_vid_pid() -> VidPid:
        from . import _PID_NK3_NRF52_BOOTLOADER

        return VidPid(vid=_VID_NITROKEY, pid=_PID_NK3_NRF52_BOOTLOADER)

    @classmethod
    def _from_path_and_serial(cls, path: str, serial: int) -> "NK3BootloaderNrf52":
        return NK3BootloaderNrf52(path, serial)


def list_bootloaders() -> list[BootloaderInfo]:
    infos = []
    infos.extend(NK3BootloaderLpc55._list())
    infos.extend(NK3BootloaderNrf52._list())
    return infos


def open_bootloader(info: BootloaderInfo) -> AbstractContextManager[NK3Bootloader]:
    if info.variant == Variant.LPC55:
        return NK3BootloaderLpc55._open(info=info)

    if info.variant == Variant.NRF52:
        return NK3BootloaderNrf52._open(info=info)

    typing.assert_never(info.variant)
