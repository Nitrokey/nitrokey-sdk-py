# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Union

from nitrokey.trussed._bootloader import ModelData
from nitrokey.trussed._bootloader.nrf52 import SignatureKey

from ._bootloader import NK3Bootloader as NK3Bootloader  # noqa: F401
from ._device import NK3 as NK3  # noqa: F401

_PID_NK3_DEVICE = 0x42B2
_PID_NK3_LPC55_BOOTLOADER = 0x42DD
_PID_NK3_NRF52_BOOTLOADER = 0x42E8

_NK3_DATA = ModelData(
    firmware_repository_name="nitrokey-3-firmware",
    firmware_pattern_string="firmware-nk3-v.*\\.zip$",
    nrf52_signature_keys=[
        SignatureKey(
            name="Nitrokey",
            is_official=True,
            der="3059301306072a8648ce3d020106082a8648ce3d03010703420004a0849b19007ccd4661c01c533804b7fd0c4d8c0e7583653f1f36a8331afff298b542bd00a3dc47c16bf428ac4d2864137d63f702d89e5b42674e0549b4232618",
        ),
        SignatureKey(
            name="Nitrokey Test",
            is_official=False,
            der="3059301306072a8648ce3d020106082a8648ce3d0301070342000493e461ab0582bda1f45b0ce47d66bc4e8623e289c31af2098cde6ebd8631da85acf17e412d406c1e38c2de654a8fd0196506a85b169a756aeac2505a541cdd5d",
        ),
    ],
)


def list() -> List[Union[NK3, NK3Bootloader]]:
    devices: List[Union[NK3, NK3Bootloader]] = []
    devices.extend(NK3Bootloader.list())
    devices.extend(NK3.list())
    return devices


def open(path: str) -> Optional[Union[NK3, NK3Bootloader]]:
    device = NK3.open(path)
    bootloader_device = NK3Bootloader.open(path)
    if device and bootloader_device:
        raise Exception(f"Found multiple devices at path {path}")
    if device:
        return device
    if bootloader_device:
        return bootloader_device
    return None
