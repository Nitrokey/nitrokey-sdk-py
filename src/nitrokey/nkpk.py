# Copyright 2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Sequence, Union

from fido2.hid import CtapHidDevice, list_descriptors, open_device

from nitrokey import _VID_NITROKEY
from nitrokey.trussed import Fido2Certs, TrussedDevice, Version
from nitrokey.trussed._base import Model
from nitrokey.trussed._bootloader import ModelData
from nitrokey.trussed._bootloader.nrf52 import SignatureKey, TrussedBootloaderNrf52

_PID_NKPK_DEVICE = 0x42F3
_PID_NKPK_BOOTLOADER = 0x42F4

_FIDO2_CERTS = [
    Fido2Certs(
        start=Version(0, 1, 0),
        hashes=[
            "c7512dfcd15ffc5a7b4000e4898e5956ee858027794c5086cc137a02cd15d123",
        ],
    ),
]

_NKPK_DATA = ModelData(
    firmware_repository_name="nitrokey-passkey-firmware",
    firmware_pattern_string="firmware-nkpk-v.*\\.zip$",
    nrf52_signature_keys=[
        SignatureKey(
            name="Nitrokey",
            is_official=True,
            der="3059301306072a8648ce3d020106082a8648ce3d0301070342000445121cdf7a10826faa58c8cbe7bb1a40fe71c85c7756324eac09610d4710e9dadd473c0c9d35838b5cce301e796b2e14a8c29c86f0eb15f36325096506e275e6",
        ),
        SignatureKey(
            name="Nitrokey Test",
            is_official=False,
            der="3059301306072a8648ce3d020106082a8648ce3d03010703420004d9a355a2927bd6ecb7ed714294d4692ad31ae9dd21853bf99e2cf7182d1acd6c2ada4a9707ab43f9e6194480d94e477dce4de9be5c35119c714bac459b21cbdc",
        ),
    ],
)


class NKPK(TrussedDevice):
    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device, _FIDO2_CERTS)

    @property
    def model(self) -> Model:
        return Model.NKPK

    @property
    def pid(self) -> int:
        return _PID_NKPK_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey Passkey"

    @classmethod
    def from_device(cls, device: CtapHidDevice) -> "NKPK":
        return cls(device)

    @classmethod
    def list(cls) -> List["NKPK"]:
        descriptors = [
            desc
            for desc in list_descriptors()  # type: ignore
            if desc.vid == _VID_NITROKEY and desc.pid == _PID_NKPK_DEVICE
        ]

        devices = []

        # iterate on all descriptors found and open the device
        for desc in descriptors:
            devices.append(cls.from_device(open_device(desc.path)))
        return devices


class NKPKBootloader(TrussedBootloaderNrf52):
    @property
    def model(self) -> Model:
        return Model.NKPK

    @property
    def name(self) -> str:
        return "Nitrokey Passkey Bootloader"

    @property
    def pid(self) -> int:
        return _PID_NKPK_BOOTLOADER

    @classmethod
    def list(cls) -> List["NKPKBootloader"]:
        return cls._list_vid_pid(_VID_NITROKEY, _PID_NKPK_BOOTLOADER)

    @classmethod
    def open(cls, path: str) -> Optional["NKPKBootloader"]:
        return cls._open_vid_pid(_VID_NITROKEY, _PID_NKPK_BOOTLOADER, path)

    @property
    def _signature_keys(self) -> Sequence[SignatureKey]:
        return _NKPK_DATA.nrf52_signature_keys


def list() -> List[Union[NKPK, NKPKBootloader]]:
    devices: List[Union[NKPK, NKPKBootloader]] = []
    devices.extend(NKPKBootloader.list())
    devices.extend(NKPK.list())
    return devices


def open(path: str) -> Optional[Union[NKPK, NKPKBootloader]]:
    device = NKPK.open(path)
    bootloader_device = NKPKBootloader.open(path)
    if device and bootloader_device:
        raise Exception(f"Found multiple devices at path {path}")
    if device:
        return device
    if bootloader_device:
        return bootloader_device
    return None
