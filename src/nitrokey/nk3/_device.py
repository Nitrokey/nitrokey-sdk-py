# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List

from fido2.hid import CtapHidDevice, list_descriptors, open_device

from nitrokey import _VID_NITROKEY
from nitrokey.trussed import Fido2Certs, Model, TrussedDevice, Version

FIDO2_CERTS = [
    Fido2Certs(
        start=Version(0, 1, 0),
        hashes=[
            "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d",
        ],
    ),
    Fido2Certs(
        start=Version(1, 0, 3),
        hashes=[
            "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b",  # NK3xN/lpc55
            "4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0",  # NK3AM/nrf52
            "f1ed1aba24b16e8e3fabcda72b10cbfa54488d3b778bda552162d60c6dd7b4fa",  # NK3AM/nrf52 test
        ],
    ),
]


class NK3(TrussedDevice):
    """A Nitrokey 3 device running the firmware."""

    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device, FIDO2_CERTS)

    @property
    def model(self) -> Model:
        return Model.NK3

    @property
    def pid(self) -> int:
        from . import _PID_NK3_DEVICE

        return _PID_NK3_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey 3"

    @classmethod
    def from_device(cls, device: CtapHidDevice) -> "NK3":
        return cls(device)

    @classmethod
    def list(cls) -> List["NK3"]:
        from . import _PID_NK3_DEVICE

        descriptors = [
            desc
            for desc in list_descriptors()  # type: ignore
            if desc.vid == _VID_NITROKEY and desc.pid == _PID_NK3_DEVICE
        ]

        devices = []

        # iterate on all descriptors found and open the device
        for desc in descriptors:
            devices.append(cls.from_device(open_device(desc.path)))
        return devices
