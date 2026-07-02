# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
import re
from abc import abstractmethod
from contextlib import contextmanager
from typing import Iterator, Optional, Self, TypeVar

from nitrokey.trussed import Uuid, Version

from .._utils import VidPid
from . import FirmwareMetadata, ProgressCallback, TrussedBootloader, Variant
from .lpc55_upload.mboot.interfaces.usb import MbootUSBInterface
from .lpc55_upload.mboot.mcuboot import McuBoot
from .lpc55_upload.mboot.properties import PropertyTag
from .lpc55_upload.sbfile.sb2.images import BootImageV21
from .lpc55_upload.utils.interfaces.device.usb_device import UsbDevice

RKTH = bytes.fromhex("050aad3e77791a81e59c5b2ba5a158937e9460ee325d8ccba09734b8fdebb171")
KEK = bytes([0xAA] * 32)
UUID_LEN = 4
FILENAME_PATTERN = re.compile("(firmware|alpha)-nk3..-lpc55-(?P<version>.*)\\.sb2$")

T = TypeVar("T", bound="TrussedBootloaderLpc55")

logger = logging.getLogger(__name__)


class TrussedBootloaderLpc55(TrussedBootloader):
    """A Nitrokey 3 device running the LPC55 bootloader."""

    def __init__(self, device: UsbDevice) -> None:
        self._validate_vid_pid(device.vid, device.pid)
        self._path = device.path
        self.device = McuBoot(MbootUSBInterface(device))

    @property
    def variant(self) -> Variant:
        return Variant.LPC55

    @property
    def path(self) -> str:
        if isinstance(self._path, bytes):
            return self._path.decode("UTF-8")
        return self._path

    @property
    def status(self) -> str:
        return self.device.status_string

    def reboot(self) -> bool:
        if not self.device.reset(reopen=False):
            # On Windows, this function returns false even if the reset was successful
            if platform.system() == "Windows":
                logger.warning("Failed to reboot Nitrokey 3 bootloader")
            else:
                raise Exception("Failed to reboot Nitrokey 3 bootloader")
        return True

    def uuid(self) -> Optional[Uuid]:
        uuid = self.device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid:
            raise ValueError("Missing response for UUID property query")
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")

        # See GetProperties::device_uuid in the lpc55 crate:
        # https://github.com/lpc55/lpc55-host/blob/main/src/bootloader/property.rs#L222
        wrong_endian = (uuid[3] << 96) + (uuid[2] << 64) + (uuid[1] << 32) + uuid[0]
        right_endian = wrong_endian.to_bytes(16, byteorder="little")
        return Uuid(int.from_bytes(right_endian, byteorder="big"))

    def update(
        self, image: bytes, callback: Optional[ProgressCallback] = None, check_errors: bool = False
    ) -> None:
        success = self.device.receive_sb_file(
            image, progress_callback=callback, check_errors=check_errors
        )
        logger.debug(f"Firmware update finished with status {self.status}")
        if success:
            self.reboot()
        else:
            raise Exception(f"Firmware update failed with status {self.status}")

    @classmethod
    @contextmanager
    def _open_path(cls, path: str) -> Iterator[Self]:
        devices = UsbDevice.enumerate(path=path)
        if len(devices) == 0:
            raise Exception(f"No HID device at {path}")
        if len(devices) > 1:
            raise Exception(f"Multiple HID devices at {path}")
        device = devices[0]

        try:
            yield cls._from_device(device)
        finally:
            device.close()

    @classmethod
    @abstractmethod
    def _from_device(cls, device: UsbDevice) -> Self: ...

    @staticmethod
    def _variant() -> Variant:
        return Variant.LPC55

    @staticmethod
    @abstractmethod
    def _expected_vid_pid() -> VidPid: ...

    @classmethod
    def _list_paths(cls) -> list[str]:
        vid_pid = cls._expected_vid_pid()
        paths = [device.path for device in UsbDevice.enumerate(vid=vid_pid.vid, pid=vid_pid.pid)]
        return [path.decode() for path in paths]


def parse_firmware_image(data: bytes) -> FirmwareMetadata:
    image = BootImageV21.parse(data, kek=KEK)
    bcd_version = image.header.product_version
    version = Version(major=bcd_version.major, minor=bcd_version.minor, patch=bcd_version.service)
    metadata = FirmwareMetadata(version=version)
    if image.cert_block:
        if image.cert_block.rkth == RKTH:
            metadata.signed_by = "Nitrokey"
            metadata.signed_by_nitrokey = True
        else:
            metadata.signed_by = f"unknown issuer (RKTH: {image.cert_block.rkth.hex()})"
    return metadata
