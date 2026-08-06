# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import hashlib
import logging
import platform
import re
import sys
from typing import Optional, TypeVar

from nitrokey.trussed import Uuid, Version

from . import FirmwareMetadata, ProgressCallback, TrussedBootloader, Variant
from .lpc55_upload.mboot.interfaces.usb import MbootUSBInterface
from .lpc55_upload.mboot.mcuboot import McuBoot
from .lpc55_upload.mboot.properties import PropertyTag
from .lpc55_upload.sbfile.sb2.commands import CmdLoad
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

    def __enter__(self: T) -> T:
        self.device.open()
        return self

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

    def close(self) -> None:
        self.device.close()

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
    def _list_vid_pid(cls: type[T], vid: int, pid: int) -> list[T]:
        devices = []
        for device in UsbDevice.enumerate(vid=vid, pid=pid):
            try:
                devices.append(cls(device))
            except ValueError:
                logger.warning(
                    f"Invalid Nitrokey 3 LPC55 bootloader returned by enumeration: {device}"
                )
        logger.debug(f"Found {len(devices)} Nitrokey 3 LPC55 bootloader(s)")
        return devices

    @classmethod
    def _open(cls: type[T], path: str) -> Optional[T]:
        devices = UsbDevice.enumerate(path=path)
        if len(devices) == 0:
            logger.warning(f"No HID device at {path}")
            return None
        if len(devices) > 1:
            logger.warning(f"Multiple HID devices at {path}: {devices}")
            return None

        try:
            return cls(devices[0])
        except ValueError:
            logger.warning(f"No Nitrokey 3 bootloader at path {path}", exc_info=sys.exc_info())
            return None


def _inner_checksum(image: BootImageV21) -> bytes:
    """
    Calculates the checksum of the raw (unsigned) image from a SB2 file containing a Master Boot
    Image (MBI). We assume that there is only a single Load command containing the full image and
    that it is an MBI type 4 image. To produce the unsigned image from the MBI, we have to clear
    the MBI header (placed in the vector table) and cut off the certificate block (at the location
    indicated in the MBI header).

    See: https://spsdk.readthedocs.io/en/latest/examples/_knowledge_base/mbi_summary.html
    """
    MBI_PATCH_START = 0x20
    MBI_PATCH_LEN = 0xB

    loads = [cmd for section in image.boot_sections for cmd in section if isinstance(cmd, CmdLoad)]
    assert len(loads) == 1
    mbi = memoryview(loads[0].data)

    assert len(mbi) > MBI_PATCH_START + MBI_PATCH_LEN
    assert mbi[0x24] == 0x04  # SPT-Xip
    offset_loc = 0x28
    header_size = 4
    marker = int.from_bytes(mbi[offset_loc:][:header_size], "little")

    # cut off certificate block
    raw_image = mbi[:marker]

    h = hashlib.sha256()
    h.update(raw_image[:MBI_PATCH_START])
    # zero out MBI header
    h.update(b"\x00" * MBI_PATCH_LEN)
    h.update(raw_image[MBI_PATCH_START:][MBI_PATCH_LEN:])
    return h.digest()


def parse_firmware_image(data: bytes) -> FirmwareMetadata:
    image = BootImageV21.parse(data, kek=KEK)
    bcd_version = image.header.product_version
    version = Version(major=bcd_version.major, minor=bcd_version.minor, patch=bcd_version.service)
    inner_checksum = _inner_checksum(image)
    metadata = FirmwareMetadata(version=version, inner_checksum=inner_checksum)
    if image.cert_block:
        if image.cert_block.rkth == RKTH:
            metadata.signed_by = "Nitrokey"
            metadata.signed_by_nitrokey = True
        else:
            metadata.signed_by = f"unknown issuer (RKTH: {image.cert_block.rkth.hex()})"
    return metadata
