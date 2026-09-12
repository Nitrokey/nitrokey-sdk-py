import hashlib
from enum import Enum

from nitrokey.trussed._bootloader.nrf52_upload.dfu.ihex_parser import IhexParser


class _FileEndings(str, Enum):
    IHEX = ".ihex"
    BIN = ".bin"


class FirmwareChecksum:
    def __init__(self, name: str, content: bytes) -> None:
        self.name = name.lower()
        self.content = content

    def _hash_ihex(self, ihex_content: bytes) -> bytes:
        return self._hash_bin(IhexParser()._convert_ihex(ihex_content))

    def _hash_bin(self, bin_content: bytes | bytearray) -> bytes:
        return hashlib.sha256(bin_content).digest()

    def calculate_checksum(self) -> bytes:
        """.bin firmwares are using with the NRF52 chipsets while .ihex is used with LPC55.
        For NRF52 firmware, the checksum is made by a direct cryptographic hash over the file.
        For LPC55 firmware, the metadata and certificate block is ignored during checksum calculation"""
        if self.name.endswith(_FileEndings.IHEX):
            return self._hash_ihex(self.content)
        elif self.name.endswith(_FileEndings.BIN):
            return self._hash_bin(self.content)

        raise ValueError("Invalid file ending for firmware")
