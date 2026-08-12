# Copyright (c) 2016 - 2019 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from enum import Enum
from typing import Optional

from .ihex_parser import IhexParser


class nRFArch(Enum):
    NRF51 = 1
    NRF52 = 2
    NRF52840 = 3


class nRFHex(IhexParser):
    """
    Converts and merges .hex and .bin files into one .bin file.
    """

    info_struct_address_base = 0x00003000
    info_struct_address_offset = 0x1000

    info_struct_magic_number = 0x51B1E5DB
    info_struct_magic_number_offset = 0x004

    s1x0_mbr_end_address = 0x1000
    s132_mbr_end_address = 0x3000

    def __init__(
        self, source: str, bootloader: Optional[str] = None, arch: Optional[nRFArch] = None
    ) -> None:
        """
        Constructor that requires a firmware file path.
        Softdevices can take an optional bootloader file path as parameter.

        :param str source: The file path for the firmware
        :param str bootloader: Optional file path to bootloader firmware
        :return: None
        """
        super().__init__()
        self.arch = arch
        self.file_format = "hex"

        if source.endswith(".bin"):
            self.file_format = "bin"

        self.loadfile(source, self.file_format)

        if self.file_format == "hex":
            self._removeuicr()
            self._removembr()

        self.bootloaderhex = None

        if bootloader is not None:
            self.bootloaderhex = nRFHex(bootloader)

    def _removeuicr(self) -> None:
        uicr_start_address = 0x10000000
        del self._buf[uicr_start_address:]
        # self._buf = {k: v for k, v in self._buf.items() if k < uicr_start_address}

    def _removembr(self) -> None:
        mbr_end_address = 0x1000
        del self._buf[:mbr_end_address]
        # self._buf = {k: v for k, v in self._buf.items() if k >= mbr_end_address}

    def size(self) -> int:
        return len(self._buf)

    def bootloadersize(self) -> int:
        if self.bootloaderhex:
            return self.bootloaderhex.size()
        return 0

    def tobinfile(self, file: str) -> None:
        """
        Writes a binary version of source and bootloader respectively to fobj which could be a
        file object or a file path.

        :param str fobj: File path or object the function writes to
        :return: None
        """
        # If there is a bootloader this will make the recursion call use the samme file object.

        fobj = open(file, "wb")

        super().writebinfile(fobj)

        if self.bootloaderhex is not None:
            fobj.write(self.bootloaderhex._buf)
            # self.bootloaderhex.tobinfile(fobj)

        fobj.close()
