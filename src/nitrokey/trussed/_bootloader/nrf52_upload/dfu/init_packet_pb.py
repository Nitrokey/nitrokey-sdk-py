#
# Copyright (c) 2016 Nordic Semiconductor ASA
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
#

from . import dfu_cc_pb2 as pb


class InitPacketPB:
    def __init__(self, from_bytes: bytes) -> None:
        # construct from a protobuf string/buffer
        self.packet = pb.Packet()
        self.packet.ParseFromString(from_bytes)

        if self.packet.HasField("signed_command"):
            self.init_command = self.packet.signed_command.command.init
        else:
            self.init_command = self.packet.command.init

        self._validate()

    def _validate(self) -> None:
        if (
            self.init_command.type == pb.APPLICATION
            or self.init_command.type == pb.EXTERNAL_APPLICATION
        ) and self.init_command.app_size == 0:
            raise RuntimeError(
                "app_size is not set. It must be set when type is APPLICATION/EXTERNAL_APPLICATION"
            )
        elif self.init_command.type == pb.SOFTDEVICE and self.init_command.sd_size == 0:
            raise RuntimeError(
                "sd_size is not set. It must be set when type is SOFTDEVICE"
            )
        elif self.init_command.type == pb.BOOTLOADER and self.init_command.bl_size == 0:
            raise RuntimeError(
                "bl_size is not set. It must be set when type is BOOTLOADER"
            )
        elif self.init_command.type == pb.SOFTDEVICE_BOOTLOADER and (
            self.init_command.sd_size == 0 or self.init_command.bl_size == 0
        ):
            raise RuntimeError(
                "Either sd_size or bl_size is not set. Both must be set when type "
                "is SOFTDEVICE_BOOTLOADER"
            )

        if (
            self.init_command.fw_version < 0
            or self.init_command.fw_version > 0xFFFFFFFF
            or self.init_command.hw_version < 0
            or self.init_command.hw_version > 0xFFFFFFFF
        ):
            raise RuntimeError(
                "Invalid range of firmware argument. [0 - 0xffffffff] is valid range"
            )

    def get_init_command_bytes(self) -> bytes:
        return self.init_command.SerializeToString()

    def __str__(self) -> str:
        return str(self.init_command)
