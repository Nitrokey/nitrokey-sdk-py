#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Protocol base."""
from abc import ABC, abstractmethod
from types import TracebackType
from typing import TYPE_CHECKING, Optional, Type, Union

from ....utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from ....utils.interfaces.device.base import DeviceBase

if TYPE_CHECKING:
    from typing_extensions import Self


class ProtocolBase(ABC):
    """Protocol base class."""

    device: DeviceBase
    identifier: str

    def __init__(self, device: DeviceBase) -> None:
        """Initialize the MbootSerialProtocol object.

        :param device: The device instance
        """
        self.device = device

    def __str__(self) -> str:
        return f"identifier='{self.identifier}', device={self.device}"

    def __enter__(self) -> "Self":
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    @abstractmethod
    def write_command(self, packet: CmdPacketBase) -> None:
        """Write command to the device.

        :param packet: Command packet to be sent
        """

    @abstractmethod
    def write_data(self, data: bytes) -> None:
        """Write data to the device.

        :param data: Data to be send
        """

    @abstractmethod
    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from device.

        :return: read data
        """
