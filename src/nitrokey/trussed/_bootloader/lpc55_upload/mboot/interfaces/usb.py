#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB Mboot interface implementation."""

from ...mboot.protocol.bulk_protocol import MbootBulkProtocol
from ...utils.interfaces.device.usb_device import UsbDevice

USB_DEVICES = {
    # NAME   | VID   | PID
    "MKL27": (0x15A2, 0x0073),
    "LPC55": (0x1FC9, 0x0021),
    "IMXRT": (0x1FC9, 0x0135),
    "MXRT10": (0x15A2, 0x0073),  # this is ID of flash-loader for RT101x
    "MXRT20": (0x15A2, 0x0073),  # this is ID of flash-loader for RT102x
    "MXRT50": (0x15A2, 0x0073),  # this is ID of flash-loader for RT105x
    "MXRT60": (0x15A2, 0x0073),  # this is ID of flash-loader for RT106x
    "LPC55xx": (0x1FC9, 0x0020),
    "LPC551x": (0x1FC9, 0x0022),
    "RT6xx": (0x1FC9, 0x0021),
    "RT5xx_A": (0x1FC9, 0x0020),
    "RT5xx_B": (0x1FC9, 0x0023),
    "RT5xx_C": (0x1FC9, 0x0023),
    "RT5xx": (0x1FC9, 0x0023),
    "RT6xxM": (0x1FC9, 0x0024),
    "LPC553x": (0x1FC9, 0x0025),
    "MCXN9xx": (0x1FC9, 0x014F),
    "MCXA1xx": (0x1FC9, 0x0155),
    "MCXN23x": (0x1FC9, 0x0158),
}


class MbootUSBInterface(MbootBulkProtocol):
    """USB interface."""

    identifier = "usb"
    device: UsbDevice
    usb_devices = USB_DEVICES

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the MbootUSBInterface object.

        :param device: The device instance
        """
        assert isinstance(device, UsbDevice)
        super().__init__(device=device)

    @property
    def name(self) -> str:
        """Get the name of the device."""
        assert isinstance(self.device, UsbDevice)
        for name, value in self.usb_devices.items():
            if value[0] == self.device.vid and value[1] == self.device.pid:
                return name
        return "Unknown"
