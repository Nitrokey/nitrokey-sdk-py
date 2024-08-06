#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level Hid device."""
import logging
import warnings
from typing import TYPE_CHECKING, List, Optional

from ....exceptions import SPSDKConnectionError, SPSDKError
from ....utils.exceptions import SPSDKTimeoutError
from ....utils.interfaces.device.base import DeviceBase

if TYPE_CHECKING:
    import hid

logger = logging.getLogger(__name__)


class UsbDevice(DeviceBase):
    """USB device class."""

    def __init__(
        self,
        vid: int,
        pid: int,
        path: bytes,
        vendor_name: str,
        product_name: str,
        interface_number: int,
    ) -> None:
        """Initialize the USB interface object."""
        self._opened = False
        self.vid = vid
        self.pid = pid
        self.path = path
        self.vendor_name = vendor_name
        self.product_name = product_name
        self.interface_number = interface_number
        self._timeout = 2000
        self._device: Optional["hid.device"] = None

    @property
    def timeout(self) -> int:
        """Timeout property."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Timeout property setter."""
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False othervise.
        """
        return self._device is not None

    def open(self) -> None:
        """Open the interface.

        :raises SPSDKError: if device is already opened
        :raises SPSDKConnectionError: if the device can not be opened
        """
        import hid

        logger.debug(f"Opening the Interface: {str(self)}")
        if self.is_opened:
            # This would get HID_DEVICE into broken state
            raise SPSDKError("Can't open already opened device")
        try:
            self._device = hid.device()
            self._device.open_path(self.path)
        except Exception as error:
            self._device = None
            raise SPSDKConnectionError(
                f"Unable to open device '{str(self)}'"
            ) from error

    def close(self) -> None:
        """Close the interface.

        :raises SPSDKConnectionError: if no device is available
        :raises SPSDKConnectionError: if the device can not be opened
        """
        logger.debug(f"Closing the Interface: {str(self)}")
        if self._device is not None:
            try:
                self._device.close()
                self._device = None
            except Exception as error:
                raise SPSDKConnectionError(
                    f"Unable to close device '{str(self)}'"
                ) from error

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        :raises SPSDKConnectionError: Raises an error if device is not opened for reading
        :raises SPSDKConnectionError: Raises if device is not available
        :raises SPSDKConnectionError: Raises if reading fails
        :raises SPSDKTimeoutError: Time-out
        """
        timeout = timeout or self.timeout
        if self._device is None:
            raise SPSDKConnectionError("Device is not opened for reading")
        try:
            data = self._device.read(length, timeout_ms=timeout)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if not data:
            logger.error("Cannot read from HID device")
            raise SPSDKTimeoutError()
        return bytes(data)

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Timeout to be used
        :raises SPSDKConnectionError: Sending data to device failure
        """
        timeout = timeout or self.timeout
        if self._device is None:
            raise SPSDKConnectionError("Device is not opened for writing")
        try:
            bytes_written = self._device.write(data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if bytes_written < 0 or bytes_written < len(data):
            raise SPSDKConnectionError(
                f"Invalid size of written bytes has been detected: {bytes_written} != {len(data)}"
            )

    def __str__(self) -> str:
        """Return information about the USB interface."""
        return (
            f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"
            f"path={self.path!r}"
        )

    def __hash__(self) -> int:
        return hash(self.path)

    @classmethod
    def enumerate(
        cls,
        vid: Optional[int] = None,
        pid: Optional[int] = None,
        path: Optional[str] = None,
    ) -> List["UsbDevice"]:
        """Get list of all connected devices which matches device_id."""
        try:
            import hid
        except ImportError as err:
            logger.warning("Failed to import hid module", exc_info=True)
            warnings.warn(
                f"Failed to list LPC55 bootloaders due to a missing library: {err}",
                category=RuntimeWarning,
            )
            return []

        devices = []

        # iterate on all devices found
        for dev in hid.enumerate(vendor_id=vid or 0, product_id=pid or 0):
            if path is None or dev["path"] == path.encode():
                new_device = cls(
                    vid=dev["vendor_id"],
                    pid=dev["product_id"],
                    path=dev["path"],
                    vendor_name=dev["manufacturer_string"],
                    product_name=dev["product_string"],
                    interface_number=dev["interface_number"],
                )
                devices.append(new_device)
        return devices
