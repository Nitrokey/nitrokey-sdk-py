# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import ctypes
import sys
import typing
from contextlib import AbstractContextManager

from ._base import Model as Model
from ._base import TrussedBase as TrussedBase
from ._bootloader import FirmwareContainer as FirmwareContainer
from ._bootloader import FirmwareMetadata as FirmwareMetadata
from ._bootloader import TrussedBootloader as TrussedBootloader
from ._bootloader import Variant as Variant
from ._bootloader import parse_firmware_image as parse_firmware_image
from ._connection import HAS_CCID_SUPPORT as HAS_CCID_SUPPORT
from ._connection import App as App
from ._connection import DeviceConnectionInfo as DeviceConnectionInfo
from ._connection import Transport as Transport
from ._device import DeviceInfo as DeviceInfo
from ._device import TrussedDevice as TrussedDevice
from ._exceptions import CcidErrorCode as CcidErrorCode
from ._exceptions import ConnectionError as ConnectionError
from ._exceptions import CtapErrorCode as CtapErrorCode
from ._exceptions import DeviceError as DeviceError
from ._exceptions import TimeoutException as TimeoutException
from ._exceptions import TrussedException as TrussedException
from ._utils import Fido2Certs as Fido2Certs
from ._utils import Uuid as Uuid
from ._utils import Version as Version
from ._utils import VidPid as VidPid

# module-level constants have no docstrings in Python, so this is documented in
# docs/api/nitrokey.trussed.rst
DEFAULT_TRANSPORT = Transport.CTAPHID


def recommended_transport() -> Transport:
    """Helper function to inform which transport should be used by default.

    Some features do not work over CCID, therefore it is only used when CTAPHID is not available, meaning on windows when not an administrator.
    See also the :py:const:`DEFAULT_TRANSPORT` constant that defines the default transport if it is not set
    explicitly."""

    if HAS_CCID_SUPPORT:
        # Linux or MacOS don't need admin to access with CTAPHID
        if sys.platform == "win32" or sys.platform == "cygwin":
            try:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    return Transport.CCID
            except Exception:
                pass

    return Transport.CTAPHID


def list_devices(
    transport: Transport | None = None, model: Model | None = None
) -> list[DeviceInfo]:
    models = [model] if model is not None else Model.all()
    return DeviceInfo._list(transport=transport, models=models)


def open_device(info: DeviceInfo) -> AbstractContextManager[TrussedDevice]:
    if info.model == Model.NK3:
        from nitrokey.nk3 import NK3

        return NK3._open(info)

    if info.model == Model.NKPK:
        from nitrokey.nkpk import NKPK

        return NKPK._open(info)

    typing.assert_never(info.model)
