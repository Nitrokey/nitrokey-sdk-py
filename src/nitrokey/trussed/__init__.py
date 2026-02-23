# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import ctypes
import sys
from importlib.util import find_spec
from typing import List, Optional

from ._base import Model as Model  # noqa: F401
from ._base import TrussedBase as TrussedBase  # noqa: F401
from ._bootloader import FirmwareContainer as FirmwareContainer  # noqa: F401
from ._bootloader import FirmwareMetadata as FirmwareMetadata  # noqa: F401
from ._bootloader import TrussedBootloader as TrussedBootloader  # noqa: F401
from ._bootloader import Variant as Variant  # noqa: F401
from ._bootloader import parse_firmware_image as parse_firmware_image  # noqa: F401
from ._device import App as App  # noqa: F401
from ._device import TrussedDevice as TrussedDevice  # noqa: F401
from ._exceptions import TimeoutException as TimeoutException  # noqa: F401
from ._exceptions import TrussedException as TrussedException  # noqa: F401
from ._utils import Fido2Certs as Fido2Certs  # noqa: F401
from ._utils import Uuid as Uuid  # noqa: F401
from ._utils import Version as Version  # noqa: F401


def should_default_ccid() -> bool:
    """Helper function to inform whether CCID should be the default communication protocol

    Some features do not work over CCID, therefore it is only used when CTAPHID is not available, meaning on windows when not an administrator"""
    if find_spec("smartcard") is None:
        return False

    if sys.platform != "win32" and sys.platform != "cygwin":
        # Linux or MacOS don't need admin to access with CTAPHID
        return False

    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return False
        else:
            return True
    except Exception:
        return False


def list(
    *, use_ccid: bool = False, model: Optional[Model] = None, exclusive: bool = True
) -> List[TrussedBase]:
    devices: List[TrussedBase] = []

    if model is None or model == Model.NK3:
        from nitrokey import nk3

        devices.extend(nk3.list(use_ccid, exclusive))

    if model is None or model == Model.NKPK:
        from nitrokey import nkpk

        devices.extend(nkpk.list(use_ccid, exclusive))

    return devices


def open(path: str, *, model: Optional[Model] = None) -> Optional[TrussedBase]:
    devices: List[TrussedBase] = []

    if model is None or model == Model.NK3:
        from nitrokey import nk3

        nk3_device = nk3.open(path)
        if nk3_device is not None:
            devices.append(nk3_device)

    if model is None or model == Model.NKPK:
        from nitrokey import nkpk

        nkpk_device = nkpk.open(path)
        if nkpk_device is not None:
            devices.append(nkpk_device)

    if len(devices) > 1:
        raise Exception(f"Found multiple devices at path {path}")
    if len(devices) == 1:
        return devices[0]
    return None
