# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import re
from dataclasses import dataclass
from re import Pattern
from typing import TYPE_CHECKING

from nitrokey.updates import Repository

from ._base import NitrokeyTrussedBase as NitrokeyTrussedBase  # noqa: F401
from ._bootloader import Device as Device  # noqa: F401
from ._bootloader import FirmwareContainer as FirmwareContainer  # noqa: F401
from ._bootloader import FirmwareMetadata as FirmwareMetadata  # noqa: F401
from ._bootloader import (  # noqa: F401
    NitrokeyTrussedBootloader as NitrokeyTrussedBootloader,
)
from ._bootloader import Variant as Variant  # noqa: F401
from ._bootloader import parse_firmware_image as parse_firmware_image  # noqa: F401
from ._device import App as App  # noqa: F401
from ._device import NitrokeyTrussedDevice as NitrokeyTrussedDevice  # noqa: F401
from ._exceptions import (  # noqa: F401
    NitrokeyTrussedException as NitrokeyTrussedException,
)
from ._exceptions import TimeoutException as TimeoutException  # noqa: F401
from ._utils import Fido2Certs as Fido2Certs  # noqa: F401
from ._utils import Uuid as Uuid  # noqa: F401
from ._utils import Version as Version  # noqa: F401

if TYPE_CHECKING:
    from ._bootloader.nrf52 import SignatureKey


@dataclass
class DeviceData:
    name: str
    firmware_repository_name: str
    firmware_pattern_string: str
    nrf52_signature_keys: list["SignatureKey"]

    @property
    def firmware_repository(self) -> Repository:
        return Repository(owner="Nitrokey", name=self.firmware_repository_name)

    @property
    def firmware_pattern(self) -> Pattern[str]:
        return re.compile(self.firmware_pattern_string)
