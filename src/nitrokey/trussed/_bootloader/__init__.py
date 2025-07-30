# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import hashlib
import json
import logging
import sys
from abc import abstractmethod
from dataclasses import dataclass
from io import BytesIO
from re import Pattern
from typing import TYPE_CHECKING, Callable, Dict, Optional, Tuple, Union
from zipfile import ZipFile

from .._base import Model, TrussedBase
from .._utils import Version

if TYPE_CHECKING:
    from .nrf52 import SignatureKey

logger = logging.getLogger(__name__)


ProgressCallback = Callable[[int, int], None]


@dataclass
class ModelData:
    firmware_repository_name: str
    firmware_pattern_string: str
    nrf52_signature_keys: list["SignatureKey"]


def get_model_data(model: Model) -> ModelData:
    if model == Model.NK3:
        from nitrokey.nk3 import _NK3_DATA

        return _NK3_DATA
    if model == Model.NKPK:
        from nitrokey.nkpk import _NKPK_DATA

        return _NKPK_DATA
    raise ValueError(f"Unknown model {model}")


class Variant(enum.Enum):
    LPC55 = "lpc55"
    NRF52 = "nrf52"

    @classmethod
    def from_str(cls, s: str) -> "Variant":
        for variant in cls:
            if variant.value == s:
                return variant
        raise ValueError(f"Unknown variant {s}")


def _validate_checksum(checksums: dict[str, str], path: str, data: bytes) -> None:
    if path not in checksums:
        raise ValueError(f"Missing checksum for file {path} in firmware container")
    m = hashlib.sha256()
    m.update(data)
    checksum = m.hexdigest()
    if checksum != checksums[path]:
        raise ValueError(f"Invalid checksum for file {path} in firmware container")


@dataclass
class FirmwareContainer:
    version: Version
    pynitrokey: Optional[Version]
    sdk: Optional[Version]
    images: Dict[Variant, bytes]

    @classmethod
    def parse(cls, path: Union[str, BytesIO], model: Model) -> "FirmwareContainer":
        with ZipFile(path) as z:
            checksum_lines = z.read("sha256sums").decode("utf-8").splitlines()
            checksum_pairs = [line.split("  ", maxsplit=1) for line in checksum_lines]
            checksums = {path: checksum for checksum, path in checksum_pairs}

            manifest_bytes = z.read("manifest.json")
            _validate_checksum(checksums, "manifest.json", manifest_bytes)
            manifest = json.loads(manifest_bytes)
            actual_model = Model.from_str(manifest["device"])
            if actual_model != model:
                raise ValueError(
                    f"Expected firmware container for {model}, got {actual_model}"
                )
            version = Version.from_v_str(manifest["version"])
            pynitrokey = None
            if "pynitrokey" in manifest:
                pynitrokey = Version.from_v_str(manifest["pynitrokey"])
            sdk = None
            if "sdk" in manifest:
                sdk = Version.from_v_str(manifest["sdk"])

            images = {}
            for variant, image in manifest["images"].items():
                image_bytes = z.read(image)
                _validate_checksum(checksums, image, image_bytes)
                images[Variant.from_str(variant)] = image_bytes

            return cls(
                version=version,
                pynitrokey=pynitrokey,
                sdk=sdk,
                images=images,
            )


@dataclass
class FirmwareMetadata:
    version: Version
    signed_by: Optional[str] = None
    signed_by_nitrokey: bool = False


class TrussedBootloader(TrussedBase):
    @abstractmethod
    def update(
        self,
        image: bytes,
        callback: Optional[ProgressCallback] = None,
    ) -> None: ...

    @property
    @abstractmethod
    def variant(self) -> Variant: ...


def get_firmware_filename_pattern(variant: Variant) -> Pattern[str]:
    from .lpc55 import FILENAME_PATTERN as FILENAME_PATTERN_LPC55
    from .nrf52 import FILENAME_PATTERN as FILENAME_PATTERN_NRF52

    if variant == Variant.LPC55:
        return FILENAME_PATTERN_LPC55
    elif variant == Variant.NRF52:
        return FILENAME_PATTERN_NRF52
    else:
        raise ValueError(f"Unexpected variant {variant}")


def parse_filename(filename: str) -> Optional[Tuple[Variant, Version]]:
    for variant in Variant:
        pattern = get_firmware_filename_pattern(variant)
        match = pattern.search(filename)
        if match:
            version = Version.from_v_str(match.group("version"))
            return (variant, version)
    return None


def validate_firmware_image(
    variant: Variant,
    data: bytes,
    version: Optional[Version],
    model: Model,
) -> FirmwareMetadata:
    try:
        metadata = parse_firmware_image(variant, data, model)
    except Exception:
        logger.exception("Failed to parse firmware image", exc_info=sys.exc_info())
        raise Exception("Failed to parse firmware image")

    if version:
        if version.core() != metadata.version:
            raise Exception(
                f"The firmware image for the release {version} has an unexpected product "
                f"version ({metadata.version})."
            )

    if not metadata.signed_by:
        raise Exception("Firmware image is not signed")

    if not metadata.signed_by_nitrokey:
        raise Exception(
            f"Firmware image is not signed by Nitrokey (signed by: {metadata.signed_by})"
        )

    return metadata


def parse_firmware_image(
    variant: Variant, data: bytes, model: Model
) -> FirmwareMetadata:
    from .lpc55 import parse_firmware_image as parse_firmware_image_lpc55
    from .nrf52 import parse_firmware_image as parse_firmware_image_nrf52

    if variant == Variant.LPC55:
        return parse_firmware_image_lpc55(data)
    elif variant == Variant.NRF52:
        return parse_firmware_image_nrf52(
            data, get_model_data(model).nrf52_signature_keys
        )
    else:
        raise ValueError(f"Unexpected variant {variant}")
