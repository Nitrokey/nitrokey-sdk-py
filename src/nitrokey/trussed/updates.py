# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import importlib.metadata
import logging
import platform
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Set
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError
from io import BytesIO
from typing import TYPE_CHECKING, Any, Callable, Iterator, List, Optional, Tuple, Union

from nitrokey._helpers import Retries
from nitrokey.trussed import TimeoutException, TrussedBase, Version
from nitrokey.trussed._base import Model
from nitrokey.trussed._bootloader import (
    FirmwareContainer,
    TrussedBootloader,
    Variant,
    get_model_data,
    validate_firmware_image,
)
from nitrokey.trussed._bootloader.lpc55_upload.mboot.exceptions import (
    McuBootConnectionError,
)
from nitrokey.trussed._device import TrussedDevice
from nitrokey.trussed.admin_app import BootMode, Status
from nitrokey.trussed.admin_app import Variant as AdminAppVariant
from nitrokey.updates import Asset, Release, Repository

if TYPE_CHECKING:
    import typing_extensions

logger = logging.getLogger(__name__)


@enum.unique
class Warning(enum.Enum):
    """
    A warning that can occur during a firmware update.

    By default, these warnings abort the firmware update.  This enum can be used to select types
    of warnings that should be ignored and not cause the firmware update to fail.
    """

    IFS_MIGRATION_V2 = "ifs-migration-v2"
    MISSING_STATUS = "missing-status"
    SDK_VERSION = "sdk-version"
    UPDATE_FROM_BOOTLOADER = "update-from-bootloader"

    @property
    def message(self) -> str:
        if self == Warning.IFS_MIGRATION_V2:
            return (
                "Not enough space on the internal filesystem to perform the firmware"
                " update. See the release notes for more information:"
                " https://github.com/Nitrokey/nitrokey-3-firmware/releases/tag/v1.8.2-test.20250312"
            )
        if self == Warning.MISSING_STATUS:
            return (
                "Could not determine the device state as the current firmware is too old."
                " Please update to firmware version v1.3.1 first."
            )
        if self == Warning.SDK_VERSION:
            return (
                "Your Nitrokey SDK version is outdated.  Please update this program to the latest"
                " version and try again."
            )
        if self == Warning.UPDATE_FROM_BOOTLOADER:
            return (
                "The current state of the device cannot be checked as it is already in bootloader"
                " mode. Please review the release notes at:"
                " https://github.com/Nitrokey/nitrokey-3-firmware/releases"
            )

        if TYPE_CHECKING:
            typing_extensions.assert_never(self)

        return self.value

    @classmethod
    def from_str(cls, s: str) -> "Warning":
        for w in cls:
            if w.value == s:
                return w
        raise ValueError(f"Unexpected update warning id: {s}")


@enum.unique
class _Migration(enum.Enum):
    # IFS migration to use journaling on the NRF52 introduced in v1.3.0 (NK3)
    NRF_IFS_MIGRATION = enum.auto()
    # IFS migration to filesystem layout 2 (FIDO2 RK migration) in v1.8.2 (NK3)
    IFS_MIGRATION_V2 = enum.auto()

    @classmethod
    def get(
        cls,
        model: Model,
        variant: Union[Variant, AdminAppVariant],
        current: Optional[Version],
        new: Version,
    ) -> frozenset["_Migration"]:
        if model != Model.NK3:
            return frozenset()

        if isinstance(variant, AdminAppVariant):
            if variant == AdminAppVariant.USBIP:
                raise ValueError("Cannot perform firmware update for USBIP runner")
            elif variant == AdminAppVariant.LPC55:
                variant = Variant.LPC55
            elif variant == AdminAppVariant.NRF52:
                variant = Variant.NRF52
            else:
                if TYPE_CHECKING:
                    typing_extensions.assert_never(variant)

                raise ValueError(f"Unsupported device variant: {variant}")

        migrations = set()

        if variant == Variant.NRF52:
            if (
                current is None
                or current <= Version(1, 2, 2)
                and new >= Version(1, 3, 0)
            ):
                migrations.add(cls.NRF_IFS_MIGRATION)

        ifs_migration_v2 = Version(1, 8, 2)
        if (
            current is not None
            and current < ifs_migration_v2
            and new >= ifs_migration_v2
        ):
            migrations.add(cls.IFS_MIGRATION_V2)

        return frozenset(migrations)


def get_firmware_repository(model: Model) -> Repository:
    data = get_model_data(model)
    return Repository(owner="Nitrokey", name=data.firmware_repository_name)


def get_firmware_update(model: Model, release: Release) -> Asset:
    data = get_model_data(model)
    return release.require_asset(re.compile(data.firmware_pattern_string))


def _get_extra_information(migrations: Set[_Migration]) -> List[str]:
    """Return additional information for the device after update based on update-path"""

    out = []
    if _Migration.NRF_IFS_MIGRATION in migrations:
        out += [
            "",
            "During this update process the internal filesystem will be migrated!",
            "- Migration will only work, if your internal filesystem does not contain more than 45 Resident Keys. If you have more please remove some.",
            "- After the update it might take up to 3 minutes for the first boot.",
            "Never unplug the device while the LED is active!",
        ]
    return out


def _get_finalization_wait_retries(migrations: Set[_Migration]) -> int:
    """Return number of retries to wait for the device after update based on update-path"""

    out = 60
    if _Migration.NRF_IFS_MIGRATION in migrations:
        # max time 150secs == 300 retries
        out = 500
    return out


class UpdateUi(ABC):
    @abstractmethod
    def error(self, *msgs: Any) -> Exception:
        pass

    @abstractmethod
    def show_warning(self, warning: Warning) -> None:
        pass

    @abstractmethod
    def raise_warning(self, warning: Warning) -> Exception:
        pass

    @abstractmethod
    def abort(self, *msgs: Any) -> Exception:
        pass

    @abstractmethod
    def abort_downgrade(self, current: Version, image: Version) -> Exception:
        pass

    @abstractmethod
    def abort_pynitrokey_version(
        self, current: Version, required: Version
    ) -> Exception:
        pass

    @abstractmethod
    def confirm_download(self, current: Optional[Version], new: Version) -> None:
        pass

    @abstractmethod
    def confirm_update(self, current: Optional[Version], new: Version) -> None:
        pass

    @abstractmethod
    def confirm_pynitrokey_version(self, current: Version, required: Version) -> None:
        pass

    @abstractmethod
    def confirm_extra_information(self, extra_info: List[str]) -> None:
        pass

    @abstractmethod
    def confirm_update_same_version(self, version: Version) -> None:
        pass

    @abstractmethod
    def pre_bootloader_hint(self) -> None:
        pass

    @abstractmethod
    def request_bootloader_confirmation(self) -> None:
        pass

    @abstractmethod
    @contextmanager
    def download_progress_bar(self, desc: str) -> Iterator[Callable[[int, int], None]]:
        pass

    @abstractmethod
    @contextmanager
    def update_progress_bar(self) -> Iterator[Callable[[int, int], None]]:
        pass

    @abstractmethod
    @contextmanager
    def finalization_progress_bar(self) -> Iterator[Callable[[int, int], None]]:
        pass


class DeviceHandler(ABC):
    @abstractmethod
    def await_bootloader(self, model: Model) -> TrussedBootloader: ...

    @abstractmethod
    def await_device(
        self,
        model: Model,
        wait_retries: Optional[int],
        callback: Optional[Callable[[int, int], None]],
    ) -> TrussedDevice: ...


class Updater:
    def __init__(
        self,
        ui: UpdateUi,
        device_handler: DeviceHandler,
        ignore_warnings: Set[Warning] = frozenset(),
    ) -> None:
        self.ui = ui
        self.device_handler = device_handler
        self.ignore_warnings = ignore_warnings

    def _trigger_warning(self, warning: Warning) -> None:
        if warning in self.ignore_warnings:
            self.ui.show_warning(warning)
        else:
            raise self.ui.raise_warning(warning)

    def update(
        self,
        device: TrussedBase,
        image: Optional[str],
        update_version: Optional[str],
        ignore_pynitrokey_version: bool = False,
    ) -> Tuple[Version, Status]:
        model = device.model

        update_from_bootloader = False
        current_version = None
        status = None
        if isinstance(device, TrussedBootloader):
            update_from_bootloader = True
            self._trigger_warning(Warning.UPDATE_FROM_BOOTLOADER)
        elif isinstance(device, TrussedDevice):
            current_version = device.admin.version()
            status = device.admin.status()
        else:
            raise self.ui.error(f"Unexpected Trussed device: {device}")

        logger.info(f"Firmware version before update: {current_version or ''}")
        container = self._prepare_update(model, image, update_version, current_version)

        if not update_from_bootloader:
            if status is None:
                if model == Model.NK3:
                    if container.version > Version.from_str("1.3.1"):
                        self._trigger_warning(Warning.MISSING_STATUS)
                else:
                    self.ui.error(f"Missing status for {model} device")

        self._check_minimum_version(container, ignore_pynitrokey_version)

        self.ui.confirm_update(current_version, container.version)

        migrations = None
        if status is not None and status.variant is not None:
            migrations = self._check_migrations(
                model, status.variant, current_version, container.version, status
            )
        elif isinstance(device, TrussedBootloader):
            migrations = self._check_migrations(
                model, device.variant, current_version, container.version, status
            )

        with self._get_bootloader(device) as bootloader:
            if bootloader.variant not in container.images:
                raise self.ui.error(
                    "The firmware release does not contain an image for the "
                    f"{bootloader.variant.value} hardware variant"
                )
            try:
                validate_firmware_image(
                    bootloader.variant,
                    container.images[bootloader.variant],
                    container.version,
                    model,
                )
            except Exception as e:
                raise self.ui.error("Failed to validate firmware image", e)

            if migrations is None:
                migrations = self._check_migrations(
                    model,
                    bootloader.variant,
                    current_version,
                    container.version,
                    status,
                )

            self._perform_update(bootloader, container)

        wait_retries = _get_finalization_wait_retries(migrations)
        with self.ui.finalization_progress_bar() as callback:
            with self.device_handler.await_device(
                model, wait_retries, callback
            ) as device:
                version = device.admin.version()
                if version != container.version:
                    raise self.ui.error(
                        f"The firmware update to {container.version} was successful, but the "
                        f"firmware is still reporting version {version}."
                    )
                status = device.admin.status()

        return container.version, status

    def _prepare_update(
        self,
        model: Model,
        image: Optional[str],
        version: Optional[str],
        current_version: Optional[Version],
    ) -> FirmwareContainer:
        if image:
            try:
                container = FirmwareContainer.parse(image, model)
            except Exception as e:
                raise self.ui.error("Failed to parse firmware container", e)
            self._validate_version(current_version, container.version)
            return container
        else:
            repository = get_firmware_repository(model)
            if version:
                try:
                    logger.info(f"Downloading firmare version {version}")
                    release = repository.get_release(version)
                except Exception as e:
                    raise self.ui.error(f"Failed to get firmware release {version}", e)
            else:
                try:
                    release = repository.get_latest_release()
                    logger.info(f"Latest firmware version: {release}")
                except Exception as e:
                    raise self.ui.error("Failed to find latest firmware release", e)

            try:
                release_version = Version.from_v_str(release.tag)
            except ValueError as e:
                raise self.ui.error("Failed to parse version from release tag", e)
            self._validate_version(current_version, release_version)
            self.ui.confirm_download(current_version, release_version)
            return self._download_update(model, release)

    def _download_update(self, model: Model, release: Release) -> FirmwareContainer:
        try:
            update = get_firmware_update(model, release)
        except Exception as e:
            raise self.ui.error(
                f"Failed to find firmware image for release {release}",
                e,
            )

        try:
            logger.info(f"Trying to download firmware update from URL: {update.url}")

            with self.ui.download_progress_bar(update.tag) as callback:
                data = update.read(callback=callback)
        except Exception as e:
            raise self.ui.error(
                f"Failed to download latest firmware update {update.tag}", e
            )

        try:
            container = FirmwareContainer.parse(BytesIO(data), model)
        except Exception as e:
            raise self.ui.error(
                f"Failed to parse firmware container for {update.tag}", e
            )

        release_version = Version.from_v_str(release.tag)
        if release_version != container.version:
            raise self.ui.error(
                f"The firmware container for {update.tag} has the version {container.version}"
            )

        return container

    def _check_minimum_version(
        self, container: FirmwareContainer, ignore_pynitrokey_version: bool
    ) -> None:
        if container.sdk:
            try:
                sdk_version = Version.from_str(importlib.metadata.version("nitrokey"))
            except PackageNotFoundError:
                raise self.ui.error("Failed to determine the Nitrokey SDK version")

            if container.sdk > sdk_version:
                logger.warning(
                    f"Minimum SDK version required for update is {container.sdk} (current version: {sdk_version})"
                )
                self._trigger_warning(Warning.SDK_VERSION)
        elif container.pynitrokey:
            # The minimum pynitrokey version has been replaced by the minimum SDK version, so we
            # only check it if there is no minimum SDK version set.

            # this is the version of pynitrokey when we moved to the SDK
            pynitrokey_version = Version.from_str("0.4.49")
            if container.pynitrokey > pynitrokey_version:
                if ignore_pynitrokey_version:
                    self.ui.confirm_pynitrokey_version(
                        current=pynitrokey_version, required=container.pynitrokey
                    )
                else:
                    raise self.ui.abort_pynitrokey_version(
                        current=pynitrokey_version, required=container.pynitrokey
                    )

    def _validate_version(
        self,
        current_version: Optional[Version],
        new_version: Version,
    ) -> None:
        logger.info(f"Current firmware version: {current_version}")
        logger.info(f"Updated firmware version: {new_version}")

        if current_version:
            if current_version.core() > new_version.core():
                raise self.ui.abort_downgrade(current_version, new_version)
            elif current_version == new_version:
                if current_version.complete and new_version.complete:
                    same_version = current_version
                else:
                    same_version = current_version.core()
                self.ui.confirm_update_same_version(same_version)

    @contextmanager
    def _get_bootloader(self, device: TrussedBase) -> Iterator[TrussedBootloader]:
        model = device.model
        if isinstance(device, TrussedDevice):
            self.ui.request_bootloader_confirmation()
            try:
                device.admin.reboot(BootMode.BOOTROM)
            except TimeoutException:
                raise self.ui.abort(
                    "The reboot was not confirmed with the touch button"
                )

            # needed for udev to properly handle new device
            time.sleep(1)

            self.ui.pre_bootloader_hint()

            exc = None
            for t in Retries(3):
                logger.debug(f"Trying to connect to bootloader ({t})")
                try:
                    with self.device_handler.await_bootloader(model) as bootloader:
                        # noop to test communication
                        bootloader.uuid
                        yield bootloader
                        break
                except McuBootConnectionError as e:
                    logger.debug("Received connection error", exc_info=True)
                    exc = e
            else:
                msgs = [f"Failed to connect to {model} bootloader"]
                if platform.system() == "Linux":
                    msgs += ["Are the Nitrokey udev rules installed and active?"]
                raise self.ui.error(*msgs, exc)
        elif isinstance(device, TrussedBootloader):
            yield device
        else:
            raise self.ui.error(f"Unexpected {model} device: {device}")

    def _check_migrations(
        self,
        model: Model,
        variant: Union[Variant, AdminAppVariant],
        current_version: Optional[Version],
        new_version: Version,
        status: Optional[Status],
    ) -> frozenset["_Migration"]:
        try:
            migrations = _Migration.get(
                model=model,
                variant=variant,
                current=current_version,
                new=new_version,
            )
        except ValueError as e:
            raise self.ui.error(str(e))

        txt = _get_extra_information(migrations)
        self.ui.confirm_extra_information(txt)

        if _Migration.IFS_MIGRATION_V2 in migrations:
            if status and status.ifs_blocks is not None and status.ifs_blocks < 5:
                self._trigger_warning(Warning.IFS_MIGRATION_V2)

        return migrations

    def _perform_update(
        self, device: TrussedBootloader, container: FirmwareContainer
    ) -> None:
        logger.debug("Starting firmware update")
        image = container.images[device.variant]
        with self.ui.update_progress_bar() as callback:
            try:
                device.update(image, callback=callback)
            except Exception as e:
                raise self.ui.error("Failed to perform firmware update", e)
        logger.debug("Firmware update finished successfully")
