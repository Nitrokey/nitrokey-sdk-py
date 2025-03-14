# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import logging
import platform
import time
import warnings
from abc import ABC, abstractmethod
from collections.abc import Set
from contextlib import contextmanager
from io import BytesIO
from typing import Any, Callable, Iterator, List, Optional, Union

from nitrokey._helpers import Retries
from nitrokey.nk3 import NK3, NK3Bootloader
from nitrokey.trussed import TimeoutException, TrussedBase, Version
from nitrokey.trussed._bootloader import (
    FirmwareContainer,
    Model,
    Variant,
    validate_firmware_image,
)
from nitrokey.trussed._bootloader.lpc55_upload.mboot.exceptions import (
    McuBootConnectionError,
)
from nitrokey.trussed.admin_app import BootMode, Status
from nitrokey.trussed.admin_app import Variant as AdminAppVariant
from nitrokey.updates import Asset, Release

logger = logging.getLogger(__name__)


@enum.unique
class _Migration(enum.Enum):
    # IFS migration to use journaling on the NRF52 introduced in v1.3.0
    NRF_IFS_MIGRATION = enum.auto()
    # IFS migration to filesystem layout 2 in v1.8.2 (FIDO2 RK migration)
    IFS_MIGRATION_V2 = enum.auto()

    @classmethod
    def get(
        cls,
        variant: Union[Variant, AdminAppVariant],
        current: Optional[Version],
        new: Version,
    ) -> frozenset["_Migration"]:
        if isinstance(variant, AdminAppVariant):
            if variant == AdminAppVariant.USBIP:
                raise ValueError("Cannot perform firmware update for USBIP runner")
            elif variant == AdminAppVariant.LPC55:
                variant = Variant.LPC55
            elif variant == AdminAppVariant.NRF52:
                variant = Variant.NRF52
            else:
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


def get_firmware_update(release: Release) -> Asset:
    return release.require_asset(Model.NK3.firmware_pattern)


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

    def request_repeated_update(self) -> Optional[Exception]:
        warnings.warn(
            "UpdateUi.request_repeated_update is no longer needed", DeprecationWarning
        )
        return None

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


class Updater:
    def __init__(
        self,
        ui: UpdateUi,
        await_bootloader: Callable[[], NK3Bootloader],
        await_device: Callable[
            [Optional[int], Optional[Callable[[int, int], None]]], NK3
        ],
    ) -> None:
        self.ui = ui
        self.await_bootloader = await_bootloader
        self.await_device = await_device

    def update(
        self,
        device: TrussedBase,
        image: Optional[str],
        update_version: Optional[str],
        ignore_pynitrokey_version: bool = False,
    ) -> Version:
        current_version = device.admin.version() if isinstance(device, NK3) else None
        status = device.admin.status() if isinstance(device, NK3) else None
        logger.info(f"Firmware version before update: {current_version or ''}")
        container = self._prepare_update(image, update_version, current_version)

        if container.pynitrokey:
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

        self.ui.confirm_update(current_version, container.version)

        migrations = None
        if status is not None and status.variant is not None:
            migrations = self._check_migrations(
                status.variant, current_version, container.version, status
            )
        elif isinstance(device, NK3Bootloader):
            migrations = self._check_migrations(
                device.variant, current_version, container.version, status
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
                    Model.NK3,
                )
            except Exception as e:
                raise self.ui.error("Failed to validate firmware image", e)

            if migrations is None:
                migrations = self._check_migrations(
                    bootloader.variant, current_version, container.version, status
                )

            self._perform_update(bootloader, container)

        wait_retries = _get_finalization_wait_retries(migrations)
        with self.ui.finalization_progress_bar() as callback:
            with self.await_device(wait_retries, callback) as device:
                version = device.admin.version()
                if version != container.version:
                    raise self.ui.error(
                        f"The firmware update to {container.version} was successful, but the "
                        f"firmware is still reporting version {version}."
                    )

        return container.version

    def _prepare_update(
        self,
        image: Optional[str],
        version: Optional[str],
        current_version: Optional[Version],
    ) -> FirmwareContainer:
        if image:
            try:
                container = FirmwareContainer.parse(image, Model.NK3)
            except Exception as e:
                raise self.ui.error("Failed to parse firmware container", e)
            self._validate_version(current_version, container.version)
            return container
        else:
            repository = Model.NK3.firmware_repository
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
            return self._download_update(release)

    def _download_update(self, release: Release) -> FirmwareContainer:
        try:
            update = get_firmware_update(release)
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
            container = FirmwareContainer.parse(BytesIO(data), Model.NK3)
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
    def _get_bootloader(self, device: TrussedBase) -> Iterator[NK3Bootloader]:
        if isinstance(device, NK3):
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
                    with self.await_bootloader() as bootloader:
                        # noop to test communication
                        bootloader.uuid
                        yield bootloader
                        break
                except McuBootConnectionError as e:
                    logger.debug("Received connection error", exc_info=True)
                    exc = e
            else:
                msgs = ["Failed to connect to Nitrokey 3 bootloader"]
                if platform.system() == "Linux":
                    msgs += ["Are the Nitrokey udev rules installed and active?"]
                raise self.ui.error(*msgs, exc)
        elif isinstance(device, NK3Bootloader):
            yield device
        else:
            raise self.ui.error(f"Unexpected Nitrokey 3 device: {device}")

    def _check_migrations(
        self,
        variant: Union[Variant, AdminAppVariant],
        current_version: Optional[Version],
        new_version: Version,
        status: Optional[Status],
    ) -> frozenset["_Migration"]:
        try:
            migrations = _Migration.get(
                variant=variant, current=current_version, new=new_version
            )
        except ValueError as e:
            raise self.ui.error(str(e))

        txt = _get_extra_information(migrations)
        self.ui.confirm_extra_information(txt)

        if _Migration.IFS_MIGRATION_V2 in migrations:
            if status and status.ifs_blocks is not None and status.ifs_blocks < 5:
                raise self.ui.error(
                    "Not enough space on the internal filesystem to perform the firmware "
                    "update. See the release notes for more information: "
                    "https://github.com/Nitrokey/nitrokey-3-firmware/releases/tag/v1.8.2-test.20250312"
                )

        return migrations

    def _perform_update(
        self, device: NK3Bootloader, container: FirmwareContainer
    ) -> None:
        logger.debug("Starting firmware update")
        image = container.images[device.variant]
        with self.ui.update_progress_bar() as callback:
            try:
                device.update(image, callback=callback)
            except Exception as e:
                raise self.ui.error("Failed to perform firmware update", e)
        logger.debug("Firmware update finished successfully")
