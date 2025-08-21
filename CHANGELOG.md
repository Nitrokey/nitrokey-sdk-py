# Changelog

## Unreleased

-

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.4.1...HEAD)

## [v0.4.1](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.4.1) (2025-08-21)

- Add support for `protobuf` v6.
- `nitrokey.trussed.admin_app`: Fix validation of `ConfigFieldType.U8` values.
- `nitrokey.trussed`: Add `list` and `open` functions.
- `nitrokey.trussed.updates`:
  - Add default values for the `image` and `update_version` arguments for `Updater.update`.
  - Only call `UpdateUi.confirm_extra_information` if the passed list is not empty.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.4.0...v0.4.1)

## [v0.4.0](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.4.0) (2025-08-04)

- `nitrokey.trussed.admin_app.InitStatus`: add support for `EXT_FLASH_NEED_REFORMAT`
- Use `poetry-core` v2 as build backend.
- Bump minimum Python version to 3.10.
- `nitrokey.trussed.Model`: Remove `firmware_repository` and `firmware_pattern` properties.
- `nitrokey.nk3.updates`:
  - Move to `nitrokey.trussed.updates` and prepare adding NKPK support.
  - Return device status after an update.
  - Add `model` argument to `get_firmware_update`.
  - Add `get_firmware_repository` method.
  - Replace connection callbacks in `Updater` with `DeviceHandler` class.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.3.2...v0.4.0)

## [v0.3.2](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.3.2) (2025-07-08)

- Add support for `fido2` v2.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.3.1...v0.3.2)

## [v0.3.1](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.3.1) (2025-03-28)

- `nitropy.nk3.updates`: Remove reboot during update.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.3.0...v0.3.1)

## [v0.3.0](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.3.0) (2025-03-21)

- Bump minimum Python version from 3.9 to 3.9.2.
- `nitrokey.nk3.updates`:
  - Remove `UpdatePath`, `get_extra_information` and `get_finalization_wait_retries` from public API.
  - Remove obsolete `UpdateUi.request_repeated_update` method.
  - Show warning when updating from bootloader mode and if the status command is not available.
  - Reboot devices in firmware mode before the update to make sure that the status is up to date.
  - Add `Warning` enum, `show_warning` and `raise_warning` methods to `UpdateUi` and `ignore_warnings` argument to `UpdateUi.__init__`.
- Add support for updates to Nitrokey 3 firmware v1.8.2.
- Add support for setting a minimum SDK version in firmware update containers.
  - Add an `sdk` field to `nitrokey.trussed.FirmwareContainer`.
  - Check SDK version in `nitrokey.nk3.updates.Updater.update`.
  - Add `nitrokey.nk3.updates.Warning.SDK_VERSION` variant.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.4...v0.3.0)

## [v0.2.4](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.2.4) (2025-01-22)

- The list methods of `NK3` and `NKPK` now only open the respective device, based on the USB vendor and product ID.
- Use trusted publishing for PyPI.
- Add support for `poetry-core` v2.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.3...v0.2.4)

## [v0.2.3](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.2.3) (2024-11-02)

- Remove `ecdsa` dependency
- Remove two step update handling on macOS
- Correct update message
- Add RPM specification file
- Add CI test to make sure versions in `pyproject.toml` and `python3-nitrokey.spec` are the same

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.2...v0.2.3)

## [v0.2.2](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.2.2) (2024-10-23)

- Relax version requirement of `cryptography` to `>=41` and `ecdsa` to `>=0.18,<=0.19`.

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.1...v0.2.2)

## [v0.2.1](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.2.1) (2024-10-21)

### Features

- `trussed.admin_app`: Add `AdminApp.list_available_fields` function for listing all support config fields

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.0...v0.2.1)

## [v0.2.0](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.2.0) (2024-09-11)

This release refactors the code used for communication with the bootloader, reducing the number of dependencies.

### Features

- `trussed.admin_app`: Add error codes `CONFIG_ERROR` and `RNG_ERROR` to `InitStatus` enum

### Other Changes

- Update `protobuf` dependency to 5.26
- Vendor `spsdk` dependency to reduce the total number of dependencies
- Replace `libusbsio` dependency with `hidapi`

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.1.0...v0.2.0)

## [v0.1.0](https://github.com/Nitrokey/nitrokey-sdk-py/releases/tag/v0.1.0) (2024-07-29)

Initial release with support for Nitrokey 3 and Nitrokey Passkey devices and the admin, provisioner and secrets app.
