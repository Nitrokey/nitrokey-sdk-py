# Changelog

## Unreleased

-

[All Changes](https://github.com/Nitrokey/nitrokey-sdk-py/compare/v0.2.1...HEAD)

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
