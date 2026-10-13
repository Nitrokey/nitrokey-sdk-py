import enum
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from fido2 import cbor

from ._connection import App
from ._device import TrussedDevice
from ._exceptions import TrussedException


@enum.unique
class _StorageCommand(Enum):
    STATUS = 0x00
    UNLOCK = 0x01
    LOCK = 0x02
    SET_PIN = 0x03
    CHANGE_PIN = 0x04

    def __str__(self) -> str:
        return f"{self.name} ({self.value:#04x})"


@enum.unique
class StorageError(Enum):
    INVALID_REQUEST = 0x01
    SERIALIZATION_FAILED = 0x02
    INTERNAL_ERROR = 0x03
    PIN_TOO_LONG = 0x04
    PIN_TOO_SHORT = 0x05
    INVALID_PIN = 0x06
    PIN_ALREADY_SET = 0x07
    PIN_NOT_SET = 0x08
    PIN_BLOCKED = 0x09

    def __str__(self) -> str:
        return f"{self.name} ({self.value:#04x})"

    @staticmethod
    def _from_int(value: int) -> "StorageError | None":
        for error in StorageError:
            if error.value == value:
                return error
        return None


@dataclass(kw_only=True, frozen=True)
class UnknownStorageError:
    """An unknown error returned by storage-app."""

    code: int

    def __str__(self) -> str:
        return f"{self.code:#04x}"


class StorageException(TrussedException):
    def __init__(self, command: _StorageCommand, error: StorageError | UnknownStorageError) -> None:
        super().__init__(f"storage-app command {command} failed with error {error}")
        self._command = command
        self.error = error


@dataclass(kw_only=True, frozen=True)
class StorageStatus:
    """Current status of storage-app."""

    unlocked: bool
    pin_set: bool
    pin_retries: int

    @staticmethod
    def _from_cbor(data: bytes) -> "StorageStatus | None":
        try:
            m = cbor.decode(data)
        except ValueError:
            return None
        if (
            not isinstance(m, Mapping)
            or "unlocked" not in m
            or "pin_set" not in m
            or "pin_retries" not in m
        ):
            return None
        unlocked = m["unlocked"]
        pin_set = m["pin_set"]
        pin_retries = m["pin_retries"]
        if (
            not isinstance(unlocked, bool)
            or not isinstance(pin_set, bool)
            or not isinstance(pin_retries, int)
        ):
            return None
        return StorageStatus(unlocked=unlocked, pin_set=pin_set, pin_retries=pin_retries)


class StorageApp:
    def __init__(self, device: TrussedDevice) -> None:
        self.device = device

    def _call(self, command: _StorageCommand, request: Mapping[Any, Any] | None = None) -> bytes:
        self.device._logger.debug(f"Executing storage-app command {command}")
        if request is not None:
            data = cbor.encode(request)
        else:
            data = bytes()
        response = self.device._call_app(App.STORAGE, data=command.value.to_bytes(1, "big") + data)
        if len(response) == 0:
            raise self._trussed_exception(command, "returned an empty response")
        if response[0] != 0:
            raise self._storage_exception(command, response[0])
        return response[1:]

    def _storage_exception(self, command: _StorageCommand, error_code: int) -> StorageException:
        error: StorageError | UnknownStorageError
        storage_error = StorageError._from_int(error_code)
        if storage_error is None:
            error = UnknownStorageError(code=error_code)
        else:
            error = storage_error
        e = StorageException(command, error)
        self.device._logger.error(str(e))
        return e

    def _trussed_exception(self, command: _StorageCommand, msg: str) -> TrussedException:
        e = TrussedException(f"storage-app command {command} {msg}")
        self.device._logger.error(str(e))
        return e

    def status(self) -> StorageStatus:
        response = self._call(_StorageCommand.STATUS)
        status = StorageStatus._from_cbor(response)
        if status is None:
            self.device._logger.error(f"Failed to parse storage status: {response.hex()}")
            raise self._trussed_exception(_StorageCommand.STATUS, "returned an invalid response")
        return status

    def unlock(self, pin: bytes) -> None:
        self._call(_StorageCommand.UNLOCK, {"pin": pin})

    def lock(self) -> None:
        self._call(_StorageCommand.LOCK)

    def set_pin(self, pin: bytes) -> None:
        self._call(_StorageCommand.SET_PIN, {"pin": pin})

    def change_pin(self, old_pin: bytes, new_pin: bytes) -> None:
        self._call(_StorageCommand.CHANGE_PIN, {"old_pin": old_pin, "new_pin": new_pin})
