import enum
from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Optional

from fido2 import cbor
from fido2.ctap import CtapError

from . import App, TimeoutException, TrussedDevice, Uuid, Version

RNG_LEN = 57
UUID_LEN = 16
VERSION_LEN = 4


@enum.unique
class AdminCommand(Enum):
    # legacy commands -- can be called directly or using the admin namespace
    UPDATE = 0x51
    REBOOT = 0x53
    RNG = 0x60
    VERSION = 0x61
    UUID = 0x62
    LOCKED = 0x63

    # new commands -- can only be called using the admin namespace
    STATUS = 0x80
    TEST_SE050 = 0x81
    GET_CONFIG = 0x82
    SET_CONFIG = 0x83
    FACTORY_RESET = 0x84
    FACTORY_RESET_APP = 0x85
    LIST_AVAILABLE_FIELDS = 0x86

    def is_legacy_command(self) -> bool:
        if self == AdminCommand.UPDATE:
            return True
        if self == AdminCommand.REBOOT:
            return True
        if self == AdminCommand.RNG:
            return True
        if self == AdminCommand.VERSION:
            return True
        if self == AdminCommand.UUID:
            return True
        if self == AdminCommand.LOCKED:
            return True
        return False


@enum.unique
class BootMode(Enum):
    FIRMWARE = enum.auto()
    BOOTROM = enum.auto()


@enum.unique
class InitStatus(IntFlag):
    NFC_ERROR = 0b0001
    INTERNAL_FLASH_ERROR = 0b0010
    EXTERNAL_FLASH_ERROR = 0b0100
    MIGRATION_ERROR = 0b1000
    SE050_ERROR = 0b00010000
    CONFIG_ERROR = 0b00100000
    RNG_ERROR = 0b01000000
    EXT_FLASH_NEED_REFORMAT = 0b10000000

    def is_error(self) -> bool:
        return self.value != 0

    def __str__(self) -> str:
        if self == 0:
            return "ok"
        errors = [error for error in InitStatus if error in self if error.name]
        value = sum(errors)
        messages = [error.name for error in errors if error.name]
        if self.value != value:
            messages.append("UNKNOWN")
        return ", ".join(messages) + " (" + hex(self.value) + ")"


@enum.unique
class Variant(Enum):
    USBIP = 0
    LPC55 = 1
    NRF52 = 2


@dataclass
class Status:
    init_status: Optional[InitStatus] = None
    ifs_blocks: Optional[int] = None
    efs_blocks: Optional[int] = None
    variant: Optional[Variant] = None


@enum.unique
class FactoryResetStatus(Enum):
    SUCCESS = 0
    NOT_CONFIRMED = 0x01
    APP_NOT_ALLOWED = 0x02
    APP_FAILED_PARSE = 0x03

    @classmethod
    def from_int(cls, i: int) -> Optional["FactoryResetStatus"]:
        for status in FactoryResetStatus:
            if status.value == i:
                return status
        return None

    @classmethod
    def check(cls, i: int, msg: str) -> None:
        status = FactoryResetStatus.from_int(i)
        if status != FactoryResetStatus.SUCCESS:
            if status is None:
                raise Exception(f"Unknown error {i:x}")
            if status == FactoryResetStatus.NOT_CONFIRMED:
                error = "Operation was not confirmed with touch"
            elif status == FactoryResetStatus.APP_NOT_ALLOWED:
                error = "The application does not support factory reset through nitropy"
            elif status == FactoryResetStatus.APP_FAILED_PARSE:
                error = "The application name must be utf-8"
            raise Exception(f"{msg}: {error}")


@enum.unique
class ConfigStatus(Enum):
    SUCCESS = 0
    READ_FAILED = 1
    WRITE_FAILED = 2
    DESERIALIZATION_FAILED = 3
    SERIALIZATION_FAILED = 4
    INVALID_KEY = 5
    INVALID_VALUE = 6
    DATA_TOO_LONG = 7

    @classmethod
    def from_int(cls, i: int) -> Optional["ConfigStatus"]:
        for status in ConfigStatus:
            if status.value == i:
                return status
        return None

    @classmethod
    def check(cls, i: int, msg: str) -> None:
        status = ConfigStatus.from_int(i)
        if status != ConfigStatus.SUCCESS:
            if status:
                error = str(status)
            else:
                error = f"unknown error {i:x}"
            raise Exception(f"{msg}: {error}")


@enum.unique
class ConfigFieldType(Enum):
    BOOL = 0
    U8 = 1

    @classmethod
    def from_int(cls, i: int) -> Optional["ConfigFieldType"]:
        for ty in ConfigFieldType:
            if ty.value == i:
                return ty
        return None

    def is_valid(self, value: str) -> bool:
        if self == ConfigFieldType.BOOL:
            return value in ["true", "false"]
        elif self == ConfigFieldType.U8:
            try:
                intval = int(value)
                if intval < 256 and intval > 0:
                    return True
                else:
                    return False
            except ValueError:
                return False

    def __str__(self) -> str:
        if self == ConfigFieldType.BOOL:
            return "Bool"
        elif self == ConfigFieldType.U8:
            return "u8"


@dataclass
class ConfigField:
    name: str
    requires_touch_confirmation: bool
    requires_reboot: bool
    destructive: bool
    ty: ConfigFieldType


class AdminApp:
    def __init__(self, device: TrussedDevice) -> None:
        self.device = device

    def _call(
        self,
        command: AdminCommand,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> Optional[bytes]:
        try:
            if command.is_legacy_command():
                return self.device._call(
                    command.value,
                    command.name,
                    response_len=response_len,
                    data=data,
                )
            else:
                return self.device._call_app(
                    App.ADMIN,
                    response_len=response_len,
                    data=command.value.to_bytes(1, "big") + data,
                )
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                return None
            else:
                raise

    def is_locked(self) -> bool:
        response = self._call(AdminCommand.LOCKED, response_len=1)
        assert response is not None
        return response[0] == 1

    def reboot(self, mode: BootMode = BootMode.FIRMWARE) -> bool:
        try:
            if mode == BootMode.FIRMWARE:
                self._call(AdminCommand.REBOOT)
            elif mode == BootMode.BOOTROM:
                try:
                    self._call(AdminCommand.UPDATE)
                except CtapError as e:
                    # The admin app returns an Invalid Length error if the user confirmation
                    # request times out
                    if e.code == CtapError.ERR.INVALID_LENGTH:
                        raise TimeoutException()
                    else:
                        raise e
        except OSError as e:
            # OS error is expected as the device does not respond during the reboot
            self.device._logger.debug("ignoring OSError after reboot", exc_info=e)
        return True

    def rng(self) -> bytes:
        data = self._call(AdminCommand.RNG, response_len=RNG_LEN)
        assert data is not None
        return data

    def status(self) -> Status:
        status = Status()
        reply = self._call(AdminCommand.STATUS)
        if reply is not None:
            if not reply:
                raise ValueError("The device returned an empty status")
            status.init_status = InitStatus(reply[0])
            if len(reply) >= 4:
                status.ifs_blocks = reply[1]
                status.efs_blocks = int.from_bytes(reply[2:4], "big")
            if len(reply) >= 5:
                try:
                    status.variant = Variant(reply[4])
                except ValueError:
                    pass
        return status

    def uuid(self) -> Optional[Uuid]:
        uuid = self._call(AdminCommand.UUID)
        if uuid is None or len(uuid) == 0:
            # Firmware version 1.0.0 does not support querying the UUID
            return None
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")
        return Uuid(int.from_bytes(uuid, byteorder="big"))

    def version(self) -> Version:
        reply = self._call(AdminCommand.VERSION, data=bytes([0x01]))
        assert reply is not None
        if len(reply) == VERSION_LEN:
            version = int.from_bytes(reply, "big")
            return Version.from_int(version)
        else:
            return Version.from_str(reply.decode("utf-8"))

    def se050_tests(self) -> Optional[bytes]:
        return self._call(AdminCommand.TEST_SE050)

    def has_config(self, key: str) -> bool:
        reply = self._call(AdminCommand.GET_CONFIG, data=key.encode())
        if not reply or len(reply) < 1:
            return False
        return ConfigStatus.from_int(reply[0]) == ConfigStatus.SUCCESS

    def get_config(self, key: str) -> str:
        reply = self._call(AdminCommand.GET_CONFIG, data=key.encode())
        if not reply or len(reply) < 1:
            raise ValueError("The device returned an empty response")
        ConfigStatus.check(reply[0], "Failed to get config value")
        return reply[1:].decode()

    def set_config(self, key: str, value: str) -> None:
        request = cbor.encode({"key": key, "value": value})
        reply = self._call(AdminCommand.SET_CONFIG, data=request, response_len=1)
        assert reply
        ConfigStatus.check(reply[0], "Failed to set config value")

    def list_available_fields(self) -> list[ConfigField]:
        reply = self._call(AdminCommand.LIST_AVAILABLE_FIELDS)
        # Function not supported, return values for 1.7.0 release
        if not reply:
            return [
                ConfigField(
                    "fido.disable_skip_up_timeout",
                    False,
                    False,
                    False,
                    ConfigFieldType.BOOL,
                ),
                ConfigField(
                    "opcard.use_se050_backend",
                    True,
                    True,
                    True,
                    ConfigFieldType.BOOL,
                ),
            ]
        parsed = cbor.decode(reply)
        assert isinstance(parsed, list)
        ret = []

        for field in parsed:
            ty = ConfigFieldType.from_int(field["t"])
            if ty is None:
                ty = ConfigFieldType.BOOL

            ret.append(
                ConfigField(
                    field["n"],
                    field["c"],
                    field["r"],
                    field["d"],
                    ty,
                )
            )
        return ret

    def factory_reset(self) -> bool:
        try:
            reply = self._call(AdminCommand.FACTORY_RESET, response_len=1)
        except OSError as e:
            if e.errno == 5:
                self.device._logger.debug("ignoring OSError after reboot", exc_info=e)
                return True
            else:
                raise e
        if reply:
            FactoryResetStatus.check(reply[0], "Failed to factory reset the device")
        return reply is not None

    def factory_reset_app(self, application: str) -> bool:
        reply = self._call(
            AdminCommand.FACTORY_RESET_APP,
            data=application.encode("ascii"),
            response_len=1,
        )
        if reply:
            FactoryResetStatus.check(
                reply[0], "Failed to factory reset the application"
            )
        return reply is not None
