# Moved the dataclasses from secrets_app to here to prevent circular import when trying to import in CXF

import dataclasses
from enum import Enum, IntEnum
from typing import Any, Optional

import tlv8


@dataclasses.dataclass
class ListItemProperties:
    touch_required: bool
    secret_encryption: bool
    pws_data_exist: bool

    @classmethod
    def _get_bit(cls, x: int, n: int) -> bool:
        return ((x >> n) & 1) == 1

    @classmethod
    def from_byte(cls, b: int) -> "ListItemProperties":
        return ListItemProperties(
            touch_required=cls._get_bit(b, 0),
            secret_encryption=cls._get_bit(b, 1),
            pws_data_exist=cls._get_bit(b, 2),
        )

    def __str__(self) -> str:
        data = [
            "touch required" if self.touch_required else "",
            "PIN required" if self.secret_encryption else "",
            "PWS data available" if self.pws_data_exist else "",
        ]
        return ",".join([d for d in data if d])


@dataclasses.dataclass
class ListItem:
    kind: "Kind"
    algorithm: "Algorithm"
    label: bytes
    properties: ListItemProperties

    @classmethod
    def get_type_name(cls, x: Any) -> str:
        return str(x).split(".")[-1]

    def __str__(self) -> str:
        return (
            f"{self.label.decode()}"
            f"\t{self.get_type_name(self.kind)}/{self.get_type_name(self.algorithm)}"
            f"\t{self.properties}"
        )


@dataclasses.dataclass
class ListItemSerializable:
    kind: "Kind"
    algorithm: "Algorithm"
    label: str
    properties: ListItemProperties

    @classmethod
    def from_list_item(cls, list_item: ListItem) -> "ListItemSerializable":
        return ListItemSerializable(
            kind=list_item.kind,
            algorithm=list_item.algorithm,
            label=list_item.label.decode("utf-8", errors="ignore"),
            properties=list_item.properties,
        )

    def to_list_item(self) -> ListItem:
        return ListItem(
            kind=self.kind,
            algorithm=self.algorithm,
            label=self.label.encode(),
            properties=self.properties,
        )


@dataclasses.dataclass
class PasswordSafeEntry:
    login: Optional[bytes]
    password: Optional[bytes]
    metadata: Optional[bytes]
    properties: Optional[bytes] = None
    name: Optional[bytes] = None

    def tlv_encode(self) -> list[tlv8.Entry]:
        entries = [
            (tlv8.Entry(Tag.PwsLogin.value, self.login) if self.login is not None else None),
            (
                tlv8.Entry(Tag.PwsPassword.value, self.password)
                if self.password is not None
                else None
            ),
            (
                tlv8.Entry(Tag.PwsMetadata.value, self.metadata)
                if self.metadata is not None
                else None
            ),
        ]
        # Filter out empty entries
        return [r for r in entries if r is not None]


@dataclasses.dataclass
class RawBytes:
    data: list[int]


@dataclasses.dataclass
class SelectResponse:
    # Application version
    version: Optional[bytes]
    # PIN attempt counter
    pin_attempt_counter: Optional[int]
    # Salt, challenge-response auth only, tag Name
    salt: Optional[bytes]
    # Challenge field, challenge-response auth only
    challenge: Optional[bytes]
    # Selected algorithm, challenge-response auth only
    algorithm: Optional[bytes]
    # Serial number of the device
    serial_number: Optional[bytes]

    def version_str(self) -> str:
        if self.version:
            return f"{self.version[0]}.{self.version[1]}.{self.version[2]}"
        else:
            return "unknown"

    def __str__(self) -> str:
        return (
            "Nitrokey Secrets\n"
            f"\tVersion: {self.version_str()}\n"
            f"\tPIN attempt counter: {self.pin_attempt_counter}\n"
            f"\tSerial number: {self.serial_number.hex() if self.serial_number else 'None'}"
        )


class SecretsAppExceptionID(IntEnum):
    MoreDataAvailable = 0x61FF
    VerificationFailed = 0x6300
    UnspecifiedNonpersistentExecutionError = 0x6400
    UnspecifiedPersistentExecutionError = 0x6500
    WrongLength = 0x6700
    LogicalChannelNotSupported = 0x6881
    SecureMessagingNotSupported = 0x6882
    CommandChainingNotSupported = 0x6884
    SecurityStatusNotSatisfied = 0x6982
    ConditionsOfUseNotSatisfied = 0x6985
    OperationBlocked = 0x6983
    IncorrectDataParameter = 0x6A80
    FunctionNotSupported = 0x6A81
    NotFound = 0x6A82
    NotEnoughMemory = 0x6A84
    IncorrectP1OrP2Parameter = 0x6A86
    KeyReferenceNotFound = 0x6A88
    InstructionNotSupportedOrInvalid = 0x6D00
    ClassNotSupported = 0x6E00
    UnspecifiedCheckingError = 0x6F00
    Success = 0x9000


class SecretsAppHealthCheckException(Exception):
    pass


@dataclasses.dataclass
class SecretsAppException(Exception):
    code: str
    context: str

    def to_id(self) -> SecretsAppExceptionID:
        return SecretsAppExceptionID(int(self.code, 16))

    def to_string(self) -> str:
        d = {
            "61FF": "MoreDataAvailable",
            "6300": "VerificationFailed",
            "6400": "UnspecifiedNonpersistentExecutionError",
            "6500": "UnspecifiedPersistentExecutionError",
            "6700": "WrongLength",
            "6881": "LogicalChannelNotSupported",
            "6882": "SecureMessagingNotSupported",
            "6884": "CommandChainingNotSupported",
            "6982": "SecurityStatusNotSatisfied",
            "6985": "ConditionsOfUseNotSatisfied",
            "6983": "OperationBlocked",
            "6a80": "IncorrectDataParameter",
            "6a81": "FunctionNotSupported",
            "6a82": "NotFound",
            "6a84": "NotEnoughMemory",
            "6a86": "IncorrectP1OrP2Parameter",
            "6a88": "KeyReferenceNotFound",
            "6d00": "InstructionNotSupportedOrInvalid",
            "6e00": "ClassNotSupported",
            "6f00": "UnspecifiedCheckingError",
            "9000": "Success",
        }
        return d.get(self.code, "Unknown SW code")

    def __repr__(self) -> str:
        return f"SecretsAppException(code={self.code}/{self.to_string()})"

    def __str__(self) -> str:
        return self.__repr__()


class CCIDInstruction(Enum):
    Select = 0xA4


class Instruction(Enum):
    Put = 0x1
    Delete = 0x2
    SetCode = 0x3
    Reset = 0x4
    List = 0xA1
    Calculate = 0xA2
    Validate = 0xA3
    CalculateAll = 0xA4  # 0xA4 is Select as well # Unused
    SendRemaining = 0xA5
    VerifyCode = 0xB1
    # Place extending commands in 0xBx space
    VerifyPIN = 0xB2
    ChangePIN = 0xB3
    SetPIN = 0xB4
    GetCredential = 0xB5
    UpdateCredential = 0xB7


class Tag(Enum):
    CredentialId = 0x71  # also known as Name
    NameList = 0x72
    Key = 0x73
    Challenge = 0x74
    Response = 0x75
    Properties = 0x78
    InitialCounter = 0x7A
    Version = 0x79
    Algorithm = 0x7B
    # Touch = 0x7c,
    # Extension starting from 0x80
    Password = 0x80
    NewPassword = 0x81
    PINCounter = 0x82
    PwsLogin = 0x83
    PwsPassword = 0x84
    PwsMetadata = 0x85
    SerialNumber = 0x8F


class Kind(IntEnum):
    Hotp = 0x10
    Totp = 0x20
    HotpReverse = 0x30
    Hmac = 0x40
    NotSet = 0xF0

    @classmethod
    def from_attribute_byte(cls, attribute_byte: bytes) -> str:
        a = int(attribute_byte)
        k = cls.from_attribute_byte_type(a)
        if k != Kind.NotSet:
            return str(k).split(".")[-1].upper()
        else:
            return "PWS"

    @classmethod
    def from_attribute_byte_type(cls, a: int) -> "Kind":
        v = a & 0xF0
        for k in Kind:
            if k.value == v:
                return k
        raise ValueError("Invalid attribute byte")


STRING_TO_KIND = {
    "HOTP": Kind.Hotp,
    "TOTP": Kind.Totp,
    "HOTP_REVERSE": Kind.HotpReverse,
    "HMAC": Kind.Hmac,
}


class Algorithm(IntEnum):
    Sha1 = 0x01
    Sha256 = 0x02
    Sha512 = 0x03


ALGORITHM_TO_KIND = {"SHA1": Algorithm.Sha1, "SHA256": Algorithm.Sha256}
