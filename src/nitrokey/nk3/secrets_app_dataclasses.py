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


class Algorithm(IntEnum):
    Sha1 = 0x01
    Sha256 = 0x02
    Sha512 = 0x03


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
