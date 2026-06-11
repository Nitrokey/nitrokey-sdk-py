from __future__ import annotations

import json
import secrets
import string
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional, Tuple, TypeAlias, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if TYPE_CHECKING:
    from nitrokey.nk3.secrets_app import ListItem, ListItemSerializable, PasswordSafeEntry

# https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html

uint: TypeAlias = int
tstr: TypeAlias = str
b64url: TypeAlias = str
uri: TypeAlias = str


# This function exists because CXF standard has no fixed method of assigning unique IDs
def _get_random_id() -> b64url:
    id = uuid.uuid4().bytes
    id_b64 = urlsafe_b64encode(id).decode()
    return id_b64


@dataclass
class Version:
    major: uint
    minor: uint


@dataclass
class Header:
    version: Version
    exporterRpId: tstr
    exporterDisplayName: tstr
    timestamp: uint
    accounts: List[Account]

    def items(self) -> List[Item]:
        if not self.accounts:
            return []
        items = []
        for account in self.accounts:
            items.extend(account.items)
        return items

    def encrypt(self, key: CXFKey) -> dict[str, Any]:
        payload_bytes = json.dumps(self.to_dict()).encode()
        aesgcm = AESGCM(key._key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, payload_bytes, None)
        encrypted = ct + nonce
        return {
            "EncryptedCXF": urlsafe_b64encode(encrypted).decode()
        }  # Returning as dict to maintain downstream compatibility

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def decrypt(d: dict[str, Any], key: CXFKey) -> Header:
        encrypted_b64 = d.get("EncryptedCXF", "")
        encrypted = urlsafe_b64decode(encrypted_b64)
        nonce = encrypted[-12:]
        ct = encrypted[:-12]
        aesgcm = AESGCM(key._key)
        payload_bytes = aesgcm.decrypt(nonce, ct, None)
        payload = json.loads(payload_bytes)
        cxfpayload = CXFPayload.from_dict(payload)
        return cxfpayload

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Header:
        accounts = []
        for acc in d.get("accounts", []):
            accounts.append(Account.from_dict(acc))
        version = d.get("version", {})
        return Header(
            version=Version(version.get("major", 1), version.get("minor", 0)),
            exporterRpId=d.get("exporterRpId", ""),
            exporterDisplayName=d.get("exporterDisplayName", ""),
            timestamp=d.get("timestamp", 0),
            accounts=accounts,
        )

    @staticmethod
    def from_items(items: List[Item]) -> "Header":
        return Header(
            version=Version(1, 0),  # v1.0
            exporterRpId="nitrokey",  # We are exporting from an authenticator device. Are we supposed to have a RP ID in this case?
            exporterDisplayName="Nitrokey NK3",
            accounts=[
                Account(
                    id=_get_random_id(),
                    username="",  # We are assuming one NK3 is held by one person only
                    email="",
                    collections=[],
                    items=items,
                )
            ],
            timestamp=uint(time.time()),
        )


@dataclass
class Account:
    id: b64url
    username: tstr
    email: tstr
    collections: List[Collection]
    items: List[Item]
    fullName: Optional[tstr] = None
    extensions: Optional[List[Extension]] = None

    @staticmethod
    def from_dict(acc: dict[str, Any]) -> "Account":
        items = []
        for item_d in acc.get("items", []):
            items.append(Item.from_dict(item_d))
        return Account(
            id=acc["id"],
            username=acc.get("username", ""),
            email=acc.get("email", ""),
            collections=acc.get("collections", []),
            items=items,
            fullName=acc.get("fullName"),
            extensions=acc.get("extensions"),
        )


@dataclass
class Collection:
    id: b64url
    title: tstr
    items: List[LinkedItem]
    creationAt: Optional[uint] = None
    modifiedAt: Optional[uint] = None
    subtitle: Optional[tstr] = None
    icon: Optional[tstr] = None
    subCollections: Optional[List[Collection]] = None
    extensions: Optional[List[Extension]] = None


@dataclass
class LinkedItem:
    item: b64url
    account: Optional[b64url] = None


@dataclass
class Item:
    id: b64url
    title: tstr
    credentials: List[Credential]
    creationAt: Optional[uint] = None
    modifiedAt: Optional[uint] = None
    subtitle: Optional[tstr] = None
    favorite: Optional[bool] = None
    scope: Optional[CredentialScope] = None
    tags: Optional[List[tstr]] = None
    extensions: Optional[List[Extension]] = None

    def to_password_safe_entry(self) -> Tuple["ListItem" | None, "PasswordSafeEntry"]:
        from .secrets_app import PasswordSafeEntry

        # credid = item.title.encode() if item.title else b""
        cred = self.credentials[0] if self.credentials else None
        cred_basic_auth = BasicAuth.from_dict(asdict(cred)) if cred else None
        login = cred_basic_auth.username.value.encode() if cred_basic_auth else b""
        password = cred_basic_auth.password.value.encode() if cred_basic_auth else b""
        extension = self.extensions[0] if self.extensions else None
        extension = NitrokeyPasswordExtension.from_dict(asdict(extension)) if extension else None
        metadata = extension.metadata.encode() if extension else b""
        list_item_serializable = (
            extension.item
            if extension and isinstance(extension, NitrokeyPasswordExtension)
            else None
        )
        list_item = list_item_serializable.to_list_item() if list_item_serializable else None
        pse = PasswordSafeEntry(login, password, metadata)
        return list_item, pse

    @staticmethod
    def from_dict(item_d: dict[str, Any]) -> "Item":
        credentials = []
        for cred in item_d.get("credentials", []):
            if "password" in cred and cred["password"]:  # Check whether cred is BasicAuth
                credentials.append(BasicAuth.from_dict(cred))
        extensions = []
        for ext in item_d.get("extensions", []):
            if ext["name"] == "Nitrokey Password Extension":
                extensions.append(NitrokeyPasswordExtension.from_dict(ext))
        return Item(
            id=item_d["id"],
            title=item_d["title"],
            credentials=cast(List[Credential], credentials),
            creationAt=item_d.get("creationAt"),
            modifiedAt=item_d.get("modifiedAt"),
            subtitle=item_d.get("subtitle"),
            favorite=item_d.get("favorite"),
            scope=item_d.get("scope"),
            tags=item_d.get("tags"),
            extensions=cast(List[Extension], extensions),
        )

    @staticmethod
    def from_password_safe_entry(item: "ListItem", pse: "PasswordSafeEntry") -> "Item":
        from .secrets_app import ListItemSerializable

        return Item(
            id=_get_random_id(),
            title=item.label.decode("utf-8", errors="ignore"),
            credentials=[
                BasicAuth(
                    urls=[],  # Nitrokey does not store URLs
                    username=EditableField(
                        id=_get_random_id(),
                        fieldType=FieldType.STRING,
                        value=pse.login.decode("utf-8", errors="ignore") if pse.login else "",
                    ),
                    password=EditableField(
                        id=_get_random_id(),
                        fieldType=FieldType.CONCEALED_STRING,
                        value=pse.password.decode("utf-8", errors="ignore") if pse.password else "",
                    ),
                )
            ],
            extensions=[
                NitrokeyPasswordExtension(
                    metadata=pse.metadata.decode("utf-8", errors="ignore") if pse.metadata else "",
                    item=ListItemSerializable.from_list_item(item),
                )
            ],
        )


@dataclass
class CredentialScope:
    urls: List[uri]


@dataclass
class Extension:
    name: tstr


@dataclass
class Credential:
    type: CredentialType = field(init=False)


class CredentialType(str, Enum):
    BASIC_AUTH = "basic-auth"


class FieldType(str, Enum):
    STRING = "string"
    CONCEALED_STRING = "concealed-string"
    EMAIL = "email"
    NUMEBR = "number"
    BOOLEAN = "boolean"
    DATE = "date"
    YEAR_MONTH = "year-month"
    WIFI = "wifi-network-security-type"
    COUNTRY_CODE = "country-code"
    SUBDIVISION_CODE = "subdivision-code"


@dataclass
class EditableField:
    fieldType: FieldType
    value: tstr
    id: Optional[b64url] = None
    label: Optional[tstr] = None
    designation: Optional[tstr] = None


@dataclass
class BasicAuth(Credential):
    urls: List[tstr]
    username: EditableField
    password: EditableField

    def __post_init__(self) -> None:
        self.type = CredentialType.BASIC_AUTH

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "BasicAuth":
        username = d["username"]
        password = d["password"]
        return BasicAuth(
            urls=d.get("urls", []),
            username=EditableField(
                fieldType=FieldType(username["fieldType"]),
                value=username["value"],
                id=username.get("id"),
                label=username.get("label"),
                designation=username.get("designation"),
            ),
            password=EditableField(
                fieldType=FieldType(password["fieldType"]),
                value=password["value"],
                id=password.get("id"),
                label=password.get("label"),
                designation=password.get("designation"),
            ),
        )


# TODO other credentials like Credit Card and Passkey Dict


@dataclass
class NitrokeyPasswordExtension(Extension):
    metadata: tstr
    item: "ListItemSerializable"

    name: tstr = field(init=False, default="Nitrokey Password Extension")

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "NitrokeyPasswordExtension":
        from .secrets_app import Algorithm, Kind, ListItemProperties, ListItemSerializable

        item_d = d.get("item", {})
        props = item_d.get("properties", {})
        label = item_d.get("label", "")
        return NitrokeyPasswordExtension(
            metadata=d.get("metadata", ""),
            item=ListItemSerializable(
                kind=Kind(item_d.get("kind", 240)),
                algorithm=Algorithm(item_d.get("algorithm", 1)),
                label=label,
                properties=ListItemProperties(
                    touch_required=props.get("touch_required", True),
                    secret_encryption=props.get(
                        "secret_encryption", True
                    ),  # Fail safe. Will be encrypted in case of errors
                    pws_data_exist=props.get("pws_data_exist", False),
                ),
            ),
        )


CXFPayload: TypeAlias = Header


@dataclass
class CXFKey:
    _key: bytes

    @staticmethod
    def generate_passphrase() -> str:
        alphabet = string.ascii_uppercase + string.digits
        chars = [secrets.choice(alphabet) for _ in range(25)]
        groups = [chars[i : i + 5] for i in range(0, 25, 5)]
        return "-".join("".join(g) for g in groups)

    @staticmethod
    def from_passphrase(passphrase: str) -> "CXFKey":
        passphrase = passphrase.strip().replace("-", "").replace(" ", "").upper()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x99\xf2L\x93\xe1\xe3%6\x0f}\x17\x0f",  # Random but constant salt
            info=None,
        )
        key = hkdf.derive(passphrase.encode())
        return CXFKey(_key=key)


class PasswordToCXF:
    @classmethod
    def password_to_item(cls, item: "ListItem", pse: "PasswordSafeEntry") -> Item:
        return Item.from_password_safe_entry(item, pse)

    @classmethod
    def items_to_cxf(cls, items: List[Item]) -> CXFPayload:
        return Header.from_items(items)

    @classmethod
    def cxf_from_dict(cls, d: dict[str, Any]) -> CXFPayload:
        return Header.from_dict(d)
