from __future__ import annotations

import json
import secrets
import string
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional, TypeAlias, cast

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
            if account.items:
                items.extend(account.items)
        return items

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
    def from_items(items: List[Item]) -> Header:
        return Header(
            version=Version(1, 0),  # v1.0
            exporterRpId="nitrokey.com",  # Exporting from authenticator
            exporterDisplayName="Nitrokey NK3",
            accounts=[
                Account(
                    id=_get_random_id(),
                    username="",  # We are assuming one NK3 is help by one person only
                    email="",
                    collections=[],
                    items=items,
                )
            ],
            timestamp=uint(time.time()),
        )

    def encrypt(self, key: CXFKey) -> dict[str, Any]:
        payload_bytes = json.dumps(asdict(self)).encode()
        aesgcm = AESGCM(key._key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, payload_bytes, None)
        encrypted = ct + nonce
        return {
            "EncryptedCXF": urlsafe_b64encode(encrypted).decode(),
            "version": 1,  # We cmay bump this up later
        }  # Returning as dict to maintain downstream compatibility

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def decrypt(d: dict[str, Any], key: CXFKey) -> Header:
        assert d.get("version", 0) == 1, "Invalid version"
        encrypted_b64 = d.get("EncryptedCXF", "")
        encrypted = urlsafe_b64decode(encrypted_b64)
        nonce = encrypted[-12:]
        ct = encrypted[:-12]
        aesgcm = AESGCM(key._key)
        payload_bytes = aesgcm.decrypt(nonce, ct, None)
        payload = json.loads(payload_bytes)
        cxfpayload = CXFPayload.from_dict(payload)
        return cxfpayload


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
    def from_dict(acc: dict[str, Any]) -> Account:
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
            extensions=acc.get(
                "extensions"
            ),  # This will break all non-nitrokey extensions. Nitrokey extension is handled in Items.
        )


@dataclass
class Collection:
    id: b64url
    title: tstr
    items: List[dict[str, Any]]
    creationAt: Optional[uint] = None
    modifiedAt: Optional[uint] = None
    subtitle: Optional[tstr] = None
    subCollections: Optional[List[Collection]] = None
    extensions: Optional[List[Extension]] = None


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

    @staticmethod
    def from_dict(item_d: dict[str, Any]) -> Item:
        credentials = []
        for cred in item_d.get("credentials", []):
            if cred["type"] == CredentialType.BASIC_AUTH:  # Check whether cred is BasicAuth
                credentials.append(BasicAuth.from_dict(cred))
        extensions = []
        for ext in item_d.get("extensions", []):
            if ext["name"] == "nitrokey.com/SecretsAppMetadata":
                extensions.append(SecretsAppMetadata.from_dict(ext))
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
    def from_password_representation(pr: PasswordRepresentation) -> Item:
        from .secrets_app import ListItemSerializable

        item = pr.item
        pse = pr.pse
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
                SecretsAppMetadata(
                    metadata=pse.metadata.decode("utf-8", errors="ignore") if pse.metadata else "",
                    item=ListItemSerializable.from_list_item(item),
                )
            ],
        )

    def password_representation(self) -> List[PasswordRepresentation]:
        from .secrets_app import (
            Algorithm,
            Kind,
            ListItemProperties,
            ListItemSerializable,
            PasswordSafeEntry,
        )

        # credid = item.title.encode() if item.title else b""
        item = self
        pr_list = []
        for cred in item.credentials:
            if cred.type != CredentialType.BASIC_AUTH:
                continue
            cred_basic_auth = BasicAuth.from_dict(asdict(cred)) if cred else None
            login = (
                cred_basic_auth.username.value.encode()
                if cred_basic_auth and cred_basic_auth.username
                else b""
            )
            password = (
                cred_basic_auth.password.value.encode()
                if cred_basic_auth and cred_basic_auth.password
                else b""
            )
            extension = item.extensions[0] if item and item.extensions else None
            extension = SecretsAppMetadata.from_dict(asdict(extension)) if extension else None
            metadata = extension.metadata.encode() if extension else _get_random_id().encode()
            list_item_serializable = (
                extension.item
                if extension and isinstance(extension, SecretsAppMetadata)
                else ListItemSerializable(
                    kind=Kind.NotSet,
                    algorithm=Algorithm.Sha1,
                    label=_get_random_id(),
                    properties=ListItemProperties(
                        touch_required=True,
                        secret_encryption=True,  # Fail safe
                        pws_data_exist=True,
                    ),
                )
            )
            list_item = list_item_serializable.to_list_item()
            pse = PasswordSafeEntry(login, password, metadata)
            pr = PasswordRepresentation(item=list_item, pse=pse)
            pr_list.append(pr)

        return pr_list


@dataclass
class CredentialScope:
    urls: List[uri]
    androidApps: List[dict[str, Any]]  # Not defining AndroidAppId since it is not used.


@dataclass
class Extension:
    name: tstr


@dataclass
class Credential:
    type: CredentialType = field(init=False)


class CredentialType(str, Enum):
    BASIC_AUTH = "basic-auth"
    # TODO Add the rest of them
    # https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html#enum-credential-type


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

    @staticmethod
    def from_dict(d: dict[str, Any]) -> EditableField:
        return EditableField(
            fieldType=FieldType(d["fieldType"]),
            value=d["value"],
            id=d.get("id"),
            label=d.get("label"),
            designation=d.get("designation"),
        )


@dataclass
class BasicAuth(Credential):
    urls: List[tstr]
    username: Optional[EditableField]
    password: Optional[EditableField]

    def __post_init__(self) -> None:
        self.type = CredentialType.BASIC_AUTH

    @staticmethod
    def from_dict(d: dict[str, Any]) -> BasicAuth:
        return BasicAuth(
            urls=d.get("urls", []),
            username=EditableField.from_dict(d.get("username", {})),
            password=EditableField.from_dict(d.get("password", {})),
        )


# TODO other credentials like Credit Card and Passkey Dict


@dataclass
class SecretsAppMetadata(Extension):
    metadata: tstr
    item: "ListItemSerializable"
    name: tstr = field(init=False, default="nitrokey.com/SecretsAppMetadata")

    @staticmethod
    def from_dict(d: dict[str, Any]) -> SecretsAppMetadata:
        from .secrets_app import Algorithm, Kind, ListItemProperties, ListItemSerializable

        item_d = d.get("item", {})
        props = item_d.get("properties", {})
        label = item_d.get("label", "")
        return SecretsAppMetadata(
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
class PasswordRepresentation:  # Nitrokey specific for format. Not defined in CXF
    item: "ListItem"
    pse: "PasswordSafeEntry"


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
    def use_passphrase(passphrase: str) -> CXFKey:
        passphrase = passphrase.strip().replace("-", "").replace(" ", "").upper()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\xc8*\xdf\xf6Ac\xb9|S'u\xb0\x98\x19b@",  # Random but constant salt
            info=b"nitrokey-export-encryption-key",
        )
        key = hkdf.derive(passphrase.encode())
        return CXFKey(_key=key)
