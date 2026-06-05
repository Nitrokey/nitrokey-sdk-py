from __future__ import annotations

import time
import uuid
from base64 import urlsafe_b64encode
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, TypeAlias, Any

from nitrokey.nk3.secrets_app_dataclasses import (
    Algorithm,
    Kind,
    ListItem,
    ListItemProperties,
    ListItemSerializable,
    PasswordSafeEntry,
)

# https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html

uint: TypeAlias = int
tstr: TypeAlias = str
b64url: TypeAlias = str
uri: TypeAlias = str


def _get_random_id() -> (
    b64url
):  # This function exists because CXF standard has no fixed method of assigning unique IDs
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


@dataclass
class Account:
    id: b64url
    username: tstr
    email: tstr
    collections: List[Collection]
    items: List[Item]
    fullName: Optional[tstr] = None
    extensions: Optional[List[Extension]] = None


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


@dataclass
class CredentialScope:
    urls: List[uri]
    androidApps: List[AndroidAppId]


@dataclass
class AndroidAppId:
    bundleId: tstr
    certificate: Optional[AndroidAppCertificateFingerprint] = None
    name: Optional[tstr] = None


@dataclass
class AndroidAppCertificateFingerprint:
    fingerprint: b64url
    hashAlg: HashAlgorithms


@dataclass
class Extension:
    name: tstr


@dataclass
class Credential:
    type: CredentialType = field(init=False)


class HashAlgorithms(str, Enum):
    Sha256 = "sha256"
    Sha512 = "sha512"


class CredentialType(str, Enum):
    ADDRESS = "address"
    API_KEY = "api-key"
    BASIC_AUTH = "basic-auth"
    CREDIT_CARD = "credit-card"
    CUSTOM_FIELDS = "custom-fields"
    DRIVERS_LICENSE = "drivers-license"
    FILE = "file"
    GENERATED_PASSWORD = "generated-password"
    PASSKEY = "passkey"
    TOTP = "totp"
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


@dataclass
class BasicAuth(Credential):
    urls: List[tstr]
    username: EditableField
    password: EditableField

    def __post_init__(self) -> None:
        self.type = CredentialType.BASIC_AUTH


@dataclass
class NitrokeyPasswordExtension(Extension):
    metadata: tstr
    item: ListItemSerializable

    name: tstr = field(init=False, default="Nitrokey Password Extension")


CXFPayload: TypeAlias = Header


class PasswordToCXF:
    @classmethod
    def password_to_item(cls, item: ListItem, pse: PasswordSafeEntry) -> Item:
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

    @classmethod
    def items_to_cxf(cls, items: List[Item]) -> CXFPayload:
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

    @classmethod
    def cxf_to_items(cls, payload: CXFPayload) -> List[Item]:
        return (
            payload.accounts[0].items
            if payload and payload.accounts and payload.accounts[0]
            else []
        )

    @classmethod
    def item_to_password(cls, item: Item) -> Tuple[ListItem | None, PasswordSafeEntry]:
        credid = item.title.encode() if item.title else b""
        cred = item.credentials[0] if item.credentials else None
        cred_basic_auth = cls.basic_auth_from_dict(asdict(cred)) if cred else None
        login = cred_basic_auth.username.value.encode() if cred_basic_auth else b""
        password = cred_basic_auth.password.value.encode() if cred_basic_auth else b""
        extension = item.extensions[0] if item and item.extensions else None
        metadata = extension.metadata.encode() if extension and type(extension) == NitrokeyPasswordExtension else b""
        list_item_serializable = extension.item if extension and type(extension) == NitrokeyPasswordExtension else None
        list_item = list_item_serializable.to_list_item() if list_item_serializable else None
        pse = PasswordSafeEntry(login, password, metadata)
        return list_item, pse

    @classmethod
    def basic_auth_from_dict(cls, d: dict[str, Any]) -> BasicAuth:
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


    @classmethod
    def nitrokey_password_extension_from_dict(cls, d: dict[str, Any]) -> NitrokeyPasswordExtension:
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
                    secret_encryption=props.get("secret_encryption", True), #Fail safe. Will be encrypted in case of errors
                    pws_data_exist=props.get("pws_data_exist", False),
                ),
            ),
        )

    @classmethod
    def cxf_from_dict(cls, d: dict[str, Any]) -> CXFPayload:
        accounts = []
        for acc in d.get("accounts", []):
            items = []
            for item_d in acc.get("items", []):
                credentials = []
                for cred in item_d.get("credentials", []):
                    credentials.append(
                        cls.basic_auth_from_dict(cred)
                    )
                extensions = []
                for ext in item_d.get("extensions", []):
                    list_item_d = ext.get("item", {})
                    props = list_item_d.get("properties", {})
                    label = list_item_d.get("label", "")
                    extensions.append(
                        cls.nitrokey_password_extension_from_dict(ext)
                    )
                items.append(
                    Item(
                        id=item_d["id"],
                        title=item_d["title"],
                        credentials=credentials,
                        creationAt=item_d.get("creationAt"),
                        modifiedAt=item_d.get("modifiedAt"),
                        subtitle=item_d.get("subtitle"),
                        favorite=item_d.get("favorite"),
                        scope=item_d.get("scope"),
                        tags=item_d.get("tags"),
                        extensions=extensions if extensions else [], 
                    )
                )
            accounts.append(
                Account(
                    id=acc["id"],
                    username=acc.get("username", ""),
                    email=acc.get("email", ""),
                    collections=acc.get("collections", []),
                    items=items,
                    fullName=acc.get("fullName"),
                    extensions=acc.get("extensions"),
                )
            )
        version = d.get("version", {})
        return Header(
            version=Version(version.get("major", 1), version.get("minor", 0)),
            exporterRpId=d.get("exporterRpId", ""),
            exporterDisplayName=d.get("exporterDisplayName", ""),
            timestamp=d.get("timestamp", 0),
            accounts=accounts,
        )


# TODO other credentials like Credit Card and Passkey Dict
