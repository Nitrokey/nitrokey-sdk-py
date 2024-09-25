"""
Oath Authenticator client

Used through CTAPHID transport, via the custom vendor command.
Can be used directly over CCID as well.
"""

import dataclasses
import hmac
import logging
import typing
from enum import Enum, IntEnum
from hashlib import pbkdf2_hmac
from secrets import token_bytes
from struct import pack
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

import tlv8
from semver.version import Version

from nitrokey.nk3 import NK3
from nitrokey.trussed import App

LogFn = Callable[[str], Any]
WriteCorpusFn = Callable[[typing.Union["Instruction", "CCIDInstruction"], bytes], Any]


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
    def get_type_name(cls, x: typing.Any) -> str:
        return str(x).split(".")[-1]

    def __str__(self) -> str:
        return (
            f"{self.label.decode()}"
            f"\t{self.get_type_name(self.kind)}/{self.get_type_name(self.algorithm)}"
            f"\t{self.properties}"
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
            (
                tlv8.Entry(Tag.PwsLogin.value, self.login)
                if self.login is not None
                else None
            ),
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


class Kind(Enum):
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


class Algorithm(Enum):
    Sha1 = 0x01
    Sha256 = 0x02
    Sha512 = 0x03


ALGORITHM_TO_KIND = {
    "SHA1": Algorithm.Sha1,
    "SHA256": Algorithm.Sha256,
}


class SecretsApp:
    """
    This is a Secrets App client
    https://github.com/Nitrokey/trussed-secrets-app
    """

    log: logging.Logger
    logfn: LogFn
    dev: NK3
    write_corpus_fn: Optional[WriteCorpusFn]
    _cache_status: Optional[SelectResponse]
    _metadata: dict[Any, Any]

    def __init__(self, dev: NK3, logfn: Optional[LogFn] = None):
        self._cache_status = None
        self.write_corpus_fn = None
        self.log = logging.getLogger("otpapp")
        if logfn is not None:
            self.logfn = logfn
        else:
            self.logfn = self.log.info
        self.dev = dev
        self._metadata = {}

    def _custom_encode(
        self, structure: Optional[Sequence[Union[tlv8.Entry, RawBytes, None]]] = None
    ) -> bytes:
        if not structure:
            return b""

        def transform(d: Union[tlv8.Entry, RawBytes, None]) -> bytes:
            if not d:
                return b""
            if isinstance(d, RawBytes):
                res = bytes(d.data)
                # self.logfn(f"Transforming {d} -> {res.hex()}")
                return res
            elif isinstance(d, tlv8.Entry):
                res = tlv8.encode([d])
                # self.logfn(f"Transforming {d} -> {res.hex()}")
                return res
            return b""

        encoded_structure = b"".join(map(transform, structure))
        return encoded_structure

    def _send_receive(
        self,
        ins: typing.Union[Instruction, CCIDInstruction],
        structure: Optional[Sequence[Union[tlv8.Entry, RawBytes, None]]] = None,
    ) -> bytes:
        encoded_structure = self._custom_encode(structure)
        ins_b, p1, p2 = self._encode_command(ins)
        bytes_data = _iso7816_compose(ins_b, p1, p2, data=encoded_structure)
        if self.write_corpus_fn:
            self.write_corpus_fn(ins, bytes_data)
        return self._send_receive_inner(bytes_data, log_info=f"{ins}")

    def _send_receive_inner(self, data: bytes, log_info: str = "") -> bytes:
        self.logfn(f"Sending {log_info if log_info else ''} (data: {len(data)} bytes)")

        try:
            result = self.dev._call_app(App.SECRETS, data=data)
        except Exception as e:
            self.logfn(f"Got exception: {e}")
            raise

        status_bytes, result = result[:2], result[2:]
        self.logfn(f"Received [{status_bytes.hex()}] (data: {len(result)} bytes)")

        log_multipacket = False
        data_final = result
        MORE_DATA_STATUS_BYTE = 0x61
        while status_bytes[0] == MORE_DATA_STATUS_BYTE:
            if log_multipacket:
                self.logfn(f"Got RemainingData status: [{status_bytes.hex()}]")
            log_multipacket = True
            ins_b, p1, p2 = self._encode_command(Instruction.SendRemaining)
            bytes_data = _iso7816_compose(ins_b, p1, p2)
            try:
                result = self.dev._call_app(App.SECRETS, data=bytes_data)
            except Exception as e:
                self.logfn(f"Got exception: {e}")
                raise
            # Data order is different here than in APDU - SW is first, then the data if any
            status_bytes, result = result[:2], result[2:]
            self.logfn(f"Received [{status_bytes.hex()}] (data: {len(result)} bytes)")
            if status_bytes[0] in [0x90, MORE_DATA_STATUS_BYTE]:
                data_final += result

        if status_bytes != b"\x90\x00" and status_bytes[0] != MORE_DATA_STATUS_BYTE:
            raise SecretsAppException(status_bytes.hex(), "Received error")

        if log_multipacket:
            self.logfn(
                f"Received final data: [{status_bytes.hex()}] (data: {len(data_final)} bytes)"
            )

        if data_final:
            try:
                tlv8.decode(data_final)
                self.logfn("TLV-decoding of data successful")
            except Exception:
                self.logfn("TLV-decoding of data failed")
                pass

        return data_final

    @classmethod
    def _encode_command(
        cls, command: typing.Union[Instruction, CCIDInstruction]
    ) -> bytes:
        p1 = 0
        p2 = 0
        if command == Instruction.Reset:
            p1 = 0xDE
            p2 = 0xAD
        elif command == CCIDInstruction.Select:
            p1 = 0x04
            p2 = 0x00
        elif command == Instruction.Calculate or command == Instruction.CalculateAll:
            p1 = 0x00
            p2 = 0x01
        return bytes([command.value, p1, p2])

    def reset(self) -> None:
        """
        Remove all credentials from the database
        """
        self.logfn("Executing reset")
        self._send_receive(Instruction.Reset)

    def list(self, extended: bool = False) -> list[Union[Tuple[bytes, bytes], bytes]]:
        """
        Return a list of the registered credentials
        :return: List of bytestrings, or tuple of bytestrings, if "extended" switch is provided
        @deprecated
        """
        raw_res = self._send_receive(Instruction.List)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        res: list[Union[Tuple[bytes, bytes], bytes]] = []
        for e in resd:
            # e: tlv8.Entry
            if extended:
                res.append((e.data[0], e.data[1:]))
            else:
                res.append(e.data[1:])
        return res

    def list_with_properties(self, version: int = 1) -> List[ListItem]:
        """
        Return a list of the registered credentials with properties
        :return: List of ListItems
        """
        data = [RawBytes([version])]
        raw_res = self._send_receive(Instruction.List, data)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        res = []
        for e in resd:
            # e: tlv8.Entry
            if self.feature_extended_list():
                attribute_byte, label, properties = e.data[0], e.data[1:-1], e.data[-1]
            else:
                attribute_byte, label, properties = e.data[0], e.data[1:], 0
            res.append(
                ListItem(
                    kind=Kind.from_attribute_byte_type(attribute_byte),
                    algorithm=Algorithm.Sha1,
                    label=label,
                    properties=ListItemProperties.from_byte(properties),
                )
            )
        return res

    def get_credential(self, cred_id: bytes) -> PasswordSafeEntry:
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
        ]
        raw_res = self._send_receive(Instruction.GetCredential, structure=structure)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        res = {}
        self.logfn("Per field dissection:")
        for e in resd:
            # e: tlv8.Entry
            res[e.type_id] = e.data
            self.logfn(f"{hex(e.type_id)} {hex(len(e.data))}")
        p = PasswordSafeEntry(
            login=res.get(Tag.PwsLogin.value),
            password=res.get(Tag.PwsPassword.value),
            metadata=res.get(Tag.PwsMetadata.value),
            name=res.get(Tag.CredentialId.value),
            properties=res.get(Tag.Properties.value),
        )
        p.properties = p.properties.hex().encode() if p.properties else None
        return p

    def rename_credential(self, cred_id: bytes, new_name: bytes) -> None:
        """
        Rename credential.
        An alias for the update_credential() call.
        @param cred_id: The credential ID to modify
        @param new_name: New ID for the credential
        """
        return self.update_credential(cred_id, new_name)

    def update_credential(
        self,
        cred_id: bytes,
        new_name: Optional[bytes] = None,
        login: Optional[bytes] = None,
        password: Optional[bytes] = None,
        metadata: Optional[bytes] = None,
        touch_button: Optional[bool] = None,
    ) -> None:
        """
        Update credential fields - name, attributes, and PWS fields.
        Unpopulated fields will not be encoded and used during the update process
        (won't change the current value).
        @param cred_id: The credential ID to modify
        @param new_name: New ID for the credential
        @param login: New login field content
        @param password: New password field content
        @param metadata: New metadata field content
        @param touch_button: Set if the touch button use should be required
        """
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
            tlv8.Entry(Tag.CredentialId.value, new_name) if new_name else None,
            (
                self.encode_properties_to_send(touch_button, False, tlv=True)
                if touch_button is not None
                else None
            ),
            tlv8.Entry(Tag.PwsLogin.value, login) if login is not None else None,
            (
                tlv8.Entry(Tag.PwsPassword.value, password)
                if password is not None
                else None
            ),
            (
                tlv8.Entry(Tag.PwsMetadata.value, metadata)
                if metadata is not None
                else None
            ),
        ]
        structure = list(filter(lambda x: x is not None, structure))
        self._send_receive(Instruction.UpdateCredential, structure=structure)

    def delete(self, cred_id: bytes) -> None:
        """
        Delete credential with the given id. Does not fail, if the given credential does not exist.
        :param credid: Credential ID
        """
        self.logfn(f"Sending delete request for {cred_id!r}")
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
        ]
        self._send_receive(Instruction.Delete, structure)

    def register_yk_hmac(self, slot: int, secret: bytes) -> None:
        """
        Register a Yubikey-compatible challenge-response slot.
        @param slot: challenge-response slot
        @param secret: the secret
        """
        assert slot in [1, 2]
        self.register(
            f"HmacSlot{slot}".encode(),
            secret,
            kind=Kind.Hmac,
        )

    def register(
        self,
        credid: bytes,
        secret: bytes = b"0" * 20,
        digits: int = 6,
        kind: Kind = Kind.NotSet,
        algo: Algorithm = Algorithm.Sha1,
        initial_counter_value: int = 0,
        touch_button_required: bool = False,
        pin_based_encryption: bool = False,
        login: Optional[bytes] = None,
        password: Optional[bytes] = None,
        metadata: Optional[bytes] = None,
    ) -> None:
        """
        Register new OTP Credential
        :param credid: Credential ID
        :param secret: The shared key
        :param digits: Digits of the produced code
        :param kind: OTP variant - HOTP or TOTP
        :param algo: The hash algorithm to use - SHA1, SHA256 or SHA512
        :param initial_counter_value: The counter's initial value for the HOTP Credential (HOTP only)
        :param touch_button_required: User Presence confirmation is required to use this Credential
        :param pin_based_encryption: User preference for additional PIN-based encryption
        :param login: Login field for Password Safe
        :param password: Password field for Password Safe
        :param metadata: Metadata field for Password Safe
        :return: None
        """
        if initial_counter_value > 0xFFFFFFFF:
            raise Exception("Initial counter value must be smaller than 4 bytes")
        if algo == Algorithm.Sha512:
            raise NotImplementedError(
                "This hash algorithm is not supported by the firmware"
            )

        self.logfn(
            f"Setting new credential: {credid!r}, {kind}, {algo}, counter: {initial_counter_value}, {touch_button_required=}, {pin_based_encryption=}"
        )

        structure: list[Optional[Union[tlv8.Entry, RawBytes]]] = [
            tlv8.Entry(Tag.CredentialId.value, credid),
            # header (2) + secret (N)
            tlv8.Entry(
                Tag.Key.value, bytes([kind.value | algo.value, digits]) + secret
            ),
            self.encode_properties_to_send(touch_button_required, pin_based_encryption),
            (
                tlv8.Entry(
                    Tag.InitialCounter.value, initial_counter_value.to_bytes(4, "big")
                )
                if kind in [Kind.Hotp, Kind.HotpReverse]
                else None
            ),
            *PasswordSafeEntry(
                name=credid, login=login, password=password, metadata=metadata
            ).tlv_encode(),
        ]
        entries = [x for x in structure if x is not None]
        self._send_receive(Instruction.Put, entries)

    @classmethod
    def encode_properties_to_send(
        cls, touch_button_required: bool, pin_based_encryption: bool, tlv: bool = False
    ) -> RawBytes:
        """
        Encode properties structure into a single byte
        @param touch_button_required: whether the touch button use is required
        @param pin_based_encryption: whether the PIN-encryption is requested (only during registration)
        @param tlv: set True, if this should be encoded as TLV, as opposed to the default "TV", w/o L
        """
        structure = [
            Tag.Properties.value,
            1 if tlv else None,
            (0x02 if touch_button_required else 0x00)
            | (0x04 if pin_based_encryption else 0x00),
        ]
        structure = list(filter(lambda x: x is not None, structure))
        return RawBytes(structure)  # type: ignore[arg-type]

    def calculate(self, cred_id: bytes, challenge: Optional[int] = None) -> bytes:
        """
        Calculate the OTP code for the credential named `cred_id`, and with challenge `challenge`.

        :param cred_id: The name of the credential
        :param challenge: Challenge for the calculations (TOTP only).
            Should be equal to: timestamp/period. The commonly used period value is 30.
        :return: OTP code as a byte string
        """
        if challenge is None:
            challenge = 0
        self.logfn(
            f"Sending calculate request for {cred_id!r} and challenge {challenge!r}"
        )
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
            tlv8.Entry(Tag.Challenge.value, pack(">Q", challenge)),
        ]
        res = self._send_receive(Instruction.Calculate, structure=structure)
        header = res[:2]
        assert header.hex() in ["7605", "7700"]
        digits = res[2]
        digest = res[3:]
        truncated_code = int.from_bytes(digest, byteorder="big", signed=False)
        code = (truncated_code & 0x7FFFFFFF) % pow(10, digits)
        codes: bytes = str(code).zfill(digits).encode()
        self.logfn(
            f"Received digest: {digest.hex()}, for challenge {challenge}, digits: {digits}, truncated code: {truncated_code!r}, pre-code: {code!r},"
            f" final code: {codes!r}"
        )
        return codes

    def verify_code(self, cred_id: bytes, code: int) -> bool:
        """
        Proceed with the incoming OTP code verification (aka reverse HOTP).
        :param cred_id: The name of the credential
        :param code: The HOTP code to verify. u32 representation.
        :return: fails with OTPAppException error; returns True if code matches the value calculated internally.
        """
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
            tlv8.Entry(Tag.Response.value, pack(">L", code)),
        ]
        self._send_receive(Instruction.VerifyCode, structure=structure)
        return True

    def set_code(self, passphrase: str) -> None:
        """
        Set the code with the defaults as suggested in the protocol specification:
        - https://developers.yubico.com/OATH/YKOATH_Protocol.html
        """
        secret = self.get_secret_for_passphrase(passphrase)
        challenge = token_bytes(8)
        response = self.get_response_for_secret(challenge, secret)
        self.set_code_raw(secret, challenge, response)

    def get_secret_for_passphrase(self, passphrase: str) -> bytes:
        #   secret = PBKDF2(USER_PASSPHRASE, DEVICEID, 1000)[:16]
        # salt = self.select().name
        # FIXME use the proper SALT
        # FIXME USB/IP Sim changes its ID after each reset and after setting the code (??)
        salt = b"a" * 8
        secret = pbkdf2_hmac("sha256", passphrase.encode(), salt, 1000)
        return secret[:16]

    def get_response_for_secret(self, challenge: bytes, secret: bytes) -> bytes:
        response = hmac.HMAC(key=secret, msg=challenge, digestmod="sha1").digest()
        return response

    def set_code_raw(self, key: bytes, challenge: bytes, response: bytes) -> None:
        """
        Set or clear the passphrase used to authenticate to other commands. Raw interface.
        :param key: User passphrase processed through PBKDF2(ID,1000), and limited to the first 16 bytes.
        :param challenge: The current challenge taken from the SELECT command.
        :param response: The data calculated on the client, as a proof of a correct setup.
        """
        algo = Algorithm.Sha1.value
        kind = Kind.Totp.value
        structure = [
            tlv8.Entry(Tag.Key.value, bytes([kind | algo]) + key),
            tlv8.Entry(Tag.Challenge.value, challenge),
            tlv8.Entry(Tag.Response.value, response),
        ]
        self._send_receive(Instruction.SetCode, structure=structure)

    def clear_code(self) -> None:
        """
        Clear the passphrase used to authenticate to other commands.
        """
        structure = [
            tlv8.Entry(Tag.Key.value, bytes()),
        ]
        self._send_receive(Instruction.SetCode, structure=structure)

    def validate(self, passphrase: str) -> None:
        """
        Authenticate using a passphrase
        """
        stat = self.select()
        if stat.algorithm != bytes([Algorithm.Sha1.value]):
            raise RuntimeError("For the authentication only SHA1 is supported")
        challenge = stat.challenge
        if challenge is None:
            # This should never happen
            raise RuntimeError(
                "There is some problem with the device's state. Challenge is not available."
            )
        secret = self.get_secret_for_passphrase(passphrase)
        response = self.get_response_for_secret(challenge, secret)
        self.validate_raw(challenge, response)

    def validate_raw(self, challenge: bytes, response: bytes) -> bytes:
        """
        Authenticate using a passphrase. Raw interface.
        :param challenge: The current challenge taken from the SELECT command.
        :param response: The response calculated against the challenge and the secret
        """
        structure = [
            tlv8.Entry(Tag.Response.value, response),
            tlv8.Entry(Tag.Challenge.value, challenge),
        ]
        raw_res = self._send_receive(Instruction.Validate, structure=structure)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        return resd.data  # type: ignore[return-value]

    def select(self) -> SelectResponse:
        """
        Execute SELECT command, which returns details about the device,
        including the challenge needed for the authentication.
        :return SelectResponse Status structure. Challenge and Algorithm fields are None, if the passphrase is not set.
        """
        AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
        structure = [RawBytes(AID)]
        raw_res = self._send_receive(CCIDInstruction.Select, structure=structure)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        rd = {}
        for e in resd:
            # e: tlv8.Entry
            rd[e.type_id] = e.data

        counter = rd.get(Tag.PINCounter.value)
        if counter is not None:
            # counter is passed as 1B array - convert it to int
            counter = int.from_bytes(counter, byteorder="big")

        r = SelectResponse(
            version=rd.get(Tag.Version.value),
            pin_attempt_counter=counter,
            salt=rd.get(Tag.CredentialId.value),
            challenge=rd.get(Tag.Challenge.value),
            algorithm=rd.get(Tag.Algorithm.value),
            serial_number=rd.get(Tag.SerialNumber.value),
        )
        return r

    def set_pin_raw(self, password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.SetPIN, structure=structure)

    def change_pin_raw(self, password: str, new_password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
            tlv8.Entry(Tag.NewPassword.value, new_password),
        ]
        self._send_receive(Instruction.ChangePIN, structure=structure)

    def verify_pin_raw(self, password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.VerifyPIN, structure=structure)

    def get_feature_status_cached(self) -> SelectResponse:
        self._cache_status = (
            self.select() if self._cache_status is None else self._cache_status
        )
        return self._cache_status

    def feature_active_PIN_authentication(self) -> bool:
        return self.get_feature_status_cached().challenge is None

    def feature_old_application_version(self) -> bool:
        v = self.get_feature_status_cached().version
        return b"444" == v

    def feature_challenge_response_support(self) -> bool:
        if self.get_feature_status_cached().challenge is not None:
            return True
        return False

    def feature_pws_support(self) -> bool:
        return self._semver_equal_or_newer("4.11.0")

    def feature_extended_list(self) -> bool:
        return self._semver_equal_or_newer("4.11.0")

    def protocol_v2_confirm_all_requests_with_pin(self) -> bool:
        # 4.7.0 version requires providing PIN each request
        return self.get_feature_status_cached().version_str() == "4.7.0"

    def protocol_v3_separate_pin_and_no_pin_space(self) -> bool:
        # 4.10.0 makes logical separation between the PIN-encrypted and non-PIN encrypted spaces, except
        # for overwriting the credentials
        return self._semver_equal_or_newer("4.10.0")

    def is_pin_healthy(self) -> bool:
        counter = self.select().pin_attempt_counter
        return not (counter is None or counter == 0)

    def _semver_equal_or_newer(self, required_version: str) -> bool:
        current = Version.parse(self.get_feature_status_cached().version_str())
        semver_req_version = Version.parse(required_version)
        return current >= semver_req_version


def _iso7816_compose(
    ins: int,
    p1: int,
    p2: int,
    data: bytes = b"",
) -> bytes:
    cls = 0
    data_len = len(data)
    if data_len == 0:
        return pack(">BBBB", cls, ins, p1, p2)
    else:
        if data_len <= 255:
            return pack(">BBBBB", cls, ins, p1, p2, data_len) + data
        else:
            return pack(">BBBBBH", cls, ins, p1, p2, 0, data_len) + data
