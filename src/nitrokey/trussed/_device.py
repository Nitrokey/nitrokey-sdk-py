# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
from abc import abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional, Self, Sequence, TypeVar

from fido2.hid import CtapHidDevice

from . import DEFAULT_TRANSPORT
from ._base import Model, TrussedBase
from ._connection import (
    App,
    Connection,
    ConnectionInfo,
    Transport,
    VidPid,
    list_connections,
    open_connection,
)
from ._utils import Fido2Certs, Uuid

T = TypeVar("T", bound="TrussedDevice")

logger = logging.getLogger(__name__)


@dataclass(kw_only=True, frozen=True)
class DeviceInfo:
    model: Model
    connection: ConnectionInfo


class TrussedDevice(TrussedBase):
    def __init__(self, connection: Connection, fido2_certs: Sequence[Fido2Certs]) -> None:
        vid_pid = connection.vid_pid()
        if vid_pid is not None:
            self._validate_vid_pid(vid_pid.vid, vid_pid.pid)
        self._transport = connection.transport()
        self._path = connection.path()
        self._logger = logger.getChild(connection.logger_name())

        self.connection = connection
        self.fido2_certs = fido2_certs

        from .admin_app import AdminApp

        self.admin = AdminApp(self)
        self.admin.status()

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def path(self) -> Optional[str]:
        return self._path

    def ctaphid_device(self) -> CtapHidDevice | None:
        return self.connection.ctaphid_device()

    def close(self) -> None:
        self.connection.close()

    def reboot(self) -> bool:
        from .admin_app import BootMode

        return self.admin.reboot(BootMode.FIRMWARE)

    def uuid(self) -> Optional[Uuid]:
        return self.admin.uuid()

    def wink(self) -> None:
        self.connection.wink()

    def _call_admin_legacy(
        self, command: int, command_name: str, response_len: Optional[int] = None, data: bytes = b""
    ) -> bytes:
        response = self.connection.call_admin_app_legacy(
            command=command, data=data, response_len=response_len
        )

        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {command_name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    def _call_app(self, app: App, response_len: Optional[int] = None, data: bytes = b"") -> bytes:
        response = self.connection.call_app(app, data, response_len)

        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {app.name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    @classmethod
    @abstractmethod
    def from_connection(cls: type[T], connection: Connection) -> T: ...

    @classmethod
    @contextmanager
    def open(cls, info: DeviceInfo) -> Iterator[Self]:
        model = cls._model()
        if info.model != model:
            raise Exception("Cannot open {info.model} device as {model}")
        with open_connection(info.connection) as connection:
            yield cls.from_connection(connection)

    @classmethod
    def list(cls, *, transport: Transport | None = None) -> Sequence[DeviceInfo]:
        if transport is None:
            transport = DEFAULT_TRANSPORT
        connections = list_connections(
            transport, vid_pid=cls._expected_vid_pid(), atr=cls._expected_atr()
        )
        model = cls._model()
        return [DeviceInfo(model=model, connection=connection) for connection in connections]

    @staticmethod
    @abstractmethod
    def _model() -> Model: ...

    @staticmethod
    @abstractmethod
    def _expected_vid_pid() -> VidPid: ...

    @staticmethod
    @abstractmethod
    def _expected_atr() -> bytes: ...
