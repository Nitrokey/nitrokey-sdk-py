# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import typing
from abc import abstractmethod
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Self

from fido2.hid import CtapHidDevice

from ._base import Model, TrussedBase
from ._connection import App, Connection, DeviceConnectionInfo, Transport, open_connection
from ._utils import Fido2Certs, Uuid

logger = logging.getLogger(__name__)


@dataclass(kw_only=True, frozen=True)
class DeviceInfo:
    model: Model
    transport: Transport
    connection: DeviceConnectionInfo

    @staticmethod
    def _list(transport: Transport | None, models: Sequence[Model]) -> list["DeviceInfo"]:
        from . import DEFAULT_TRANSPORT

        if transport is None:
            transport = DEFAULT_TRANSPORT

        if transport == Transport.CCID:
            return DeviceInfo._list_ccid(models)

        if transport == Transport.CTAPHID:
            return DeviceInfo._list_ctaphid(models)

        typing.assert_never(transport)

    @staticmethod
    def _list_ccid(models: Sequence[Model]) -> list["DeviceInfo"]:
        # TODO: do we even need to check the ATR?

        from ._connection.ccid import list_ccid

        connections = list_ccid(
            filter_atr=frozenset(model._device_atr for model in models),
            filter_reader=frozenset(model.name for model in models),
            exclusive=True,
        )
        infos = []
        for connection in connections:
            matched_models = [model for model in models if model.name in connection.reader]

            if len(matched_models) > 1:
                raise Exception(
                    f"Multiple models match reader '{connection.reader}': {matched_models}"
                )
            if len(matched_models) == 0:
                raise Exception(f"No model matches reader '{connection.reader}'")

            infos.append(
                DeviceInfo(model=matched_models[0], transport=Transport.CCID, connection=connection)
            )
        return infos

    @staticmethod
    def _list_ctaphid(models: Sequence[Model]) -> list["DeviceInfo"]:
        from ._connection.ctaphid import list_ctaphid

        vid_pid_to_model = {model._device_vid_pid: model for model in models}
        connections = list_ctaphid(filter=frozenset(vid_pid_to_model))
        return [
            DeviceInfo(
                model=vid_pid_to_model[connection.vid_pid],
                transport=Transport.CTAPHID,
                connection=connection,
            )
            for connection in connections
        ]


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
    def pid(self) -> int:
        return self.model._device_vid_pid.pid

    @property
    def name(self) -> str:
        return self.model.name

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def path(self) -> str | None:
        return self._path

    def ctaphid_device(self) -> CtapHidDevice | None:
        return self.connection.ctaphid_device()

    def reboot(self) -> bool:
        from .admin_app import BootMode

        return self.admin.reboot(BootMode.FIRMWARE)

    def uuid(self) -> Uuid | None:
        return self.admin.uuid()

    def wink(self) -> None:
        self.connection.wink()

    def _call_admin_legacy(
        self, command: int, command_name: str, response_len: int | None = None, data: bytes = b""
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

    def _call_app(self, app: App, response_len: int | None = None, data: bytes = b"") -> bytes:
        response = self.connection.call_app(app, data, response_len)

        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {app.name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    @classmethod
    @abstractmethod
    def _from_connection(cls, connection: Connection) -> Self: ...

    @classmethod
    @contextmanager
    def _open(cls, info: DeviceInfo) -> Iterator[Self]:
        model = cls._model()
        if info.model != model:
            raise Exception("Cannot open {info.model} device as {model}")
        with open_connection(info.connection) as connection:
            yield cls._from_connection(connection)

    @classmethod
    def _list(cls, transport: Transport | None) -> Sequence[DeviceInfo]:
        return DeviceInfo._list(transport=transport, models=[cls._model()])

    @staticmethod
    @abstractmethod
    def _model() -> Model: ...
