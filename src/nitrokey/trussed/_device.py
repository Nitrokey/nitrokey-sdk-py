# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import sys
from abc import abstractmethod
from typing import List, Optional, Sequence, TypeVar

from ._base import TrussedBase
from ._connection import App, Connection
from ._connection.ccid import list_ccid
from ._connection.ctaphid import list_ctaphid, open_ctaphid
from ._utils import Fido2Certs, Uuid

T = TypeVar("T", bound="TrussedDevice")

logger = logging.getLogger(__name__)


class TrussedDevice(TrussedBase):
    def __init__(self, connection: Connection, fido2_certs: Sequence[Fido2Certs]) -> None:
        vid_pid = connection.vid_pid()
        if vid_pid is not None:
            (vid, pid) = vid_pid
            self._validate_vid_pid(vid, pid)
        self._path = connection.path()
        self._logger = logger.getChild(connection.logger_name())

        self.connection = connection
        self.fido2_certs = fido2_certs

        from .admin_app import AdminApp

        self.admin = AdminApp(self)
        self.admin.status()

    @property
    def path(self) -> Optional[str]:
        return self._path

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
    def from_device(cls: type[T], connection: Connection) -> T: ...

    @classmethod
    def open(cls: type[T], path: str) -> Optional[T]:
        try:
            connection = open_ctaphid(path)
        except Exception:
            logger.warn(f"No CTAPHID device at path {path}", exc_info=sys.exc_info())
            return None
        try:
            return cls.from_device(connection)
        except ValueError:
            logger.warn(f"No Nitrokey device at path {path}", exc_info=sys.exc_info())
            return None

    @classmethod
    @abstractmethod
    def list_ccid(cls: type[T]) -> List[T]: ...

    @classmethod
    @abstractmethod
    def list_ctaphid(cls: type[T]) -> List[T]: ...

    @classmethod
    def _list_vid_pid(cls: type[T], vid: int, pid: int) -> List[T]:
        connections = list_ctaphid(vid, pid)
        return [cls.from_device(connection) for connection in connections]

    @classmethod
    def _list_pcsc_atr(cls: type[T], atr: List[int], exclusive: bool) -> List[T]:
        connections = list_ccid(atr, exclusive)
        return [cls.from_device(connection) for connection in connections]
