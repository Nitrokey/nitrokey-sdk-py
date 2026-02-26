import typing
from datetime import datetime, timedelta
from typing import Optional, Sequence

from .._exceptions import CcidErrorCode, ConnectionError, DeviceError
from .._utils import Iso7816Apdu
from . import HAS_CCID_SUPPORT, App, Connection

if HAS_CCID_SUPPORT:
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
    from smartcard.ExclusiveTransmitCardConnection import ExclusiveTransmitCardConnection
    from smartcard.System import readers

    class CcidConnection(Connection):
        def __init__(
            self, card: ExclusiveConnectCardConnection | ExclusiveTransmitCardConnection
        ) -> None:
            self.card = card
            self._secrets_pin_cache: datetime | None = None

        def logger_name(self) -> str:
            return str(self.card.getReader())

        def close(self) -> None:
            self.card.disconnect()
            self.card.release()

        def wink(self) -> None:
            pass

        def _transmit(self, data: bytes | Iso7816Apdu) -> tuple[bytes, int, int]:
            if isinstance(data, Iso7816Apdu):
                data = data.to_bytes()
            try:
                data, sw1, sw2 = self.card.transmit(list(data))
                return bytes(data), sw1, sw2
            except CardConnectionException as e:
                raise ConnectionError() from e

        def _select(self, app: App) -> None:
            select = bytes([0x00, 0xA4, 0x04, 0x00, len(app.aid())]) + app.aid()
            _, sw1, sw2 = self._transmit(select)
            while True:
                if sw1 == 0x61:
                    _, sw1, sw2 = self._transmit(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2))
                    continue
                break
            if sw1 != 0x90 or sw2 != 0x00:
                raise DeviceError(CcidErrorCode(sw1=sw1, sw2=sw2))

        def _call(self, app: App, command: bytes | Iso7816Apdu) -> bytes:
            # SELECT resets the PIN verification status of secrets-app, so we skip the next select
            # within 100 ms of a PIN verification
            skip_perform_select = (
                self._secrets_pin_cache
                and (datetime.now() - self._secrets_pin_cache) < timedelta(milliseconds=100)
                and app == App.SECRETS
            )
            if not skip_perform_select:
                self._select(app)

            accumulator, sw1, sw2 = self._transmit(command)
            while True:
                if sw1 == 0x61:
                    data, sw1, sw2 = self._transmit(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2))
                    accumulator += data
                    continue
                break

            if app == App.SECRETS:
                accumulator = bytes([sw1, sw2]) + accumulator
                # Let the secret app handle the error
                return accumulator

            if sw1 != 0x90 or sw2 != 0x00:
                raise DeviceError(CcidErrorCode(sw1=sw1, sw2=sw2))

            return accumulator

        def call_admin_app_legacy(
            self, command: int, data: bytes, response_len: Optional[int]
        ) -> bytes:
            p1 = 0
            if len(data) >= 1:
                p1 = data[0]
            apdu = Iso7816Apdu(0x00, command, 0, p1, data, le=response_len)
            return self._call(App.ADMIN, apdu)

        def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes:
            self._select(app)
            command: bytes | Iso7816Apdu
            if app == App.ADMIN or app == App.PROVISIONER:
                command = Iso7816Apdu(0x00, data[0], 0, 0, data[1:], le=response_len)
            elif app == App.SECRETS:
                command = data
            else:
                typing.assert_never(app)
            return self._call(app, command)

        def set_secrets_pin_cache(self) -> None:
            self._secrets_pin_cache = datetime.now()

    def _list(atr: list[int], exclusive: bool) -> list[CcidConnection]:
        connections = []

        for r in readers():
            raw_connection = r.createConnection()
            connection: ExclusiveConnectCardConnection | ExclusiveTransmitCardConnection
            if exclusive:
                connection = ExclusiveConnectCardConnection(raw_connection)
            else:
                connection = ExclusiveTransmitCardConnection(raw_connection)

            try:
                connection.connect()
            except NoCardException:
                continue
            except CardConnectionException:
                continue
            if atr != connection.getATR():
                connection.disconnect()
                connection.release()
                continue
            connections.append(CcidConnection(connection))

        return connections


def list_ccid(atr: list[int], exclusive: bool) -> Sequence[Connection]:
    if HAS_CCID_SUPPORT:
        return _list(atr, exclusive)
    return []
