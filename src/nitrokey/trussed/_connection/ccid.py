from typing import TYPE_CHECKING, Optional, Sequence

from .._utils import Iso7816Apdu
from . import HAS_CCID_SUPPORT, App, Connection


class PcscError(Exception):
    def __init__(self, sw1: int, sw2: int) -> None:
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f"Got error code {bytes([sw1, sw2]).hex()}")


if HAS_CCID_SUPPORT:
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
    from smartcard.ExclusiveTransmitCardConnection import ExclusiveTransmitCardConnection
    from smartcard.System import readers

    class CcidConnection:
        def __init__(
            self, card: ExclusiveConnectCardConnection | ExclusiveTransmitCardConnection
        ) -> None:
            self.card = card

        def path(self) -> Optional[str]:
            return None

        def logger_name(self) -> str:
            return str(self.card.getReader())

        def vid_pid(self) -> Optional[tuple[int, int]]:
            return None

        def close(self) -> None:
            self.card.disconnect()
            self.card.release()

        def wink(self) -> None:
            pass

        def call_admin_app_legacy(
            self, command: int, data: bytes, response_len: Optional[int]
        ) -> bytes:
            app = App.ADMIN
            select = bytes([0x00, 0xA4, 0x04, 0x00, len(app.aid())]) + app.aid()
            _, sw1, sw2 = self.card.transmit(list(select))
            while True:
                if sw1 == 0x61:
                    _, sw1, sw2 = self.card.transmit(
                        list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                    )
                    continue
                break
            if sw1 != 0x90 or sw2 != 0x00:
                raise PcscError(sw1, sw2)
            p1 = 0
            if len(data) >= 1:
                p1 = data[0]
            apdu = Iso7816Apdu(0x00, command, 0, p1, data, le=response_len)
            data, sw1, sw2 = self.card.transmit(list(apdu.to_bytes()))
            accumulator = bytes(data)
            while True:
                if sw1 == 0x61:
                    data, sw1, sw2 = self.card.transmit(
                        list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                    )
                    accumulator += bytes(data)
                    continue
                break
            if sw1 != 0x90 or sw2 != 0x00:
                raise PcscError(sw1, sw2)

            return accumulator

        def call_app(self, app: App, data: bytes, response_len: Optional[int]) -> bytes:
            select = bytes([0x00, 0xA4, 0x04, 0x00, len(app.aid())]) + app.aid()
            tmpbytes, sw1, sw2 = self.card.transmit(list(select))
            while True:
                if sw1 == 0x61:
                    _, sw1, sw2 = self.card.transmit(
                        list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                    )
                    continue
                break
            if sw1 != 0x90 or sw2 != 0x00:
                raise PcscError(sw1, sw2)

            command = None
            if app == App.ADMIN or app == App.PROVISIONER:
                command = list(
                    Iso7816Apdu(0x00, data[0], 0, 0, data[1:], le=response_len).to_bytes()
                )
            elif app == App.SECRETS:
                command = list(data)
            else:
                # TODO: use typing.assert_never
                raise ValueError(app)

            data, sw1, sw2 = self.card.transmit(command)
            accumulator = bytes(data)
            while True:
                if sw1 == 0x61:
                    data, sw1, sw2 = self.card.transmit(
                        list(Iso7816Apdu(0x00, 0xC0, 0, 0, None, sw2).to_bytes())
                    )
                    accumulator += bytes(data)
                    continue
                break

            if app == App.SECRETS:
                accumulator = bytes([sw1, sw2]) + accumulator
                # Let the secret app handle the error
                return accumulator

            if sw1 != 0x90 or sw2 != 0x00:
                raise PcscError(sw1, sw2)

            return accumulator

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

    if TYPE_CHECKING:
        _: type[Connection] = CcidConnection


def list_ccid(atr: list[int], exclusive: bool) -> Sequence[Connection]:
    if HAS_CCID_SUPPORT:
        return _list(atr, exclusive)
    return []
