# Copyright 2026 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Any

try:
    from smartcard.ExclusiveConnectCardConnection import (
        ExclusiveConnectCardConnection as ExclusiveConnectCardConnection,
    )
    from smartcard.ExclusiveTransmitCardConnection import (
        ExclusiveTransmitCardConnection as ExclusiveTransmitCardConnection,
    )
except ModuleNotFoundError:

    class ExclusiveTransmitCardConnection:  # type: ignore[no-redef]
        def __init__(self, connection: Any) -> None:
            raise NotImplementedError()

        def connect(self) -> None:
            raise NotImplementedError()

        def disconnect(self) -> None:
            raise NotImplementedError()

        def release(self) -> None:
            raise NotImplementedError()

        def getATR(self) -> list[int]:
            raise NotImplementedError()

        def transmit(self, data: list[int]) -> tuple[bytes, int, int]:
            raise NotImplementedError()

        def lock(self) -> None:
            raise NotImplementedError()

        def unlock(self) -> None:
            raise NotImplementedError()

        def getReader(self) -> str:
            raise NotImplementedError()

    class ExclusiveConnectCardConnection:  # type: ignore[no-redef]
        def __init__(self, connection: Any) -> None:
            raise NotImplementedError()

        def connect(self) -> None:
            raise NotImplementedError()

        def disconnect(self) -> None:
            raise NotImplementedError()

        def release(self) -> None:
            raise NotImplementedError()

        def getATR(self) -> list[int]:
            raise NotImplementedError()

        def transmit(self, data: list[int]) -> tuple[bytes, int, int]:
            raise NotImplementedError()

        def lock(self) -> None:
            raise NotImplementedError()

        def unlock(self) -> None:
            raise NotImplementedError()

        def getReader(self) -> str:
            raise NotImplementedError()
