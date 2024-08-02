from typing import Optional, Union

class SerialBase:
    def __init__(
        self,
        port: Optional[str],
        baudrate: int,
        rtscts: Union[bool, int],
        timeout: Optional[float],
    ) -> None: ...
    def close(self) -> None: ...
    def read(self, length: int = 1) -> bytes: ...
    def write(self, data: Union[bytes, bytearray, memoryview, list[int]]) -> int: ...

class SerialException(IOError): ...
