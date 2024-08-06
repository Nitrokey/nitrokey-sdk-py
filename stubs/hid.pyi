from typing import Any, Optional, TypedDict

class device:
    def open_path(self, path: bytes) -> None: ...
    def close(self) -> None: ...
    def read(self, max_length: int, timeout_ms: int) -> list[int]: ...
    def write(self, data: bytes) -> int: ...

class _DeviceDict(TypedDict):
    path: bytes
    vendor_id: int
    product_id: int
    manufacturer_string: str
    product_string: str
    interface_number: int

def enumerate(vendor_id: int = 0, product_id: int = 0) -> list[_DeviceDict]: ...
