from typing import Optional

class ListPortInfo:
    device: str
    vid: Optional[int]
    pid: Optional[int]
    serial_number: Optional[str]
