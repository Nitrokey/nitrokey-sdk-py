from typing import Callable

def mkPredefinedCrcFun(crc_name: str) -> Callable[[bytes, int], int]: ...
