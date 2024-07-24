from typing import Any, Iterator, Union

class EntryList:
    data: list["Entry"]

    def __iter__(self) -> Iterator["Entry"]: ...

class Entry:
    type_id: int
    data: Any

    def __init__(self, type_id: int, data: Any) -> None: ...

def decode(data: bytes) -> EntryList: ...
def encode(entries: Union[list[Entry], EntryList]) -> bytes: ...
