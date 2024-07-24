from hashlib import _Hash
from typing import Any, Callable, Literal, Optional, TypeVar, Union

T = TypeVar("T")

class BadSignatureError(Exception): ...

class VerifyingKey:
    def verify(
        self,
        signature: Union[bytes | str],
        data: Union[bytes | str],
        hashfunc: Callable[[bytes], _Hash],
    ) -> bool: ...
    @classmethod
    def from_der(cls, s: bytes) -> "VerifyingKey": ...
