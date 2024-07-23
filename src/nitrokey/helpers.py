import sys
import time
from typing import Any


def local_print(*messages: Any, **kwargs: Any) -> None:
    for item in messages:
        print(item, **kwargs)


def local_critical(
    *messages: Any, support_hint: bool = True, ret_code: int = 1, **kwargs: Any
) -> None:
    messages = ("Critical error:",) + tuple(messages)
    local_print(*messages, **kwargs)
    sys.exit(ret_code)


class Try:
    """Utility class for an execution of a repeated action with Retries."""

    def __init__(self, i: int, retries: int) -> None:
        self.i = i
        self.retries = retries

    def __str__(self) -> str:
        return f"try {self.i + 1} of {self.retries}"

    def __repr__(self) -> str:
        return f"Try(i={self.i}, retries={self.retries})"


class Retries:
    """Utility class for repeating an action multiple times until it succeeds."""

    def __init__(self, retries: int, timeout: float = 0.5) -> None:
        self.retries = retries
        self.i = 0
        self.timeout = timeout

    def __iter__(self) -> "Retries":
        return self

    def __next__(self) -> Try:
        if self.i >= self.retries:
            raise StopIteration
        if self.i > 0:
            time.sleep(self.timeout)
        t = Try(self.i, self.retries)
        self.i += 1
        return t
