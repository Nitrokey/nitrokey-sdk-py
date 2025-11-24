# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import dataclasses
from dataclasses import dataclass, field
from functools import total_ordering
from typing import Optional, Sequence


@dataclass(order=True, frozen=True)
class Uuid:
    """UUID of a Nitrokey Trussed device."""

    value: int

    def __str__(self) -> str:
        return f"{self.value:032X}"

    def __int__(self) -> int:
        return self.value


@dataclass(eq=False, frozen=True)
@total_ordering
class Version:
    """
    The version of a Nitrokey Trussed device, following Semantic Versioning
    2.0.0.

    Some sources for version information, namely the version returned by older
    devices and the firmware binaries, do not contain the pre-release
    component.  These instances are marked with *complete=False*.  This flag
    affects comparison:  The pre-release version is only taken into account if
    both version instances are complete.

    >>> Version(1, 0, 0)
    Version(major=1, minor=0, patch=0, pre=None, build=None)
    >>> Version.from_str("1.0.0")
    Version(major=1, minor=0, patch=0, pre=None, build=None)
    >>> Version.from_v_str("v1.0.0")
    Version(major=1, minor=0, patch=0, pre=None, build=None)
    >>> Version(1, 0, 0, "rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1', build=None)
    >>> Version.from_str("1.0.0-rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1', build=None)
    >>> Version.from_v_str("v1.0.0-rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1', build=None)
    >>> Version.from_v_str("v1.0.0-rc.1+git")
    Version(major=1, minor=0, patch=0, pre='rc.1', build='git')
    """

    major: int
    minor: int
    patch: int
    pre: Optional[str] = None
    build: Optional[str] = None
    complete: bool = field(default=False, repr=False)

    def __str__(self) -> str:
        """
        >>> str(Version(major=1, minor=0, patch=0))
        'v1.0.0'
        >>> str(Version(major=1, minor=0, patch=0, pre="rc.1"))
        'v1.0.0-rc.1'
        >>> str(Version(major=1, minor=0, patch=0, pre="rc.1", build="git"))
        'v1.0.0-rc.1+git'
        """

        version = f"v{self.major}.{self.minor}.{self.patch}"
        if self.pre:
            version += f"-{self.pre}"
        if self.build:
            version += f"+{self.build}"
        return version

    def __eq__(self, other: object) -> bool:
        """
        >>> Version(1, 0, 0) == Version(1, 0, 0)
        True
        >>> Version(1, 0, 0) == Version(1, 0, 1)
        False
        >>> Version.from_str("1.0.0-rc.1") == Version.from_str("1.0.0-rc.1")
        True
        >>> Version.from_str("1.0.0") == Version.from_str("1.0.0-rc.1")
        False
        >>> Version.from_str("1.0.0") == Version.from_str("1.0.0+git")
        True
        >>> Version(1, 0, 0, complete=False) == Version.from_str("1.0.0-rc.1")
        True
        >>> Version(1, 0, 0, complete=False) == Version.from_str("1.0.1")
        False
        """
        if not isinstance(other, Version):
            return NotImplemented
        lhs = (self.major, self.minor, self.patch)
        rhs = (other.major, other.minor, other.patch)

        if lhs != rhs:
            return False
        if self.complete and other.complete:
            return self.pre == other.pre
        return True

    def __lt__(self, other: object) -> bool:
        """
        >>> def cmp(a, b):
        ...     return Version.from_str(a) < Version.from_str(b)
        >>> cmp("1.0.0", "1.0.0")
        False
        >>> cmp("1.0.0", "1.0.1")
        True
        >>> cmp("1.1.0", "2.0.0")
        True
        >>> cmp("1.1.0", "1.0.3")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0")
        True
        >>> cmp("1.0.0", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0-rc.2")
        True
        >>> cmp("1.0.0-rc.2", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-alpha.1", "1.0.0-rc.1")
        True
        >>> cmp("1.0.0-alpha.1", "1.0.0-rc.1.0")
        True
        >>> cmp("1.0.0-alpha.1", "1.0.0-alpha.1.0")
        True
        >>> cmp("1.0.0-rc.2", "1.0.0-rc.10")
        True
        >>> Version(1, 0, 0, "rc.1") < Version(1, 0, 0)
        False
        """

        if not isinstance(other, Version):
            return NotImplemented

        lhs = (self.major, self.minor, self.patch)
        rhs = (other.major, other.minor, other.patch)

        if lhs == rhs and self.complete and other.complete:
            # relevant rules:
            # 1. pre-releases sort before regular releases
            # 2. two pre-releases for the same core version are sorted by the pre-release component
            #    (split into subcomponents)
            if self.pre == other.pre:
                return False
            elif self.pre is None:
                # self is regular release, other is pre-release
                return False
            elif other.pre is None:
                # self is pre-release, other is regular release
                return True
            else:
                # both are pre-releases
                def int_or_str(s: str) -> object:
                    if s.isdigit():
                        return int(s)
                    else:
                        return s

                lhs_pre = [int_or_str(s) for s in self.pre.split(".")]
                rhs_pre = [int_or_str(s) for s in other.pre.split(".")]
                return lhs_pre < rhs_pre
        else:
            return lhs < rhs

    def core(self) -> "Version":
        """
        Returns the core part of this version, i. e. the version without the
        pre-release and build components.

        >>> Version(1, 0, 0).core()
        Version(major=1, minor=0, patch=0, pre=None, build=None)
        >>> Version(1, 0, 0, "rc.1").core()
        Version(major=1, minor=0, patch=0, pre=None, build=None)
        >>> Version(1, 0, 0, "rc.1", "git").core()
        Version(major=1, minor=0, patch=0, pre=None, build=None)
        """
        return dataclasses.replace(self, pre=None, build=None)

    @classmethod
    def from_int(cls, version: int) -> "Version":
        # This is the reverse of the calculation in runners/lpc55/build.rs (CARGO_PKG_VERSION):
        # https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/runners/lpc55/build.rs#L131
        major = version >> 22
        minor = (version >> 6) & ((1 << 16) - 1)
        patch = version & ((1 << 6) - 1)
        return cls(major=major, minor=minor, patch=patch)

    @classmethod
    def from_str(cls, s: str) -> "Version":
        version_parts = s.split("+", maxsplit=1)
        s = version_parts[0]
        build = version_parts[1] if len(version_parts) == 2 else None

        version_parts = s.split("-", maxsplit=1)
        pre = version_parts[1] if len(version_parts) == 2 else None

        str_parts = version_parts[0].split(".")
        if len(str_parts) != 3:
            raise ValueError(f"Invalid firmware version: {s}")

        try:
            int_parts = [int(part) for part in str_parts]
        except ValueError as e:
            raise ValueError(f"Invalid component in firmware version: {s}") from e

        [major, minor, patch] = int_parts
        return cls(major=major, minor=minor, patch=patch, pre=pre, build=build, complete=True)

    @classmethod
    def from_v_str(cls, s: str) -> "Version":
        if not s.startswith("v"):
            raise ValueError(f"Missing v prefix for firmware version: {s}")
        return Version.from_str(s[1:])


@dataclass
class Fido2Certs:
    start: Version
    hashes: list[str]

    @staticmethod
    def get(certs: Sequence["Fido2Certs"], version: Version) -> Optional["Fido2Certs"]:
        matching_certs = [c for c in certs if version >= c.start]
        if matching_certs:
            return max(matching_certs, key=lambda c: c.start)
        else:
            return None


class Iso7816Apdu:
    def __init__(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: Optional[bytes] = None,
        le: Optional[int] = None,
    ) -> None:
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data or b""
        self.le = le

    def _encode_lc(self) -> bytes:
        """Encode Lc according to short / extended format."""
        lc_len = len(self.data)
        if lc_len == 0:
            return b""
        if lc_len <= 0xFF:
            return bytes([lc_len])
        if lc_len <= 0xFFFF:
            return b"\x00" + lc_len.to_bytes(2, "big")
        raise ValueError("Data too long (max 6535 bytes)")

    def _encode_le(self) -> bytes:
        """Encode Le according to short / extended format."""
        if self.le is None:
            return b""
        if self.le == 0:
            return b"\x00"
        if self.le <= 0xFF:
            return bytes([self.le])
        if self.le <= 0xFFFF:
            return b"\x00" + self.le.to_bytes(2, "big")
        raise ValueError("Le out of range (max 65535)")

    def to_bytes(self) -> bytes:
        """Serialize the APDU to its binary representation."""
        header = bytes([self.cla, self.ins, self.p1, self.p2])

        # No data, no Le → case 1
        if not self.data and self.le is None:
            return header

        lc = self._encode_lc()
        le = self._encode_le()

        # Cases:
        # 2: no data, Le present
        # 3: data present, no Le
        # 4: data present, Le present
        return header + lc + self.data + le
