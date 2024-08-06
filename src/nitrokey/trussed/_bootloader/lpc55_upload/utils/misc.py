#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions used throughout the SPSDK."""
import re
from enum import Enum
from math import ceil
from secrets import token_bytes
from typing import List, Optional, Union

from ..exceptions import SPSDKError, SPSDKValueError


class Endianness(str, Enum):
    """Endianness enum."""

    BIG = "big"
    LITTLE = "little"

    @classmethod
    def values(cls) -> List[str]:
        """Get enumeration values."""
        return [mem.value for mem in Endianness.__members__.values()]


class BinaryPattern:
    """Binary pattern class.

    Supported patterns:
        - rand: Random Pattern
        - zeros: Filled with zeros
        - ones: Filled with all ones
        - inc: Filled with repeated numbers incremented by one 0-0xff
        - any kind of number, that will be repeated to fill up whole image.
          The format could be decimal, hexadecimal, bytes.
    """

    SPECIAL_PATTERNS = ["rand", "zeros", "ones", "inc"]

    def __init__(self, pattern: str) -> None:
        """Constructor of pattern class.

        :param pattern: Supported patterns:
                        - rand: Random Pattern
                        - zeros: Filled with zeros
                        - ones: Filled with all ones
                        - inc: Filled with repeated numbers incremented by one 0-0xff
                        - any kind of number, that will be repeated to fill up whole image.
                        The format could be decimal, hexadecimal, bytes.
        :raises SPSDKValueError: Unsupported pattern detected.
        """
        try:
            value_to_int(pattern)
        except SPSDKError:
            if pattern not in BinaryPattern.SPECIAL_PATTERNS:
                raise SPSDKValueError(  # pylint: disable=raise-missing-from
                    f"Unsupported input pattern {pattern}"
                )

        self._pattern = pattern

    def get_block(self, size: int) -> bytes:
        """Get block filled with pattern.

        :param size: Size of block to return.
        :return: Filled up block with specified pattern.
        """
        if self._pattern == "zeros":
            return bytes(size)

        if self._pattern == "ones":
            return bytes(b"\xff" * size)

        if self._pattern == "rand":
            return token_bytes(size)

        if self._pattern == "inc":
            return bytes((x & 0xFF for x in range(size)))

        pattern = value_to_bytes(self._pattern, align_to_2n=False)
        block = bytes(pattern * (int((size / len(pattern))) + 1))
        return block[:size]

    @property
    def pattern(self) -> str:
        """Get the pattern.

        :return: Pattern in string representation.
        """
        try:
            return hex(value_to_int(self._pattern))
        except SPSDKError:
            return self._pattern


def align(number: int, alignment: int = 4) -> int:
    """Align number (size or address) size to specified alignment, typically 4, 8 or 16 bytes boundary.

    :param number: input to be aligned
    :param alignment: the boundary to align; typical value is power of 2
    :return: aligned number; result is always >= size (e.g. aligned up)
    :raises SPSDKError: When there is wrong alignment
    """
    if alignment <= 0 or number < 0:
        raise SPSDKError("Wrong alignment")

    return (number + (alignment - 1)) // alignment * alignment


def align_block(
    data: Union[bytes, bytearray],
    alignment: int = 4,
    padding: Optional[Union[int, str, BinaryPattern]] = None,
) -> bytes:
    """Align binary data block length to specified boundary by adding padding bytes to the end.

    :param data: to be aligned
    :param alignment: boundary alignment (typically 2, 4, 16, 64 or 256 boundary)
    :param padding: byte to be added or BinaryPattern
    :return: aligned block
    :raises SPSDKError: When there is wrong alignment
    """
    assert isinstance(data, (bytes, bytearray))

    if alignment < 0:
        raise SPSDKError("Wrong alignment")
    current_size = len(data)
    num_padding = align(current_size, alignment) - current_size
    if not num_padding:
        return bytes(data)
    if not padding:
        padding = BinaryPattern("zeros")
    elif not isinstance(padding, BinaryPattern):
        padding = BinaryPattern(str(padding))
    return bytes(data + padding.get_block(num_padding))


def align_block_fill_random(data: bytes, alignment: int = 4) -> bytes:
    """Same as `align_block`, just parameter `padding` is fixed to `-1` to fill with random data."""
    return align_block(data, alignment, BinaryPattern("rand"))


def get_bytes_cnt_of_int(
    value: int, align_to_2n: bool = True, byte_cnt: Optional[int] = None
) -> int:
    """Returns count of bytes needed to store handled integer.

    :param value: Input integer value.
    :param align_to_2n: The result will be aligned to standard sizes 1,2,4,8,12,16,20.
    :param byte_cnt: The result count of bytes.
    :raises SPSDKValueError: The integer input value doesn't fit into byte_cnt.
    :return: Number of bytes needed to store integer.
    """
    cnt = 0
    if value == 0:
        return byte_cnt or 1

    while value != 0:
        value >>= 8
        cnt += 1

    if align_to_2n and cnt > 2:
        cnt = int(ceil(cnt / 4)) * 4

    if byte_cnt and cnt > byte_cnt:
        raise SPSDKValueError(
            f"Value takes more bytes than required byte count {byte_cnt} after align."
        )

    cnt = byte_cnt or cnt

    return cnt


def value_to_int(
    value: Union[bytes, bytearray, int, str], default: Optional[int] = None
) -> int:
    """Function loads value from lot of formats to integer.

    :param value: Input value.
    :param default: Default Value in case of invalid input.
    :return: Value in Integer.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, int):
        return value

    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, Endianness.BIG.value)

    if isinstance(value, str) and value != "":
        match = re.match(
            r"(?P<prefix>0[box])?(?P<number>[0-9a-f_]+)(?P<suffix>[ul]{0,3})$",
            value.strip().lower(),
        )
        if match:
            base = {"0b": 2, "0o": 8, "0": 10, "0x": 16, None: 10}[
                match.group("prefix")
            ]
            try:
                return int(match.group("number"), base=base)
            except ValueError:
                pass

    if default is not None:
        return default
    raise SPSDKError(f"Invalid input number type({type(value)}) with value ({value})")


def value_to_bytes(
    value: Union[bytes, bytearray, int, str],
    align_to_2n: bool = True,
    byte_cnt: Optional[int] = None,
    endianness: Endianness = Endianness.BIG,
) -> bytes:
    """Function loads value from lot of formats.

    :param value: Input value.
    :param align_to_2n: When is set, the function aligns length of return array to 1,2,4,8,12 etc.
    :param byte_cnt: The result count of bytes.
    :param endianness: The result bytes endianness ['big', 'little'].
    :return: Value in bytes.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    value = value_to_int(value)
    return value.to_bytes(
        get_bytes_cnt_of_int(value, align_to_2n, byte_cnt=byte_cnt), endianness.value
    )


def size_fmt(num: Union[float, int], use_kibibyte: bool = True) -> str:
    """Size format."""
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][use_kibibyte]
    i = "B"
    for i in ["B"] + [i + suffix for i in list("kMGTP")]:
        if num < base:
            break
        num /= base

    return f"{int(num)} {i}" if i == "B" else f"{num:3.1f} {i}"


def swap16(x: int) -> int:
    """Swap bytes in half word (16bit).

    :param x: Original number
    :return: Number with swapped bytes
    :raises SPSDKError: When incorrect number to be swapped is provided
    """
    if x < 0 or x > 0xFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)
