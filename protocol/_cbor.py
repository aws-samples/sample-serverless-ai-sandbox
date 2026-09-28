# kiro-classification: public
"""Structural CBOR primitives, shared by the Protocol_Codec and the adversarial generators.

Nothing here knows about messages, and nothing here is a codec on its own. Three capabilities:
`encode_head`, which writes an item head at a chosen width; `scan`, which locates every item in
an encoding and accepts only RFC 8949's deterministic profile; and `replace`, which substitutes
one located span for another.

Both consumers need the same subset, from opposite directions. `protocol.codec` builds its
encoder on `encode_head` at the shortest width and its decoder on `scan`, so the profile is
enforced structurally in one place rather than restated. The generators for Properties 2 and 4
take a canonical encoding apart with `scan` and put it back together wrongly, which is exactly
what the codec must refuse to emit and must refuse to accept.

This module sits at `protocol/` rather than under `protocol/generators/` for a reason beyond
tidiness: importing anything from `protocol.generators` executes that package's `__init__`,
which imports Hypothesis. Hypothesis is a development dependency, and the Sandbox_Runtime image
carries the codec, so a codec that reached into the generators subpackage would not import in
the image at all.

`scan` deliberately does not check map key ordering. Ordering is a property of a whole map
rather than of an item's head, and the codec's decoder checks it while materialising values,
where it has the decoded keys to hand and can report which map offends.
"""

from __future__ import annotations

import enum
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

__all__ = [
    "BREAK",
    "FALSE_SIMPLE",
    "INDEFINITE_INFO",
    "MAX_HEAD_ARGUMENT",
    "TRUE_SIMPLE",
    "CborScanError",
    "Item",
    "Major",
    "encode_head",
    "minimal_width",
    "replace",
    "scan",
    "wider_widths",
]


class CborScanError(Exception):
    """The bytes handed to `scan` are not in the subset the Protocol_Codec emits."""


class Major(enum.IntEnum):
    """The CBOR major types this protocol uses."""

    UINT = 0
    NEGINT = 1
    BYTES = 2
    TEXT = 3
    ARRAY = 4
    MAP = 5
    SIMPLE = 7


#: Additional information 31, which marks an indefinite-length item.
INDEFINITE_INFO: Final = 31

#: The break code that closes an indefinite-length item.
BREAK: Final = 0xFF

#: Widths in bytes of the argument that follows the head byte. 0 means the argument is the
#: head byte's own additional information.
_WIDTHS: Final[tuple[int, ...]] = (0, 1, 2, 4, 8)

_INFO_FOR_WIDTH: Final[dict[int, int]] = {1: 24, 2: 25, 4: 26, 8: 27}

_WIDTH_FOR_INFO: Final[dict[int, int]] = {24: 1, 25: 2, 26: 4, 27: 8}

_PACK_FOR_WIDTH: Final[dict[int, str]] = {2: ">H", 4: ">I", 8: ">Q"}

_CONTAINERS: Final = frozenset({Major.ARRAY, Major.MAP})

_STRINGS: Final = frozenset({Major.BYTES, Major.TEXT})

#: Simple values 20 and 21: false and true. No other simple value appears in this protocol.
FALSE_SIMPLE: Final = 20
TRUE_SIMPLE: Final = 21

_ALLOWED_SIMPLE: Final = frozenset({FALSE_SIMPLE, TRUE_SIMPLE})

#: The widest argument a CBOR head carries. Beyond it an encoder needs a bignum tag, and this
#: protocol declares none.
MAX_HEAD_ARGUMENT: Final = (1 << 64) - 1


def minimal_width(argument: int) -> int:
    """The narrowest width the deterministic profile permits for `argument`."""
    if argument < 0:
        raise ValueError(f"a CBOR head argument is never negative, got {argument}")
    for width in _WIDTHS:
        if argument < (24 if width == 0 else 1 << (8 * width)):
            return width
    raise ValueError(f"argument {argument} does not fit in a CBOR head")


def wider_widths(argument: int) -> tuple[int, ...]:
    """Every width above the minimal one that still holds `argument`.

    Each is a non-shortest encoding of the same value, which is the deterministic-profile
    violation Property 2's second half quantifies over.
    """
    minimum = minimal_width(argument)
    return tuple(width for width in _WIDTHS if width > minimum)


def encode_head(major: int, argument: int, width: int | None = None) -> bytes:
    """Write an item head. `width=None` writes the shortest form the profile requires."""
    if width is None:
        width = minimal_width(argument)
    if width not in _WIDTHS:
        raise ValueError(f"width {width} is not a CBOR head width")
    if width == 0:
        if argument >= 24:
            raise ValueError(f"argument {argument} needs an explicit width")
        return bytes((major << 5 | argument,))
    if argument >= 1 << (8 * width):
        raise ValueError(f"argument {argument} does not fit in {width} bytes")
    head = bytes((major << 5 | _INFO_FOR_WIDTH[width],))
    if width == 1:
        return head + bytes((argument,))
    return head + struct.pack(_PACK_FOR_WIDTH[width], argument)


@dataclass(frozen=True, slots=True)
class Item:
    """One CBOR item located inside an encoding, with its children if it has any."""

    major: Major
    #: The head's decoded argument: the value for an unsigned integer, the byte length for a
    #: string, the entry count for a container, the simple value for a simple.
    argument: int
    start: int
    head_length: int
    end: int
    #: Array elements, or a map's keys and values interleaved in encoded order.
    children: tuple[Item, ...] = ()

    @property
    def payload_start(self) -> int:
        return self.start + self.head_length

    @property
    def is_string(self) -> bool:
        return self.major in _STRINGS

    @property
    def is_container(self) -> bool:
        return self.major in _CONTAINERS

    @property
    def has_argument(self) -> bool:
        """Whether the head carries a widenable argument.

        A simple value does not: `false` and `true` are the head byte and nothing else.
        """
        return self.major is not Major.SIMPLE

    @property
    def entries(self) -> tuple[tuple[Item, Item], ...]:
        """A map's key and value pairs, in encoded order."""
        if self.major is not Major.MAP:
            raise ValueError(f"a {self.major.name} item has no entries")
        pairs = zip(self.children[0::2], self.children[1::2], strict=True)
        return tuple(pairs)

    def walk(self) -> Iterator[Item]:
        """This item and every item nested inside it, outermost first."""
        yield self
        for child in self.children:
            yield from child.walk()


def _read_head(data: bytes, offset: int) -> tuple[Major, int, int]:
    if offset >= len(data):
        raise CborScanError(f"offset {offset} is past the end of {len(data)} bytes")
    head = data[offset]
    try:
        major = Major(head >> 5)
    except ValueError as exc:
        raise CborScanError(
            f"offset {offset}: unsupported major type {head >> 5}"
        ) from exc
    info = head & 0x1F
    if info < 24:
        return (major, info, 1)
    if info == INDEFINITE_INFO:
        raise CborScanError(f"offset {offset}: indefinite length is not canonical")
    if info not in _WIDTH_FOR_INFO:
        raise CborScanError(f"offset {offset}: reserved additional information {info}")
    width = _WIDTH_FOR_INFO[info]
    if offset + 1 + width > len(data):
        raise CborScanError(f"offset {offset}: head truncated")
    argument = int.from_bytes(data[offset + 1 : offset + 1 + width], "big")
    if minimal_width(argument) != width:
        raise CborScanError(
            f"offset {offset}: argument {argument} is not shortest-form"
        )
    return (major, argument, 1 + width)


def _scan_item(data: bytes, offset: int) -> Item:
    major, argument, head_length = _read_head(data, offset)
    cursor = offset + head_length

    if major is Major.SIMPLE:
        if argument not in _ALLOWED_SIMPLE:
            raise CborScanError(
                f"offset {offset}: simple value {argument} is not used here"
            )
        return Item(major, argument, offset, head_length, cursor)

    if major in _STRINGS:
        end = cursor + argument
        if end > len(data):
            raise CborScanError(f"offset {offset}: string payload truncated")
        return Item(major, argument, offset, head_length, end)

    if major in _CONTAINERS:
        count = argument * 2 if major is Major.MAP else argument
        children: list[Item] = []
        for _ in range(count):
            child = _scan_item(data, cursor)
            children.append(child)
            cursor = child.end
        return Item(major, argument, offset, head_length, cursor, tuple(children))

    return Item(major, argument, offset, head_length, cursor)


def scan(data: bytes) -> Item:
    """Locate every item in one canonically encoded CBOR value.

    Raises `CborScanError` on trailing bytes, so a caller cannot silently address the first of
    two concatenated items when it meant the whole encoding.
    """
    root = _scan_item(data, 0)
    if root.end != len(data):
        raise CborScanError(
            f"{len(data) - root.end} trailing byte(s) after the root item"
        )
    return root


def replace(data: bytes, start: int, end: int, replacement: bytes) -> bytes:
    """Substitute `data[start:end]` with `replacement`.

    Safe for the rewrites here because a container's definite length counts entries rather
    than bytes, and no byte string in this protocol carries an embedded CBOR encoding, so
    resizing a nested item never invalidates an enclosing head.
    """
    if not 0 <= start <= end <= len(data):
        raise ValueError(f"span {start}:{end} is outside {len(data)} bytes")
    return data[:start] + replacement + data[end:]
