# kiro-classification: public
"""`non_canonical_variant()`: parseable encodings that violate the deterministic profile.

The design's generator for the second half of Property 2 rewrites one encoded item of a
canonical encoding into an equivalent non-deterministic form: an indefinite-length string or
map, a non-shortest integer or length encoding, or a map with keys out of sorted order. Each
rewrite is *equivalent* — a permissive CBOR reader decodes the variant to the same value — which
is what makes the property a statement about the profile rather than about well-formedness. A
codec that accepted one would break R8.5, because re-encoding under the profile would produce
different bytes than were received.

Composition is the caller's, as the design states it: draw an encoding from `encode(message())`
and flat-map it through here.

    st.builds(encode, message()).flatmap(non_canonical_variant)
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from protocol._cbor import (
    BREAK,
    INDEFINITE_INFO,
    Item,
    Major,
    encode_head,
    replace,
    scan,
    wider_widths,
)

__all__ = ["NonCanonical", "Violation", "non_canonical_variant"]


class Violation(enum.StrEnum):
    """Which rule of RFC 8949's deterministic encoding profile the variant breaks."""

    #: A byte or text string re-expressed as an indefinite-length item with one chunk.
    INDEFINITE_STRING = "indefinite-string"
    #: An array or map re-expressed as an indefinite-length container.
    INDEFINITE_CONTAINER = "indefinite-container"
    #: A head argument written in a wider form than the value requires.
    NON_SHORTEST_HEAD = "non-shortest-head"
    #: Two adjacent map entries transposed, so the keys no longer ascend by encoded bytes.
    UNSORTED_MAP_KEYS = "unsorted-map-keys"


@dataclass(frozen=True, slots=True)
class NonCanonical:
    """One rewritten encoding, with the rule it breaks and where."""

    canonical: bytes
    wire: bytes
    violation: Violation
    #: Offset of the item the rewrite addressed, for a failure message that says where.
    at: int


_Rewrite = Callable[[bytes], bytes]


def _indefinite_string(item: Item) -> _Rewrite:
    """`58 03 616263` becomes `5f 43 616263 ff`: same payload, indefinite head."""

    def rewrite(data: bytes) -> bytes:
        payload = data[item.payload_start : item.end]
        chunked = (
            bytes((item.major << 5 | INDEFINITE_INFO,))
            + encode_head(item.major, len(payload))
            + payload
            + bytes((BREAK,))
        )
        return replace(data, item.start, item.end, chunked)

    return rewrite


def _indefinite_container(item: Item) -> _Rewrite:
    """The entries are untouched; only the head and the terminator change."""

    def rewrite(data: bytes) -> bytes:
        payload = data[item.payload_start : item.end]
        opened = bytes((item.major << 5 | INDEFINITE_INFO,)) + payload + bytes((BREAK,))
        return replace(data, item.start, item.end, opened)

    return rewrite


def _non_shortest_head(item: Item, width: int) -> _Rewrite:
    def rewrite(data: bytes) -> bytes:
        widened = encode_head(item.major, item.argument, width)
        return replace(data, item.start, item.payload_start, widened)

    return rewrite


def _transposed_entries(item: Item, index: int) -> _Rewrite:
    """Swap entries `index` and `index + 1` of a map.

    The input is canonical, so every adjacent pair is in ascending encoded-byte order and any
    transposition breaks the ordering rule.
    """
    entries = item.entries
    first_key, first_value = entries[index]
    second_key, second_value = entries[index + 1]

    def rewrite(data: bytes) -> bytes:
        first = data[first_key.start : first_value.end]
        second = data[second_key.start : second_value.end]
        return replace(data, first_key.start, second_value.end, second + first)

    return rewrite


def _candidates(root: Item) -> list[tuple[Violation, int, _Rewrite]]:
    """Every single-item rewrite available in this encoding."""
    found: list[tuple[Violation, int, _Rewrite]] = []
    for item in root.walk():
        if item.is_string:  # nosemgrep: is-function-without-parentheses — @property
            found.append(
                (Violation.INDEFINITE_STRING, item.start, _indefinite_string(item))
            )
        if item.is_container:  # nosemgrep: is-function-without-parentheses — @property
            found.append(
                (
                    Violation.INDEFINITE_CONTAINER,
                    item.start,
                    _indefinite_container(item),
                )
            )
        if item.has_argument:
            for width in wider_widths(item.argument):
                found.append(
                    (
                        Violation.NON_SHORTEST_HEAD,
                        item.start,
                        _non_shortest_head(item, width),
                    )
                )
        if item.major is Major.MAP and item.argument >= 2:
            for index in range(item.argument - 1):
                found.append(
                    (
                        Violation.UNSORTED_MAP_KEYS,
                        item.start,
                        _transposed_entries(item, index),
                    )
                )
    return found


def non_canonical_variant(canonical: bytes) -> SearchStrategy[NonCanonical]:
    """Rewrite one item of `canonical` into an equivalent non-deterministic form.

    `canonical` must be one complete encoding in the deterministic profile; anything else
    raises `CborScanError` rather than producing a variant whose only fault is the input's.
    """
    root = scan(canonical)
    candidates = _candidates(root)
    if not candidates:  # pragma: no cover - every message is at least a four-entry map
        raise ValueError("no deterministic-profile rule is reachable in this encoding")

    def build(candidate: tuple[Violation, int, _Rewrite]) -> NonCanonical:
        violation, at, rewrite = candidate
        wire = rewrite(canonical)
        if wire == canonical:  # pragma: no cover - every rewrite changes bytes
            raise ValueError(f"{violation} at {at} left the encoding unchanged")
        return NonCanonical(canonical=canonical, wire=wire, violation=violation, at=at)

    return st.sampled_from(candidates).map(build)
