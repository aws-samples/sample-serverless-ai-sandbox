# kiro-classification: public
"""The wire format: CBOR restricted to RFC 8949's deterministic encoding profile.

Two functions, and they are inverses on the domain the profile admits. `encode_value` can only
emit the profile — every head is written at its shortest width, every string and container is
definite-length, and every map's entries are sorted by their encoded key bytes — so there is no
canonicalisation pass to maintain and no way for a caller to ask for a non-canonical encoding.
`decode_value` accepts only the profile, and that is the half that needs the argument:

R8.5 requires that deserialising a representation and re-serialising it produce bytes identical
to the input. An encoder that always emits the profile gets that for free *provided* the decoder
never accepts anything the encoder cannot reproduce. Two indefinite-length chunks, a length
written in four bytes where one would do, or a map whose keys ascend in the wrong order all decode
to a perfectly ordinary value under a permissive reader — and re-encoding that value yields
different bytes. So the criterion is met by refusing those representations, not by tolerating them
and hoping the re-encoding matches. That is why the design calls a non-deterministic encoding a
decode error rather than a curiosity.

The structural work is `protocol._cbor`'s: `encode_head` writes heads, and `scan` locates every
item while rejecting ill-formed CBOR, indefinite lengths, non-shortest heads, reserved additional
information, unused simple values, floats, tags, truncation and trailing bytes. What is added here
is what a scanner cannot see from one item's head: map key ordering, strict UTF-8 for text
strings, and the guard against a map whose keys are distinct on the wire but equal once decoded.
"""

from __future__ import annotations

from protocol._cbor import (
    FALSE_SIMPLE,
    MAX_HEAD_ARGUMENT,
    TRUE_SIMPLE,
    CborScanError,
    Item,
    Major,
    encode_head,
    scan,
)
from protocol.codec.errors import NonCanonicalEncoding, UnencodableValue
from protocol.codec.values import Value

__all__ = ["decode_value", "encode_value"]


# --- Encoding ---------------------------------------------------------------------------------


def encode_value(value: Value) -> bytes:
    """Encode one value under the deterministic profile.

    Raises `UnencodableValue` for anything outside the protocol's value space, rather than
    reaching for a CBOR feature — a float, a tag, a bignum — that no message declares and that
    the decoder would refuse on the way back in.
    """
    # bool before int: `True` is an `int` in Python, and simple value 21 is not integer 1.
    if isinstance(value, bool):
        return encode_head(Major.SIMPLE, TRUE_SIMPLE if value else FALSE_SIMPLE)
    if isinstance(value, int):
        return _encode_integer(value)
    if isinstance(value, bytes):
        return encode_head(Major.BYTES, len(value)) + value
    if isinstance(value, str):
        payload = _encode_text(value)
        return encode_head(Major.TEXT, len(payload)) + payload
    if isinstance(value, list):
        return encode_head(Major.ARRAY, len(value)) + b"".join(
            encode_value(item) for item in value
        )
    if isinstance(value, dict):
        return _encode_map(value)
    raise UnencodableValue(f"nothing in this protocol encodes a {type(value).__name__}")


def _encode_integer(value: int) -> bytes:
    """Major type 0 for a non-negative value, major type 1 for a negative one."""
    major = Major.UINT if value >= 0 else Major.NEGINT
    argument = value if value >= 0 else -1 - value
    if argument > MAX_HEAD_ARGUMENT:
        # Encodable only as a bignum, which is a tag, which this protocol does not declare.
        raise UnencodableValue(f"integer {value} does not fit in a CBOR head")
    return encode_head(major, argument)


def _encode_text(value: str) -> bytes:
    """UTF-8, strictly. A text string with no UTF-8 encoding is not a text string.

    A lone surrogate is the case that reaches here. It is not a narrowing of R8.9: process
    output and filesystem names are byte-typed throughout the catalogue precisely so the
    sequences with no UTF-8 encoding travel as major type 2, where nothing interprets them.
    """
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UnencodableValue(f"a text string must be UTF-8 encodable: {exc}") from exc


def _encode_map(value: dict[Value, Value]) -> bytes:
    """A definite-length map whose entries ascend by encoded key bytes.

    Bytewise on the *encoded* key, which is what RFC 8949 §4.2.1 specifies and is not the same
    as ordering by decoded value: key -1 encodes as `20` and sorts above key 256's `19 01 00`,
    though it is the smaller number. Nor is it the same as ordering by length first, which is
    the rule RFC 7049's canonical form used and this profile replaced.
    """
    entries = sorted(
        ((encode_value(key), encode_value(item)) for key, item in value.items()),
        key=lambda pair: pair[0],
    )
    return encode_head(Major.MAP, len(entries)) + b"".join(
        key + item for key, item in entries
    )


# --- Decoding ---------------------------------------------------------------------------------


def decode_value(wire: bytes) -> Value:
    """Decode one complete deterministic-profile CBOR value.

    Raises `NonCanonicalEncoding` for ill-formed CBOR, for any profile violation, and for
    trailing bytes after the first item — a message is one item, and silently decoding the first
    of two would leave the rest unaccounted for.
    """
    try:
        root = scan(wire)
    except CborScanError as exc:
        raise NonCanonicalEncoding(str(exc)) from exc
    return _materialise(wire, root)


def _materialise(wire: bytes, item: Item) -> Value:
    match item.major:
        case Major.UINT:
            return item.argument
        case Major.NEGINT:
            return -1 - item.argument
        case Major.BYTES:
            return wire[item.payload_start : item.end]
        case Major.TEXT:
            return _materialise_text(wire, item)
        case Major.ARRAY:
            return [_materialise(wire, child) for child in item.children]
        case Major.MAP:
            return _materialise_map(wire, item)
        case Major.SIMPLE:
            # `scan` admits only false and true here.
            return item.argument == TRUE_SIMPLE


def _materialise_text(wire: bytes, item: Item) -> str:
    """Strict UTF-8. Anything else is not re-encodable, so it cannot be accepted.

    Python's decoder rejects overlong forms, surrogates and truncated sequences, which is what
    makes `decode` then `encode` the identity on text: every accepted payload has exactly one
    encoding, and it is the one that arrived.
    """
    payload = wire[item.payload_start : item.end]
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NonCanonicalEncoding(
            f"a text string must be valid UTF-8: {exc}", at=item.start
        ) from exc


def _materialise_map(wire: bytes, item: Item) -> dict[Value, Value]:
    entries = item.entries
    built: dict[Value, Value] = {}
    previous: bytes | None = None
    for key_item, value_item in entries:
        encoded_key = wire[key_item.start : key_item.end]
        if previous is not None and encoded_key <= previous:
            detail = (
                "duplicate map key"
                if encoded_key == previous
                else "map keys must ascend by encoded bytes"
            )
            raise NonCanonicalEncoding(detail, at=key_item.start)
        previous = encoded_key
        built[_materialise(wire, key_item)] = _materialise(wire, value_item)
    if len(built) != len(entries):
        # Two keys distinct on the wire but equal once decoded: `00` is integer 0 and `f4` is
        # false, and Python holds one entry for both. Re-encoding could not reproduce the input,
        # so the representation is refused rather than silently narrowed.
        raise NonCanonicalEncoding(
            f"{len(entries)} map keys collapse to {len(built)} once decoded",
            at=item.start,
        )
    return built
