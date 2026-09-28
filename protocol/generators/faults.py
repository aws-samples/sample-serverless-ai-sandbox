# kiro-classification: public
"""`malformed()`: the four fault classes Property 4's phase order must discriminate.

The design's decode algorithm fixes three phases, and the order is the mechanism for R8.8.
A generator for that property therefore has to produce inputs that make the order *observable*,
which means four classes:

| Class | Input | Error the codec owes |
| --- | --- | --- |
| `VERSION_UNREADABLE` | the version is absent, unreadable or not the first key | decode error naming field `1` |
| `VERSION_UNSUPPORTED` | the version reads cleanly and is outside the supported range | version error carrying the received version and both bounds |
| `SCHEMA_VIOLATION` | a supported version and one violated field | decode error naming that field |
| `VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION` | both at once | version error, because Phase 1 precedes Phase 2 |

The fourth class is the whole point, and the cross product is what makes it more than an
anecdote: every out-of-range version is paired with every single-field violation, so a codec
that happened to validate in the right order for one combination and not another is caught.

A `Fault` is a declaration, not bytes. `render(encode)` applies it to the caller's canonical
encoder, which keeps this module independent of the codec and lets the same fault be rendered
by the Python encoder and the TypeScript one. Everything it does is byte surgery over the
canonical encoding plus a handful of literal replacement values, because an encoder able to
emit an unsupported version or a wrongly typed field would be a defect in the codec.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

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
)
from protocol.generators.messages import Envelope, Value, message, message_of
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Catalogue,
    MessageType,
    TypeKind,
    load_catalogue,
)

__all__ = [
    "Encoder",
    "Expectation",
    "Fault",
    "FaultClass",
    "FaultKind",
    "SchemaViolation",
    "Scope",
    "Violated",
    "malformed",
    "out_of_range_versions",
    "violation_targets",
]

#: A canonical encoder: the Protocol_Codec's serialise, injected rather than imported.
type Encoder = Callable[[Envelope], bytes]

_UNSUPPORTED_MESSAGE_TYPE: Final = "exec.undeclared"

_NOT_A_DECLARED_ENUM_VALUE: Final = "not-a-declared-value"

#: The value a wrongly typed field is replaced with, chosen per expected kind so the
#: replacement is always a *different* major type rather than an out-of-domain value.
_TEXT_LITERAL: Final = encode_head(Major.TEXT, 1) + b"x"
_UINT_LITERAL: Final = encode_head(Major.UINT, 0)

_WRONG_TYPE_FOR_KIND: Final[Mapping[TypeKind, bytes]] = {
    TypeKind.UINT: _TEXT_LITERAL,
    TypeKind.INT: _TEXT_LITERAL,
    TypeKind.BOOL: _UINT_LITERAL,
    TypeKind.TEXT: _UINT_LITERAL,
    TypeKind.BYTES: _TEXT_LITERAL,
    TypeKind.LIST: _UINT_LITERAL,
    TypeKind.MAP: _UINT_LITERAL,
    TypeKind.STRUCT: _UINT_LITERAL,
}

#: The widest integer a CBOR head can carry. Beyond it an encoder needs a bignum tag, which
#: this protocol does not use, so an out-of-range value above it is unreachable by surgery.
_MAX_HEAD_INTEGER: Final = (1 << 64) - 1


class Expectation(enum.StrEnum):
    """Which of the codec's two error types the fault must produce."""

    DECODE_ERROR = "decode-error"
    VERSION_ERROR = "version-error"


class FaultClass(enum.StrEnum):
    """The four classes the design's Property 4 names."""

    VERSION_UNREADABLE = "version-unreadable"
    VERSION_UNSUPPORTED = "version-unsupported"
    SCHEMA_VIOLATION = "schema-violation"
    VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION = (
        "version-unsupported-and-schema-violation"
    )


class FaultKind(enum.StrEnum):
    """How a fault is built. Several kinds share one `FaultClass`."""

    #: Zero bytes: there is no map head, so Phase 0 cannot begin.
    EMPTY_WIRE = "empty-wire"
    #: Cut short inside the head or the first entry.
    TRUNCATED_WIRE = "truncated-wire"
    #: Key 1 is present and first, but its value is a text string.
    VERSION_NOT_AN_INTEGER = "version-not-an-integer"
    #: Key 1 is present but not first, which Phase 0 must reject rather than search for.
    VERSION_KEY_MISPLACED = "version-key-misplaced"
    #: An indefinite-length envelope, so there is no definite map head to read.
    INDEFINITE_ENVELOPE = "indefinite-envelope"
    #: A readable version outside the supported range.
    UNSUPPORTED_VERSION = "unsupported-version"
    #: A supported version and one violated field.
    SCHEMA_VIOLATION = "schema-violation"
    #: Both, which is the case that discriminates the phase order.
    UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION = (
        "unsupported-version-and-schema-violation"
    )


_UNREADABLE_KINDS: Final = frozenset(
    {
        FaultKind.EMPTY_WIRE,
        FaultKind.TRUNCATED_WIRE,
        FaultKind.VERSION_NOT_AN_INTEGER,
        FaultKind.VERSION_KEY_MISPLACED,
        FaultKind.INDEFINITE_ENVELOPE,
    }
)

_CLASS_FOR_KIND: Final[Mapping[FaultKind, FaultClass]] = {
    FaultKind.UNSUPPORTED_VERSION: FaultClass.VERSION_UNSUPPORTED,
    FaultKind.SCHEMA_VIOLATION: FaultClass.SCHEMA_VIOLATION,
    FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION: (
        FaultClass.VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION
    ),
}


class Scope(enum.StrEnum):
    """Whether the violated field is an envelope key or a body field."""

    ENVELOPE = "envelope"
    BODY = "body"


class SchemaViolation(enum.StrEnum):
    """How one field is made inadmissible."""

    #: The value is replaced with one of a different CBOR major type.
    WRONG_TYPE = "wrong-type"
    #: An integer outside its declared range.
    OUT_OF_RANGE = "out-of-range"
    #: A text value outside its declared enum.
    NOT_IN_ENUM = "not-in-enum"
    #: A required field removed from the body.
    MISSING_REQUIRED_FIELD = "missing-required-field"
    #: A body key the message type does not declare.
    UNKNOWN_BODY_KEY = "unknown-body-key"
    #: A `t` value the catalogue does not declare, so no body schema selects.
    UNKNOWN_MESSAGE_TYPE = "unknown-message-type"


@dataclass(frozen=True, slots=True)
class Violated:
    """One single-field schema violation, resolved against a drawn message."""

    violation: SchemaViolation
    scope: Scope
    #: The envelope key, or the body field key.
    key: int
    #: The catalogue's name for the field, for a failure message that reads.
    name: str
    #: The encoded value that substitutes for the field's, where the violation substitutes.
    replacement: bytes | None = None


def _encode_integer(value: int) -> bytes:
    """Canonically encode one integer, which is all the surgery here ever writes."""
    if value >= 0:
        return encode_head(Major.UINT, value)
    return encode_head(Major.NEGINT, -1 - value)


def out_of_range_versions(catalogue: Catalogue) -> tuple[int, ...]:
    """Versions the codec must reject in Phase 1, ascending.

    Derived from the declared range rather than listed, so widening `supportedMax` narrows this
    set instead of leaving a stale value that would now be admissible.
    """
    candidates = {
        catalogue.supported_min - 1,
        catalogue.supported_max + 1,
        0,
        2,
        255,
        256,
        65536,
        1 << 32,
        _MAX_HEAD_INTEGER,
    }
    return tuple(
        sorted(
            version
            for version in candidates
            if 0 <= version <= _MAX_HEAD_INTEGER and not catalogue.supports(version)
        )
    )


def violation_targets(
    message_type: MessageType, drawn: Envelope
) -> tuple[Violated, ...]:
    """Every single-field violation reachable in this drawn message.

    Resolved against the message rather than against the schema alone, because a violation
    that substitutes or removes a field needs that field to be present, and an optional field
    may have been omitted.
    """
    targets: list[Violated] = [
        Violated(
            SchemaViolation.UNKNOWN_MESSAGE_TYPE,
            Scope.ENVELOPE,
            ENVELOPE_KEY_TYPE,
            "t",
            encode_head(Major.TEXT, len(_UNSUPPORTED_MESSAGE_TYPE))
            + _UNSUPPORTED_MESSAGE_TYPE.encode(),
        ),
        Violated(
            SchemaViolation.WRONG_TYPE,
            Scope.ENVELOPE,
            ENVELOPE_KEY_TYPE,
            "t",
            _WRONG_TYPE_FOR_KIND[TypeKind.TEXT],
        ),
        Violated(
            SchemaViolation.WRONG_TYPE,
            Scope.ENVELOPE,
            ENVELOPE_KEY_BODY,
            "b",
            _WRONG_TYPE_FOR_KIND[TypeKind.MAP],
        ),
        # A key beyond the declared block. Keys are contiguous from 1, so one past the last
        # declared key is undeclared, and it still sorts last under the deterministic profile.
        Violated(
            SchemaViolation.UNKNOWN_BODY_KEY,
            Scope.BODY,
            len(message_type.body) + 1,
            str(len(message_type.body) + 1),
            _UINT_LITERAL,
        ),
    ]

    body = drawn[ENVELOPE_KEY_BODY]
    present: frozenset[Value] = (
        frozenset(body.keys()) if isinstance(body, dict) else frozenset()
    )

    for field in message_type.body:
        if field.key not in present:
            continue
        spec = field.spec
        targets.append(
            Violated(
                SchemaViolation.WRONG_TYPE,
                Scope.BODY,
                field.key,
                field.name,
                _WRONG_TYPE_FOR_KIND[spec.kind],
            )
        )
        if not field.optional:
            targets.append(
                Violated(
                    SchemaViolation.MISSING_REQUIRED_FIELD,
                    Scope.BODY,
                    field.key,
                    field.name,
                )
            )
        if spec.enum is not None:
            targets.append(
                Violated(
                    SchemaViolation.NOT_IN_ENUM,
                    Scope.BODY,
                    field.key,
                    field.name,
                    encode_head(Major.TEXT, len(_NOT_A_DECLARED_ENUM_VALUE))
                    + _NOT_A_DECLARED_ENUM_VALUE.encode(),
                )
            )
        if spec.range is not None:
            outside = _outside_range(spec.range.min, spec.range.max)
            if outside is not None:
                targets.append(
                    Violated(
                        SchemaViolation.OUT_OF_RANGE,
                        Scope.BODY,
                        field.key,
                        field.name,
                        _encode_integer(outside),
                    )
                )
    return tuple(targets)


def _outside_range(low: int, high: int) -> int | None:
    """A value outside `[low, high]` that a CBOR head can carry, or None if there is none."""
    if high + 1 <= _MAX_HEAD_INTEGER:
        return high + 1
    if low - 1 >= -_MAX_HEAD_INTEGER - 1:
        return low - 1
    return (
        None  # pragma: no cover - no catalogue range spans the whole encodable domain
    )


@dataclass(frozen=True, slots=True)
class Fault:
    """One malformed wire representation, declared rather than encoded."""

    kind: FaultKind
    #: The well-formed message the fault is applied to.
    message: Envelope
    #: The version the rendered wire carries, when the fault rewrites it.
    version: int | None = None
    violated: Violated | None = None
    #: For `TRUNCATED_WIRE`: how many bytes of the encoding survive.
    keep_bytes: int | None = None

    @property
    def fault_class(self) -> FaultClass:
        if self.kind in _UNREADABLE_KINDS:
            return FaultClass.VERSION_UNREADABLE
        return _CLASS_FOR_KIND[self.kind]

    @property
    def expectation(self) -> Expectation:
        if self.fault_class in (
            FaultClass.VERSION_UNSUPPORTED,
            FaultClass.VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION,
        ):
            return Expectation.VERSION_ERROR
        return Expectation.DECODE_ERROR

    @property
    def acceptable_field_identities(self) -> frozenset[str]:
        """The spellings a decode error may use for the field it names.

        The design fixes the envelope case — field `1` when the version is unreadable — and
        leaves the body case to the codec, so a body field is accepted under its integer key,
        its catalogue name, or either qualified by the body key. Pinning one spelling here
        would be this module deciding an interface that belongs to the codec.
        """
        if self.expectation is not Expectation.DECODE_ERROR:
            return frozenset()
        if self.violated is None:
            return frozenset({str(ENVELOPE_KEY_VERSION), "v"})
        key, name = self.violated.key, self.violated.name
        if self.violated.scope is Scope.ENVELOPE:
            return frozenset({str(key), name})
        return frozenset(
            {
                str(key),
                name,
                f"{ENVELOPE_KEY_BODY}.{key}",
                f"b.{key}",
                f"b.{name}",
            }
        )

    def identifies(self, reported: str) -> bool:
        """Whether `reported` names the field this fault violates."""
        return reported in self.acceptable_field_identities

    def render(self, encode: Encoder) -> bytes:
        """Apply the fault to `encode(self.message)` and return the malformed bytes."""
        wire = encode(self.message)
        if self.kind is FaultKind.EMPTY_WIRE:
            return b""
        if self.kind is FaultKind.TRUNCATED_WIRE:
            keep = 1 if self.keep_bytes is None else self.keep_bytes
            return wire[: min(keep, len(wire) - 1)]

        root = scan(wire)
        if self.kind is FaultKind.INDEFINITE_ENVELOPE:
            return (
                bytes((Major.MAP << 5 | INDEFINITE_INFO,))
                + wire[root.payload_start : root.end]
                + bytes((BREAK,))
            )
        if self.kind is FaultKind.VERSION_KEY_MISPLACED:
            return _transpose_first_two_entries(wire, root)

        if self.kind is FaultKind.VERSION_NOT_AN_INTEGER:
            return _replace_envelope_value(
                wire, root, ENVELOPE_KEY_VERSION, _TEXT_LITERAL
            )

        if self.version is not None:
            wire = _replace_envelope_value(
                wire, root, ENVELOPE_KEY_VERSION, _encode_integer(self.version)
            )
            root = scan(wire)
        if self.violated is not None:
            wire = _apply(wire, root, self.violated)
        return wire


def _entry_for_key(root: Item, key: int) -> tuple[Item, Item]:
    for key_item, value_item in root.entries:
        if key_item.major is Major.UINT and key_item.argument == key:
            return (key_item, value_item)
    raise ValueError(f"the encoding carries no entry keyed {key}")


def _replace_envelope_value(
    wire: bytes, root: Item, key: int, replacement: bytes
) -> bytes:
    _, value_item = _entry_for_key(root, key)
    return replace(wire, value_item.start, value_item.end, replacement)


def _transpose_first_two_entries(wire: bytes, root: Item) -> bytes:
    entries = root.entries
    first_key, first_value = entries[0]
    second_key, second_value = entries[1]
    first = wire[first_key.start : first_value.end]
    second = wire[second_key.start : second_value.end]
    return replace(wire, first_key.start, second_value.end, second + first)


def _apply(wire: bytes, root: Item, violated: Violated) -> bytes:
    if violated.scope is Scope.ENVELOPE:
        assert violated.replacement is not None
        return _replace_envelope_value(wire, root, violated.key, violated.replacement)

    _, body = _entry_for_key(root, ENVELOPE_KEY_BODY)
    if violated.violation is SchemaViolation.UNKNOWN_BODY_KEY:
        assert violated.replacement is not None
        entry = encode_head(Major.UINT, violated.key) + violated.replacement
        # Append before re-heading, so the head's offsets stay valid.
        appended = replace(wire, body.end, body.end, entry)
        return replace(
            appended,
            body.start,
            body.payload_start,
            encode_head(Major.MAP, body.argument + 1),
        )

    key_item, value_item = _entry_for_key(body, violated.key)
    if violated.violation is SchemaViolation.MISSING_REQUIRED_FIELD:
        removed = replace(wire, key_item.start, value_item.end, b"")
        return replace(
            removed,
            body.start,
            body.payload_start,
            encode_head(Major.MAP, body.argument - 1),
        )

    assert violated.replacement is not None
    return replace(wire, value_item.start, value_item.end, violated.replacement)


# --- Strategies ------------------------------------------------------------------------


@st.composite
def _violated_message(
    draw: st.DrawFn, catalogue: Catalogue
) -> tuple[Envelope, Violated]:
    t = draw(st.sampled_from(catalogue.message_types))
    drawn = draw(message_of(t, catalogue=catalogue))
    targets = violation_targets(catalogue.messages[t], drawn)
    return (drawn, draw(st.sampled_from(targets)))


@st.composite
def _version_unreadable(draw: st.DrawFn, catalogue: Catalogue) -> Fault:
    drawn = draw(message(catalogue=catalogue))
    kind = draw(st.sampled_from(sorted(_UNREADABLE_KINDS)))
    if kind is FaultKind.TRUNCATED_WIRE:
        # One byte through the first entry's head: enough to be a plausible prefix, never
        # enough to carry a version.
        return Fault(
            kind, drawn, keep_bytes=draw(st.integers(min_value=1, max_value=3))
        )
    return Fault(kind, drawn)


@st.composite
def _version_unsupported(draw: st.DrawFn, catalogue: Catalogue) -> Fault:
    return Fault(
        FaultKind.UNSUPPORTED_VERSION,
        draw(message(catalogue=catalogue)),
        version=draw(st.sampled_from(out_of_range_versions(catalogue))),
    )


@st.composite
def _schema_violation(draw: st.DrawFn, catalogue: Catalogue) -> Fault:
    drawn, violated = draw(_violated_message(catalogue))
    return Fault(FaultKind.SCHEMA_VIOLATION, drawn, violated=violated)


@st.composite
def _both(draw: st.DrawFn, catalogue: Catalogue) -> Fault:
    """The cross product: every out-of-range version against every single-field violation."""
    drawn, violated = draw(_violated_message(catalogue))
    return Fault(
        FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION,
        drawn,
        version=draw(st.sampled_from(out_of_range_versions(catalogue))),
        violated=violated,
    )


def malformed(*, catalogue: Catalogue | None = None) -> SearchStrategy[Fault]:
    """The four fault classes, drawn with equal weight (R8.6, R8.7, R8.8).

    Equal weight rather than proportional to the number of ways each class can be built, so
    the cross-product class — the one that discriminates a correct phase order from an
    accidental one — gets a quarter of the draws rather than a residue.
    """
    resolved = catalogue if catalogue is not None else load_catalogue()
    return st.one_of(
        _version_unreadable(resolved),
        _version_unsupported(resolved),
        _schema_violation(resolved),
        _both(resolved),
    )
