# kiro-classification: public
"""`message()`: valid Sandbox_Protocol messages, derived from the schema catalogue (R8.4).

The design's generator for Property 1 draws a message type from the catalogue and populates
its body from that type's schema, with byte-string fields drawn from arbitrary byte sequences
including empty, and integer fields drawn from the boundaries of their declared ranges. That
is what this module does, and it does it by walking `TypeSpec` rather than by restating any
message shape: a field added to `messages.yaml` is populated here with no edit, and a field
whose type changes is drawn from the new type or fails loudly.

A drawn message is the four-key envelope map itself — `{1: version, 2: type, 3: id, 4: body}`
with small unsigned integer keys — because that is what the design's message shape table says a
message is. No wrapper class: the codec owns the message type, and a second representation
here would be a thing to keep in step for no gain. `Value` and `Envelope` are therefore the
codec's own aliases, re-exported so a caller reaching for the generators does not have to know
which package defines the value space.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from protocol.codec import Message, Value
from protocol.generators.byte_domains import MAX_OUTPUT_BYTES, output_bytes
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Catalogue,
    Field,
    IntRange,
    MessageType,
    TypeKind,
    TypeSpec,
    load_catalogue,
)

__all__ = [
    "MAX_CONTAINER_SIZE",
    "Envelope",
    "Value",
    "body",
    "correlation_id",
    "integer_boundaries",
    "message",
    "message_of",
    "value_for",
]

#: One message: the definite-length four-key CBOR map from the design's message shape table.
type Envelope = Message

#: Containers stay small. A message carrying a hundred-element list exercises the same code
#: path as one carrying three, and it costs a thousand-iteration codec property real time.
MAX_CONTAINER_SIZE: Final = 4

#: Byte fields nested inside a list or a map get a lower ceiling than a top-level one, so an
#: `env` map cannot multiply its per-entry ceiling by its entry count into a megabyte message.
MAX_NESTED_BYTES: Final = 256

MAX_CORRELATION_ID_BYTES: Final = 16

MAX_TEXT_LENGTH: Final = 32

#: The CBOR head-width crossings, as integer values rather than as lengths. An integer field
#: whose declared range spans one of these reaches a width the codec must select correctly.
_CBOR_ARGUMENT_BOUNDARIES: Final[tuple[int, ...]] = (
    23,
    24,
    255,
    256,
    65535,
    65536,
    4294967295,
    4294967296,
)

#: Values where an encoder's sign or zero handling changes.
_SIGN_BOUNDARIES: Final[tuple[int, ...]] = (-1, 0, 1)


def integer_boundaries(range_: IntRange) -> tuple[int, ...]:
    """The values an integer field of this range is drawn from, ascending.

    The declared bounds, which is what the design's generator names, plus the values inside
    them where an encoding decision changes: the sign transition, and each CBOR head-width
    crossing and its neighbour. A field declared 0 to 4,294,967,295 encodes across four head
    widths, and a codec that mis-selects one fails only at a crossing.
    """
    candidates = {*range_.boundaries(), *_SIGN_BOUNDARIES}
    for crossing in _CBOR_ARGUMENT_BOUNDARIES:
        candidates.update((crossing, -crossing))
    return tuple(
        sorted(value for value in candidates if range_.min <= value <= range_.max)
    )


def _integer(spec: TypeSpec) -> SearchStrategy[int]:
    if spec.range is None:  # pragma: no cover - the loader rejects such a catalogue
        raise ValueError(f"a {spec.kind} field must declare its range")
    return st.one_of(
        st.sampled_from(integer_boundaries(spec.range)),
        st.integers(min_value=spec.range.min, max_value=spec.range.max),
    )


def _text(spec: TypeSpec) -> SearchStrategy[str]:
    if spec.enum is not None:
        return st.sampled_from(spec.enum)
    # Surrogates are excluded because CBOR major type 3 is a UTF-8 text string and a lone
    # surrogate has no UTF-8 encoding. That is not a narrowing of R8.9: process output and
    # filesystem names are byte-typed precisely so the unencodable cases live there, and
    # `output_bytes()` covers them.
    return st.text(
        alphabet=st.characters(exclude_categories=["Cs"]), max_size=MAX_TEXT_LENGTH
    )


def correlation_id() -> SearchStrategy[bytes]:
    """The envelope's `id`: an opaque correlation handle, empty included."""
    return st.binary(max_size=MAX_CORRELATION_ID_BYTES)


def value_for(spec: TypeSpec, *, nested: bool = False) -> SearchStrategy[Value]:
    """A value admissible for `spec`, drawn from the domain its kind declares."""
    match spec.kind:
        case TypeKind.UINT | TypeKind.INT:
            return _integer(spec)
        case TypeKind.BOOL:
            return st.booleans()
        case TypeKind.TEXT:
            return _text(spec)
        case TypeKind.BYTES:
            # Every byte field is drawn from the adversarial domain whether or not it is
            # annotated: the catalogue types them as bytes because the protocol carries them
            # verbatim, and a field the annotation happens not to cover is carried no
            # differently.
            return output_bytes(
                max_size=MAX_NESTED_BYTES if nested else MAX_OUTPUT_BYTES
            )
        case TypeKind.LIST:
            if spec.items is None:  # pragma: no cover - the loader rejects this
                raise ValueError("a list must declare items")
            return st.lists(
                value_for(spec.items, nested=True), max_size=MAX_CONTAINER_SIZE
            )
        case TypeKind.MAP:
            if spec.keys is None or spec.values is None:
                # The envelope's `b` declares neither, because its schema is selected by `t`.
                return st.just({})
            return st.dictionaries(
                value_for(spec.keys, nested=True),
                value_for(spec.values, nested=True),
                max_size=MAX_CONTAINER_SIZE,
            )
        case TypeKind.STRUCT:
            return _fields(spec.fields, nested=True)


def _fields(
    fields: Sequence[Field], *, nested: bool
) -> SearchStrategy[dict[Value, Value]]:
    """A map keyed by the declared integer keys, omitting optional fields sometimes.

    Omission is drawn independently of every other field. The catalogue declares optionality
    per field and states no cross-field rule — `proc.status.exitCode` is absent while the
    process is running, but nothing in the schema ties the two — so a generator that inferred
    one would be asserting a constraint the codec does not validate.
    """
    if not fields:
        return st.just({})

    drawn = {field.key: value_for(field.spec, nested=nested) for field in fields}
    optional = tuple(field.key for field in fields if field.optional)

    @st.composite
    def _draw(draw: st.DrawFn) -> dict[Value, Value]:
        omitted = {key for key in optional if draw(st.booleans())}
        return {
            key: draw(strategy) for key, strategy in drawn.items() if key not in omitted
        }

    return _draw()


def body(message_type: MessageType) -> SearchStrategy[dict[Value, Value]]:
    """The body map for one message type, keyed by the catalogue's integer field keys."""
    return _fields(message_type.body, nested=False)


def message_of(
    t: str, *, catalogue: Catalogue | None = None
) -> SearchStrategy[Envelope]:
    """A valid message of exactly one type."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    if t not in resolved.messages:
        raise KeyError(f"the catalogue declares no message type {t!r}")
    message_type = resolved.messages[t]

    @st.composite
    def _draw(draw: st.DrawFn) -> Envelope:
        return {
            # The emitted version, not a drawn one: a message carrying an unsupported version
            # is not a valid message, and Property 4's `malformed()` owns that domain.
            ENVELOPE_KEY_VERSION: resolved.protocol_version,
            ENVELOPE_KEY_TYPE: message_type.t,
            ENVELOPE_KEY_ID: draw(correlation_id()),
            ENVELOPE_KEY_BODY: draw(body(message_type)),
        }

    return _draw()


def message(
    *, types: Sequence[str] | None = None, catalogue: Catalogue | None = None
) -> SearchStrategy[Envelope]:
    """Any valid Sandbox_Protocol message (R8.4).

    Draws a message type from the catalogue and populates its body from that type's schema.
    `types` narrows the draw, which is what a property needing a message with a non-empty body
    uses rather than filtering after the fact.
    """
    resolved = catalogue if catalogue is not None else load_catalogue()
    chosen = tuple(types) if types is not None else resolved.message_types
    if not chosen:
        raise ValueError("message() needs at least one message type to draw from")
    return st.one_of([message_of(t, catalogue=resolved) for t in chosen])
