# kiro-classification: public
"""Property 3: byte-exact process output preservation (R8.9).

The design states this property in both languages, so the number here is claimed a second time
in `properties.test.ts` by design and uniqueness is asserted per language. Both halves quantify
over the same domain: `output_bytes()` is the shared generator, and the TypeScript half reads the
`byte_domains.json` mirror of the module this half imports, so an adversarial class that catches
one language would have been drawn in the other.

Two things make this property a statement about the format rather than about one message type.

*Every field that carries output, not just `exec.chunk.data`.* R8.9 is about process output, and
the catalogue marks each field carrying it with `carries: output` — command output, file content
read back, file content written, and pseudo-terminal bytes. The carrier is drawn from that
annotation rather than listed, so a message type added with an output field is covered here with
no edit, and `test_every_output_annotation_sits_on_a_top_level_bytes_field` fails loudly if a
future annotation lands somewhere this derivation would skip. The rest of the message around the
carrier is drawn by the shared `message_of()`, so the bytes under test travel inside a message
the schema declares rather than inside a hand-built envelope.

*Equality on `bytes`, taken after a real `encode` and `decode`.* Task 2.1 typed every output and
name field as a byte string, which is what makes byte-exactness provable rather than lossy: there
is no `str` anywhere on this path, and a codec that transcoded through text would fail on the
first lone surrogate rather than quietly normalising it. The deterministic profile's own concerns
— length-prefix widths, sorted keys — belong to Property 2; what is asserted here is only that
the bytes handed in are the bytes handed back.

The deterministic test below carries each named adversarial class through the codec by name. It
draws nothing, so it is not a second property test; it is the per-class evidence that
"including sequences that are not valid UTF-8" is carried by the classes the design lists rather
than by whatever a sampler happened to reach. Generator coverage itself is asserted in
`protocol/generators/test_generators.py`, which is why it is not re-asserted here.
"""

from __future__ import annotations

from typing import Final

from hypothesis import given, settings
from hypothesis import strategies as st

from protocol.codec import Message, Value, decode, encode
from protocol.generators import ADVERSARIAL_BYTE_CLASSES, output_bytes
from protocol.generators.messages import message_of
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Carries,
    load_catalogue,
)
from tests.harness import CODEC_EXAMPLES

CATALOGUE = load_catalogue()

#: Every `(message type, body key)` whose field the catalogue annotates `carries: output`, in
#: catalogue order. Derived, not listed: see the module docstring.
OUTPUT_CARRIERS: Final[tuple[tuple[str, int], ...]] = tuple(
    (t, field.key)
    for t, field, spec in CATALOGUE.byte_typed_fields()
    if spec.carries is Carries.OUTPUT and spec is field.spec
)


def _body_of(message: Message) -> dict[Value, Value]:
    """The body map of a message, as a mapping rather than as a `Value`."""
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict), f"body is {type(body).__name__}, not a map"
    return body


def _carried(message: Message, key: int) -> bytes:
    """The byte string body field `key` carries, insisting it is still a byte string."""
    carried = _body_of(message)[key]
    assert isinstance(carried, bytes), (
        f"body field {key} came back as {type(carried).__name__}, not bytes; "
        "an output field that is not byte-typed cannot be byte-exact"
    )
    return carried


@st.composite
def _output_in_context(draw: st.DrawFn) -> tuple[str, int, Message, bytes]:
    """A valid message with a drawn byte sequence placed in one of its output fields.

    The surrounding message is drawn rather than fixed so the bytes under test travel with
    company: neighbouring fields, an empty or populated correlation id, and — for `exec.result` —
    a second output field holding unrelated bytes of its own.
    """
    t, key = draw(st.sampled_from(OUTPUT_CARRIERS))
    message = draw(message_of(t, catalogue=CATALOGUE))
    data = draw(output_bytes())
    # Assignment rather than draw-and-read: the field may be optional, and the value the
    # generator would have put there is not the value this property is quantifying over.
    _body_of(message)[key] = data
    return (t, key, message, data)


# Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including sequences
# that are not valid UTF-8, carrying that sequence as process output through one serialise and
# deserialise cycle yields a byte sequence identical to the input.
@given(case=_output_in_context())
@settings(max_examples=CODEC_EXAMPLES)
def test_process_output_is_byte_exact(case: tuple[str, int, Message, bytes]) -> None:
    t, key, message, data = case

    carried = _carried(decode(encode(message), catalogue=CATALOGUE), key)

    where = f"{t} body field {key}"
    # Length first: a truncation at an embedded NUL or a length-prefix crossing reads far more
    # clearly as a length mismatch than as a diff of two long hex strings.
    assert len(carried) == len(data), (
        f"{where} carried {len(carried)} bytes, not {len(data)}"
    )
    assert carried == data, (
        f"{where} was altered in transit: {data.hex()} became {carried.hex()}"
    )


def _chunk_carrying(data: bytes) -> Message:
    """An `exec.chunk` reporting `data` on stdout: the smallest message that carries output."""
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: "exec.chunk",
        ENVELOPE_KEY_ID: b"",
        ENVELOPE_KEY_BODY: {1: 0, 2: data},
    }


def test_every_named_adversarial_class_survives_the_round_trip() -> None:
    """Each class the design names, carried by name rather than by sampling."""
    for name, sequences in ADVERSARIAL_BYTE_CLASSES.items():
        for data in sequences:
            carried = _carried(
                decode(
                    encode(_chunk_carrying(data), catalogue=CATALOGUE),
                    catalogue=CATALOGUE,
                ),
                key=2,
            )
            assert carried == data, (
                f"{name} sequence {data.hex()} became {carried.hex()}"
            )


def test_every_output_annotation_sits_on_a_top_level_bytes_field() -> None:
    """The carrier derivation skips nothing the catalogue annotates `carries: output`.

    `OUTPUT_CARRIERS` reads a field's own spec, so an annotation nested inside a list or a map
    would leave that output field out of the property's domain. Nothing in the catalogue nests
    one today; this is what makes it a failure rather than a silent narrowing if one ever does.
    """
    nested = [
        (t, field.name)
        for t, field, spec in CATALOGUE.byte_typed_fields()
        if spec.carries is Carries.OUTPUT and spec is not field.spec
    ]
    assert not nested, f"output annotations nested below a field: {nested}"
    assert OUTPUT_CARRIERS, "the catalogue declares no output-carrying field"
    for t, key in OUTPUT_CARRIERS:
        assert CATALOGUE.messages[t].field_by_key(key).spec.carries is Carries.OUTPUT
