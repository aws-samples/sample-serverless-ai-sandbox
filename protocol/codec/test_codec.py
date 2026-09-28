# kiro-classification: public
"""Unit tests for the Protocol_Codec (R8.2, R8.3, R8.9).

None of these is a property test and none carries a property tag. The design fixes 44 correctness
properties, each implemented by exactly one test, and Properties 1 through 4 arrive in tasks 2.5
through 2.8 over the shared generators. What is asserted here is what an example-based test is
better at than a sampled one: the exact bytes the deterministic profile requires, taken from RFC
8949's own test vectors, and one instance of each way a representation can be refused.

Two of the groups below deserve a note.

*Quantified over the catalogue.* The round-trip and encoding-shape tests build one message per
declared message type from the schema rather than listing messages, so a type added to
`messages.yaml` is covered with no edit here. The builder is deliberately dull — the low end of
every declared range, the first value of every closed enum — because the interesting distributions
are the generators' job.

*Agreement with the shared fault generator.* `protocol.generators.faults` fixes the spellings a
decode error may use for the field it names, and leaves the choice among them to the codec.
Property 4 will check the codec's choice against that set by sampling; the tests here enumerate
every single-field schema violation the generator can build against every message type, and every
out-of-range version against every one of those violations, and check the same thing exhaustively.
They are not Property 4 — they draw nothing — but they are what stops the two sides from
disagreeing about field identity, and what asserts the phase ordering on exactly the input the
design says a test should construct directly, long before the property runs.
"""

from __future__ import annotations

import re
from typing import Final

import cbor2
import pytest

from protocol._cbor import BREAK, INDEFINITE_INFO, Major, scan
from protocol.codec import (
    ROOT_IDENTITY,
    VERSION_IDENTITY,
    CodecError,
    DecodeError,
    Message,
    NonCanonicalEncoding,
    SchemaViolationError,
    UnencodableValue,
    Value,
    VersionError,
    decode,
    decode_value,
    encode,
    encode_value,
    read_version,
    require_supported,
    validate,
)
from protocol.generators.faults import (
    Expectation,
    Fault,
    FaultClass,
    FaultKind,
    out_of_range_versions,
    violation_targets,
)
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Field,
    TypeKind,
    TypeSpec,
    load_catalogue,
)

CATALOGUE = load_catalogue()

#: Bytes that are not valid UTF-8, carried through every byte-typed field the builder populates,
#: so the round-trip tests exercise R8.9 rather than only ASCII.
INVALID_UTF8: Final = b"\xff\xfe\x00\x80"

CORRELATION_ID: Final = b"\x00\xff"


# --- Building one message per declared type, from the schema ---------------------------------


def _example_value(spec: TypeSpec) -> Value:
    match spec.kind:
        case TypeKind.UINT | TypeKind.INT:
            assert spec.range is not None
            return spec.range.min
        case TypeKind.BOOL:
            return True
        case TypeKind.TEXT:
            return spec.enum[0] if spec.enum is not None else "example"
        case TypeKind.BYTES:
            return INVALID_UTF8
        case TypeKind.LIST:
            assert spec.items is not None
            return [_example_value(spec.items)]
        case TypeKind.MAP:
            if spec.keys is None or spec.values is None:
                return {}
            return {_example_value(spec.keys): _example_value(spec.values)}
        case TypeKind.STRUCT:
            return _example_body(spec.fields, include_optional=True)


def _example_body(
    fields: tuple[Field, ...], *, include_optional: bool
) -> dict[Value, Value]:
    return {
        field.key: _example_value(field.spec)
        for field in fields
        if include_optional or not field.optional
    }


def _example_message(t: str, *, include_optional: bool = True) -> Message:
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: CORRELATION_ID,
        ENVELOPE_KEY_BODY: _example_body(
            CATALOGUE.messages[t].body, include_optional=include_optional
        ),
    }


def _example_messages() -> list[Message]:
    """One message per declared type, and a second omitting the optional fields."""
    messages: list[Message] = []
    for t in CATALOGUE.message_types:
        messages.append(_example_message(t))
        if any(field.optional for field in CATALOGUE.messages[t].body):
            messages.append(_example_message(t, include_optional=False))
    return messages


def test_the_catalogue_declares_message_types_to_quantify_over() -> None:
    """Guards every quantified test below against passing vacuously."""
    assert CATALOGUE.message_types
    assert len(_example_messages()) > len(CATALOGUE.message_types)


# --- Round-trips (R8.2, R8.3) ----------------------------------------------------------------


def test_every_declared_message_type_survives_a_round_trip() -> None:
    for message in _example_messages():
        assert decode(encode(message)) == message


def test_every_wire_representation_re_encodes_to_the_bytes_it_arrived_as() -> None:
    """The R8.5 direction, asserted here on the codec's own output.

    Property 2 states this over sampled messages and adds the half about non-canonical input;
    this is the example-based half, and it is what would fail first if the encoder stopped
    emitting the profile.
    """
    for message in _example_messages():
        wire = encode(message)
        assert encode(decode(wire)) == wire


def test_output_bytes_survive_a_round_trip_unchanged() -> None:
    """R8.9, on the message type that carries process output chunks."""
    payloads = (
        b"",
        b"\xff",
        b"\xfe\xff",
        b"\xed\xa0\x80",  # A lone surrogate, encoded as bytes.
        b"\xc0\x80",  # An overlong NUL.
        b"\xe2\x82",  # A truncated three-byte sequence.
        b"\x00" * 8,
        bytes(range(256)),
        b"\xff" * 23,
        b"\xff" * 24,
        b"\xff" * 255,
        b"\xff" * 256,
        b"\xff" * 65_536,
    )
    for payload in payloads:
        message: Message = {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: "exec.chunk",
            ENVELOPE_KEY_ID: CORRELATION_ID,
            ENVELOPE_KEY_BODY: {1: 1, 2: payload},
        }
        decoded = decode(encode(message))
        body = decoded[ENVELOPE_KEY_BODY]
        assert isinstance(body, dict)
        assert body[2] == payload


# --- The encoding is the deterministic profile ------------------------------------------------


def test_the_encoding_is_the_profile_the_scanner_accepts() -> None:
    """`scan` admits only the profile, so it is the check on what the encoder emits."""
    for message in _example_messages():
        root = scan(encode(message))
        assert root.major is Major.MAP
        assert root.argument == 4


def test_the_protocol_version_is_the_first_entry_on_the_wire() -> None:
    """Key 1 sorts first under the profile, which is the mechanism R8.8 rests on."""
    for message in _example_messages():
        wire = encode(message)
        first_key, first_value = scan(wire).entries[0]
        assert first_key.major is Major.UINT
        assert first_key.argument == ENVELOPE_KEY_VERSION
        assert first_value.argument == CATALOGUE.protocol_version


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "00"),
        (1, "01"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (1_000_000, "1a000f4240"),
        ((1 << 64) - 1, "1bffffffffffffffff"),
        (-1, "20"),
        (-24, "37"),
        (-25, "3818"),
        (-256, "38ff"),
        (False, "f4"),
        (True, "f5"),
        (b"", "40"),
        (b"\x01\x02\x03\x04", "4401020304"),
        ("", "60"),
        ("a", "6161"),
        ("\u00fc", "62c3bc"),
        ([], "80"),
        ([1, [2, 3]], "8201820203"),
        ({}, "a0"),
        ({1: 2, 3: 4}, "a201020304"),
    ],
)
def test_encode_value_matches_the_rfc_8949_vectors(value: Value, expected: str) -> None:
    """Shortest-form heads and definite lengths, against the specification's own examples."""
    assert encode_value(value).hex() == expected


def test_map_entries_are_sorted_by_encoded_key_bytes() -> None:
    """Bytewise on the encoded key, not on the decoded value.

    -1 is the smallest number here and sorts last, because major type 1 puts its head byte at
    `20`, above `01`, `1818` and `190100`.
    """
    assert (
        encode_value({-1: 0, 256: 0, 24: 0, 1: 0}).hex() == "a40100181800190100002000"
    )


def test_map_entries_of_different_major_types_sort_by_their_heads() -> None:
    """`01` then `40` then `60`: an integer key, a byte-string key, a text key."""
    assert encode_value({"": 0, b"": 0, 1: 0}).hex() == "a3010040006000"  # nosemgrep: useless-literal — testing different CBOR key types


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        None,
        bytearray(b"ab"),
        (1, 2),
        1 << 64,
        -(1 << 64) - 1,
        "\ud800",
    ],
)
def test_encode_value_refuses_anything_outside_the_protocol_value_space(
    value: object,
) -> None:
    with pytest.raises(UnencodableValue):
        encode_value(value)  # type: ignore[arg-type]


# --- Non-deterministic and ill-formed representations are refused (R8.5) ----------------------


def _indefinite(major: Major, payload: bytes) -> bytes:
    return bytes((major << 5 | INDEFINITE_INFO,)) + payload + bytes((BREAK,))


@pytest.mark.parametrize(
    ("name", "wire"),
    [
        ("indefinite byte string", _indefinite(Major.BYTES, bytes.fromhex("43616263"))),
        ("indefinite text string", _indefinite(Major.TEXT, bytes.fromhex("63616263"))),
        ("indefinite array", _indefinite(Major.ARRAY, bytes.fromhex("010203"))),
        ("indefinite map", _indefinite(Major.MAP, bytes.fromhex("0102"))),
        ("non-shortest one-byte head", bytes.fromhex("1817")),
        ("non-shortest two-byte head", bytes.fromhex("190018")),
        ("non-shortest eight-byte head", bytes.fromhex("1b0000000000000001")),
        ("non-shortest byte-string length", bytes.fromhex("5801ff")),
        # `a2 1818 00 01 00`: key 24 before key 1, which the profile orders the other way.
        ("map keys out of sorted order", bytes.fromhex("a21818000100")),
        ("duplicate map keys", bytes.fromhex("a201000100")),
        ("keys that collapse once decoded", bytes.fromhex("a20000f400")),
        ("a tag", bytes.fromhex("c11a514b67b0")),
        ("a half-precision float", bytes.fromhex("f90000")),
        ("a double-precision float", bytes.fromhex("fb3ff199999999999a")),
        ("the null simple value", bytes.fromhex("f6")),
        ("an unassigned simple value", bytes.fromhex("f818")),
        ("a bare break", bytes.fromhex("ff")),
        ("a truncated head", bytes.fromhex("19")),
        ("a truncated byte-string payload", bytes.fromhex("43ab")),
        ("a truncated map", bytes.fromhex("a201")),
        ("trailing bytes", bytes.fromhex("000000")),
        ("no bytes at all", b""),
        ("invalid UTF-8 in a text string", bytes.fromhex("61ff")),
        ("an overlong NUL in a text string", bytes.fromhex("62c080")),
    ],
)
def test_decode_value_refuses_a_representation_outside_the_profile(
    name: str, wire: bytes
) -> None:
    with pytest.raises(NonCanonicalEncoding):
        decode_value(wire)


def test_the_refused_representations_are_otherwise_plausible() -> None:
    """Several of them decode to an ordinary value under a permissive reader.

    That is the point of refusing them: re-encoding the value under the profile would produce
    different bytes than arrived, which is exactly what R8.5 forbids. The check here is the
    weaker, self-contained one — the canonical encoding of the same value differs from the input
    — so the assertion does not depend on a second CBOR library.
    """
    equivalents: tuple[tuple[bytes, Value], ...] = (
        (_indefinite(Major.BYTES, bytes.fromhex("43616263")), b"abc"),
        (bytes.fromhex("1817"), 23),
        (bytes.fromhex("5801ff"), b"\xff"),
        (bytes.fromhex("a21818000100"), {24: 0, 1: 0}),
    )
    for wire, value in equivalents:
        assert encode_value(value) != wire


def test_decode_reports_the_offset_of_the_item_at_fault_where_there_is_one() -> None:
    with pytest.raises(NonCanonicalEncoding) as raised:
        decode_value(bytes.fromhex("a21818000100"))
    # The out-of-order key itself: `a2` then key 24 across bytes 1 and 2, its value at 3.
    assert raised.value.at == 4


# --- Schema validation names the offending field (R8.6's material) ----------------------------


def _violation(value: Value | Message) -> SchemaViolationError:
    with pytest.raises(SchemaViolationError) as raised:
        validate(value)
    return raised.value


def test_a_value_that_is_not_a_map_is_not_a_message() -> None:
    assert _violation(7).field == ROOT_IDENTITY


def test_a_missing_envelope_key_is_named() -> None:
    message = _example_message("fs.ack")
    del message[ENVELOPE_KEY_ID]
    assert _violation(message).field == "id"


def test_an_undeclared_envelope_key_is_named_by_its_number() -> None:
    message = _example_message("fs.ack")
    message[5] = 0
    assert _violation(message).field == "5"


def test_a_non_integer_envelope_key_is_refused() -> None:
    envelope: dict[Value, Value] = {
        key: item for key, item in _example_message("fs.ack").items()
    }
    envelope["v"] = 1
    assert _violation(envelope).field == "'v'"


@pytest.mark.parametrize(
    ("t", "key", "replacement", "expected_field"),
    [
        ("fs.ack", ENVELOPE_KEY_TYPE, 0, "t"),
        ("fs.ack", ENVELOPE_KEY_TYPE, "exec.undeclared", "t"),
        ("fs.ack", ENVELOPE_KEY_BODY, 0, "b"),
        ("fs.ack", ENVELOPE_KEY_ID, "not-bytes", "id"),
    ],
)
def test_an_inadmissible_envelope_value_is_named(
    t: str, key: int, replacement: Value, expected_field: str
) -> None:
    message = _example_message(t)
    message[key] = replacement
    assert _violation(message).field == expected_field


@pytest.mark.parametrize(
    ("t", "body", "expected_field"),
    [
        # An undeclared body key, named by its number under the body.
        ("fs.ack", {1: 0}, "b.1"),
        ("fs.read", {1: INVALID_UTF8, 2: 0}, "b.2"),
        # A required field absent.
        ("fs.read", {}, "b.path"),
        # A field of the wrong type.
        ("fs.read", {1: "a text path"}, "b.path"),
        ("exec.chunk", {1: 0, 2: "text output"}, "b.data"),
        # A boolean where an integer belongs: simple value 21 is not integer 1.
        ("exec.chunk", {1: True, 2: b""}, "b.stream"),
        # An integer outside its declared range.
        ("exec.chunk", {1: 2, 2: b""}, "b.stream"),
        ("exec.result", {1: 256, 2: b"", 3: b""}, "b.exitCode"),
        # A text value outside its closed enum.
        (
            "proc.status",
            {1: INVALID_UTF8, 2: "sleeping"},
            "b.state",
        ),
        # A text value with no UTF-8 encoding.
        ("port.url", {1: "\ud800"}, "b.url"),
        # Nested: inside a list of structs, and inside a map's keys and values.
        (
            "fs.listing",
            {1: [{1: INVALID_UTF8, 2: "block-device", 3: 0}]},
            "b.entries[0].kind",
        ),
        (
            "fs.listing",
            {1: [{1: INVALID_UTF8, 2: "file", 3: 0}, "not a struct"]},
            "b.entries[1]",
        ),
        (
            "exec.request",
            {1: [INVALID_UTF8], 2: INVALID_UTF8, 3: {"text key": b""}, 4: 0, 5: True},
            "b.env[0].key",
        ),
        (
            "exec.request",
            {1: [INVALID_UTF8], 2: INVALID_UTF8, 3: {b"": 0}, 4: 0, 5: True},
            "b.env[0].value",
        ),
        (
            "exec.request",
            {1: [0], 2: INVALID_UTF8, 3: {}, 4: 0, 5: True},
            "b.argv[0]",
        ),
    ],
)
def test_an_inadmissible_body_field_is_named(
    t: str, body: dict[Value, Value], expected_field: str
) -> None:
    message = _example_message(t)
    message[ENVELOPE_KEY_BODY] = body
    assert _violation(message).field == expected_field


def test_an_omitted_optional_field_is_admissible() -> None:
    """`proc.status.exitCode` is absent while the process is running."""
    message = _example_message("proc.status", include_optional=False)
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    assert 3 not in body
    assert decode(encode(message)) == message


# --- The encoder emits only what this codec would accept back ---------------------------------


def test_encode_refuses_a_version_outside_the_supported_range() -> None:
    """So an unsupported-version input can only be built by byte surgery, never by encoding."""
    message = _example_message("fs.ack")
    message[ENVELOPE_KEY_VERSION] = CATALOGUE.supported_max + 1
    with pytest.raises(SchemaViolationError) as raised:
        encode(message)
    assert raised.value.field == "v"


def test_encode_refuses_a_message_the_catalogue_does_not_declare() -> None:
    message = _example_message("fs.ack")
    message[ENVELOPE_KEY_TYPE] = "exec.undeclared"
    with pytest.raises(SchemaViolationError):
        encode(message)


# --- Why the pinned CBOR library is a cross-check and not the codec ---------------------------


def test_the_pinned_library_agrees_on_every_declared_message() -> None:
    """An independent encoder, used as an oracle for the cases where it can be one.

    `cbor2` is pinned for this protocol, and on the catalogue's actual value space its canonical
    mode and this encoder produce the same bytes. That is worth asserting: it is the closest
    thing available to a second implementation of the profile without leaving Python.
    """
    for message in _example_messages():
        assert cbor2.dumps(message, canonical=True) == encode(message)


def test_the_pinned_library_orders_map_keys_by_a_superseded_rule() -> None:
    """And that is the first reason the encoder is not `cbor2.dumps(..., canonical=True)`.

    `cbor2` orders map keys shortest-encoding-first, which is RFC 7049 §3.9's canonical rule.
    RFC 8949 §4.2.1 replaced it with a plain bytewise comparison of the encoded keys. The two
    agree whenever every key of a map has the same head width, which is why the test above
    passes on this catalogue — and they disagree the moment one does not, so a map keyed across
    two major types would silently encode two ways.
    """
    keys: dict[Value, Value] = {-1: 0, 24: 0}
    assert cbor2.dumps(keys, canonical=True).hex() == "a22000181800"
    assert encode_value(keys).hex() == "a21818002000"


@pytest.mark.parametrize(
    "wire",
    [
        bytes.fromhex("5f43616263ff"),  # An indefinite-length byte string.
        bytes.fromhex("1817"),  # A non-shortest head.
        bytes.fromhex("a21818000100"),  # Map keys out of order.
        bytes.fromhex("a201000100"),  # A duplicate map key.
        bytes.fromhex("a20000f400"),  # Keys that collapse once decoded.
        bytes.fromhex("000000"),  # Trailing bytes after the first item.
    ],
)
def test_the_pinned_library_accepts_what_the_profile_refuses(wire: bytes) -> None:
    """And that is the second reason, the one that matters for R8.5.

    `cbor2.loads` is a permissive reader: it decodes every representation here without
    complaint, and re-encoding what it returns produces different bytes than arrived. A codec
    built on it would satisfy R8.3 and quietly fail R8.5, which is why the profile is enforced
    on the way in by this package's own decoder.
    """
    permissive = cbor2.loads(wire)
    assert cbor2.dumps(permissive, canonical=True) != wire
    with pytest.raises(NonCanonicalEncoding):
        decode_value(wire)


# --- Agreement with the shared fault generator on field identity ------------------------------


def test_every_single_field_schema_violation_is_named_acceptably() -> None:
    """The codec's field identity is one `protocol.generators.faults` accepts.

    Enumerated rather than sampled: every violation target the generator can build, against
    every declared message type, with the optional fields both present and absent. Property 4
    checks the same agreement by sampling, and adds the version faults and the phase ordering
    this says nothing about.
    """
    checked = 0
    for message in _example_messages():
        message_type = CATALOGUE.messages[str(message[ENVELOPE_KEY_TYPE])]
        for violated in violation_targets(message_type, message):
            fault = Fault(FaultKind.SCHEMA_VIOLATION, message, violated=violated)
            with pytest.raises(DecodeError) as raised:
                decode(fault.render(encode))
            assert fault.identifies(raised.value.field), (
                f"{message_type.t}: {violated.violation} on {violated.name} was reported as "
                f"{raised.value.field!r}, which is not in {sorted(fault.acceptable_field_identities)}"
            )
            checked += 1
    assert checked, "no violation target was reachable"


# --- Phase 0: the version is readable from the front, or it is not readable at all ------------


def _decode_error(wire: bytes) -> DecodeError:
    with pytest.raises(DecodeError) as raised:
        decode(wire)
    return raised.value


def test_phase_0_reads_the_version_of_every_declared_message_type() -> None:
    for message in _example_messages():
        assert read_version(encode(message)) == CATALOGUE.protocol_version


def test_phase_0_reads_a_version_no_encoder_here_would_emit() -> None:
    """Byte surgery over a canonical encoding, which is the only way such an input exists.

    Phase 0 is structural extraction, not admissibility: it reports what the representation says
    and leaves the judgement to Phase 1. A Phase 0 that refused an unsupported version would make
    R8.7's error unreachable, because there would be no received version to report.
    """
    for version in out_of_range_versions(CATALOGUE):
        fault = Fault(
            FaultKind.UNSUPPORTED_VERSION, _example_message("fs.ack"), version=version
        )
        assert read_version(fault.render(encode)) == version


def _unsorted_below_the_version(t: str) -> bytes:
    """A canonical encoding with its second and third entries transposed.

    Key 1 stays first, so Phase 0 succeeds and Phase 1 admits the version; the profile violation
    is below both, where only Phase 2 can see it.
    """
    wire = encode(_example_message(t))
    root = scan(wire)
    spans = [wire[key.start : value.end] for key, value in root.entries]
    spans[1], spans[2] = spans[2], spans[1]
    return wire[root.start : root.payload_start] + b"".join(spans)


@pytest.mark.parametrize(
    ("name", "kind", "keep_bytes"),
    [
        ("no bytes at all", FaultKind.EMPTY_WIRE, None),
        ("the map head alone", FaultKind.TRUNCATED_WIRE, 1),
        ("the map head and the version key", FaultKind.TRUNCATED_WIRE, 2),
        # Three bytes is `a4 01 01`: a readable version on an unfinished representation, which is
        # why Phase 0 establishes that the whole item is there before trusting what it read.
        ("a readable version on a truncated envelope", FaultKind.TRUNCATED_WIRE, 3),
        ("an indefinite-length envelope", FaultKind.INDEFINITE_ENVELOPE, None),
        ("the version key not first", FaultKind.VERSION_KEY_MISPLACED, None),
        ("a version that is not an integer", FaultKind.VERSION_NOT_AN_INTEGER, None),
    ],
)
def test_phase_0_failure_is_a_decode_error_naming_the_version_key(
    name: str, kind: FaultKind, keep_bytes: int | None
) -> None:
    """R8.6 for the case where the version itself is unreadable.

    Deliberately not a version error: no version was received, so there is none to report.
    """
    fault = Fault(kind, _example_message("fs.ack"), keep_bytes=keep_bytes)
    assert fault.fault_class is FaultClass.VERSION_UNREADABLE
    error = _decode_error(fault.render(encode))
    assert error.field == VERSION_IDENTITY
    assert fault.identifies(error.field)


@pytest.mark.parametrize(
    ("name", "wire"),
    [
        ("a value that is not a map", encode_value(7)),
        ("an empty map", encode_value({})),
        # Key 2 sorts after key 1, so a map that starts at 2 has no version entry to read.
        ("a map whose first key is not the version", encode_value({2: 0})),
        # A byte-string key sorts after every integer key, so it is first only if it is alone.
        ("a map whose first key is not an integer", encode_value({b"": 0})),
        ("a map whose version is a byte string", encode_value({1: b"\x01"})),
        ("a map whose version is negative", encode_value({1: -1})),
        ("a map whose version is a boolean", encode_value({1: True})),
        ("trailing bytes after the envelope", encode_value({1: 1}) + b"\x00"),
    ],
)
def test_phase_0_refuses_a_representation_it_cannot_read_a_version_from(
    name: str, wire: bytes
) -> None:
    with pytest.raises(DecodeError) as raised:
        read_version(wire)
    assert raised.value.field == VERSION_IDENTITY


# --- Phase 1: admissibility, and the version error it raises (R8.7) ---------------------------


def test_phase_1_admits_the_version_this_codec_emits() -> None:
    require_supported(CATALOGUE.protocol_version)
    for version in range(CATALOGUE.supported_min, CATALOGUE.supported_max + 1):
        require_supported(version)


def test_phase_1_reports_the_received_version_and_both_bounds() -> None:
    """All three numbers R8.7 names, and the bounds come from the catalogue."""
    for version in out_of_range_versions(CATALOGUE):
        with pytest.raises(VersionError) as raised:
            require_supported(version)
        error = raised.value
        assert error.received == version
        assert error.supported_min == CATALOGUE.supported_min
        assert error.supported_max == CATALOGUE.supported_max
        assert error.supported == (CATALOGUE.supported_min, CATALOGUE.supported_max)
        assert str(version) in str(error)
        assert str(CATALOGUE.supported_max) in str(error)


def test_decode_raises_a_version_error_for_an_unsupported_version() -> None:
    for version in out_of_range_versions(CATALOGUE):
        fault = Fault(
            FaultKind.UNSUPPORTED_VERSION, _example_message("fs.ack"), version=version
        )
        assert fault.expectation is Expectation.VERSION_ERROR
        with pytest.raises(VersionError) as raised:
            decode(fault.render(encode))
        assert raised.value.received == version


def test_the_two_error_shapes_are_distinguishable() -> None:
    """R8.8 is a claim about which of the two arrives, so neither may be the other.

    A `VersionError` that were also a `DecodeError` would make the criterion untestable: every
    `pytest.raises(DecodeError)` would pass on a version error too.
    """
    assert not issubclass(VersionError, DecodeError)
    assert not issubclass(DecodeError, VersionError)


# --- Phase 2 reports through the same decode error shape --------------------------------------


def test_a_profile_violation_below_the_version_is_a_decode_error() -> None:
    """The design calls a non-deterministic encoding a decode error, so `decode` raises one.

    It names the root rather than a field, because no field is at fault: the representation as a
    whole is one this codec could not have emitted, which is what R8.5 turns on.
    """
    for t in CATALOGUE.message_types:
        wire = _unsorted_below_the_version(t)
        # Phase 0 and Phase 1 both pass on it; only the profile check in Phase 2 objects.
        assert read_version(wire) == CATALOGUE.protocol_version
        with pytest.raises(NonCanonicalEncoding):
            decode_value(wire)
        error = _decode_error(wire)
        assert error.field == ROOT_IDENTITY


def test_a_schema_violation_reports_the_field_validation_named() -> None:
    """The mapping is a re-raise, so `decode` and `validate` cannot disagree on field identity."""
    message = _example_message("fs.read")
    message[ENVELOPE_KEY_BODY] = {1: "a text path"}
    wire = cbor2.dumps(message, canonical=True)
    with pytest.raises(SchemaViolationError) as violation:
        validate(decode_value(wire))
    assert _decode_error(wire).field == violation.value.field == "b.path"


# --- R8.8: the phase order decides which error arrives ----------------------------------------


def test_an_unsupported_version_and_a_schema_violation_together_raise_a_version_error() -> (
    None
):
    """R8.8, on exactly the input the design says a test should construct directly.

    The full cross product: every out-of-range version against every single-field violation the
    shared fault generator can build, on every declared message type. A codec that validated
    before checking the version would satisfy R8.6 and R8.7 and fail here, which is the entire
    reason the criterion exists. Property 4 samples the same domain; this enumerates it.
    """
    versions = out_of_range_versions(CATALOGUE)
    assert versions, "no out-of-range version was reachable"
    checked = 0
    for message in _example_messages():
        message_type = CATALOGUE.messages[str(message[ENVELOPE_KEY_TYPE])]
        for violated in violation_targets(message_type, message):
            for version in versions:
                fault = Fault(
                    FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION,
                    message,
                    version=version,
                    violated=violated,
                )
                assert fault.expectation is Expectation.VERSION_ERROR
                with pytest.raises(VersionError) as raised:
                    decode(fault.render(encode))
                assert raised.value.received == version
                checked += 1
    assert checked, "no violation target was reachable"


def test_the_same_violation_alone_raises_a_decode_error() -> None:
    """The control for the test above: without the version fault the violation is what surfaces.

    Without this pair, a codec that raised a version error unconditionally would pass R8.8's test.
    """
    message = _example_message("fs.read")
    violated = next(
        target
        for target in violation_targets(CATALOGUE.messages["fs.read"], message)
        if target.name == "path"
    )
    alone = Fault(FaultKind.SCHEMA_VIOLATION, message, violated=violated)
    assert alone.expectation is Expectation.DECODE_ERROR
    assert alone.identifies(_decode_error(alone.render(encode)).field)

    both = Fault(
        FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION,
        message,
        version=out_of_range_versions(CATALOGUE)[0],
        violated=violated,
    )
    with pytest.raises(VersionError):
        decode(both.render(encode))


# --- The error shapes carry what the catalogue says they report --------------------------------


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@pytest.mark.parametrize(
    ("t", "error"),
    [
        ("error.decode", DecodeError(field="v", detail="unreadable")),
        ("error.version", VersionError(received=9, supported_min=1, supported_max=1)),
    ],
)
def test_each_error_shape_carries_every_field_its_message_type_declares(
    t: str, error: CodecError
) -> None:
    """The catalogue declares the two error message types; these are what would fill them.

    Asserted rather than assumed, because the Sandbox_Runtime will render these exceptions into
    those messages, and an attribute the body declares but the exception does not carry would only
    be discovered there.
    """
    declared = [field.name for field in CATALOGUE.messages[t].body]
    assert declared
    for name in declared:
        assert hasattr(error, _snake(name)), (
            f"{t} declares body field {name}, which {type(error).__name__} does not carry"
        )
