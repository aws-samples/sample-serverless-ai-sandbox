# kiro-classification: public
"""Unit tests for the shared generators (R8.4, R8.9).

The generators are test infrastructure, so a defect in them is invisible: a domain that
quietly stopped covering the adversarial cases would leave Properties 1 through 5 passing
while asserting much less than they claim. These tests assert the coverage the design names,
rather than the properties themselves, which arrive with the codec in tasks 2.5 through 2.9.

Four things are checked here:

- every byte-typed field in the catalogue is drawn from the adversarial byte domain, quantified
  over the catalogue so a message type added with a narrower domain fails;
- every adversarial class and every length boundary the design names is reachable;
- each fault class carries the expectation the decode phase order owes it, and each
  deterministic-profile violation actually produces a non-canonical encoding;
- `catalogue.json` is what `export_catalogue` would write today, so the TypeScript half cannot
  read a stale mirror.

The canonical encoder these tests apply the fault and wire generators to is the Protocol_Codec's
own. It was a local one for as long as the codec did not exist, and it is not any more: the
non-canonical variants Property 2 quantifies over are rewrites of a canonical encoding, so if the
encoder producing that encoding were not the codec's, the property would be asserting something
about bytes the codec never emits. The fault and wire generators still take an encoder as an
argument, because the TypeScript codec has to be able to render the same faults.

None of these tests is a property test, and none carries a property tag. The design fixes 44
correctness properties, each implemented by exactly one test; a generator self-test implements
none of them — Properties 1 through 5 arrive with the codec in tasks 2.5 through 2.9 — so a tag
here would either claim a number that belongs to a later test or weaken a convention that exists
to stop a property and its test drifting apart.

Hypothesis appears here as a *sampler* rather than as a property runner, in the single place
`_sample` provides, and every sample is derandomised: a coverage claim such as "every adversarial
class is reachable" is a statement about the strategy, so it needs many draws from one strategy,
and it has to give the same answer on every run or it is a coin toss dressed as an assertion. The
same reasoning applies on the TypeScript side, where `fc.sample` is the public equivalent.
"""

from __future__ import annotations

from typing import Final

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from protocol._cbor import (
    CborScanError,
    Item,
    Major,
    encode_head,
    minimal_width,
    scan,
    wider_widths,
)
from protocol.codec import encode, encode_value
from protocol.generators import (
    ADVERSARIAL_BYTE_CLASSES,
    CBOR_LENGTH_BOUNDARIES,
    STDERR,
    STDOUT,
    Expectation,
    FaultClass,
    Scope,
    Value,
    command_spec,
    malformed,
    message,
    non_canonical_variant,
    out_of_range_versions,
    output_bytes,
    path_component,
)
from protocol.generators.byte_domains import (
    PATH_SEPARATOR,
    RESERVED_PATH_COMPONENTS,
)
from protocol.generators.export_byte_domains import (
    BYTE_DOMAINS_JSON_PATH,
)
from protocol.generators.export_byte_domains import (
    render as render_byte_domains,
)
from protocol.generators.export_byte_domains import (
    serialise as serialise_byte_domains,
)
from protocol.generators.export_catalogue import CATALOGUE_JSON_PATH, render
from protocol.generators.messages import Envelope, integer_boundaries
from protocol.generators.wire import Violation
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    TypeKind,
    TypeSpec,
    load_catalogue,
)
from tests.harness import MINIMUM_EXAMPLES

CATALOGUE = load_catalogue()

#: Draws for a coverage claim over one strategy, which needs enough of them to be a claim rather
#: than a hope. Two of the claims here are over a set of a dozen or more members drawn from four
#: weighted branches, and a thousand draws leaves the rarest of them a coin toss.
COVERAGE_DRAWS: Final = 2_000

#: Draws for a coverage claim made once per catalogue field. The catalogue declares 21 byte-typed
#: specs, so this count is paid 21 times over, which makes the suite's time the binding constraint
#: rather than the claim's strength: two of `output_bytes()`'s four branches carry an adversarial
#: run, and all but one class of run is undecodable, so a field the generator populates at all is
#: reached within the first handful of draws and a hundred more are insurance.
PER_FIELD_DRAWS: Final = 120


def _sample[T](
    strategy: st.SearchStrategy[T], count: int = MINIMUM_EXAMPLES
) -> list[T]:
    """Draw `count` examples from `strategy`, the same list on every run.

    Hypothesis is the sampler here, not the runner: `derandomize` fixes the seed and no example
    database is consulted, so a coverage assertion over the result is reproducible and a failure
    is the same failure locally and in CI. Health checks are off because these are draws rather
    than a property run — the generators reach into the cached catalogue on every draw, which
    Hypothesis reports as slow data generation on the first one.
    """
    drawn: list[T] = []

    def collect(value: T) -> None:
        drawn.append(value)

    profile = settings(
        max_examples=count,
        derandomize=True,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    given(value=strategy)(profile(collect))()
    return drawn


# --- The canonical encoder the fault and wire generators are applied to ---------------------


def _encode_envelope(envelope: Envelope) -> bytes:
    """The codec's serialise, as the `Encoder` the fault generator asks for.

    A thin adapter rather than a second encoder: `encode` also validates against the catalogue,
    and every message a fault is applied to is a valid one, because a fault is byte surgery over
    a well-formed encoding.
    """
    return encode(envelope)


def test_the_codec_encoder_emits_the_profile_the_scanner_accepts() -> None:
    """The scanner rejects non-canonical input, so it is the check on what the encoder emits."""
    encoded = encode_value({1: 1, 2: "exec.request", 3: b"", 4: {1: b"\xff" * 300}})
    root = scan(encoded)
    assert root.major is Major.MAP
    assert root.argument == 4
    assert root.end == len(encoded)


def test_the_codec_encoder_writes_shortest_form_heads() -> None:
    for value in _sample(st.integers(min_value=0, max_value=(1 << 64) - 1)):
        encoded = encode_value(value)
        assert len(encoded) == 1 + minimal_width(value)


# --- The byte domains, which are what Properties 3 and 5 quantify over ----------------------


def test_output_bytes_draws_byte_sequences_within_the_ceiling() -> None:
    for data in _sample(output_bytes(max_size=512)):
        assert isinstance(data, bytes)
        assert len(data) <= 512


def test_output_bytes_reaches_every_adversarial_class() -> None:
    """Each named class is reachable, so none has been dropped by a later edit.

    Membership is a substring test rather than equality because three of the four branches
    splice a class member into surrounding arbitrary bytes.
    """
    seen: set[str] = set()
    for example in _sample(output_bytes(max_size=512), COVERAGE_DRAWS):
        for name, sequences in ADVERSARIAL_BYTE_CLASSES.items():
            if any(sequence in example for sequence in sequences):
                seen.add(name)
    assert seen == set(ADVERSARIAL_BYTE_CLASSES)


def test_output_bytes_reaches_every_length_boundary_that_fits() -> None:
    """A codec that mis-selects a length-prefix width fails only at a crossing."""
    expected = {size for size in CBOR_LENGTH_BOUNDARIES if size <= 512}
    lengths = {
        len(example) for example in _sample(output_bytes(max_size=512), COVERAGE_DRAWS)
    }
    assert expected <= lengths


def test_no_adversarial_sequence_is_valid_utf8() -> None:
    """The domain's whole purpose: R8.9 is about sequences a text codec would corrupt."""
    for name, sequences in ADVERSARIAL_BYTE_CLASSES.items():
        if name == "nul-run":
            continue  # NUL is valid UTF-8; its hazard is C string truncation, not decoding.
        for sequence in sequences:
            with pytest.raises(UnicodeDecodeError):
                sequence.decode("utf-8")


def test_path_component_is_a_usable_linux_filename() -> None:
    for component in _sample(path_component()):
        assert component
        assert 0x00 not in component
        assert PATH_SEPARATOR not in component
        assert component not in RESERVED_PATH_COMPONENTS


# --- `message()`, derived from the catalogue rather than restating it ------------------------


def test_the_catalogue_declares_byte_typed_fields_to_quantify_over() -> None:
    """Guards the two tests below against passing vacuously on an empty catalogue."""
    assert list(CATALOGUE.byte_typed_fields())


def test_message_populates_only_declared_keys_with_admissible_values() -> None:
    """Every drawn message matches its type's schema, key by key.

    This is the assertion that makes `message()` derived rather than merely adjacent to the
    catalogue: it walks the same `TypeSpec` the codec will validate against, so a generator
    that populated a field with the wrong type fails here rather than inside Property 1, where
    it would be indistinguishable from a codec defect.
    """

    for drawn in _sample(message()):
        message_type = CATALOGUE.messages[str(drawn[ENVELOPE_KEY_TYPE])]
        body = drawn[ENVELOPE_KEY_BODY]
        assert isinstance(body, dict)

        declared = {field.key: field for field in message_type.body}
        assert set(body) <= set(declared)
        for field in message_type.body:
            if not field.optional:
                assert field.key in body, f"{message_type.t}.{field.name} is required"
        for key, value in body.items():
            assert isinstance(key, int)
            field = declared[key]
            _assert_admissible(value, field.spec, f"{message_type.t}.{field.name}")


def test_message_carries_the_emitted_version_and_a_declared_type() -> None:
    assert CATALOGUE.supports(CATALOGUE.protocol_version)
    for drawn in _sample(message()):
        assert drawn[ENVELOPE_KEY_VERSION] == CATALOGUE.protocol_version
        assert drawn[ENVELOPE_KEY_TYPE] in CATALOGUE.messages
        assert isinstance(drawn[ENVELOPE_KEY_ID], bytes)


def test_message_draws_every_type_in_the_catalogue() -> None:
    """A type the generator never draws is a type Property 1 never covers."""
    drawn = {
        str(example[ENVELOPE_KEY_TYPE])
        for example in _sample(message(), COVERAGE_DRAWS)
    }
    assert drawn == set(CATALOGUE.message_types)


def test_every_byte_typed_field_is_drawn_from_the_adversarial_domain() -> None:
    """The generator reaches an invalid-UTF-8 value in each annotated field (R8.9).

    Quantified over `byte_typed_fields()`, so a message type added with an output or name field
    that the generator populates from a narrower domain is a failure rather than an omission.
    """
    unreached: list[str] = []
    for t, field, _spec in CATALOGUE.byte_typed_fields():
        examples = _sample(message(types=[t]), PER_FIELD_DRAWS)
        if not any(
            _holds_invalid_utf8(example[ENVELOPE_KEY_BODY], field.key)
            for example in examples
        ):
            unreached.append(f"{t}.{field.name}")
    assert not unreached, f"never drew invalid UTF-8 into: {', '.join(unreached)}"


def test_integer_boundaries_include_the_declared_bounds_and_stay_inside_them() -> None:
    """The design's Property 1 generator names the declared bounds specifically."""
    checked = 0
    for message_type in CATALOGUE.messages.values():
        for field in message_type.body:
            for spec in field.spec.walk():
                if spec.range is None:
                    continue
                checked += 1
                values = integer_boundaries(spec.range)
                assert spec.range.min in values
                assert spec.range.max in values
                assert all(spec.range.min <= v <= spec.range.max for v in values)
                assert list(values) == sorted(values)
    assert checked, "the catalogue declares no integer ranges to draw boundaries from"


# --- `non_canonical_variant()`, the second half of Property 2 -------------------------------


def test_every_deterministic_profile_rule_is_reachable() -> None:
    """Each rule the profile fixes is reachable in every message.

    An unsorted-key variant needs a map with two or more entries. The envelope has four, so
    every message reaches all four rules, and the assertion is per message rather than over the
    union — a rule reachable only in the one message type that happens to carry a nested map
    would be a narrowing this would otherwise hide.
    """
    for canonical in _canonical_encodings():
        reached = {
            variant.violation
            for variant in _sample(non_canonical_variant(canonical), 60)
        }
        assert reached == set(Violation), f"only reached {sorted(reached)}"


def test_a_variant_differs_from_the_canonical_encoding_it_rewrites() -> None:
    for canonical in _canonical_encodings():
        for variant in _sample(non_canonical_variant(canonical), 30):
            assert variant.canonical == canonical
            assert variant.wire != canonical
            assert 0 <= variant.at < len(canonical)


def test_a_variant_violates_the_profile_rather_than_well_formedness() -> None:
    """The rewrite has to be *equivalent*, or Property 2 tests parsing, not the profile.

    The scanner accepts only the profile, so it is the discriminator: three of the four rules
    make it raise, and the fourth leaves a well-formed encoding whose keys no longer ascend.
    That distinction is the point — an unsorted map parses cleanly under any CBOR reader, which
    is why a codec can accept it by accident and why R8.5 has to be asserted rather than assumed.
    """
    for canonical in _canonical_encodings():
        for variant in _sample(non_canonical_variant(canonical), 40):
            if variant.violation is Violation.UNSORTED_MAP_KEYS:
                rescanned = scan(variant.wire)
                assert not _keys_ascend(variant.wire, rescanned)
            else:
                with pytest.raises(CborScanError):
                    scan(variant.wire)


def test_wider_widths_offers_a_non_shortest_encoding_of_the_same_value() -> None:
    for argument in (0, 1, 23, 24, 255, 256, 65535):
        for width in wider_widths(argument):
            assert width > minimal_width(argument)
            widened = encode_head(Major.UINT, argument, width)
            assert len(widened) == 1 + width
            with pytest.raises(CborScanError):
                scan(widened)


# --- `malformed()`, which is what Property 4 quantifies over ---------------------------------


def test_each_fault_class_carries_the_expectation_the_phase_order_owes_it() -> None:
    """Phase 1 precedes Phase 2, so an unsupported version outranks a schema violation."""
    version_bearing = {
        FaultClass.VERSION_UNSUPPORTED,
        FaultClass.VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION,
    }

    for fault in _sample(malformed()):
        if fault.fault_class in version_bearing:
            assert fault.expectation is Expectation.VERSION_ERROR
            assert fault.version is not None
            assert not CATALOGUE.supports(fault.version)
        else:
            assert fault.expectation is Expectation.DECODE_ERROR
            assert fault.acceptable_field_identities


def test_a_fault_renders_to_bytes_that_are_not_the_well_formed_encoding() -> None:
    for fault in _sample(malformed()):
        rendered = fault.render(_encode_envelope)
        assert rendered != _encode_envelope(fault.message)


def test_malformed_reaches_all_four_fault_classes() -> None:
    """The cross-product class is the one that discriminates the phase order."""
    drawn = {fault.fault_class for fault in _sample(malformed(), 1_000)}
    assert drawn == set(FaultClass)


def test_the_cross_product_pairs_every_version_with_every_violation_scope() -> None:
    """Not an anecdote: both scopes are reached alongside an out-of-range version."""
    both = [
        fault
        for fault in _sample(malformed(), COVERAGE_DRAWS)
        if fault.fault_class is FaultClass.VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION
    ]
    assert both
    assert {fault.violated.scope for fault in both if fault.violated} == set(Scope)
    versions = {fault.version for fault in both}
    assert len(versions) > 1


def test_out_of_range_versions_are_derived_from_the_declared_range() -> None:
    versions = out_of_range_versions(CATALOGUE)
    assert versions
    assert all(not CATALOGUE.supports(version) for version in versions)
    assert CATALOGUE.supported_max + 1 in versions
    assert CATALOGUE.protocol_version not in versions


def test_a_decode_error_fault_names_the_field_it_violates() -> None:
    """`identifies` is how Property 4 checks the reported field without pinning a spelling."""

    for fault in _sample(malformed()):
        if fault.expectation is not Expectation.DECODE_ERROR:
            continue
        for spelling in fault.acceptable_field_identities:
            assert fault.identifies(spelling)
        assert not fault.identifies("a-field-no-codec-would-name")


# --- `command_spec()`, the runtime half of Property 5 ----------------------------------------


def test_command_spec_streams_partition_into_the_captured_output() -> None:
    """The concatenation Property 5 asserts is a property of the drawn schedule too."""
    exit_range = CATALOGUE.messages["exec.result"].field_by_name("exitCode").spec.range
    assert exit_range is not None

    for spec in _sample(command_spec()):
        assert exit_range.min <= spec.exit_code <= exit_range.max
        joined = b"".join(chunk.data for chunk in spec.chunks)
        assert len(joined) == len(spec.stdout) + len(spec.stderr)
        assert all(chunk.stream in (STDOUT, STDERR) for chunk in spec.chunks)


def test_command_spec_reaches_an_interleaved_schedule() -> None:
    """A property asserting the streams stay separate is vacuous without one."""
    assert any(spec.interleaves for spec in _sample(command_spec(), 500))


def test_command_spec_reaches_a_negative_exit_code() -> None:
    """`exitCode` is signed because termination by signal N is reported as -N."""
    assert any(spec.exit_code < 0 for spec in _sample(command_spec(), 500))


# --- The mirror the TypeScript half reads ---------------------------------------------------


def test_catalogue_json_is_the_mirror_export_catalogue_would_write() -> None:
    """A stale mirror silently narrows the TypeScript generators, so it fails the suite.

    Regenerate with `python -m protocol.generators.export_catalogue`.
    """
    assert CATALOGUE_JSON_PATH.read_text(encoding="utf-8") == render(CATALOGUE)


def test_byte_domains_json_is_the_mirror_the_exporter_would_write() -> None:
    """The adversarial domain the TypeScript half reads is this one, not a copy of it.

    Regenerate with `python -m protocol.generators.export_byte_domains`.
    """
    assert BYTE_DOMAINS_JSON_PATH.read_text(encoding="utf-8") == render_byte_domains()


def test_the_byte_domain_mirror_carries_every_class_and_boundary() -> None:
    """The mirror is the whole domain, so nothing reaches TypeScript narrowed."""
    mirrored = serialise_byte_domains()
    assert set(mirrored["adversarialByteClasses"]) == set(ADVERSARIAL_BYTE_CLASSES)
    for name, sequences in ADVERSARIAL_BYTE_CLASSES.items():
        assert mirrored["adversarialByteClasses"][name] == [s.hex() for s in sequences]
    assert mirrored["cborLengthBoundaries"] == list(CBOR_LENGTH_BOUNDARIES)
    assert mirrored["pathSeparator"] == PATH_SEPARATOR
    assert mirrored["reservedPathComponents"] == [
        component.hex() for component in RESERVED_PATH_COMPONENTS
    ]


# --- Helpers --------------------------------------------------------------------------------


def _canonical_encodings() -> list[bytes]:
    """One canonical encoding per message type in the catalogue.

    The wire generator takes bytes rather than a strategy, so its tests iterate encodings
    directly instead of nesting a draw inside a Hypothesis example.
    """
    return [
        _encode_envelope(_sample(message(types=[t]), 1)[0])
        for t in CATALOGUE.message_types
    ]


def _holds_invalid_utf8(body: Value, key: int) -> bool:
    """Whether the value at `key` carries, anywhere inside it, undecodable bytes."""
    if not isinstance(body, dict) or key not in body:
        return False
    return any(_is_invalid_utf8(found) for found in _walk_values(body[key]))


def _walk_values(value: Value) -> list[Value]:
    if isinstance(value, list):
        return [inner for item in value for inner in _walk_values(item)]
    if isinstance(value, dict):
        return [
            inner
            for key, item in value.items()
            for inner in (*_walk_values(key), *_walk_values(item))
        ]
    return [value]


def _is_invalid_utf8(value: Value) -> bool:
    if not isinstance(value, bytes):
        return False
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _keys_ascend(wire: bytes, root: Item) -> bool:
    """Whether every map in `wire` has its keys in ascending encoded-byte order.

    The scanner records offsets, so the encoded form of a key is the slice it spans. That is
    the comparison RFC 8949's deterministic profile specifies, rather than a comparison of
    decoded key values, which would order `256` before `24`.
    """
    for item in root.walk():
        if item.major is not Major.MAP:
            continue
        encoded = [wire[key.start : key.end] for key, _value in item.entries]
        if encoded != sorted(encoded):
            return False
    return True


def _assert_admissible(value: Value, spec: TypeSpec, where: str) -> None:
    """Assert `value` is admissible for `spec`, recursing into containers."""
    match spec.kind:
        case TypeKind.UINT | TypeKind.INT:
            assert isinstance(value, int) and not isinstance(value, bool), where
            assert spec.range is not None
            assert spec.range.min <= value <= spec.range.max, f"{where}={value}"
        case TypeKind.BOOL:
            assert isinstance(value, bool), where
        case TypeKind.TEXT:
            assert isinstance(value, str), where
            if spec.enum is not None:
                assert value in spec.enum, f"{where}={value!r}"
        case TypeKind.BYTES:
            assert isinstance(value, bytes), where
        case TypeKind.LIST:
            assert isinstance(value, list), where
            assert spec.items is not None
            for index, item in enumerate(value):
                _assert_admissible(item, spec.items, f"{where}[{index}]")
        case TypeKind.MAP:
            assert isinstance(value, dict), where
            if spec.keys is not None and spec.values is not None:
                for key, item in value.items():
                    _assert_admissible(key, spec.keys, f"{where}.<key>")
                    _assert_admissible(item, spec.values, f"{where}[{key!r}]")
        case TypeKind.STRUCT:
            assert isinstance(value, dict), where
            declared = {field.key: field for field in spec.fields}
            assert set(value) <= set(declared), where
            for key, item in value.items():
                assert isinstance(key, int)
                field = declared[key]
                _assert_admissible(item, field.spec, f"{where}.{field.name}")
