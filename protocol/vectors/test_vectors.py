# kiro-classification: public
"""The Python half of the cross-implementation comparison, plus the corpus's own coverage.

Two jobs, and they are different jobs. The first is the comparison itself: for every vector,
Python decodes the committed bytes field by field and encodes the declared fields back to bytes,
which is the same pair of assertions `vectors.test.ts` makes about the same two files. The
second is the corpus's coverage, asserted here rather than assumed, because a corpus is only as
good as what it contains and a regeneration that quietly narrowed it would otherwise leave both
languages agreeing about less than they did yesterday while staying green.

No `@given` anywhere. This is not one of the 44 properties — it is the check that the four the
codec claims mean what they appear to mean — and a corpus check should read fixed vectors rather
than draw fresh ones, or the two languages would not be comparing the same bytes. Hypothesis
appears in `export_vectors.py` as a derandomised sampler and nowhere here.

#### Why this file asserts both directions when TypeScript asserts them too

Because the two directions in one language are not the claim. The claim is that the four legs
agree: Python's encoder, Python's decoder, TypeScript's encoder and TypeScript's decoder all
pinned to one committed `wire` and one committed field list. Each language asserting
`decode(wire) == fields` and `encode(fields) == wire` gives exactly that, and gives the reverse
direction the task requires without a second artefact: TypeScript's own encoding of the declared
fields is asserted equal to `wire`, and `wire` is what Python decodes here, so the bytes
TypeScript produces are bytes Python reads correctly. A corpus that only asserted TypeScript
could read Python's bytes would leave TypeScript's encoder checked against nothing but itself.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path as FilePath
from typing import Final

import pytest

from protocol.codec import (
    DecodeError,
    NonCanonicalEncoding,
    Value,
    VersionError,
    decode,
    decode_value,
    encode,
    encode_value,
)
from protocol.generators.byte_domains import ADVERSARIAL_BYTE_CLASSES
from protocol.generators.faults import FaultKind
from protocol.generators.wire import Violation
from protocol.schema import ENVELOPE_KEY_BODY, TypeSpec, load_catalogue
from protocol.vectors import (
    MESSAGES_JSON_PATH,
    REJECTIONS_JSON_PATH,
    VALUES_JSON_PATH,
    Expect,
    MessageVector,
    Path,
    as_value,
    describe_path,
    leaves,
    load_messages,
    load_rejections,
    load_values,
    resolve,
)
from protocol.vectors.export_vectors import (
    build_messages,
    build_rejections,
    build_values,
    render_messages,
    render_rejections,
    render_values,
)

CATALOGUE = load_catalogue()

MESSAGES: Final = load_messages()
VALUES: Final = load_values()
REJECTIONS: Final = load_rejections()

#: Head-width crossings a corpus has to reach, since a width-selection bug fails only at one.
#: All are inside `exec.request.timeoutMs`, declared 0 to 4,294,967,295.
HEAD_WIDTH_CROSSINGS: Final = (0, 23, 24, 255, 256, 65535, 65536, 4294967295)


def _describe(vector: MessageVector, path: Path) -> str:
    return f"{vector.name}: {describe_path(CATALOGUE, vector.t, path)}"


# --- The corpus is the one the exporter would write today ---------------------------------------


@pytest.mark.parametrize(
    ("path", "rendered"),
    [
        (
            MESSAGES_JSON_PATH,
            lambda: render_messages(build_messages(CATALOGUE), CATALOGUE),
        ),
        (VALUES_JSON_PATH, lambda: render_values(build_values())),
        (REJECTIONS_JSON_PATH, lambda: render_rejections(build_rejections(CATALOGUE))),
    ],
    ids=["messages", "values", "rejections"],
)
def test_the_committed_corpus_is_the_one_the_exporter_writes(
    path: FilePath, rendered: Callable[[], str]
) -> None:
    """A stale corpus is a comparison against bytes no codec produces any more.

    Also where the corpus's determinism is checked rather than trusted, and in the context that
    matters: this runs inside a pytest session, which has imported most of the repository. That is
    precisely the difference that made a Hypothesis-generated corpus irreproducible — see
    `export_vectors.py` — so a regeneration that depended on which modules happened to be loaded
    would fail here rather than at review time.

    Regenerate with `python -m protocol.vectors.export_vectors`.
    """
    assert path.read_text(encoding="utf-8") == rendered()


# --- Interpretation: the committed bytes decode to the declared fields --------------------------


def test_every_message_vector_decodes_to_the_declared_fields() -> None:
    """Field by field, and no field more.

    Comparing the leaf *sets* as well as the values is what makes this a field-by-field check
    rather than a spot check: a decoder that dropped an optional field or invented an extra map
    entry would satisfy every per-path assertion and fail here.
    """
    assert MESSAGES, "the corpus is empty, so every assertion below is vacuous"
    for vector in MESSAGES:
        found = leaves(as_value(decode(vector.wire)))
        assert set(found) == set(vector.fields), (
            f"{vector.name}: decoded fields "
            f"{sorted(describe_path(CATALOGUE, vector.t, p) for p in set(found) - set(vector.fields))} "
            f"unexpected, "
            f"{sorted(describe_path(CATALOGUE, vector.t, p) for p in set(vector.fields) - set(found))} "
            f"missing"
        )
        for path, expected in vector.fields.items():
            assert found[path] == expected, (
                f"{_describe(vector, path)}: decoded {found[path]!r}, expected {expected!r}"
            )
            # Values of different kinds can compare equal in Python — `True == 1`, and `0 ==
            # False` — so the kind is asserted separately rather than left to `==`.
            assert type(found[path]) is type(expected), _describe(vector, path)


def test_every_absent_field_is_absent_from_the_decoded_message() -> None:
    """An omitted optional field is a fact about the message, not an accident of the encoding."""
    checked = 0
    for vector in MESSAGES:
        decoded = as_value(decode(vector.wire))
        for path in vector.absent:
            checked += 1
            assert not resolve(decoded, path).found, (
                f"{_describe(vector, path)} is declared absent but decoded present"
            )
    assert checked, "no vector declares an absent field, so this assertion is vacuous"


# --- Production: the declared fields encode to the committed bytes ------------------------------


def test_every_message_vector_re_encodes_to_the_committed_wire() -> None:
    """The direction that catches an encoder disagreement rather than a decoder one.

    Built from the declared fields rather than from `decode(wire)`, deliberately. Re-encoding
    what the decoder just produced tests the codec against itself, which Property 2 already does;
    building from the file tests it against the corpus, which is what the other language does too.
    """
    for vector in MESSAGES:
        rebuilt = vector.value
        assert isinstance(rebuilt, dict)
        produced = encode(
            {key: item for key, item in rebuilt.items() if isinstance(key, int)}
        )
        assert produced == vector.wire, (
            f"{vector.name}: encoded {produced.hex()}, corpus holds {vector.wire.hex()}"
        )


def test_every_value_vector_round_trips_in_both_directions() -> None:
    """The profile's own rules, above all map key ordering, at the value level."""
    assert VALUES
    for vector in VALUES:
        produced = encode_value(vector.value)
        assert produced == vector.wire, (
            f"{vector.name}: encoded {produced.hex()}, corpus holds {vector.wire.hex()}"
        )
        assert decode_value(vector.wire) == vector.value, vector.name


# --- Refusal: both codecs reject the same representations ---------------------------------------


def test_every_rejection_vector_is_refused_with_the_declared_error() -> None:
    """Agreement on refusal is half of agreement on the wire.

    R8.5's byte identity holds only because the decoder refuses every representation the encoder
    could not have emitted, so two codecs that accept different sets do not agree however well
    each one's accepted set round-trips.
    """
    assert REJECTIONS
    for vector in REJECTIONS:
        where = f"{vector.name} ({vector.wire.hex()})"
        if vector.expect is Expect.NON_CANONICAL:
            with pytest.raises(NonCanonicalEncoding):
                decode_value(vector.wire)
            continue
        if vector.expect is Expect.VERSION_ERROR:
            with pytest.raises(VersionError) as version_raised:
                decode(vector.wire)
            assert version_raised.value.received == vector.received, where
            assert version_raised.value.supported_min == CATALOGUE.supported_min, where
            assert version_raised.value.supported_max == CATALOGUE.supported_max, where
            continue
        with pytest.raises(DecodeError) as raised:
            decode(vector.wire)
        assert not isinstance(raised.value, VersionError), where
        assert raised.value.field in vector.field_identities, (
            f"{where} was refused against field {raised.value.field!r}, which is not in "
            f"{sorted(vector.field_identities)}"
        )


# --- The corpus contains what it claims to contain ----------------------------------------------


def test_every_message_type_in_the_catalogue_has_vectors() -> None:
    """Every type, not a sample: an unvectored message type is an unchecked wire format."""
    covered = {vector.t for vector in MESSAGES}
    assert covered == set(CATALOGUE.message_types), (
        f"no vectors for {sorted(set(CATALOGUE.message_types) - covered)}"
    )


def test_both_construction_halves_are_present() -> None:
    """The explicit half covers the catalogue; the sampled half covers the shared generators."""
    origins = {vector.origin for vector in MESSAGES}
    assert origins == {"explicit", "sampled"}
    for t in CATALOGUE.message_types:
        for origin in ("explicit", "sampled"):
            assert any(v.t == t and v.origin == origin for v in MESSAGES), (
                f"{t}/{origin}"
            )


def _byte_leaves() -> set[bytes]:
    return {
        value
        for vector in MESSAGES
        for value in vector.fields.values()
        if isinstance(value, bytes)
    }


def _all_leaves() -> list[Value]:
    return [value for vector in VALUES for value in leaves(vector.value).values()]


def test_every_adversarial_byte_class_survives_into_the_message_vectors() -> None:
    """The cases most worth comparing are the ones a size cap would drop first.

    `protocol/generators/messages.py` draws every byte field from `output_bytes()` whether or not
    the catalogue annotates it, so the sampled half reaches invalid UTF-8 in name-carrying fields
    as well as output-carrying ones. That only helps if the corpus kept those draws, which is
    what this asserts: per class, in a message, not merely somewhere in the repository.
    """
    present = _byte_leaves()
    for name, sequences in ADVERSARIAL_BYTE_CLASSES.items():
        assert present & set(sequences), f"no message vector carries a {name} sequence"


def test_every_annotated_byte_field_carries_an_adversarial_sequence_somewhere() -> None:
    """Per field and not merely per class, for both `carries` annotations.

    R8.9 is about output, and `carries: name` fields are the ones where a codec would most
    plausibly have been written to decode bytes as text — a filename looks like a string until a
    filesystem hands you one that is not valid UTF-8. So the assertion is that *every* annotated
    field in *every* message type has been sent an invalid sequence, not that the corpus contains
    such sequences somewhere. A field reached only by a shape that happened to give it an empty
    byte string would otherwise be a field where the two codecs have never been compared on the
    case that matters.
    """
    sequences = {
        sequence
        for class_sequences in ADVERSARIAL_BYTE_CLASSES.values()
        for sequence in class_sequences
    }
    annotated = {
        (t, field.key)
        for t, message in CATALOGUE.messages.items()
        for field in message.body
        if any(spec.carries is not None for spec in _specs(field.spec))
    }
    assert annotated, (
        "the catalogue annotates no byte field, so this assertion is vacuous"
    )

    reached = {
        (vector.t, path[1])
        for vector in MESSAGES
        for path, value in vector.fields.items()
        if len(path) >= 2
        and path[0] == ENVELOPE_KEY_BODY
        and isinstance(value, bytes)
        and value in sequences
    }
    missing = sorted(f"{t}.{key}" for t, key in annotated - reached)
    assert not missing, (
        f"annotated fields never sent an adversarial sequence: {missing}"
    )


def _specs(spec: TypeSpec) -> Iterator[TypeSpec]:
    """`spec` and every spec nested inside it, outermost first."""
    yield spec
    for nested in (spec.items, spec.keys, spec.values):
        if nested is not None:
            yield from _specs(nested)
    for field in spec.fields:
        yield from _specs(field.spec)


def test_every_adversarial_byte_sequence_is_somewhere_in_the_corpus() -> None:
    """Per sequence and not merely per class, which the value-level vectors guarantee."""
    present = _byte_leaves() | {v for v in _all_leaves() if isinstance(v, bytes)}
    missing = [
        sequence.hex()
        for sequences in ADVERSARIAL_BYTE_CLASSES.values()
        for sequence in sequences
        if sequence not in present
    ]
    assert not missing, f"absent from the corpus: {missing}"


def test_the_empty_byte_string_and_empty_containers_are_present() -> None:
    """The values a length-prefix bug reaches first."""
    assert b"" in _byte_leaves()
    leaf_values = [value for vector in MESSAGES for value in vector.fields.values()]
    assert {} in leaf_values and [] in leaf_values


def test_every_integer_head_width_crossing_is_present() -> None:
    """A codec that mis-selects a head width fails only at a crossing."""
    integers = {
        value
        for vector in MESSAGES
        for value in vector.fields.values()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    missing = [at for at in HEAD_WIDTH_CROSSINGS if at not in integers]
    assert not missing, f"no message vector carries timeoutMs-scale integers {missing}"


def test_nested_maps_with_keys_of_differing_head_width_are_present() -> None:
    """The specific divergence class this corpus exists to catch.

    A nested map whose keys differ in head width is where RFC 8949 §4.2.1's bytewise ordering
    parts company with RFC 7049 §3.9's shortest-encoding-first rule, which is what
    `cbor2.dumps(canonical=True)` still applies and what an independently written TypeScript
    codec is most likely to have reimplemented by accident. Asserted at both levels: inside a
    message, where the catalogue's `env` is the only nested map, and at value level, where key
    sets the message schema cannot express separate the two rules outright.
    """
    widths: set[int] = set()
    for vector in MESSAGES:
        for path in vector.fields:
            # A byte-string step is a nested-map key; its head width is one byte plus the width
            # its length needs.
            widths |= {
                len(encode_value(step)) - len(step)
                for step in path
                if isinstance(step, bytes)
            }
    assert len(widths) >= 3, (
        f"message vectors reach only {sorted(widths)} distinct nested-map key head widths"
    )

    named = {vector.name for vector in VALUES}
    assert {
        "map.keys.cbor2-counterexample",
        "map.keys.mixed-sign-head-widths",
        "map.keys.byte-strings-content-order",
        "map.keys.byte-strings-head-widths",
        "map.keys.mixed-major-types",
    } <= named


def test_the_recorded_counterexample_is_in_the_corpus_verbatim() -> None:
    """The design names one pair of hex strings; the corpus carries both, on opposite sides.

    `{-1: 0, 24: 0}` is `a21818002000` under the profile and `a22000181800` under `cbor2`. The
    first is a value vector that must encode and decode; the second is a rejection vector that
    must be refused. A codec that took a library's canonical form for the profile's fails both.
    """
    counterexample = next(
        v for v in VALUES if v.name == "map.keys.cbor2-counterexample"
    )
    assert counterexample.value == {-1: 0, 24: 0}
    assert counterexample.wire.hex() == "a21818002000"

    library = next(v for v in REJECTIONS if v.name == "value/cbor2-key-order")
    assert library.wire.hex() == "a22000181800"
    assert library.expect is Expect.NON_CANONICAL


def test_the_rejection_vectors_span_every_fault_kind_and_every_profile_rule() -> None:
    """Inherited taxonomies rather than a restated subset of them.

    Both sets come from the shared generators, so a fault kind or a profile rule added there
    reaches the corpus on the next regeneration. Asserting the span here is what turns that from
    an intention into a fact.
    """
    names = {vector.name for vector in REJECTIONS}
    for kind in FaultKind:
        assert f"fault/{kind}" in names, f"no rejection vector for fault kind {kind}"
    for rule in Violation:
        assert any(
            name.startswith("profile/") and name.endswith(f"/{rule}") for name in names
        ), f"no rejection vector for profile rule {rule}"
    for t in CATALOGUE.message_types:
        assert any(name.startswith(f"profile/{t}/") for name in names), t


def test_both_rejected_key_orderings_appear_as_message_level_vectors() -> None:
    """The ordering trap reached through `decode`, not only through `decode_value`.

    A value-level rejection proves the profile check refuses the bytes. A message-level one
    proves the *phase order* lets it get that far: the version is readable, first and supported,
    so Phases 0 and 1 pass and Phase 2 is what objects. Those are different claims, and only the
    second one resembles what a peer would actually send.
    """
    at_message_level = [
        v for v in REJECTIONS if v.name.endswith("/env.sorted-by-decoded-key")
    ]
    assert len(at_message_level) >= 2, (
        "the nested-map ordering trap is not reached in a message"
    )
    for vector in at_message_level:
        assert vector.expect is Expect.DECODE_ERROR
