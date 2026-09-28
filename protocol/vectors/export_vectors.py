# kiro-classification: public
"""Generate the vector corpus with the Python codec, deterministically.

The corpus is produced here and read by both languages' tests, so this module is the Python
codec acting as the *producer* of the wire and nothing else: every `wire` field in the three
committed files is `protocol.codec.encode` or `encode_value` output, or a deliberate rewrite of
one. That is what makes the TypeScript side's assertions cross-implementation rather than
self-referential.

#### Why the corpus is built two ways

Coverage of the message *catalogue* and coverage of the *value domains* are different problems,
and one construction cannot do both honestly:

- **Explicit shapes** walk every message type and assign each field a value chosen for the
  encoding decision it forces: empty, each named adversarial byte class, each end of each
  declared integer range, each CBOR head-width crossing, optional fields present and absent.
  This half is exhaustive over the catalogue by construction — a message type added to
  `messages.yaml` gets vectors here with no edit, and a field whose type changes is filled from
  the new type or fails loudly.
- **Seeded samples** fill each message type from a `random.Random` at a fixed seed, drawing byte
  fields from the same four-branch domain `output_bytes()` uses — arbitrary bytes, the named
  adversarial sequences, lengths that cross a CBOR length-prefix boundary, and arbitrary bytes
  with an adversarial run spliced in. Every byte field is drawn from it whether or not the
  catalogue annotates the field, which is the same deliberate choice
  `protocol/generators/messages.py` documents, so this half reaches invalid UTF-8 in
  name-carrying fields and not only in output-carrying ones.

Neither half is allowed to sample the other's cases away: `test_vectors.py` asserts that every
message type, every adversarial byte class and every head-width crossing is present in the
committed corpus, so a change here that quietly narrowed it fails rather than reducing coverage.

#### Why Hypothesis does not generate the corpus

It cannot, at the pinned version, and this is worth recording rather than working around
silently. Hypothesis 6.165 harvests constants from every *local* module present in `sys.modules`
and injects them into primitive draws. The set of loaded modules differs between
`python -m protocol.vectors.export_vectors` and a `pytest` session that has imported the rest of
the repository, so the same strategy at the same seed with `derandomize=True` and `database=None`
yields different bytes in the two contexts. That is fine for the existing `_sample` uses in
`test_property_2.py` and `test_generators.py`, which assert *set coverage* and are indifferent to
which representative they got. It is fatal for a committed artefact, whose whole value is that
the bytes are the same ones the other language reads.

Suppressing the behaviour would mean monkeypatching a private cache, which is a hidden dependency
on an internal API that a pinned-version bump would break by producing a quietly different
corpus. So the sampler here is an explicit `random.Random`, and the domains it draws from are the
shared ones. Determinism is then checked rather than asserted: `test_vectors.py` regenerates the
corpus and compares it byte for byte with the committed copy, in a pytest process, which is the
context that exposed the problem in the first place.

The sampled half is also capped by encoded size, because the boundary-length branch reaches
65,536 bytes and a corpus is a file people read in diffs.

#### The map key ordering trap, which is the point of `values.json`

RFC 8949 §4.2.1 orders map keys by a bytewise comparison of their *encoded* forms. Two other
rules look right and are not: RFC 7049 §3.9's shortest-encoding-first ordering, which
`cbor2.dumps(..., canonical=True)` still applies, and a comparison of the *decoded* keys, which
is what an implementer writes when the keys happen to be byte strings. Each disagrees with the
profile as soon as keys differ in head width, and each is a plausible independent
implementation, so this is where two hand-written codecs drift. `values.json` therefore carries
key sets that separate all three rules, and `rejections.json` carries the encodings the other
two rules would have produced, which both codecs must refuse.

Run it with `python -m protocol.vectors.export_vectors`.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path as FilePath
from typing import Any, Final

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
from protocol.codec import Value, encode, encode_value
from protocol.generators.byte_domains import (
    ADVERSARIAL_BYTE_CLASSES,
    ADVERSARIAL_BYTE_SEQUENCES,
    CBOR_LENGTH_BOUNDARIES,
)
from protocol.generators.faults import (
    Expectation,
    Fault,
    FaultKind,
    SchemaViolation,
    out_of_range_versions,
    violation_targets,
)
from protocol.generators.messages import MAX_CONTAINER_SIZE, integer_boundaries
from protocol.generators.wire import Violation
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Catalogue,
    Field,
    IntRange,
    TypeKind,
    TypeSpec,
    load_catalogue,
)
from protocol.vectors.model import (
    MESSAGES_JSON_PATH,
    REJECTIONS_JSON_PATH,
    VALUES_JSON_PATH,
    Expect,
    Index,
    MapKey,
    MessageVector,
    Path,
    RejectionVector,
    ValueVector,
    describe_path,
    leaves,
    replace_at,
    step_to_json,
    to_tagged,
)

__all__ = [
    "MAX_SAMPLED_WIRE_BYTES",
    "SAMPLES_PER_TYPE",
    "build_messages",
    "build_rejections",
    "build_values",
    "main",
    "render_messages",
    "render_rejections",
    "render_values",
]

#: Seeded draws per message type. Four rather than forty: the explicit half already covers the
#: catalogue exhaustively, and this half exists to reach combinations a hand-written shape would
#: not have thought of.
SAMPLES_PER_TYPE: Final = 4

#: A sampled vector larger than this is redrawn. The boundary-length branch reaches 65,536 bytes,
#: and one such draw would be larger than the rest of the corpus put together while testing
#: nothing the explicit length shapes do not already test.
MAX_SAMPLED_WIRE_BYTES: Final = 512

#: Draw budget per message type, so the size cap cannot loop forever.
_SAMPLE_BUDGET: Final = 60

#: The seed. Any fixed value does; it is written down so a regeneration is reproducible and so a
#: deliberate reshuffle of the sampled half is a visible one-line change rather than a silent one.
SAMPLE_SEED: Final = 20250824

#: Ceilings for the sampled half. Lower than `protocol/generators/messages.py`'s, because these
#: bound a *committed file* rather than a draw that is discarded after one assertion: the shared
#: generator's job is to reach the whole domain and this one's is to record a readable sample of
#: it. The explicit shapes and `values.json` carry the length boundaries above these ceilings, so
#: nothing is lost — `string.length-boundaries` reaches 256 bytes and the boundary vectors reach
#: the full declared integer ranges.
MAX_SAMPLED_BYTES: Final = 64
MAX_NESTED_BYTES: Final = 24
MAX_CORRELATION_ID_BYTES: Final = 16
MAX_TEXT_LENGTH: Final = 16

#: Text that is not an enum value: ASCII, two-byte, three-byte and four-byte UTF-8 in one
#: string, so a text field exercises the length-prefix width its byte length lands in rather
#: than the character count a naive encoder might use.
_TEXT_SAMPLE: Final = "aä中\U0001f600"

#: Byte-string keys whose *encoded* order differs from their *decoded* order.
#:
#: Encoded: `4100` < `41ff` < `420000`, so the profile orders them b"\x00", b"\xff", b"\x00\x00".
#: Decoded: b"\x00" < b"\x00\x00" < b"\xff". A codec comparing the keys themselves rather than
#: their encodings puts the second and third the other way round and produces bytes this codec
#: refuses — which is why the same key set appears in `rejections.json` under that other rule.
_CONTENT_ORDER_KEYS: Final[tuple[bytes, ...]] = (b"\x00", b"\xff", b"\x00\x00")

#: Byte-string keys spanning three head widths: `40`, `57…`, `5818…`, `590100…`.
_HEAD_WIDTH_KEYS: Final[tuple[bytes, ...]] = (b"", b"k" * 23, b"k" * 24, b"k" * 256)


@dataclass(frozen=True, slots=True)
class Shape:
    """One rule for filling every field of a message, so a vector is reproducible by name."""

    name: str
    #: Byte fields take sequences from here in order, cycling.
    byte_pool: tuple[bytes, ...]
    #: Which end of a declared integer range an integer field takes.
    integer: str
    boolean: bool
    #: Which end of an enum a text field takes; free text takes `""` or `_TEXT_SAMPLE`.
    text: str
    #: How many entries a list or map field carries.
    entries: int
    #: Whether optional fields are present.
    optional: bool


def _shapes() -> tuple[Shape, ...]:
    """The explicit shapes, one pass over the catalogue each.

    Two extremes and then one per named adversarial byte class. The classes are iterated from
    `ADVERSARIAL_BYTE_CLASSES` rather than listed, so a class added to `byte_domains.py` reaches
    the corpus on the next regeneration instead of being silently absent from it.
    """
    extremes = (
        Shape(
            name="empty",
            byte_pool=(b"",),
            integer="min",
            boolean=False,
            text="first",
            entries=0,
            optional=False,
        ),
        Shape(
            name="filled",
            byte_pool=(b"\x00\x01\x02", _TEXT_SAMPLE.encode(), b"\xff" * 24),
            integer="max",
            boolean=True,
            text="last",
            entries=2,
            optional=True,
        ),
    )
    adversarial = tuple(
        Shape(
            name=f"adversarial.{name}",
            byte_pool=tuple(sequences),
            integer="min",
            boolean=True,
            text="first",
            entries=1,
            optional=True,
        )
        for name, sequences in ADVERSARIAL_BYTE_CLASSES.items()
    )
    return extremes + adversarial


class _Filler:
    """Fills one message from a `Shape`, recording where its integer fields ended up.

    The record is what the boundary vectors are built from: an integer field nested inside a
    struct inside a list has no path until a message exists, so the positions are collected on
    the way down rather than derived afterwards from the schema a second time.
    """

    def __init__(self, shape: Shape) -> None:
        self._shape = shape
        self._at = 0
        self.integers: list[tuple[Path, IntRange]] = []

    def _bytes(self) -> bytes:
        pool = self._shape.byte_pool
        chosen = pool[self._at % len(pool)]
        self._at += 1
        return chosen

    def _integer(self, spec: TypeSpec, prefix: Path) -> int:
        if spec.range is None:  # pragma: no cover - the loader rejects such a catalogue
            raise ValueError("an integer field must declare its range")
        self.integers.append((prefix, spec.range))
        return spec.range.min if self._shape.integer == "min" else spec.range.max

    def _text(self, spec: TypeSpec) -> str:
        if spec.enum is not None:
            return spec.enum[0] if self._shape.text == "first" else spec.enum[-1]
        return "" if self._shape.text == "first" else _TEXT_SAMPLE

    def _keys(self, spec: TypeSpec, count: int) -> list[MapKey]:
        """`count` distinct keys for a map field, drawn from the shape.

        Distinctness has to be enforced rather than assumed: a pool short enough to repeat would
        collapse two entries into one and the vector would silently carry fewer fields than its
        name claims.
        """
        seen: list[MapKey] = []
        while len(seen) < count:
            drawn = self.value(spec, ())
            if isinstance(
                drawn, list | dict
            ):  # pragma: no cover - no map key is a container
                raise TypeError(f"a {spec.kind} is not a key the protocol can carry")
            candidate: MapKey = drawn
            if candidate in seen:
                candidate = (
                    candidate + bytes((len(seen),))
                    if isinstance(candidate, bytes)
                    else f"{candidate}{len(seen)}"
                )
            seen.append(candidate)
        return seen

    def value(self, spec: TypeSpec, prefix: Path) -> Value:
        match spec.kind:
            case TypeKind.UINT | TypeKind.INT:
                return self._integer(spec, prefix)
            case TypeKind.BOOL:
                return self._shape.boolean
            case TypeKind.TEXT:
                return self._text(spec)
            case TypeKind.BYTES:
                return self._bytes()
            case TypeKind.LIST:
                if spec.items is None:  # pragma: no cover - the loader rejects this
                    raise ValueError("a list must declare items")
                return [
                    self.value(spec.items, (*prefix, Index(at)))
                    for at in range(self._shape.entries)
                ]
            case TypeKind.MAP:
                if spec.keys is None or spec.values is None:
                    # The envelope's `b`, whose schema is selected by `t` rather than declared.
                    return {}
                return {
                    key: self.value(spec.values, (*prefix, key))
                    for key in self._keys(spec.keys, self._shape.entries)
                }
            case TypeKind.STRUCT:
                return self.fields(spec.fields, prefix)

    def fields(self, fields: Sequence[Field], prefix: Path) -> dict[Value, Value]:
        return {
            field.key: self.value(field.spec, (*prefix, field.key))
            for field in fields
            if self._shape.optional or not field.optional
        }


def _omitted(catalogue: Catalogue, t: str, shape: Shape) -> tuple[Path, ...]:
    """The optional body fields this shape leaves out, by path."""
    if shape.optional:
        return ()
    return tuple(
        (ENVELOPE_KEY_BODY, field.key)
        for field in catalogue.messages[t].body
        if field.optional
    )


def _vector(
    catalogue: Catalogue,
    *,
    name: str,
    t: str,
    origin: str,
    body: dict[Value, Value],
    correlation_id: bytes,
    absent: tuple[Path, ...] = (),
) -> MessageVector:
    """Assemble one message vector, encoding it with the Python codec.

    `encode` rather than `encode_value`, so the vector's bytes have passed the schema on the way
    out: a corpus carrying a representation the codec would refuse to emit would be asking the
    TypeScript side to agree about something outside the protocol.
    """
    value: Value = {
        ENVELOPE_KEY_VERSION: catalogue.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: correlation_id,
        ENVELOPE_KEY_BODY: body,
    }
    assert isinstance(value, dict)
    return MessageVector(
        name=name,
        t=t,
        origin=origin,
        wire=encode(
            {int(key): item for key, item in value.items() if isinstance(key, int)}
        ),
        fields=leaves(value),
        absent=absent,
    )


def _explicit(catalogue: Catalogue) -> Iterator[MessageVector]:
    """One vector per message type per shape."""
    for t in catalogue.message_types:
        for shape in _shapes():
            filler = _Filler(shape)
            body = filler.fields(catalogue.messages[t].body, (ENVELOPE_KEY_BODY,))
            yield _vector(
                catalogue,
                name=f"{t}/{shape.name}",
                t=t,
                origin="explicit",
                body=body,
                correlation_id=filler._bytes(),
                absent=_omitted(catalogue, t, shape),
            )


def _integer_boundary(catalogue: Catalogue) -> Iterator[MessageVector]:
    """One vector per integer field per boundary of its declared range.

    A codec that mis-selects a CBOR head width fails only at a crossing, and a crossing reached
    by chance in a random draw is a crossing that may not be reached in the next run. The base
    message carries one entry per container so that an integer nested inside a struct inside a
    list — `fs.listing.entries[0].size`, the only such field — has a position to be set at.
    """
    base = Shape(
        name="boundary",
        byte_pool=(b"",),
        integer="min",
        boolean=False,
        text="first",
        entries=1,
        optional=True,
    )
    for t in catalogue.message_types:
        filler = _Filler(base)
        body = filler.fields(catalogue.messages[t].body, (ENVELOPE_KEY_BODY,))
        envelope: Value = {ENVELOPE_KEY_BODY: body}
        for path, range_ in filler.integers:
            for at in integer_boundaries(range_):
                mutated = replace_at(envelope, path, at)
                assert isinstance(mutated, dict)
                replaced = mutated[ENVELOPE_KEY_BODY]
                assert isinstance(replaced, dict)
                yield _vector(
                    catalogue,
                    name=f"{t}/boundary{_render_path(path)}={at}",
                    t=t,
                    origin="explicit",
                    body=replaced,
                    correlation_id=b"",
                )


def _render_path(path: Path) -> str:
    """A path as a vector name carries it: `.4.1` or `.4.1[0].3`."""
    rendered = ""
    for step in path:
        rendered += f"[{step.at}]" if isinstance(step, Index) else f".{step!r}"
    return rendered.replace("'", "")


def _map_ordering(catalogue: Catalogue) -> Iterator[MessageVector]:
    """Nested maps whose keys separate the three plausible key-ordering rules.

    Built in reverse canonical order on purpose. The tagged rendering preserves that order, so
    reproducing `wire` from the vector requires actually applying RFC 8949 §4.2.1 rather than
    copying the input order — which a corpus written out already sorted would not require.
    """
    named = {
        "keys.head-width": _HEAD_WIDTH_KEYS,
        "keys.content-order": _CONTENT_ORDER_KEYS,
    }
    for t in catalogue.message_types:
        for field in catalogue.messages[t].body:
            if field.spec.kind is not TypeKind.MAP or field.spec.keys is None:
                continue
            if field.spec.keys.kind is not TypeKind.BYTES:  # pragma: no cover
                continue
            for label, keys in named.items():
                filler = _Filler(_shapes()[0])
                body = filler.fields(catalogue.messages[t].body, (ENVELOPE_KEY_BODY,))
                body[field.key] = {
                    key: bytes((at,)) for at, key in enumerate(reversed(keys))
                }
                yield _vector(
                    catalogue,
                    name=f"{t}/{field.name}.{label}",
                    t=t,
                    origin="explicit",
                    body=body,
                    correlation_id=b"",
                )


class _Sampler:
    """Fills a message from a seeded PRNG over the shared byte and integer domains.

    The four byte branches are `output_bytes()`'s, weighted equally, for the same reason it
    weights them that way: an unweighted `binary()` would make the adversarial cases a vanishing
    fraction of the domain. Applied to every byte field regardless of annotation, which is the
    choice `protocol/generators/messages.py` documents — the catalogue types a field as bytes
    because the protocol carries it verbatim, and a field the annotation happens not to cover is
    carried no differently.
    """

    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed)  # nosec B311 — not for crypto

    def _binary(self, size: int) -> bytes:
        return bytes(self._random.randrange(256) for _ in range(size))

    def bytes_value(self, ceiling: int) -> bytes:
        branch = self._random.randrange(4)
        if branch == 0:
            return self._binary(self._random.randrange(min(ceiling, 256) + 1))
        if branch == 1:
            fitting = [s for s in ADVERSARIAL_BYTE_SEQUENCES if len(s) <= ceiling]
            return self._random.choice(fitting)
        if branch == 2:
            lengths = [n for n in CBOR_LENGTH_BOUNDARIES if n <= ceiling]
            return self._binary(self._random.choice(lengths))
        run = self._random.choice(
            [s for s in ADVERSARIAL_BYTE_SEQUENCES if len(s) <= ceiling]
        )
        room = max(ceiling - len(run), 0)
        prefix = self._binary(self._random.randrange(min(room, 16) + 1))
        suffix = self._binary(self._random.randrange(min(room - len(prefix), 16) + 1))
        return prefix + run + suffix

    def integer(self, range_: IntRange) -> int:
        boundaries = integer_boundaries(range_)
        if self._random.randrange(2) == 0 and boundaries:
            return self._random.choice(boundaries)
        return self._random.randint(range_.min, range_.max)

    def text(self, spec: TypeSpec) -> str:
        if spec.enum is not None:
            return self._random.choice(list(spec.enum))
        # Surrogates excluded: CBOR major type 3 is a UTF-8 text string and a lone surrogate has
        # no UTF-8 encoding. Not a narrowing of R8.9 — the unencodable cases live in the
        # byte-typed fields, which is precisely why the protocol types them that way.
        alphabet = "aä中\U0001f600 zZ0/\\.\x7f"
        return "".join(
            self._random.choice(alphabet)
            for _ in range(self._random.randrange(MAX_TEXT_LENGTH + 1))
        )

    def value(self, spec: TypeSpec, *, nested: bool) -> Value:
        ceiling = MAX_NESTED_BYTES if nested else MAX_SAMPLED_BYTES
        match spec.kind:
            case TypeKind.UINT | TypeKind.INT:
                if spec.range is None:  # pragma: no cover - the loader rejects this
                    raise ValueError("an integer field must declare its range")
                return self.integer(spec.range)
            case TypeKind.BOOL:
                return self._random.randrange(2) == 1
            case TypeKind.TEXT:
                return self.text(spec)
            case TypeKind.BYTES:
                return self.bytes_value(ceiling)
            case TypeKind.LIST:
                if spec.items is None:  # pragma: no cover - the loader rejects this
                    raise ValueError("a list must declare items")
                return [
                    self.value(spec.items, nested=True)
                    for _ in range(self._random.randrange(MAX_CONTAINER_SIZE + 1))
                ]
            case TypeKind.MAP:
                if spec.keys is None or spec.values is None:
                    return {}
                entries: dict[Value, Value] = {}
                for _ in range(self._random.randrange(MAX_CONTAINER_SIZE + 1)):
                    entries[self.value(spec.keys, nested=True)] = self.value(
                        spec.values, nested=True
                    )
                return entries
            case TypeKind.STRUCT:
                return self.fields(spec.fields, nested=True)

    def fields(self, fields: Sequence[Field], *, nested: bool) -> dict[Value, Value]:
        """Optional fields omitted independently, as the catalogue declares them.

        Independently and not by a cross-field rule: the catalogue states none — `proc.status`
        omits `exitCode` while the process runs, but nothing in the schema ties the two — so a
        sampler that inferred one would be asserting a constraint the codec does not validate.
        """
        return {
            field.key: self.value(field.spec, nested=nested)
            for field in fields
            if not field.optional or self._random.randrange(2) == 1
        }


def _sampled(catalogue: Catalogue) -> Iterator[MessageVector]:
    """Seeded draws, one batch per message type.

    One sampler per message type rather than one for the corpus, so adding a message type to the
    catalogue does not reshuffle every other type's vectors. The seed is mixed with the type name
    for the same reason a per-type sampler exists at all.
    """
    for t in catalogue.message_types:
        sampler = _Sampler(SAMPLE_SEED + sum(t.encode()))
        kept = 0
        for at in range(_SAMPLE_BUDGET):
            if kept == SAMPLES_PER_TYPE:
                break
            body = sampler.fields(catalogue.messages[t].body, nested=False)
            correlation = sampler.bytes_value(MAX_CORRELATION_ID_BYTES)
            candidate = _vector(
                catalogue,
                name=f"{t}/sampled.{at}",
                t=t,
                origin="sampled",
                body=body,
                correlation_id=correlation,
                absent=tuple(
                    (ENVELOPE_KEY_BODY, field.key)
                    for field in catalogue.messages[t].body
                    if field.optional and field.key not in body
                ),
            )
            if len(candidate.wire) > MAX_SAMPLED_WIRE_BYTES:
                continue
            kept += 1
            yield candidate


def build_messages(catalogue: Catalogue | None = None) -> tuple[MessageVector, ...]:
    """Every valid-message vector, in a fixed order."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    built = (
        *_explicit(resolved),
        *_integer_boundary(resolved),
        *_map_ordering(resolved),
        *_sampled(resolved),
    )
    seen: dict[str, MessageVector] = {}
    for vector in built:
        if vector.name in seen:  # pragma: no cover - names are constructed distinct
            raise ValueError(f"two vectors named {vector.name!r}")
        seen[vector.name] = vector
    return tuple(seen.values())


# --- Value-level vectors -----------------------------------------------------------------------


def _ordered_map(keys: Sequence[MapKey]) -> dict[Value, Value]:
    """A map over `keys` in the order given, values chosen only to be distinguishable."""
    return {key: at for at, key in enumerate(keys)}


def build_values() -> tuple[ValueVector, ...]:
    """The profile's own encoding rules, at the level the message schema cannot reach.

    The envelope and every body map is keyed by small unsigned integers, and the one nested map
    the catalogue declares is keyed by byte strings, so the key sets that most sharply separate
    the three ordering rules — negative against unsigned, and mixed major types — are not
    expressible as a *message*. They are still the wire the two codecs share, so they are
    checked here through `encode_value` and `decode_value` directly.
    """
    heads = (0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1)
    negatives = (-1, -24, -25, -256, -257, -65536, -65537, -(2**32), -(2**64))
    lengths = (0, 1, 23, 24, 255, 256)
    return (
        _value_vector(
            "map.keys.cbor2-counterexample",
            # The literal `{-1: 0, 24: 0}`, not `_ordered_map`: this is the counterexample the
            # design names, and a reviewer should be able to read the hex straight off it.
            {-1: 0, 24: 0},
            note=(
                "The divergence the design records, value for value. cbor2's canonical=True "
                "orders these shortest-encoding first and emits a22000181800; RFC 8949 4.2.1 "
                "compares the encoded keys bytewise and emits a21818002000. The pair order "
                "below is cbor2's, so an encoder applying that rule reproduces its own bytes "
                "rather than these."
            ),
        ),
        _value_vector(
            "map.keys.mixed-sign-head-widths",
            _ordered_map((-25, -24, -1, 24, 0)),
            note=(
                "Five keys across two head widths and both integer majors. Bytewise on the "
                "encodings gives 0, 24, -1, -24, -25; shortest-encoding-first gives 0, -1, "
                "-24, 24, -25, so the two rules disagree about three of the five positions."
            ),
        ),
        _value_vector(
            "map.keys.unsigned-head-widths",
            _ordered_map(tuple(reversed(heads))),
            note=(
                "Every unsigned head width in one map, so a codec that selects the width from "
                "the value rather than from a table is exercised at each crossing."
            ),
        ),
        _value_vector(
            "map.keys.byte-strings-content-order",
            _ordered_map(tuple(reversed(_CONTENT_ORDER_KEYS))),
            note=(
                "Byte-string keys whose encoded order differs from their decoded order: the "
                "profile gives 0x00, 0xff, 0x0000 and a comparison of the keys themselves "
                "gives 0x00, 0x0000, 0xff."
            ),
        ),
        _value_vector(
            "map.keys.byte-strings-head-widths",
            _ordered_map(tuple(reversed(_HEAD_WIDTH_KEYS))),
            note=(
                "Byte-string keys at lengths 0, 23, 24 and 256, which is one, one, two and "
                "three head bytes."
            ),
        ),
        _value_vector(
            "map.keys.mixed-major-types",
            _ordered_map((True, "a", b"a", 2)),
            note=(
                "An unsigned integer, a byte string, a text string and a boolean as keys of "
                "one map. Bytewise on the encodings interleaves the majors by their head byte; "
                "shortest-encoding-first groups them by length instead."
            ),
        ),
        _value_vector(
            "map.nested-in-list-in-map",
            {
                1: [_ordered_map((-1, 24)), _ordered_map((b"\xff", b"\x00\x00"))],
                24: _ordered_map((True, 0)),
            },
            note=(
                "Three levels, so the ordering rule is applied recursively rather than only at "
                "the root."
            ),
        ),
        _value_vector(
            "integer.unsigned-head-widths",
            list(heads),
            note="Each unsigned head width as a value rather than as a key.",
        ),
        _value_vector(
            "integer.negative-head-widths",
            list(negatives),
            note=(
                "Each negative head width, where the encoded argument is -1 - n rather than n."
            ),
        ),
        _value_vector(
            "string.length-boundaries",
            [
                *(b"z" * length for length in lengths),
                *("z" * length for length in lengths),
            ],
            note=(
                "Byte and text strings at the CBOR length-prefix crossings 0, 1, 23, 24, 255 "
                "and 256."
            ),
        ),
        _value_vector(
            "string.invalid-utf8-verbatim",
            [
                sequence
                for sequences in ADVERSARIAL_BYTE_CLASSES.values()
                for sequence in sequences
            ],
            note=(
                "Every named adversarial byte sequence as a byte string, which is R8.9 at the "
                "value level: none of these has a text encoding, and all of them travel "
                "unchanged."
            ),
        ),
        _value_vector(
            "empty.containers-and-scalars",
            [b"", "", [], {}, True, False, 0, -1],
            note="The values with no payload, which a length-prefix bug reaches first.",
        ),
    )


def _value_vector(name: str, value: Value, *, note: str) -> ValueVector:
    return ValueVector(name=name, note=note, wire=encode_value(value), value=value)


# --- Rejection vectors -------------------------------------------------------------------------


def _map_item(wire: bytes, path: Sequence[int]) -> tuple[int, int]:
    """The byte span of the value at `path`, following integer map keys from the root."""
    item = scan(wire)
    for key in path:
        entry = next(
            (value for key_item, value in item.entries if key_item.argument == key),
            None,
        )
        if entry is None:  # pragma: no cover - every caller names a key it just wrote
            raise KeyError(f"no map key {key} in {wire.hex()}")
        item = entry
    return item.start, item.end


def _reordered_map(pairs: Sequence[tuple[Value, Value]]) -> bytes:
    """A definite-length map encoded with its entries in exactly the order given."""
    body = b"".join(encode_value(key) + encode_value(item) for key, item in pairs)
    return encode_head(Major.MAP, len(pairs)) + body


def _content_ordered_env(catalogue: Catalogue) -> Iterator[RejectionVector]:
    """A valid message whose nested map keys are sorted by content rather than by encoding.

    The single most valuable negative vector in the corpus, because it is the divergence class
    two independently written codecs actually fall into. Phases 0 and 1 pass — the version is
    readable, first and supported — so the refusal has to come from the profile check in Phase 2,
    and a codec that compared the keys themselves instead of their encodings would accept it and
    then re-emit different bytes than arrived, which is R8.5 broken silently.
    """
    canonical = sorted(_CONTENT_ORDER_KEYS, key=encode_value)
    by_content = sorted(_CONTENT_ORDER_KEYS)
    if (
        canonical == by_content
    ):  # pragma: no cover - the key set is chosen so they differ
        raise ValueError("the key set no longer separates the two ordering rules")

    for t in catalogue.message_types:
        for field in catalogue.messages[t].body:
            if field.spec.kind is not TypeKind.MAP or field.spec.keys is None:
                continue
            filler = _Filler(_shapes()[0])
            body = filler.fields(catalogue.messages[t].body, (ENVELOPE_KEY_BODY,))
            values: dict[Value, Value] = {
                key: bytes((at,)) for at, key in enumerate(_CONTENT_ORDER_KEYS)
            }
            body[field.key] = values
            wire = encode(
                {
                    ENVELOPE_KEY_VERSION: catalogue.protocol_version,
                    ENVELOPE_KEY_TYPE: t,
                    ENVELOPE_KEY_ID: b"",
                    ENVELOPE_KEY_BODY: body,
                }
            )
            start, end = _map_item(wire, (ENVELOPE_KEY_BODY, field.key))
            rewritten = replace(
                wire,
                start,
                end,
                _reordered_map([(key, values[key]) for key in by_content]),
            )
            yield RejectionVector(
                name=f"{t}/{field.name}.sorted-by-decoded-key",
                note="The nested map's keys are in decoded-byte order rather than "
                "encoded-byte order, which is the ordering rule RFC 8949 4.2.1 replaced. "
                "Phases 0 and 1 pass, so Phase 2's profile check is what must refuse it.",
                wire=rewritten,
                expect=Expect.DECODE_ERROR,
                field_identities=frozenset({"1", "v", "message"}),
                received=None,
            )


def _library_orderings() -> Iterator[RejectionVector]:
    """The encodings the two rejected ordering rules produce, at value level.

    `cbor2` is pinned and is an oracle in the property suite, never an authority on canonical
    form. These vectors state that plainly: the bytes a length-first encoder emits for a map the
    profile orders differently are bytes this codec refuses, so a TypeScript codec that reached
    for `cbor-x`'s idea of canonical ordering fails here rather than in production.
    """
    cases: tuple[tuple[str, dict[Value, Value], str | None, str], ...] = (
        (
            "value/cbor2-key-order",
            # The same map `values.json` carries under `map.keys.cbor2-counterexample`, so the
            # two vectors are the design's counterexample stated from both sides: the profile's
            # encoding of this value must decode, and this encoding of it must not.
            {-1: 0, 24: 0},
            "a22000181800",
            (
                "Shortest-encoding-first, which is RFC 7049 3.9 and what cbor2 canonical=True "
                "still emits. The profile's encoding of the same map is a21818002000."
            ),
        ),
        (
            "value/decoded-key-order",
            _ordered_map(_CONTENT_ORDER_KEYS),
            None,
            "Byte-string keys in decoded order rather than encoded order.",
        ),
    )
    for name, value, literal, note in cases:
        if literal is not None:
            wire = bytes.fromhex(literal)
        else:
            wire = _reordered_map(
                sorted(value.items(), key=lambda pair: _as_bytes(pair[0]))
            )
        if wire == encode_value(
            value
        ):  # pragma: no cover - both differ by construction
            raise ValueError(f"{name} is the profile's own encoding, not a rejection")
        yield RejectionVector(
            name=name,
            note=note,
            wire=wire,
            expect=Expect.NON_CANONICAL,
            field_identities=frozenset(),
            received=None,
        )


def _as_bytes(value: Value) -> bytes:
    assert isinstance(value, bytes)
    return value


def _structural(catalogue: Catalogue) -> Iterator[RejectionVector]:
    """Representations refused for reasons other than key order."""
    sample = encode(
        {
            ENVELOPE_KEY_VERSION: catalogue.protocol_version,
            ENVELOPE_KEY_TYPE: "fs.ack",
            ENVELOPE_KEY_ID: b"",
            ENVELOPE_KEY_BODY: {},
        }
    )
    yield RejectionVector(
        name="wire/empty",
        note="No bytes at all. Phase 0 has nothing to read, so the version is unreadable "
        "rather than unsupported, and the decode error names field 1.",
        wire=b"",
        expect=Expect.DECODE_ERROR,
        field_identities=frozenset({"1", "v"}),
        received=None,
    )
    yield RejectionVector(
        name="wire/truncated",
        note="A valid message with its last byte removed.",
        wire=sample[:-1],
        expect=Expect.DECODE_ERROR,
        field_identities=frozenset({"1", "v", "message"}),
        received=None,
    )
    yield RejectionVector(
        name="wire/trailing-bytes",
        note="A valid message followed by a second item. A message is one item, so decoding "
        "the first and ignoring the rest would leave bytes unaccounted for.",
        wire=sample + b"\x00",
        expect=Expect.DECODE_ERROR,
        field_identities=frozenset({"1", "v", "message"}),
        received=None,
    )
    yield RejectionVector(
        name="value/duplicate-map-keys",
        note="Two entries with the same key, in ascending order so no ordering rule objects. "
        "The profile admits neither, because re-encoding could only emit one of them.",
        wire=encode_head(Major.MAP, 2) + encode_value(1) * 2 + b"\x00\x00",
        expect=Expect.NON_CANONICAL,
        field_identities=frozenset(),
        received=None,
    )
    yield RejectionVector(
        name="value/indefinite-byte-string",
        note="One chunk, indefinite head. A permissive reader returns the same bytes; the "
        "profile refuses it because the encoder could not have produced it.",
        wire=bytes((Major.BYTES << 5 | 31,)) + encode_value(b"ab") + b"\xff",
        expect=Expect.NON_CANONICAL,
        field_identities=frozenset(),
        received=None,
    )
    yield RejectionVector(
        name="value/non-shortest-integer",
        note="Integer 1 written with a two-byte head.",
        wire=encode_head(Major.UINT, 1, 2),
        expect=Expect.NON_CANONICAL,
        field_identities=frozenset(),
        received=None,
    )


def _base(catalogue: Catalogue, t: str) -> dict[int, Value]:
    """A minimal well-formed message of type `t`, which the faults below are applied to."""
    filler = _Filler(_shapes()[0])
    return {
        ENVELOPE_KEY_VERSION: catalogue.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: b"",
        ENVELOPE_KEY_BODY: filler.fields(
            catalogue.messages[t].body, (ENVELOPE_KEY_BODY,)
        ),
    }


def _as_rejection(fault: Fault, name: str) -> RejectionVector:
    version_error = fault.expectation is Expectation.VERSION_ERROR
    return RejectionVector(
        name=name,
        note=f"From protocol.generators.faults: kind {fault.kind}, class "
        f"{fault.fault_class}, applied to {fault.message[ENVELOPE_KEY_TYPE]!r}"
        + (f", violating {fault.violated.violation}" if fault.violated else "")
        + ".",
        wire=fault.render(encode),
        expect=Expect.VERSION_ERROR if version_error else Expect.DECODE_ERROR,
        field_identities=fault.acceptable_field_identities,
        received=fault.version if version_error else None,
    )


def _from_faults(catalogue: Catalogue) -> Iterator[RejectionVector]:
    """Negative vectors built from the shared fault taxonomy, one per kind and per violation.

    `Fault` and its taxonomy are `faults.py`'s, so the corpus inherits Property 4's classification
    of a malformed representation rather than restating a subset of it: a fault kind or a schema
    violation added there appears here on the next regeneration or fails the span assertion in
    `test_vectors.py`.

    Constructed rather than drawn from `malformed()`. That is not only the determinism problem the
    module docstring describes — it is also stronger. One vector per kind *by construction* is a
    guarantee; one vector per kind from four hundred draws is a hope that the assertion afterwards
    happens to be able to confirm.
    """
    # One fixed carrier for the envelope-level kinds. `exec.request` rather than the first type
    # alphabetically, because it is the one with a body rich enough for every schema violation to
    # be reachable in it: a list, a nested map, an integer with a bounded range and a boolean.
    carrier = (
        "exec.request"
        if "exec.request" in catalogue.messages
        else catalogue.message_types[0]
    )
    base = _base(catalogue, carrier)
    unsupported = out_of_range_versions(catalogue)[0]
    targets = violation_targets(catalogue.messages[carrier], base)
    first_violation = targets[0]

    for kind in FaultKind:
        fault = Fault(
            kind=kind,
            message=base,
            version=unsupported
            if kind
            in (
                FaultKind.UNSUPPORTED_VERSION,
                FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION,
            )
            else None,
            violated=first_violation
            if kind
            in (
                FaultKind.SCHEMA_VIOLATION,
                FaultKind.UNSUPPORTED_VERSION_AND_SCHEMA_VIOLATION,
            )
            else None,
            # Three bytes: past the envelope's map head and into the first entry, so Phase 0 has
            # begun and cannot finish, which is a different failure from the empty wire above.
            keep_bytes=3 if kind is FaultKind.TRUNCATED_WIRE else None,
        )
        yield _as_rejection(fault, f"fault/{kind}")

    # One per schema violation the taxonomy declares, at the first message type where it is
    # reachable. Reachability matters: `not-in-enum` needs a field with an enum and
    # `missing-required-field` needs a required one, and no single message type has all six.
    for violation in SchemaViolation:
        for t in catalogue.message_types:
            message = _base(catalogue, t)
            target = next(
                (
                    candidate
                    for candidate in violation_targets(catalogue.messages[t], message)
                    if candidate.violation is violation
                ),
                None,
            )
            if target is None:
                continue
            yield _as_rejection(
                Fault(
                    kind=FaultKind.SCHEMA_VIOLATION, message=message, violated=target
                ),
                f"violation/{violation}",
            )
            break

    # And one body-field violation per message type, so per-type body validation is compared
    # rather than only the validation of the one type the kinds above happen to carry.
    for t in catalogue.message_types:
        message = _base(catalogue, t)
        target = next(
            (
                candidate
                for candidate in violation_targets(catalogue.messages[t], message)
                if candidate.violation is SchemaViolation.WRONG_TYPE
                and candidate.key != 2
            ),
            None,
        )
        if target is None:
            continue
        yield _as_rejection(
            Fault(kind=FaultKind.SCHEMA_VIOLATION, message=message, violated=target),
            f"violation/{t}/wrong-type",
        )


def _first(root: Item, predicate: Callable[[Item], bool]) -> Item | None:
    """The first item in scan order satisfying `predicate`, outermost first."""
    return next((item for item in root.walk() if predicate(item)), None)


def _innermost_multi_entry_map(root: Item) -> Item | None:
    """The last map with at least two entries in scan order, which is the nested one if any.

    Nested on purpose. Transposing the *envelope's* first two entries displaces key 1, which
    Phase 0 refuses before the profile check is ever reached; transposing a nested map's leaves the
    version readable, first and supported, so Phases 0 and 1 pass and Phase 2 is what objects. The
    second is the more informative vector, so it is preferred wherever a nested map exists — which
    is why this takes the last such map rather than the first.
    """
    maps = [
        item
        for item in root.walk()
        if item.major is Major.MAP and len(item.entries) >= 2
    ]
    return maps[-1] if maps else None


def _from_profile_rules(catalogue: Catalogue) -> Iterator[RejectionVector]:
    """One vector per profile rule per message type, each rewrite applied at a fixed position.

    Per message type rather than over the union, for the reason `test_property_2.py` gives: a rule
    reachable only in the type that carries a nested map would otherwise stop being reached
    without anything noticing.

    The four rewrites are RFC 8949 §4.2's four rules, the same four `protocol/generators/wire.py`
    quantifies over. They are applied here at the first eligible position rather than at a drawn
    one, because a corpus wants one fixed representative per rule and a strategy cannot supply a
    reproducible one — see the module docstring. `Violation` is still imported from `wire.py`, so
    the rule *names* remain that module's and a rule added there fails the span assertion in
    `test_vectors.py` rather than being quietly absent.
    """
    for t in catalogue.message_types:
        canonical = encode(_base(catalogue, t))
        root = scan(canonical)

        string = _first(root, lambda item: item.major in (Major.BYTES, Major.TEXT))
        if string is not None:
            payload = canonical[string.payload_start : string.end]
            yield _rule_vector(
                t,
                Violation.INDEFINITE_STRING,
                replace(
                    canonical,
                    string.start,
                    string.end,
                    bytes((string.major << 5 | INDEFINITE_INFO,))
                    + encode_head(string.major, len(payload))
                    + payload
                    + bytes((BREAK,)),
                ),
                string.start,
            )

        payload = canonical[root.payload_start : root.end]
        yield _rule_vector(
            t,
            Violation.INDEFINITE_CONTAINER,
            bytes((Major.MAP << 5 | INDEFINITE_INFO,)) + payload + bytes((BREAK,)),
            root.start,
        )

        widenable = _first(
            root, lambda item: item.has_argument and bool(wider_widths(item.argument))
        )
        if widenable is not None:
            yield _rule_vector(
                t,
                Violation.NON_SHORTEST_HEAD,
                replace(
                    canonical,
                    widenable.start,
                    widenable.payload_start,
                    encode_head(
                        widenable.major,
                        widenable.argument,
                        wider_widths(widenable.argument)[0],
                    ),
                ),
                widenable.start,
            )

        target = _innermost_multi_entry_map(root)
        if target is not None:
            entries = target.entries
            first, second = entries[0], entries[1]
            yield _rule_vector(
                t,
                Violation.UNSORTED_MAP_KEYS,
                replace(
                    canonical,
                    first[0].start,
                    second[1].end,
                    canonical[second[0].start : second[1].end]
                    + canonical[first[0].start : first[1].end],
                ),
                first[0].start,
            )


def _rule_vector(t: str, rule: Violation, wire: bytes, at: int) -> RejectionVector:
    return RejectionVector(
        name=f"profile/{t}/{rule}",
        note=f"{rule} at byte {at} of an otherwise canonical {t}. A permissive reader decodes it "
        f"to the value the canonical encoding carries, so refusing it is the profile's decision "
        f"and not a question of well-formedness.",
        wire=wire,
        expect=Expect.DECODE_ERROR,
        field_identities=frozenset({"1", "v", "message"}),
        received=None,
    )


def build_rejections(catalogue: Catalogue | None = None) -> tuple[RejectionVector, ...]:
    """Every negative vector, in a fixed order."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    built = (
        *_structural(resolved),
        *_library_orderings(),
        *_content_ordered_env(resolved),
        *_from_faults(resolved),
        *_from_profile_rules(resolved),
    )
    seen: dict[str, RejectionVector] = {}
    for vector in built:
        if vector.name in seen:  # pragma: no cover - names are constructed distinct
            raise ValueError(f"two rejection vectors named {vector.name!r}")
        seen[vector.name] = vector
    return tuple(seen.values())


# --- Rendering ---------------------------------------------------------------------------------


def _header(what: str) -> str:
    return (
        f"GENERATED {what} by protocol/vectors/export_vectors.py, using the Python "
        "Protocol_Codec as the producer. Do not edit; regenerate with "
        "`python -m protocol.vectors.export_vectors`."
    )


def _compact(value: Any) -> str:
    """One line of JSON, spaced the way a reader wants rather than the way a minifier does."""
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))


def _document(header: str, preamble: dict[str, Any], vectors: Sequence[str]) -> str:
    """Assemble a corpus file: an indented outer shape, one line per vector entry.

    Rendered rather than handed whole to `json.dumps(indent=2)` because the indented form puts
    every path step and every tagged scalar on a line of its own, which turned `messages.json`
    into 800 kB in which no vector fits on a screen. A corpus nobody can read in a diff is a
    corpus that gets regenerated instead of reviewed when it changes, and the whole value of
    committing it is that a change to the wire shows up as a reviewable change to a file.
    """
    lines = [
        "{",
        f'  "$comment": {_compact(header)},',
        *(f"  {_compact(key)}: {_compact(item)}," for key, item in preamble.items()),
        '  "vectors": [',
        *(
            f"    {entry}{',' if at + 1 < len(vectors) else ''}"
            for at, entry in enumerate(vectors)
        ),
        "  ]",
        "}",
        "",
    ]
    return "\n".join(lines)


def _commaed(lines: Sequence[str]) -> list[str]:
    return [
        f"{line}," if at + 1 < len(lines) else line for at, line in enumerate(lines)
    ]


def _object(pairs: Sequence[tuple[str, str]], indent: str) -> str:
    """An object whose values are already rendered, one key per line at `indent`."""
    body = _commaed([f"{indent}  {_compact(key)}: {item}" for key, item in pairs])
    return "\n".join(["{", *body, f"{indent}}}"])


def _array(entries: Sequence[str], indent: str) -> str:
    """An array whose entries are already rendered, or `[]` when there are none."""
    if not entries:
        return "[]"
    body = _commaed([f"{indent}  {entry}" for entry in entries])
    return "\n".join(["[", *body, f"{indent}]"])


def _field_entry(
    catalogue: Catalogue, t: str, path: Path, expected: Value | None
) -> str:
    """One field declaration, on one line: its path, the schema's name for it, its value."""
    body: dict[str, Any] = {
        "path": [step_to_json(step) for step in path],
        "field": describe_path(catalogue, t, path),
    }
    if expected is not None:
        body["expected"] = to_tagged(expected)
    return _compact(body)


def render_messages(vectors: Sequence[MessageVector], catalogue: Catalogue) -> str:
    """The exact text `messages.json` should hold."""
    entries = [
        _object(
            [
                ("name", _compact(vector.name)),
                ("t", _compact(vector.t)),
                ("origin", _compact(vector.origin)),
                ("wire", _compact(vector.wire.hex())),
                (
                    "fields",
                    _array(
                        [
                            _field_entry(catalogue, vector.t, path, expected)
                            for path, expected in vector.fields.items()
                        ],
                        "      ",
                    ),
                ),
                (
                    "absent",
                    _array(
                        [
                            _field_entry(catalogue, vector.t, path, None)
                            for path in vector.absent
                        ],
                        "      ",
                    ),
                ),
            ],
            "    ",
        )
        for vector in vectors
    ]
    return _document(
        _header("valid-message vectors"),
        {
            "schemaVersion": catalogue.schema_version,
            "protocolVersion": catalogue.protocol_version,
        },
        entries,
    )


def render_values(vectors: Sequence[ValueVector]) -> str:
    """The exact text `values.json` should hold."""
    entries = [
        _object(
            [
                ("name", _compact(vector.name)),
                ("wire", _compact(vector.wire.hex())),
                ("value", _compact(to_tagged(vector.value))),
                ("note", _compact(vector.note)),
            ],
            "    ",
        )
        for vector in vectors
    ]
    return _document(_header("value-level encoding vectors"), {}, entries)


def render_rejections(vectors: Sequence[RejectionVector]) -> str:
    """The exact text `rejections.json` should hold."""
    entries = []
    for vector in vectors:
        pairs = [
            ("name", _compact(vector.name)),
            ("wire", _compact(vector.wire.hex())),
            ("expect", _compact(str(vector.expect))),
        ]
        if vector.received is not None:
            pairs.append(("received", _compact(str(vector.received))))
        if vector.field_identities:
            pairs.append(("fieldIdentities", _compact(sorted(vector.field_identities))))
        pairs.append(("note", _compact(vector.note)))
        entries.append(_object(pairs, "    "))
    return _document(
        _header("negative vectors: representations both codecs must refuse"),
        {},
        entries,
    )


def main() -> None:
    catalogue = load_catalogue()
    _write(MESSAGES_JSON_PATH, render_messages(build_messages(catalogue), catalogue))
    _write(VALUES_JSON_PATH, render_values(build_values()))
    _write(REJECTIONS_JSON_PATH, render_rejections(build_rejections(catalogue)))


def _write(path: FilePath, text: str) -> None:
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
