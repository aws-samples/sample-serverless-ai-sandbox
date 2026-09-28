# kiro-classification: public
"""The corpus file format, and the two readings of it the comparison needs.

A vector has to say three things for a cross-implementation check to be worth running: what the
bytes are, what the fields decode to, and where a mismatch is. The third is what makes the
difference between a corpus and a smoke test, so the format addresses fields by *path* — a
sequence of map keys and list indices from the envelope down to a leaf — and every path can be
rendered against the catalogue as `b.env[0x2f]` or `b.entries[0].size`. A failure names the
message type and the field rather than dumping two hex strings and leaving the reader to diff
them.

#### Values are tagged, not inferred

JSON cannot distinguish a byte string from text, and it cannot carry `18446744073709551615`
through a JavaScript reader without silently rounding it. So every value names its kind — a
scalar as `"bytes:ff"`, `"int:-1"`, `"text:hello"`, `"bool:true"`, a container as the one-key
object `{"list": [...]}` or `{"map": [[key, value], ...]}` — and integers travel as decimal
strings, which both `int` and `BigInt` read exactly. This is the same decision
`export_catalogue.py` made about range bounds, for the same reason, and it is not cosmetic: the
protocol's whole point at R8.9 is that a byte field is not a text field, and a corpus that let
the two blur on the way through JSON would be unable to state the difference it exists to check.

Splitting a scalar at its *first* colon keeps the form unambiguous for text that contains one:
`"text:int:5"` is the string `int:5`, not the integer 5.

#### The field list serves both directions, and its order is the source's

A message vector declares its fields once, as a list of path-and-value pairs, and that one
declaration is what both directions use: the interpretation direction resolves each path in the
decoded message and compares, and the production direction rebuilds the message from the same
list and encodes it. Recording a separate copy of the whole message value for the second
direction would double the file and give two places for the expectation to drift.

The list is in the order the message was built, which for the ordering vectors puts a nested
map's keys in *reverse* canonical order. That matters: rebuilding inserts entries in list order,
so reproducing `wire` requires actually applying RFC 8949 §4.2.1's bytewise comparison rather
than copying the insertion order, which a corpus written out already sorted would not require.

#### A leaf is a scalar or an *empty* container

`fs.ack` has an empty body and `exec.request` can carry an empty `env`. If leaf enumeration
descended into containers and stopped, those fields would have no path, so nothing would be
compared and an empty map decoded as an empty list would pass. An empty container is therefore a
leaf in its own right, which makes the leaf set total over the message: every part of a decoded
message is named by exactly one path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path as FilePath
from typing import Any, Final

from protocol.codec import Message, Value
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    Catalogue,
    Field,
    TypeKind,
    TypeSpec,
)

__all__ = [
    "MESSAGES_JSON_PATH",
    "REJECTIONS_JSON_PATH",
    "VALUES_JSON_PATH",
    "Expect",
    "Index",
    "Leaf",
    "MapKey",
    "MessageVector",
    "Path",
    "RejectionVector",
    "Step",
    "ValueVector",
    "as_value",
    "describe_path",
    "from_tagged",
    "leaves",
    "load_messages",
    "load_rejections",
    "load_values",
    "rebuild",
    "replace_at",
    "resolve",
    "step_from_json",
    "step_to_json",
    "to_tagged",
]

MESSAGES_JSON_PATH: Final = FilePath(__file__).with_name("messages.json")
VALUES_JSON_PATH: Final = FilePath(__file__).with_name("values.json")
REJECTIONS_JSON_PATH: Final = FilePath(__file__).with_name("rejections.json")

#: The largest integer map key a JSON number carries exactly. Every key the catalogue declares is
#: a small unsigned integer, and the exporter asserts it rather than assuming it.
MAX_SAFE_JSON_INTEGER: Final = 2**53 - 1


@dataclass(frozen=True, slots=True)
class Index:
    """A list index, wrapped so it cannot be confused with an integer map key.

    Both are integers, and a path is a heterogeneous sequence of the two. Without the wrapper,
    `(4, 1, 0)` would be ambiguous between the third step naming key `0` of a map and element `0`
    of a list, and the ambiguity would land on `fs.listing.entries` — the one field where the
    corpus has to descend a list into a struct.
    """

    at: int


#: A value the protocol can use as a map key: everything in `Value` except the two containers.
#: Named separately because a path step is one of these *or* a list index, and a key is not.
type MapKey = int | bool | str | bytes

#: One step of a path: a map key, or a list index.
type Step = MapKey | Index

#: A path from the envelope map to one part of a message. The empty path is the message itself.
type Path = tuple[Step, ...]


class Expect(StrEnum):
    """What a rejection vector requires of the decoder.

    Three outcomes rather than one, because "both codecs refuse this" is not a strong enough
    claim: two implementations that refuse the same bytes for different reasons disagree about
    the protocol even though both reject. The first two are message-level and go through
    `decode`; the third is value-level and goes through `decode_value`, which is where the key
    ordering rules can be separated without a message schema in the way.
    """

    #: `DecodeError` from `decode`, naming one of the vector's acceptable field identities (R8.6).
    DECODE_ERROR = "decode-error"
    #: `VersionError` from `decode`, carrying the received version and both bounds (R8.7).
    VERSION_ERROR = "version-error"
    #: `NonCanonicalEncoding` from `decode_value`: a profile violation below the message level.
    NON_CANONICAL = "non-canonical"


@dataclass(frozen=True, slots=True)
class Leaf:
    """The outcome of resolving a path: whether it is present, and the value if it is."""

    found: bool
    value: Value = 0


@dataclass(frozen=True, slots=True)
class MessageVector:
    """One valid message: the bytes, and every field of it by path.

    `fields` is the whole declaration and serves both directions — `rebuild(fields)` is the
    message, and each entry is one expectation of the decoded message. Insertion order is the
    order the message was built in, which is what makes rebuilding exercise the encoder's key
    ordering rather than inheriting it from the file.
    """

    name: str
    t: str
    origin: str
    wire: bytes
    #: Every leaf of the message, by path, in source order.
    fields: dict[Path, Value]
    #: Optional fields this vector omits, named so a failure says which one reappeared.
    absent: tuple[Path, ...]

    @property
    def value(self) -> Value:
        """The message the declared fields describe."""
        return rebuild(self.fields)


@dataclass(frozen=True, slots=True)
class ValueVector:
    """One value below the message level, for the profile's own encoding rules."""

    name: str
    note: str
    wire: bytes
    value: Value


@dataclass(frozen=True, slots=True)
class RejectionVector:
    """One representation both codecs must refuse, and the error both must raise."""

    name: str
    note: str
    wire: bytes
    expect: Expect
    #: For `DECODE_ERROR`: the spellings the codec may use for the field it names.
    field_identities: frozenset[str]
    #: For `VERSION_ERROR`: the version the representation carries.
    received: int | None


# --- Tagged values ---------------------------------------------------------------------------


def to_tagged(value: Value) -> Any:
    """Render `value` as the corpus writes it, preserving map pair order."""
    # bool before int, for the reason `encode_value` orders them that way: `True` is an `int` in
    # Python, and CBOR simple value 21 is not integer 1.
    if isinstance(value, bool):
        return f"bool:{'true' if value else 'false'}"
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, bytes):
        return f"bytes:{value.hex()}"
    if isinstance(value, str):
        return f"text:{value}"
    if isinstance(value, list):
        return {"list": [to_tagged(item) for item in value]}
    return {"map": [[to_tagged(key), to_tagged(item)] for key, item in value.items()]}


def from_tagged(tagged: Any) -> Value:
    """Read a tagged value back into the protocol's value space."""
    if isinstance(tagged, str):
        kind, _, body = tagged.partition(":")
        match kind:
            case "bool":
                return body == "true"
            case "int":
                return int(body)
            case "bytes":
                return bytes.fromhex(body)
            case "text":
                return body
        raise ValueError(f"{kind!r} is not a scalar kind the protocol declares")
    if not isinstance(tagged, dict) or len(tagged) != 1:
        raise ValueError(f"{tagged!r} is not a tagged value")
    ((kind, body),) = tagged.items()
    if kind == "list":
        return [from_tagged(item) for item in body]
    if kind == "map":
        return {from_tagged(key): from_tagged(item) for key, item in body}
    raise ValueError(f"{kind!r} is not a container kind the protocol declares")


def step_to_json(step: Step) -> Any:
    """Render one path step. Integer keys stay JSON numbers; everything else is tagged.

    Integer keys are the overwhelming majority — the envelope's four and every body and struct
    field key — so they are written bare, which is both shorter and what a reader expects to see
    beside the field name. `Index` is the one form with no tagged spelling of its own, because a
    list index is not a value the protocol can carry.
    """
    if isinstance(step, Index):
        return {"index": step.at}
    if isinstance(step, bool):
        return to_tagged(step)
    if isinstance(step, int):
        if not 0 <= step <= MAX_SAFE_JSON_INTEGER:
            raise ValueError(f"integer map key {step} is outside the exact JSON range")
        return step
    return to_tagged(step)


def step_from_json(raw: Any) -> Step:
    """Read one path step."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, dict) and "index" in raw:
        return Index(int(raw["index"]))
    read = from_tagged(raw)
    if isinstance(read, list | dict):
        raise TypeError("a map key the protocol can carry is never a container")
    return read


# --- Paths -----------------------------------------------------------------------------------


def leaves(value: Value, prefix: Path = ()) -> dict[Path, Value]:
    """Every scalar and every empty container in `value`, by path.

    Total over the value: each part of it is named by exactly one path, so comparing two values
    leaf by leaf and comparing their path sets is a complete comparison rather than a sample.
    """
    if isinstance(value, dict):
        if not value:
            return {prefix: value}
        found: dict[Path, Value] = {}
        for key, item in value.items():
            if isinstance(key, list | dict):  # pragma: no cover - unencodable as a key
                raise TypeError("a map key the protocol can carry is never a container")
            found.update(leaves(item, (*prefix, key)))
        return found
    if isinstance(value, list):
        if not value:
            return {prefix: value}
        nested: dict[Path, Value] = {}
        for at, item in enumerate(value):
            nested.update(leaves(item, (*prefix, Index(at))))
        return nested
    return {prefix: value}


def resolve(value: Value, path: Path) -> Leaf:
    """Follow `path` into `value`, reporting absence rather than raising on it.

    Absence is an answer the comparison needs: an omitted optional field is a fact about the
    message, and a decoder that invented one has to fail as loudly as one that lost a byte.
    """
    current: Value = value
    for step in path:
        if isinstance(step, Index):
            if not isinstance(current, list) or not 0 <= step.at < len(current):
                return Leaf(found=False)
            current = current[step.at]
            continue
        if not isinstance(current, dict) or step not in current:
            return Leaf(found=False)
        current = current[step]
    return Leaf(found=True, value=current)


def as_value(message: Message) -> Value:
    """Widen a decoded message's key type so the path helpers accept it.

    A `dict` is invariant in both parameters, so a `dict[int, Value]` is not a `dict[Value, Value]`
    however compatible the two look. `protocol.codec.messages` widens key by key on the way into
    the encoder for the same reason; this is the same move on the way out of the decoder.
    """
    return {key: item for key, item in message.items()}


def rebuild(fields: Mapping[Path, Value]) -> Value:
    """The value whose leaves are exactly `fields`, containers created in iteration order.

    The inverse of `leaves` and the input to the production direction. Whether a container is a
    map or a list is read off the step that enters it — an `Index` enters a list, anything else
    enters a map — so no separate shape declaration is needed and the two cannot disagree.

    Iteration order is load-bearing. Map entries are inserted in the order the paths arrive, so a
    vector whose nested map keys are declared in reverse canonical order hands the encoder a map
    it has to sort. A rebuild that sorted keys itself would quietly do the encoder's job and let a
    codec that never ordered map keys pass.
    """
    if () in fields:
        return fields[()]
    if not fields:  # pragma: no cover - every message has at least the version field
        raise ValueError("a vector with no fields describes no value")
    first = next(iter(fields))
    root: Any = [] if isinstance(first[0], Index) else {}
    for path, leaf in fields.items():
        _place(root, path, leaf)
    value: Value = root
    return value


def _place(container: Any, path: Path, leaf: Value) -> None:
    step, rest = path[0], path[1:]
    if not rest:
        _assign(container, step, leaf)
        return
    existing = _lookup(container, step)
    if existing is None:
        existing = [] if isinstance(rest[0], Index) else {}
        _assign(container, step, existing)
    _place(existing, rest, leaf)


def _assign(container: Any, step: Step, item: Any) -> None:
    if isinstance(step, Index):
        if not isinstance(container, list) or step.at != len(container):
            raise ValueError(f"list index {step.at} is out of order for a rebuild")
        container.append(item)
        return
    if not isinstance(container, dict):
        raise TypeError(f"key {step!r} addresses a map, but a list is here")
    container[step] = item


def _lookup(container: Any, step: Step) -> Any:
    if isinstance(step, Index):
        if not isinstance(container, list) or step.at >= len(container):
            return None
        return container[step.at]
    if not isinstance(container, dict):
        raise TypeError(f"key {step!r} addresses a map, but a list is here")
    return container.get(step)


def replace_at(value: Value, path: Path, replacement: Value) -> Value:
    """A copy of `value` with the part at `path` replaced. Raises if the path is absent."""
    if not path:
        return replacement
    step, rest = path[0], path[1:]
    if isinstance(step, Index):
        if not isinstance(value, list) or not 0 <= step.at < len(value):
            raise KeyError(f"no element {step.at} to replace")
        return [
            replace_at(item, rest, replacement) if at == step.at else item
            for at, item in enumerate(value)
        ]
    if not isinstance(value, dict) or step not in value:
        raise KeyError(f"no key {step!r} to replace")
    return {
        key: replace_at(item, rest, replacement) if key == step else item
        for key, item in value.items()
    }


def _render_key(step: Step) -> str:
    if isinstance(step, bytes):
        return f"0x{step.hex()}" if step else "0x"
    if isinstance(step, str):
        return json.dumps(step)
    return str(step)


def _field_by_key(fields: tuple[Field, ...], key: int) -> Field | None:
    return next((field for field in fields if field.key == key), None)


def _descend(spec: TypeSpec, step: Step) -> tuple[str, TypeSpec | None]:
    """One step down a type spec: how to render it, and the spec of what it reaches."""
    if isinstance(step, Index):
        return f"[{step.at}]", spec.items
    if spec.kind is TypeKind.STRUCT:
        field = _field_by_key(spec.fields, step) if isinstance(step, int) else None
        if field is None:
            return f"[{_render_key(step)}]", None
        return f".{field.name}", field.spec
    if spec.kind is TypeKind.MAP:
        return f"[{_render_key(step)}]", spec.values
    return f"[{_render_key(step)}]", None


def describe_path(catalogue: Catalogue, t: str, path: Path) -> str:
    """`path` as the schema names it: `b.env[0x2f]`, `b.entries[0].size`, `v`.

    The catalogue's names rather than the integer keys, because a failure that says
    `b.entries[0].size` is a failure a reader can act on, where one that says `(4, 1, 0, 3)`
    needs the schema open beside it. Where the path leaves the schema — a map key, a value under
    a field the catalogue does not declare — it renders structurally and stops resolving names,
    which is the honest rendering of a path into a value that should not have been there.
    """
    if not path:
        return "message"
    head, rest = path[0], path[1:]
    envelope = (
        _field_by_key(catalogue.envelope, head) if isinstance(head, int) else None
    )
    if envelope is None:
        return "message" + "".join(f"[{_render_key(step)}]" for step in path)

    rendered = envelope.name
    if head == ENVELOPE_KEY_BODY and rest:
        message = catalogue.messages.get(t)
        field_key = rest[0]
        body = (
            _field_by_key(message.body, field_key)
            if message is not None and isinstance(field_key, int)
            else None
        )
        if body is None:
            return rendered + "".join(f"[{_render_key(step)}]" for step in rest)
        rendered += f".{body.name}"
        spec: TypeSpec | None = body.spec
        rest = rest[1:]
    else:
        spec = envelope.spec

    for step in rest:
        if spec is None:
            rendered += f"[{_render_key(step)}]"
            continue
        text, spec = _descend(spec, step)
        rendered += text
    return rendered


# --- Reading the committed corpus -------------------------------------------------------------


def _document(path: FilePath) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return parsed


def _path(raw: list[Any]) -> Path:
    return tuple(step_from_json(step) for step in raw)


def load_messages(path: FilePath | None = None) -> tuple[MessageVector, ...]:
    """The valid-message vectors, as written."""
    document = _document(path if path is not None else MESSAGES_JSON_PATH)
    return tuple(
        MessageVector(
            name=vector["name"],
            t=vector["t"],
            origin=vector["origin"],
            wire=bytes.fromhex(vector["wire"]),
            fields={
                _path(field["path"]): from_tagged(field["expected"])
                for field in vector["fields"]
            },
            absent=tuple(_path(entry["path"]) for entry in vector["absent"]),
        )
        for vector in document["vectors"]
    )


def load_values(path: FilePath | None = None) -> tuple[ValueVector, ...]:
    """The value-level encoding vectors."""
    document = _document(path if path is not None else VALUES_JSON_PATH)
    return tuple(
        ValueVector(
            name=vector["name"],
            note=vector["note"],
            wire=bytes.fromhex(vector["wire"]),
            value=from_tagged(vector["value"]),
        )
        for vector in document["vectors"]
    )


def load_rejections(path: FilePath | None = None) -> tuple[RejectionVector, ...]:
    """The negative vectors: what both codecs must refuse, and how."""
    document = _document(path if path is not None else REJECTIONS_JSON_PATH)
    return tuple(
        RejectionVector(
            name=vector["name"],
            note=vector["note"],
            wire=bytes.fromhex(vector["wire"]),
            expect=Expect(vector["expect"]),
            field_identities=frozenset(vector.get("fieldIdentities", ())),
            received=(
                int(vector["received"]) if vector.get("received") is not None else None
            ),
        )
        for vector in document["vectors"]
    )
