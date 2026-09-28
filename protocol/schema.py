# kiro-classification: public
"""Loader for the Sandbox_Protocol message catalogue (R8.1).

`messages.yaml` is the schema source. This module is the only reader of it: the
Protocol_Codec, the shared generators and the vector corpus all reach the catalogue
through `load_catalogue()` rather than parsing the document themselves, so a schema
change lands in one place.

Loading validates the document's own structure and fails closed on anything it does not
recognise, including an unknown key. A catalogue that silently ignored a misspelled
`carries` annotation would report a text field as byte-typed and defeat the rule the
annotation exists to enforce.

This module validates the *catalogue*, not messages. Validating a decoded message against
the catalogue is Phase 2 of the decode algorithm and lives with the codec.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml

CATALOGUE_PATH: Final = Path(__file__).with_name("messages.yaml")

#: The schemaVersion this loader understands. A document declaring anything else is
#: rejected rather than read on a best-effort basis.
SUPPORTED_SCHEMA_VERSION: Final = 1

#: The four envelope keys, fixed by the design's message shape table.
ENVELOPE_KEY_VERSION: Final = 1
ENVELOPE_KEY_TYPE: Final = 2
ENVELOPE_KEY_ID: Final = 3
ENVELOPE_KEY_BODY: Final = 4

_ENVELOPE_SHAPE: Final[tuple[tuple[int, str, str], ...]] = (
    (ENVELOPE_KEY_VERSION, "v", "uint"),
    (ENVELOPE_KEY_TYPE, "t", "text"),
    (ENVELOPE_KEY_ID, "id", "bytes"),
    (ENVELOPE_KEY_BODY, "b", "map"),
)


class SchemaError(Exception):
    """The catalogue document is malformed.

    This is a defect in `messages.yaml`, not in a message on the wire. Decode errors and
    version errors are the codec's, and are unrelated to this.
    """


class TypeKind(enum.StrEnum):
    """The closed type vocabulary the catalogue may use."""

    UINT = "uint"
    INT = "int"
    BOOL = "bool"
    TEXT = "text"
    BYTES = "bytes"
    LIST = "list"
    MAP = "map"
    STRUCT = "struct"


class Carries(enum.StrEnum):
    """What a byte-typed field carries, and why it must be byte-typed.

    `OUTPUT` is process output or file content (R8.9). `NAME` is a filesystem path, a path
    component, an argv element, an environment variable name or value, or a process handle.
    Both are byte sequences on a Linux system and neither is required to be valid UTF-8.
    """

    OUTPUT = "output"
    NAME = "name"


class Direction(enum.StrEnum):
    """Who sends a message type."""

    CLIENT_TO_RUNTIME = "client-to-runtime"
    RUNTIME_TO_CLIENT = "runtime-to-client"
    ORCHESTRATOR_TO_RUNTIME = "orchestrator-to-runtime"
    BOTH = "both"


@dataclass(frozen=True, slots=True)
class IntRange:
    """The inclusive interval an integer field admits."""

    min: int
    max: int

    def boundaries(self) -> tuple[int, int]:
        """The two values a boundary-drawing generator owes this field."""
        return (self.min, self.max)


@dataclass(frozen=True, slots=True)
class TypeSpec:
    """A field's type, with whatever the kind requires and nothing else."""

    kind: TypeKind
    range: IntRange | None = None
    enum: tuple[str, ...] | None = None
    carries: Carries | None = None
    items: TypeSpec | None = None
    keys: TypeSpec | None = None
    values: TypeSpec | None = None
    fields: tuple[Field, ...] = ()

    def walk(self) -> Iterator[TypeSpec]:
        """This spec and every spec nested inside it, outermost first."""
        yield self
        for nested in (self.items, self.keys, self.values):
            if nested is not None:
                yield from nested.walk()
        for field in self.fields:
            yield from field.spec.walk()


@dataclass(frozen=True, slots=True)
class Field:
    """One body field, or one envelope key."""

    key: int
    name: str
    spec: TypeSpec
    optional: bool = False


@dataclass(frozen=True, slots=True)
class MessageType:
    """One entry in the catalogue."""

    t: str
    direction: Direction
    requirements: tuple[str, ...]
    body: tuple[Field, ...]

    def field_by_name(self, name: str) -> Field:
        for field in self.body:
            if field.name == name:
                return field
        raise KeyError(f"{self.t} has no body field named {name!r}")

    def field_by_key(self, key: int) -> Field:
        for field in self.body:
            if field.key == key:
                return field
        raise KeyError(f"{self.t} has no body field keyed {key}")


@dataclass(frozen=True, slots=True)
class Catalogue:
    """The whole schema source, loaded and checked."""

    schema_version: int
    protocol_version: int
    supported_min: int
    supported_max: int
    envelope: tuple[Field, ...]
    messages: Mapping[str, MessageType]

    def supports(self, version: int) -> bool:
        """Whether `version` is admissible in Phase 1 of the decode algorithm (R8.7)."""
        return self.supported_min <= version <= self.supported_max

    @property
    def message_types(self) -> tuple[str, ...]:
        """Every `t` value, in catalogue order."""
        return tuple(self.messages)

    def byte_typed_fields(self) -> Iterator[tuple[str, Field, TypeSpec]]:
        """Every annotated spec, with the message and the field it sits under.

        The generators and the byte-typing assertion both quantify over this, so a message
        type added with a text-typed output field is a failure rather than an omission.
        """
        for message in self.messages.values():
            for field in message.body:
                for spec in field.spec.walk():
                    if spec.carries is not None:
                        yield (message.t, field, spec)


# --- Loading -------------------------------------------------------------------------


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SchemaError(f"{where}: expected a mapping, got {type(value).__name__}")
    for key in value:
        if not isinstance(key, str):
            raise SchemaError(f"{where}: non-string key {key!r}")
    return value


def _require_sequence(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise SchemaError(f"{where}: expected a list, got {type(value).__name__}")
    return value


def _require_int(value: Any, where: str) -> int:
    # bool is an int in Python; a boolean where an integer belongs is a defect.
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchemaError(f"{where}: expected an integer, got {value!r}")
    return value


def _require_str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{where}: expected a string, got {value!r}")
    return value


def _reject_unknown(mapping: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise SchemaError(f"{where}: unknown key(s) {', '.join(unknown)}")


_TYPE_SPEC_KEYS: Final = {
    "type",
    "range",
    "enum",
    "carries",
    "items",
    "keys",
    "values",
    "fields",
}
_INTEGER_KINDS: Final = frozenset({TypeKind.UINT, TypeKind.INT})


def _parse_range(raw: Any, where: str) -> IntRange:
    mapping = _require_mapping(raw, where)
    _reject_unknown(mapping, {"min", "max"}, where)
    if "min" not in mapping or "max" not in mapping:
        raise SchemaError(f"{where}: range requires both min and max")
    low = _require_int(mapping["min"], f"{where}.min")
    high = _require_int(mapping["max"], f"{where}.max")
    if low > high:
        raise SchemaError(f"{where}: range min {low} exceeds max {high}")
    return IntRange(min=low, max=high)


def _parse_type_spec(raw: Any, where: str) -> TypeSpec:
    mapping = _require_mapping(raw, where)
    _reject_unknown(mapping, _TYPE_SPEC_KEYS, where)
    if "type" not in mapping:
        raise SchemaError(f"{where}: missing type")
    try:
        kind = TypeKind(_require_str(mapping["type"], f"{where}.type"))
    except ValueError as exc:
        raise SchemaError(f"{where}.type: {exc}") from exc

    range_ = (
        _parse_range(mapping["range"], f"{where}.range") if "range" in mapping else None
    )
    if range_ is not None and kind not in _INTEGER_KINDS:
        raise SchemaError(f"{where}: range is meaningless on a {kind} field")
    if range_ is not None and kind is TypeKind.UINT and range_.min < 0:
        raise SchemaError(f"{where}: uint range cannot start below zero")
    if kind in _INTEGER_KINDS and range_ is None:
        # Property 1 draws integer fields from the boundaries of their declared ranges, so
        # an undeclared range would leave that generator with nothing to draw.
        raise SchemaError(f"{where}: a {kind} field must declare its range")

    enum_values: tuple[str, ...] | None = None
    if "enum" in mapping:
        if kind is not TypeKind.TEXT:
            raise SchemaError(f"{where}: enum is only meaningful on a text field")
        items = _require_sequence(mapping["enum"], f"{where}.enum")
        enum_values = tuple(
            _require_str(item, f"{where}.enum[{i}]") for i, item in enumerate(items)
        )
        if not enum_values:
            raise SchemaError(f"{where}.enum: must not be empty")
        if len(set(enum_values)) != len(enum_values):
            raise SchemaError(f"{where}.enum: duplicate values")

    carries: Carries | None = None
    if "carries" in mapping:
        try:
            carries = Carries(_require_str(mapping["carries"], f"{where}.carries"))
        except ValueError as exc:
            raise SchemaError(f"{where}.carries: {exc}") from exc
        if kind is not TypeKind.BYTES:
            # The rule the annotation exists for: process output and filesystem names are
            # byte strings everywhere in this protocol.
            raise SchemaError(
                f"{where}: a field carrying {carries} must be bytes, not {kind}"
            )

    items_spec = (
        _parse_type_spec(mapping["items"], f"{where}.items")
        if "items" in mapping
        else None
    )
    keys_spec = (
        _parse_type_spec(mapping["keys"], f"{where}.keys")
        if "keys" in mapping
        else None
    )
    values_spec = (
        _parse_type_spec(mapping["values"], f"{where}.values")
        if "values" in mapping
        else None
    )
    fields = (
        _parse_fields(mapping["fields"], f"{where}.fields")
        if "fields" in mapping
        else ()
    )

    if kind is TypeKind.LIST and items_spec is None:
        raise SchemaError(f"{where}: a list must declare items")
    if kind is not TypeKind.LIST and items_spec is not None:
        raise SchemaError(f"{where}: items is only meaningful on a list")
    if kind is TypeKind.MAP and (keys_spec is None) != (values_spec is None):
        raise SchemaError(f"{where}: a map declares both keys and values or neither")
    if kind is not TypeKind.MAP and (keys_spec is not None or values_spec is not None):
        raise SchemaError(f"{where}: keys and values are only meaningful on a map")
    if kind is TypeKind.STRUCT and not fields:
        raise SchemaError(f"{where}: a struct must declare at least one field")
    if kind is not TypeKind.STRUCT and fields:
        raise SchemaError(f"{where}: fields is only meaningful on a struct")

    return TypeSpec(
        kind=kind,
        range=range_,
        enum=enum_values,
        carries=carries,
        items=items_spec,
        keys=keys_spec,
        values=values_spec,
        fields=fields,
    )


def _parse_fields(raw: Any, where: str) -> tuple[Field, ...]:
    entries = _require_sequence(raw, where)
    fields: list[Field] = []
    for index, entry in enumerate(entries):
        at = f"{where}[{index}]"
        mapping = _require_mapping(entry, at)
        if "key" not in mapping or "name" not in mapping:
            raise SchemaError(f"{at}: a field requires both key and name")
        optional = mapping.get("optional", False)
        if not isinstance(optional, bool):
            raise SchemaError(f"{at}.optional: expected a boolean, got {optional!r}")
        spec_source = {
            k: v for k, v in mapping.items() if k not in {"key", "name", "optional"}
        }
        fields.append(
            Field(
                key=_require_int(mapping["key"], f"{at}.key"),
                name=_require_str(mapping["name"], f"{at}.name"),
                spec=_parse_type_spec(spec_source, at),
                optional=optional,
            )
        )
    _check_key_block(fields, where)
    return tuple(fields)


def _check_key_block(fields: Sequence[Field], where: str) -> None:
    keys = [field.key for field in fields]
    if keys != list(range(1, len(keys) + 1)):
        # Contiguous from 1, in order. Sparse or reordered keys would still encode, but
        # they make the deterministic profile's sorted-key order stop matching the order
        # the catalogue reads in, which is the one thing a reader relies on.
        raise SchemaError(
            f"{where}: keys must be contiguous from 1 in order, got {keys}"
        )
    names = [field.name for field in fields]
    if len(set(names)) != len(names):
        raise SchemaError(f"{where}: duplicate field name(s)")


def _parse_envelope(raw: Any) -> tuple[Field, ...]:
    mapping = _require_mapping(raw, "envelope")
    _reject_unknown(mapping, {"fields"}, "envelope")
    if "fields" not in mapping:
        raise SchemaError("envelope: missing fields")
    fields = _parse_fields(mapping["fields"], "envelope.fields")
    actual = tuple((field.key, field.name, str(field.spec.kind)) for field in fields)
    if actual != _ENVELOPE_SHAPE:
        raise SchemaError(
            f"envelope: must be exactly the four keys {_ENVELOPE_SHAPE}, got {actual}"
        )
    if any(field.optional for field in fields):
        raise SchemaError("envelope: no envelope key is optional")
    return fields


def _parse_message(raw: Any, index: int) -> MessageType:
    at = f"messages[{index}]"
    mapping = _require_mapping(raw, at)
    _reject_unknown(mapping, {"t", "direction", "requirements", "body"}, at)
    for required in ("t", "direction", "requirements", "body"):
        if required not in mapping:
            raise SchemaError(f"{at}: missing {required}")
    t = _require_str(mapping["t"], f"{at}.t")
    try:
        direction = Direction(_require_str(mapping["direction"], f"{at}.direction"))
    except ValueError as exc:
        raise SchemaError(f"{at}.direction: {exc}") from exc
    requirement_entries = _require_sequence(
        mapping["requirements"], f"{at}.requirements"
    )
    if not requirement_entries:
        raise SchemaError(f"{at}.requirements: must name at least one requirement")
    requirements = tuple(
        _require_str(item, f"{at}.requirements[{i}]")
        for i, item in enumerate(requirement_entries)
    )
    return MessageType(
        t=t,
        direction=direction,
        requirements=requirements,
        body=_parse_fields(mapping["body"], f"{at} ({t}) body"),
    )


def parse_catalogue(document: Any) -> Catalogue:
    """Build a `Catalogue` from an already-parsed document.

    Separate from `load_catalogue` so a test can hand in a mutated document without
    writing a file.
    """
    mapping = _require_mapping(document, "catalogue")
    _reject_unknown(
        mapping, {"schemaVersion", "protocol", "envelope", "messages"}, "catalogue"
    )
    for required in ("schemaVersion", "protocol", "envelope", "messages"):
        if required not in mapping:
            raise SchemaError(f"catalogue: missing {required}")

    schema_version = _require_int(mapping["schemaVersion"], "catalogue.schemaVersion")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise SchemaError(
            f"catalogue.schemaVersion: this loader reads {SUPPORTED_SCHEMA_VERSION}, "
            f"document declares {schema_version}"
        )

    protocol = _require_mapping(mapping["protocol"], "catalogue.protocol")
    _reject_unknown(
        protocol, {"version", "supportedMin", "supportedMax"}, "catalogue.protocol"
    )
    for required in ("version", "supportedMin", "supportedMax"):
        if required not in protocol:
            raise SchemaError(f"catalogue.protocol: missing {required}")
    version = _require_int(protocol["version"], "catalogue.protocol.version")
    low = _require_int(protocol["supportedMin"], "catalogue.protocol.supportedMin")
    high = _require_int(protocol["supportedMax"], "catalogue.protocol.supportedMax")
    if low < 0:
        raise SchemaError("catalogue.protocol.supportedMin: must not be negative")
    if low > high:
        raise SchemaError(
            f"catalogue.protocol: supportedMin {low} exceeds supportedMax {high}"
        )
    if not low <= version <= high:
        raise SchemaError(
            f"catalogue.protocol: emitted version {version} is outside "
            f"the supported range [{low}, {high}]"
        )

    entries = _require_sequence(mapping["messages"], "catalogue.messages")
    if not entries:
        raise SchemaError("catalogue.messages: must not be empty")
    messages: dict[str, MessageType] = {}
    for index, entry in enumerate(entries):
        message = _parse_message(entry, index)
        if message.t in messages:
            raise SchemaError(
                f"catalogue.messages: duplicate message type {message.t!r}"
            )
        messages[message.t] = message

    return Catalogue(
        schema_version=schema_version,
        protocol_version=version,
        supported_min=low,
        supported_max=high,
        envelope=_parse_envelope(mapping["envelope"]),
        messages=messages,
    )


@lru_cache(maxsize=1)
def load_catalogue(path: Path = CATALOGUE_PATH) -> Catalogue:
    """Read, parse and check `messages.yaml`.

    Cached, because the catalogue is immutable for the life of the process and the
    generators reach for it once per drawn example.
    """
    with path.open("rb") as handle:
        document = yaml.safe_load(handle)
    return parse_catalogue(document)
