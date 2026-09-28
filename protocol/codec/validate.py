# kiro-classification: public
"""Validating a value against the message catalogue, field by field.

This is the *schema* half of the codec, and it is deliberately separate from the *profile* half:
`protocol.codec.profile` decides whether the bytes are one deterministic-profile CBOR value, and
this module decides whether that value is a message `protocol/messages.yaml` declares. The two
fail differently and a caller cares which — a peer sending non-canonical bytes has a broken
encoder, a peer sending a well-encoded but wrongly shaped map has a broken schema assumption.

Everything is read out of the catalogue rather than restated. The envelope's four keys, every
body field, every declared range and every closed enum come from `protocol.schema`, so a message
type added to the catalogue is validated with no edit here, and a field whose type changes is
checked against the new type or fails loudly. A validator that listed the fields it knew about
would go quietly out of date, and a round-trip property over a field it had never heard of would
still pass.

The version field is checked for *type* here and not for admissibility. Admissibility is a
separate question that the decode algorithm asks earlier, before any other field is inspected, so
that a representation carrying both an unsupported version and a schema violation reports the
version (R8.8). Answering it here as well would put the ordering in two places and let them
disagree.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, TypeGuard

from protocol.codec.errors import SchemaViolationError
from protocol.codec.values import Message, Value
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_TYPE,
    Catalogue,
    Field,
    TypeKind,
    TypeSpec,
    load_catalogue,
)

__all__ = ["ROOT_IDENTITY", "envelope_field_name", "validate"]

#: The identity a violation reports when there is no field to name, because the value is not a
#: map at all. Unreachable through the decode algorithm, whose first phase reads a definite map
#: head and fails before this module is asked anything; reachable by calling `validate` directly.
ROOT_IDENTITY: Final = "message"


def validate(value: Value | Message, *, catalogue: Catalogue | None = None) -> Message:
    """Check `value` against the catalogue and return it as a message.

    Returns the envelope keyed by its integer keys, with nothing rewritten: validation
    establishes that the value already is a message, and rebuilding its contents would invite
    the rebuilt form and the validated form to differ. Raises `SchemaViolationError` naming the
    first offending field.
    """
    resolved = catalogue if catalogue is not None else load_catalogue()

    if not isinstance(value, dict):
        raise SchemaViolationError(
            field=ROOT_IDENTITY,
            detail=f"a message is a map, got {_render_type(value)}",
        )

    declared = {field.key: field for field in resolved.envelope}
    for key in value:
        if not _is_integer(key) or key not in declared:
            raise SchemaViolationError(
                field=_render_key(key),
                detail="the envelope declares no such key",
            )
    for field in resolved.envelope:
        if field.key not in value:
            raise SchemaViolationError(
                field=field.name, detail="required envelope key is absent"
            )

    envelope: Mapping[int, Value] = {
        key: item for key, item in value.items() if _is_integer(key)
    }
    for field in resolved.envelope:
        if field.key == ENVELOPE_KEY_BODY:
            continue
        _check(envelope[field.key], field.spec, field.name)

    # `_check` has already established that the discriminator is a text string.
    discriminator = envelope[ENVELOPE_KEY_TYPE]
    message_type = (
        resolved.messages.get(discriminator) if isinstance(discriminator, str) else None
    )
    if message_type is None:
        raise SchemaViolationError(
            field=declared[ENVELOPE_KEY_TYPE].name,
            detail=f"the catalogue declares no message type {discriminator!r}",
        )

    body_field = declared[ENVELOPE_KEY_BODY]
    body = envelope[ENVELOPE_KEY_BODY]
    if not isinstance(body, dict):
        raise SchemaViolationError(
            field=body_field.name,
            detail=f"a body is a map, got {_render_type(body)}",
        )
    _check_fields(body, message_type.body, body_field.name)

    return dict(envelope)


def envelope_field_name(catalogue: Catalogue, key: int) -> str:
    """The catalogue's name for one envelope key.

    The identity a violation reports is the schema's name for the field, so it is read out of
    the catalogue rather than written down here as a literal.
    """
    for field in catalogue.envelope:
        if field.key == key:
            return field.name
    raise KeyError(f"the envelope declares no key {key}")


def _check_fields(
    mapping: Mapping[Value, Value], fields: Sequence[Field], prefix: str
) -> None:
    """Check a body or a struct against its declared field block."""
    declared = {field.key: field for field in fields}
    for key in mapping:
        if not _is_integer(key) or key not in declared:
            raise SchemaViolationError(
                field=f"{prefix}.{_render_key(key)}",
                detail="the schema declares no such field",
            )
    for field in fields:
        path = f"{prefix}.{field.name}"
        if field.key not in mapping:
            if field.optional:
                continue
            raise SchemaViolationError(field=path, detail="required field is absent")
        _check(mapping[field.key], field.spec, path)


def _check(value: Value, spec: TypeSpec, path: str) -> None:
    """Check one value against one declared type, recursing into containers."""
    match spec.kind:
        case TypeKind.UINT | TypeKind.INT:
            _check_integer(value, spec, path)
        case TypeKind.BOOL:
            if not isinstance(value, bool):
                raise _wrong_type(path, "a boolean", value)
        case TypeKind.TEXT:
            _check_text(value, spec, path)
        case TypeKind.BYTES:
            if not isinstance(value, bytes):
                raise _wrong_type(path, "a byte string", value)
        case TypeKind.LIST:
            _check_list(value, spec, path)
        case TypeKind.MAP:
            _check_map(value, spec, path)
        case TypeKind.STRUCT:
            if not isinstance(value, dict):
                raise _wrong_type(path, "a struct", value)
            _check_fields(value, spec.fields, path)


def _check_integer(value: Value, spec: TypeSpec, path: str) -> None:
    # Spelled out rather than through `_is_integer` so the narrowing survives into the range
    # comparison below: a type guard narrows where it holds, not where it fails.
    if isinstance(value, bool) or not isinstance(value, int):
        raise _wrong_type(path, "an integer", value)
    if (
        spec.range is None
    ):  # pragma: no cover - the loader requires a range on both kinds
        raise AssertionError(f"{path}: a {spec.kind} field declares no range")
    if not spec.range.min <= value <= spec.range.max:
        raise SchemaViolationError(
            field=path,
            detail=f"{value} is outside the declared range "
            f"[{spec.range.min}, {spec.range.max}]",
        )


def _check_text(value: Value, spec: TypeSpec, path: str) -> None:
    if not isinstance(value, str):
        raise _wrong_type(path, "a text string", value)
    if spec.enum is not None and value not in spec.enum:
        raise SchemaViolationError(
            field=path,
            detail=f"{value!r} is not one of {', '.join(spec.enum)}",
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        # A lone surrogate. It has no UTF-8 encoding, so it is not a value major type 3 can
        # carry, and refusing it here names the field rather than failing anonymously in the
        # encoder.
        raise SchemaViolationError(
            field=path, detail=f"a text string must be UTF-8 encodable: {exc}"
        ) from exc


def _check_list(value: Value, spec: TypeSpec, path: str) -> None:
    if not isinstance(value, list):
        raise _wrong_type(path, "a list", value)
    if spec.items is None:  # pragma: no cover - the loader requires items on a list
        raise AssertionError(f"{path}: a list declares no item type")
    for index, item in enumerate(value):
        _check(item, spec.items, f"{path}[{index}]")


def _check_map(value: Value, spec: TypeSpec, path: str) -> None:
    if not isinstance(value, dict):
        raise _wrong_type(path, "a map", value)
    if spec.keys is None or spec.values is None:
        # The envelope's `b` declares neither, because its schema is selected by `t`; `validate`
        # dispatches that one on the message type instead of reaching here.
        return
    for index, (key, item) in enumerate(value.items()):
        _check(key, spec.keys, f"{path}[{index}].key")
        _check(item, spec.values, f"{path}[{index}].value")


def _wrong_type(path: str, expected: str, value: Value) -> SchemaViolationError:
    return SchemaViolationError(
        field=path, detail=f"expected {expected}, got {_render_type(value)}"
    )


def _is_integer(value: object) -> TypeGuard[int]:
    """Whether `value` is an integer rather than a boolean.

    `True` is an `int` in Python and simple value 21 is not integer 1, so the two are separate
    types on the wire and have to be separate here as well.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def _render_key(key: Value) -> str:
    """How an undeclared key is named. An integer key is named by its number."""
    return str(key) if _is_integer(key) else repr(key)


def _render_type(value: Value) -> str:
    if isinstance(value, bool):
        return "a boolean"
    return f"a {type(value).__name__}"
