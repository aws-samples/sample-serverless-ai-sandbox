# kiro-classification: public
"""Unit tests for the message catalogue and its loader (R8.1).

Two halves. The first asserts the shipped catalogue says what the design's Sandbox_Protocol
message catalogue says — the four-key envelope, the message set, and the byte-string typing
of every output and name field. The second asserts the loader fails closed, because a loader
that accepted a malformed catalogue would let the first half pass against a broken document.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
import yaml

from protocol.schema import (
    CATALOGUE_PATH,
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Carries,
    Direction,
    SchemaError,
    TypeKind,
    load_catalogue,
    parse_catalogue,
)

# Every message type the design's catalogue names, after splitting the paired rows on the
# semicolon that separates a request's fields from its response's.
EXPECTED_MESSAGE_TYPES = {
    "exec.request",
    "exec.chunk",
    "exec.result",
    "proc.start",
    "proc.handle",
    "proc.status",
    "fs.read",
    "fs.content",
    "fs.write",
    "fs.list",
    "fs.listing",
    "fs.delete",
    "fs.ack",
    "pty.open",
    "pty.data",
    "pty.resize",
    "pty.close",
    "port.expose",
    "port.url",
    "session.quiesce",
    "error.decode",
    "error.version",
}


@pytest.fixture(name="document")
def _document() -> dict[str, Any]:
    """The catalogue as a plain parsed document, for mutation by the loader tests."""
    with CATALOGUE_PATH.open("rb") as handle:
        parsed = yaml.safe_load(handle)
    assert isinstance(parsed, dict)
    return parsed


# --- The shipped catalogue -------------------------------------------------------------


def test_envelope_is_the_four_key_map() -> None:
    envelope = load_catalogue().envelope
    assert [(f.key, f.name, f.spec.kind) for f in envelope] == [
        (ENVELOPE_KEY_VERSION, "v", TypeKind.UINT),
        (ENVELOPE_KEY_TYPE, "t", TypeKind.TEXT),
        (ENVELOPE_KEY_ID, "id", TypeKind.BYTES),
        (ENVELOPE_KEY_BODY, "b", TypeKind.MAP),
    ]


def test_version_is_the_first_envelope_key() -> None:
    # Key 1 sorts first under the deterministic profile, which is what makes the version
    # readable before any other field (R8.8).
    assert load_catalogue().envelope[0].key == 1


def test_catalogue_holds_exactly_the_designed_message_set() -> None:
    assert set(load_catalogue().message_types) == EXPECTED_MESSAGE_TYPES


def test_supported_range_admits_the_emitted_version() -> None:
    catalogue = load_catalogue()
    assert catalogue.supports(catalogue.protocol_version)
    assert not catalogue.supports(catalogue.supported_min - 1)
    assert not catalogue.supports(catalogue.supported_max + 1)


def test_every_output_and_name_field_is_byte_typed() -> None:
    annotated = list(load_catalogue().byte_typed_fields())
    assert annotated, "the catalogue declares no output or name fields at all"
    for t, field, spec in annotated:
        assert spec.kind is TypeKind.BYTES, (
            f"{t}.{field.name} carries bytes as {spec.kind}"
        )


@pytest.mark.parametrize(
    ("t", "field_name"),
    [
        ("exec.chunk", "data"),
        ("exec.result", "stdout"),
        ("exec.result", "stderr"),
        ("fs.content", "data"),
        ("fs.write", "data"),
        ("pty.data", "data"),
    ],
)
def test_process_output_fields_are_byte_strings(t: str, field_name: str) -> None:
    field = load_catalogue().messages[t].field_by_name(field_name)
    assert field.spec.kind is TypeKind.BYTES
    assert field.spec.carries is Carries.OUTPUT


def test_directory_entry_names_are_byte_strings() -> None:
    entries = load_catalogue().messages["fs.listing"].field_by_name("entries")
    assert entries.spec.items is not None
    name = next(f for f in entries.spec.items.fields if f.name == "name")
    assert name.spec.kind is TypeKind.BYTES
    assert name.spec.carries is Carries.NAME


def test_filesystem_paths_and_argv_elements_are_byte_strings() -> None:
    catalogue = load_catalogue()
    for t in ("fs.read", "fs.write", "fs.list", "fs.delete"):
        assert catalogue.messages[t].field_by_name("path").spec.kind is TypeKind.BYTES
    argv = catalogue.messages["exec.request"].field_by_name("argv")
    assert argv.spec.kind is TypeKind.LIST
    assert argv.spec.items is not None
    assert argv.spec.items.kind is TypeKind.BYTES


def test_bodies_that_carry_nothing_are_empty() -> None:
    catalogue = load_catalogue()
    for t in ("session.quiesce", "pty.close", "fs.ack"):
        assert catalogue.messages[t].body == ()


def test_error_message_bodies_report_what_the_codec_owes() -> None:
    catalogue = load_catalogue()
    decode = catalogue.messages["error.decode"]
    assert [f.name for f in decode.body] == ["field", "detail"]
    version = catalogue.messages["error.version"]
    assert [f.name for f in version.body] == [
        "received",
        "supportedMin",
        "supportedMax",
    ]


def test_every_integer_field_declares_its_range() -> None:
    # Property 1 draws integer fields from their declared boundaries.
    for message in load_catalogue().messages.values():
        for field in message.body:
            for spec in field.spec.walk():
                if spec.kind in (TypeKind.UINT, TypeKind.INT):
                    assert spec.range is not None, f"{message.t}.{field.name}"
                    assert spec.range.boundaries() == (spec.range.min, spec.range.max)


def test_only_a_running_process_status_may_omit_its_exit_code() -> None:
    catalogue = load_catalogue()
    optional = {
        (m.t, f.name) for m in catalogue.messages.values() for f in m.body if f.optional
    }
    assert optional == {("proc.status", "exitCode")}


def test_stream_discriminator_admits_only_stdout_and_stderr() -> None:
    stream = load_catalogue().messages["exec.chunk"].field_by_name("stream")
    assert stream.spec.range is not None
    assert stream.spec.range.boundaries() == (0, 1)


def test_directions_cover_the_orchestrator_and_both_peers() -> None:
    directions = {m.direction for m in load_catalogue().messages.values()}
    assert Direction.ORCHESTRATOR_TO_RUNTIME in directions
    assert Direction.BOTH in directions


def test_field_lookup_rejects_an_absent_field() -> None:
    message = load_catalogue().messages["exec.result"]
    assert message.field_by_key(1).name == "exitCode"
    with pytest.raises(KeyError):
        message.field_by_name("nope")


def test_loading_is_cached() -> None:
    assert load_catalogue() is load_catalogue()  # nosemgrep: identical-is-comparison — intentional identity test


# --- The loader fails closed -----------------------------------------------------------


def test_unknown_top_level_key_is_rejected(document: dict[str, Any]) -> None:
    document["extra"] = 1
    with pytest.raises(SchemaError, match="unknown key"):
        parse_catalogue(document)


def test_unknown_type_spec_key_is_rejected(document: dict[str, Any]) -> None:
    # A misspelled annotation must fail rather than be ignored: silently dropping `carries`
    # would report a text field as byte-typed.
    document["messages"][0]["body"][0]["carrys"] = "name"
    with pytest.raises(SchemaError, match="unknown key"):
        parse_catalogue(document)


def test_unknown_schema_version_is_rejected(document: dict[str, Any]) -> None:
    document["schemaVersion"] = 2
    with pytest.raises(SchemaError, match="schemaVersion"):
        parse_catalogue(document)


def test_unknown_type_kind_is_rejected(document: dict[str, Any]) -> None:
    document["messages"][0]["body"][1]["type"] = "string"
    with pytest.raises(SchemaError, match="type"):
        parse_catalogue(document)


def test_carries_on_a_non_byte_field_is_rejected(document: dict[str, Any]) -> None:
    url = document["messages"][-4]
    assert url["t"] == "port.url"
    url["body"][0]["carries"] = "output"
    with pytest.raises(SchemaError, match="must be bytes"):
        parse_catalogue(document)


def test_an_integer_field_without_a_range_is_rejected(document: dict[str, Any]) -> None:
    chunk = next(m for m in document["messages"] if m["t"] == "exec.chunk")
    del chunk["body"][0]["range"]
    with pytest.raises(SchemaError, match="must declare its range"):
        parse_catalogue(document)


def test_non_contiguous_body_keys_are_rejected(document: dict[str, Any]) -> None:
    result = next(m for m in document["messages"] if m["t"] == "exec.result")
    result["body"][2]["key"] = 9
    with pytest.raises(SchemaError, match="contiguous from 1"):
        parse_catalogue(document)


def test_duplicate_message_type_is_rejected(document: dict[str, Any]) -> None:
    document["messages"].append(copy.deepcopy(document["messages"][0]))
    with pytest.raises(SchemaError, match="duplicate message type"):
        parse_catalogue(document)


def test_altered_envelope_shape_is_rejected(document: dict[str, Any]) -> None:
    document["envelope"]["fields"][2]["type"] = "text"
    with pytest.raises(SchemaError, match="envelope"):
        parse_catalogue(document)


def test_emitted_version_outside_the_supported_range_is_rejected(
    document: dict[str, Any],
) -> None:
    document["protocol"]["version"] = 7
    with pytest.raises(SchemaError, match="outside"):
        parse_catalogue(document)


def test_inverted_supported_range_is_rejected(document: dict[str, Any]) -> None:
    document["protocol"]["supportedMin"] = 5
    document["protocol"]["supportedMax"] = 2
    with pytest.raises(SchemaError, match="exceeds"):
        parse_catalogue(document)


def test_list_without_items_is_rejected(document: dict[str, Any]) -> None:
    request = next(m for m in document["messages"] if m["t"] == "exec.request")
    del request["body"][0]["items"]
    with pytest.raises(SchemaError, match="must declare items"):
        parse_catalogue(document)


def test_message_without_a_requirement_reference_is_rejected(
    document: dict[str, Any],
) -> None:
    document["messages"][0]["requirements"] = []
    with pytest.raises(SchemaError, match="at least one requirement"):
        parse_catalogue(document)


def test_a_missing_document_section_is_rejected(document: dict[str, Any]) -> None:
    del document["envelope"]
    with pytest.raises(SchemaError, match="missing envelope"):
        parse_catalogue(document)
