# kiro-classification: public
"""The `/run` hook: configuration delivery, per-Session values, and state restoration.

Every test here is deterministic and none uses Hypothesis. The two properties over this surface —
readiness gating with configuration path equivalence, and per-Session value uniqueness — are
numbered properties with tasks of their own, so what is asserted here is the behaviour those
properties generalise, on named examples: the delivery decision, one archive restored byte for
byte, and each identifying reason a failed restoration reports.

The State_Store is a recording stand-in. It has to be: the offline suite denies outbound network
access, and neither the bucket nor the Sandbox execution role exists yet. `runtime.run_config`
declares the seam as one method with three failure types precisely so that a stand-in like this one
is the whole of what a test needs.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import struct
import tarfile
import zlib
from http import HTTPStatus
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from protocol.codec.messages import decode, encode
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.filesystem import ConfinedRoot
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.ports import PORT_EXPOSE, ExposedPorts
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.restore import RESTORE_FAILURE_PREFIX, RestoreCause
from runtime.run_config import (
    CONFIG_REFERENCE_KEY,
    MAX_RUN_CONFIG_BYTES,
    ConfigurationError,
    ReadDenied,
    ReferenceNotFound,
    RestoreRequest,
    RunConfiguration,
    RunConfigurationReader,
    StateReadFailure,
    parse_configuration,
)
from runtime.session_values import SessionValues

CATALOGUE = load_catalogue()

TEMPLATE = "https://sandbox-1.endpoint.example/ports/{port}"
REFERENCE = "tenants/tnt-1/sessions/ses-1/1/state.tar"


class RecordingStateStore:
    """The State_Store read seam, answering from a dictionary and recording every reference."""

    def __init__(
        self,
        objects: dict[str, bytes] | None = None,
        *,
        failure: Exception | None = None,
    ) -> None:
        self._objects = objects if objects is not None else {}
        self._failure = failure
        self.reads: list[str] = []

    async def read(self, reference: str) -> bytes:
        self.reads.append(reference)
        if self._failure is not None:
            raise self._failure
        stored = self._objects.get(reference)
        if stored is None:
            raise ReferenceNotFound(f"no object is stored at {reference}")
        return stored


def document(
    *,
    ports: tuple[int, ...] = (),
    template: str | None = None,
    restore: dict[str, object] | None = None,
    padding: int = 0,
) -> bytes:
    """A configuration document, optionally padded so its size crosses the payload limit."""
    body: dict[str, object] = {}
    if ports:
        body["exposedPorts"] = list(ports)
    if template is not None:
        body["endpointUrlTemplate"] = template
    if restore is not None:
        body["restore"] = restore
    if padding:
        # Padding has to be part of a field the schema declares, because an undeclared key is
        # refused. A long enough URL template is the honest way to make a document large.
        body["endpointUrlTemplate"] = f"https://{'p' * padding}.example/{{port}}"
    return json.dumps(body).encode()


def reference_payload(reference: str = REFERENCE) -> bytes:
    """The by-reference envelope, spelled the way the Compute_Provider spells it."""
    return json.dumps({CONFIG_REFERENCE_KEY: reference}).encode()


def archive(entries: dict[str, bytes], *, mode: int = 0o644) -> bytes:
    """A `tar` stream carrying regular files at the given relative paths."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            stream.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def tree_archive(members: tuple[tuple[str, int, bytes | None], ...]) -> bytes:
    """A `tar` stream carrying the given members in the given order.

    A content of None makes a directory member. The order is a parameter because it is the axis a
    restored directory's mode used to depend on: a directory the walk to a later member passes
    through is one whose mode has already been set by its own member, or one whose member is still
    to come, and both have to end at the archive's mode.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        for name, mode, content in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if content is None:
                info.type = tarfile.DIRTYPE
                stream.addfile(info)
                continue
            info.type = tarfile.REGTYPE
            info.size = len(content)
            stream.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def compressed_archive(entries: dict[str, bytes]) -> bytes:
    """A `w:gz` stream, so a truncation of it is a truncated *compressed* artifact."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            stream.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def archive_with(member: tarfile.TarInfo, content: bytes = b"") -> bytes:
    """A `tar` stream carrying exactly one member, however unrestorable."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        member.size = len(content)
        stream.addfile(member, io.BytesIO(content) if content else None)
    return buffer.getvalue()


def build(
    tmp_path: Path,
    *,
    state_store: RecordingStateStore | None = None,
    with_root: bool = True,
    max_payload_bytes: int = MAX_RUN_CONFIG_BYTES,
) -> tuple[TestClient, ReadinessGate, SandboxLifecycle, ExposedPorts]:
    """The real application, with the real gate, ports and lifecycle actions."""
    gate = ReadinessGate()
    ports = ExposedPorts(catalogue=CATALOGUE)
    lifecycle = SandboxLifecycle(
        ports=ports,
        filesystem_root=ConfinedRoot(tmp_path) if with_root else None,
        state_store=state_store,
        max_payload_bytes=max_payload_bytes,
    )
    operations = OperationRegistry(catalogue=CATALOGUE)
    ports.register(operations)
    app = create_app(
        actions=lifecycle, operations=operations, gate=gate, catalogue=CATALOGUE
    )
    return TestClient(app), gate, lifecycle, ports


def expose(client: TestClient, port: int) -> dict[str, object]:
    """Ask `port.expose` for a port and return the reply body, keyed by field name."""
    request = encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: PORT_EXPOSE,
            ENVELOPE_KEY_ID: b"cid",
            ENVELOPE_KEY_BODY: {
                CATALOGUE.messages[PORT_EXPOSE].field_by_name("port").key: port
            },
        },
        catalogue=CATALOGUE,
    )
    response = client.post(PROTOCOL_PATH, content=request)
    assert response.status_code == HTTPStatus.OK
    reply = decode(response.content, catalogue=CATALOGUE)
    t = reply[ENVELOPE_KEY_TYPE]
    body = reply[ENVELOPE_KEY_BODY]
    assert isinstance(t, str) and isinstance(body, dict)
    return {
        field.name: body[field.key]
        for field in CATALOGUE.messages[t].body
        if field.key in body
    }


# --- R7.11: one document, two delivery paths ----------------------------------------------


def test_an_inline_payload_is_the_configuration_document(tmp_path: Path) -> None:
    client, gate, lifecycle, _ = build(tmp_path)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=document(ports=(8080,), template=TEMPLATE))

    assert started.status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.SERVING
    assert lifecycle.configuration == RunConfiguration(
        exposed_ports=(8080,), endpoint_url_template=TEMPLATE
    )
    assert expose(client, 8080) == {"url": TEMPLATE.replace("{port}", "8080")}


def test_an_oversized_payload_is_fetched_from_the_state_store(tmp_path: Path) -> None:
    """R7.11's overflow path: the runtime retrieves the configuration under the reference."""
    oversized = document(ports=(3000,), template=TEMPLATE, padding=MAX_RUN_CONFIG_BYTES)
    assert len(oversized) > MAX_RUN_CONFIG_BYTES
    store = RecordingStateStore({REFERENCE: oversized})
    client, gate, lifecycle, _ = build(tmp_path, state_store=store)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=reference_payload())

    assert started.status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.SERVING
    assert store.reads == [REFERENCE]
    assert lifecycle.configuration == parse_configuration(oversized)


def test_both_delivery_paths_apply_the_same_configuration(tmp_path: Path) -> None:
    """The equivalence the paths are built for, on one document delivered each way."""
    same = document(ports=(8080, 3000), template=TEMPLATE)
    inline_client, _, inline, _ = build(tmp_path)
    fetched_client, _, fetched, _ = build(
        tmp_path, state_store=RecordingStateStore({REFERENCE: same})
    )

    assert inline_client.post(f"{HOOK_PATH_PREFIX}/run", content=same).status_code == HTTPStatus.OK
    assert (
        fetched_client.post(f"{HOOK_PATH_PREFIX}/run", content=reference_payload()).status_code
        == HTTPStatus.OK
    )

    assert inline.configuration == fetched.configuration
    # And the same URL for the same port, which is the applied configuration observed from
    # outside rather than read off the object.
    assert expose(inline_client, 3000) == expose(fetched_client, 3000)


def test_the_delivery_decision_is_keyed_off_the_provider_declared_limit() -> None:
    """The decision on its own: a reference envelope, or a document, and nothing in between."""
    reader = RunConfigurationReader(max_payload_bytes=MAX_RUN_CONFIG_BYTES)

    assert reader.max_payload_bytes == MAX_RUN_CONFIG_BYTES
    assert reader.reference_in(reference_payload()) == REFERENCE
    assert reader.reference_in(document(ports=(80,), template=TEMPLATE)) is None


def test_an_inline_payload_above_the_declared_limit_is_refused(tmp_path: Path) -> None:
    """The provider said it would not carry this, so the payload is a defect, not input."""
    client, gate, lifecycle, _ = build(tmp_path, max_payload_bytes=64)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=document(template=TEMPLATE, padding=256))

    assert started.status_code != HTTPStatus.OK
    assert "exceeds the provider-declared limit of 64" in started.text
    assert gate.phase is RuntimePhase.FAILED
    assert lifecycle.configuration is None


def test_a_fetched_document_is_not_bounded_by_the_payload_limit(tmp_path: Path) -> None:
    """Carrying more than the provider will carry is the whole reason the reference exists."""
    oversized = document(template=TEMPLATE, padding=256)
    store = RecordingStateStore({REFERENCE: oversized})
    client, _, lifecycle, _ = build(tmp_path, state_store=store, max_payload_bytes=64)

    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=reference_payload()).status_code == HTTPStatus.OK
    assert lifecycle.configuration == parse_configuration(oversized)


def test_a_reference_this_runtime_cannot_retrieve_is_refused(tmp_path: Path) -> None:
    client, gate, _, _ = build(tmp_path, state_store=None)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=reference_payload())

    assert started.status_code != HTTPStatus.OK
    assert "no State_Store reader configured" in started.text
    assert gate.phase is RuntimePhase.FAILED


def test_a_failed_configuration_fetch_names_the_reference(tmp_path: Path) -> None:
    store = RecordingStateStore(failure=ReadDenied("access denied"))
    client, gate, _, _ = build(tmp_path, state_store=store)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=reference_payload())

    assert started.status_code != HTTPStatus.OK
    assert REFERENCE in started.text
    assert "access denied" in started.text
    assert gate.phase is RuntimePhase.FAILED


# --- The document schema, and what a malformed payload does -------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", "empty"),
        (b"not json at all", "not readable JSON"),
        (b"\xff\xfe", "not readable JSON"),
        (b"[]", "must be a JSON object"),
        (b'{"exposedPorts": [8080], "unknownKey": 1}', "does not understand"),
        (b'{"exposedPorts": "8080"}', "must be a list of port numbers"),
        (b'{"exposedPorts": [0]}', "out-of-range port 0"),
        (b'{"exposedPorts": [70000]}', "out-of-range port 70000"),
        (b'{"exposedPorts": [true]}', "not a port number"),
        (b'{"endpointUrlTemplate": ""}', "non-empty URL template"),
        (b'{"endpointUrlTemplate": "https://x.example/fixed"}', "{port}"),
        (b'{"restore": "somewhere"}', "must be an object"),
        (b'{"restore": {}}', "non-empty State_Store reference"),
        (
            b'{"restore": {"reference": "r", "sizeBytes": -1}}',
            "non-negative byte count",
        ),
        (b'{"restore": {"reference": "r", "sha256": "abc"}}', "lowercase hex digits"),
        (b'{"startConfigRef": ""}', "non-empty State_Store reference"),
        (b'{"startConfigRef": "r", "exposedPorts": [80]}', "does not understand"),
    ],
)
def test_a_malformed_payload_is_a_non_200_that_says_why(
    tmp_path: Path, payload: bytes, expected: str
) -> None:
    """R7.8 needs only that 200 is not returned; the reason is what makes it actionable."""
    client, gate, lifecycle, _ = build(tmp_path)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=payload)

    assert started.status_code != HTTPStatus.OK
    assert expected in started.text
    assert gate.phase is RuntimePhase.FAILED
    assert lifecycle.configuration is None
    assert lifecycle.values is None


def test_ports_are_sorted_and_deduplicated_so_the_order_cannot_matter() -> None:
    assert parse_configuration(
        b'{"exposedPorts": [8080, 3000, 8080]}'
    ) == RunConfiguration(exposed_ports=(3000, 8080))


def test_a_declared_port_with_no_endpoint_template_is_refused(tmp_path: Path) -> None:
    client, gate, _, ports = build(tmp_path)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=document(ports=(8080,)))

    assert started.status_code != HTTPStatus.OK
    assert "no endpoint URL template" in started.text
    assert gate.phase is RuntimePhase.FAILED
    assert ports.declared == frozenset()


def test_an_empty_configuration_declares_no_ports_and_restores_nothing(
    tmp_path: Path,
) -> None:
    """`{}` is the configuration of a Session that asked for none of these things."""
    client, gate, lifecycle, ports = build(tmp_path)

    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.SERVING
    assert lifecycle.configuration == RunConfiguration()
    assert ports.declared == frozenset()


# --- R7.12: every per-Session value, generated inside the hook ----------------------------


def test_no_per_session_value_exists_before_the_run_hook(tmp_path: Path) -> None:
    """R7.8's second sentence, and R7.12's reason for existing, in one assertion."""
    _, _, lifecycle, _ = build(tmp_path)

    assert lifecycle.values is None
    assert lifecycle.configuration is None


def test_the_values_are_generated_while_the_run_hook_executes(tmp_path: Path) -> None:
    client, _, lifecycle, _ = build(tmp_path)

    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK

    values = lifecycle.values
    assert values is not None
    assert len(values.instance_id) == 32
    assert len(values.process_handle_key) == 32
    assert len(values.egress_private_key) == 32


def test_two_sandboxes_from_one_image_generate_distinct_values(tmp_path: Path) -> None:
    """The same import, the same code, two Sandboxes: no value is shared (R7.12)."""
    first_client, _, first, _ = build(tmp_path)
    second_client, _, second, _ = build(tmp_path)
    first_client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
    second_client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")

    assert first.values is not None and second.values is not None
    assert first.values.instance_id != second.values.instance_id
    assert first.values.process_handle_key != second.values.process_handle_key
    assert first.values.egress_private_key != second.values.egress_private_key


def test_a_second_run_does_not_regenerate_the_values(tmp_path: Path) -> None:
    """The gate refuses it; the action refuses it too, so neither alone is load-bearing."""
    client, _, lifecycle, _ = build(tmp_path)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
    generated = lifecycle.values

    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.CONFLICT
    assert lifecycle.values is generated

    with pytest.raises(ConfigurationError, match="already applied"):
        asyncio.run(lifecycle.apply_configuration(b"{}"))
    assert lifecycle.values is generated


def test_the_repr_withholds_the_two_secrets() -> None:
    """A traceback is a way out of the MicroVM for a value that must never leave it."""
    values = SessionValues.generate()

    rendered = repr(values)
    assert values.instance_id in rendered
    assert values.egress_private_key.hex() not in rendered
    assert values.process_handle_key.hex() not in rendered


# --- R13.4: state restored before readiness ----------------------------------------------


def test_persisted_state_is_restored_before_the_hook_returns_200(
    tmp_path: Path,
) -> None:
    entries = {
        "notes.txt": b"a line\n",
        "nested/deeper/data.bin": bytes(range(256)),
        "empty.txt": b"",
    }
    stream = archive(entries)
    store = RecordingStateStore({REFERENCE: stream})
    client, gate, _, _ = build(tmp_path, state_store=store)

    started = client.post(
        f"{HOOK_PATH_PREFIX}/run",
        content=document(
            restore={
                "reference": REFERENCE,
                "sizeBytes": len(stream),
                "sha256": hashlib.sha256(stream).hexdigest(),
            }
        ),
    )

    assert started.status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.SERVING
    for name, content in entries.items():
        assert (tmp_path / name).read_bytes() == content


def test_a_restored_file_replaces_one_the_image_already_shipped(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(b"from the image")
    stream = archive({"notes.txt": b"from the persisted state"})
    client, _, _, _ = build(
        tmp_path, state_store=RecordingStateStore({REFERENCE: stream})
    )

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=document(restore={"reference": REFERENCE}))

    assert started.status_code == HTTPStatus.OK
    assert (tmp_path / "notes.txt").read_bytes() == b"from the persisted state"


def test_a_restored_files_mode_is_the_archives(tmp_path: Path) -> None:
    stream = archive({"script.sh": b"#!/bin/sh\n"}, mode=0o755)
    client, _, _, _ = build(
        tmp_path, state_store=RecordingStateStore({REFERENCE: stream})
    )

    client.post(f"{HOOK_PATH_PREFIX}/run", content=document(restore={"reference": REFERENCE}))

    assert (os.stat(tmp_path / "script.sh").st_mode & 0o777) == 0o755


#: The members of the directory-mode archive: a directory with content below it, an empty one, a
#: nested described directory, and a file whose parents include one the archive never describes.
_DIRECTORY_MEMBERS: tuple[tuple[str, int, bytes | None], ...] = (
    ("described", 0o755, None),
    ("described/file.bin", 0o644, b"content"),
    ("described/inner", 0o750, None),
    ("described/inner/deeper.bin", 0o600, b"deeper"),
    ("empty", 0o755, None),
    ("invented/below/leaf.bin", 0o644, b"leaf"),
)

#: What each of those paths has to be after the restore. `invented` and `invented/below` are the
#: exception and the reason the modes cannot simply be applied to every directory on the way down:
#: the archive never described them, so they are created owner-only rather than given a mode
#: borrowed from something else, because a permissive intermediate directory would widen access to
#: everything restored beneath it.
_EXPECTED_MODES: dict[str, int] = {
    "described": 0o755,
    "described/file.bin": 0o644,
    "described/inner": 0o750,
    "described/inner/deeper.bin": 0o600,
    "empty": 0o755,
    "invented": 0o700,
    "invented/below": 0o700,
    "invented/below/leaf.bin": 0o644,
}


@pytest.mark.parametrize(
    "reverse", [False, True], ids=["parents-first", "children-first"]
)
def test_a_restored_directorys_mode_is_the_archives(
    tmp_path: Path, reverse: bool
) -> None:
    """R13.4: a directory comes back as it was persisted, whatever followed it in the stream.

    Both member orders, because the mode used to depend on the order: `_open_directory` applied its
    mode argument to a directory that already existed, so the walk down to a directory's first child
    chmodded the directory back to the owner-only default a moment after its own member had set the
    archive's mode. An empty directory kept the archive's mode and a populated one did not, which is
    the asymmetry this asserts away. Reversing the order also covers the other direction: a walk
    that creates a directory before its describing member arrives must not stop that member setting
    the mode.
    """
    members = tuple(reversed(_DIRECTORY_MEMBERS)) if reverse else _DIRECTORY_MEMBERS
    stream = tree_archive(members)
    client, _, _, _ = build(
        tmp_path, state_store=RecordingStateStore({REFERENCE: stream})
    )

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=document(restore={"reference": REFERENCE}))

    assert started.status_code == HTTPStatus.OK, started.text
    assert {
        path: os.stat(tmp_path / path).st_mode & 0o777 for path in _EXPECTED_MODES
    } == _EXPECTED_MODES


# --- R13.7: a non-200 with a reason identifying the restoration failure -------------------


def damaged_compressed_archive() -> bytes:
    """A compressed archive whose recorded checksum does not describe its own bytes.

    Framed by hand rather than by flipping a byte in a `w:gz` stream, because where a flip lands
    decides which layer notices and that is not something a test should depend on. This is the one
    corruption the *format* is specified to catch: the gzip trailer records a CRC32 over the
    decompressed bytes, so a wrong one is a damaged artifact by definition. The `tar` inside carries
    no end-of-archive blocks, which is what makes the reader read to the end of the compressed
    stream and therefore reach the check.

    It surfaces as `gzip.BadGzipFile` — an `OSError`, and so not a `tarfile.TarError` — which is the
    same family as the truncation above and used to escape unidentified for the same reason.
    """
    content = b"restored content " * 8
    member = tarfile.TarInfo("data.bin")
    member.type = tarfile.REGTYPE
    member.mode = 0o644
    member.size = len(content)
    raw = member.tobuf() + content + b"\x00" * (-len(content) % tarfile.BLOCKSIZE)
    deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = deflate.compress(raw) + deflate.flush()
    header = b"\x1f\x8b\x08\x00" + b"\x00" * 4 + b"\x00\xff"
    trailer = struct.pack("<II", zlib.crc32(raw) ^ 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    return header + body + trailer


def half_a_compressed_archive() -> bytes:
    """A real compressed archive cut in half.

    Enough content that the cut lands inside the deflate stream rather than in the gzip trailer, so
    the decompressor runs out of input with a member still to come. That is the condition, and it is
    an `EOFError` rather than anything `tarfile` raises, which is why it went unidentified.
    """
    whole = compressed_archive({"data.bin": b"restored content " * 512})
    return whole[: len(whole) // 2]


_HALF_A_COMPRESSED_ARCHIVE = half_a_compressed_archive()


def failing_restore(
    tmp_path: Path,
    *,
    stored: bytes | None = None,
    failure: Exception | None = None,
    restore: dict[str, object] | None = None,
    with_root: bool = True,
) -> tuple[HTTPStatus, str, RuntimePhase]:
    """Drive one failing `/run` and return the status, the reason, and the phase."""
    objects = {} if stored is None else {REFERENCE: stored}
    store = RecordingStateStore(objects, failure=failure)
    client, gate, _, _ = build(tmp_path, state_store=store, with_root=with_root)
    response = client.post(
        f"{HOOK_PATH_PREFIX}/run",
        content=document(restore=restore or {"reference": REFERENCE}),
    )
    return HTTPStatus(response.status_code), response.text, gate.phase


@pytest.mark.parametrize(
    ("cause", "stored", "failure", "restore"),
    [
        (RestoreCause.REFERENCE_ABSENT, None, None, None),
        (
            RestoreCause.READ_DENIED,
            None,
            ReadDenied("the Sandbox execution role may not read this prefix"),
            None,
        ),
        (
            RestoreCause.TRANSFER_FAILED,
            None,
            StateReadFailure("connection reset"),
            None,
        ),
        (
            RestoreCause.TRUNCATED_TRANSFER,
            archive({"a.txt": b"a"}),
            None,
            {"reference": REFERENCE, "sizeBytes": 999_999},
        ),
        (
            RestoreCause.DIGEST_MISMATCH,
            archive({"a.txt": b"a"}),
            None,
            {"reference": REFERENCE, "sha256": "0" * 64},
        ),
        (RestoreCause.ARCHIVE_UNREADABLE, b"not an archive at all", None, None),
        # A compressed artifact that stopped part-way, which is what a partially transferred
        # object looks like. Neither `sizeBytes` nor `sha256` is configured, deliberately: both
        # are optional in the document, so the reader is the only thing that can notice, and the
        # decompressor reports it as an `EOFError` rather than as anything `tarfile` raises.
        (
            RestoreCause.ARCHIVE_UNREADABLE,
            _HALF_A_COMPRESSED_ARCHIVE,
            None,
            None,
        ),
        (RestoreCause.ARCHIVE_UNREADABLE, b"\x1f\x8b\x08\x00", None, None),
        # And a compressed artifact that is damaged rather than short, which the compression
        # layer reports as its own error type rather than as anything `tarfile` raises.
        (RestoreCause.ARCHIVE_UNREADABLE, damaged_compressed_archive(), None, None),
    ],
)
def test_each_restoration_failure_reports_its_own_cause(
    tmp_path: Path,
    cause: RestoreCause,
    stored: bytes | None,
    failure: Exception | None,
    restore: dict[str, object] | None,
) -> None:
    """R13.7: the reason identifies the failure, from a closed set the Control_Plane records."""
    status, reason, phase = failing_restore(
        tmp_path, stored=stored, failure=failure, restore=restore
    )

    assert status != HTTPStatus.OK
    assert reason.startswith(RESTORE_FAILURE_PREFIX)
    assert f"[{cause}]" in reason
    assert REFERENCE in reason
    assert phase is RuntimePhase.FAILED


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        (tarfile.TarInfo("../escape.txt"), "resolves outside"),
        (tarfile.TarInfo("nested/../../escape.txt"), "resolves outside"),
    ],
)
def test_a_member_that_leaves_the_root_is_refused(
    tmp_path: Path, member: tarfile.TarInfo, expected: str
) -> None:
    member.type = tarfile.REGTYPE
    status, reason, phase = failing_restore(tmp_path, stored=archive_with(member))

    assert status != HTTPStatus.OK
    assert f"[{RestoreCause.MEMBER_REFUSED}]" in reason
    assert expected in reason
    assert phase is RuntimePhase.FAILED
    assert not (tmp_path.parent / "escape.txt").exists()


def test_an_absolute_member_is_refused(tmp_path: Path) -> None:
    member = tarfile.TarInfo("/etc/passwd")
    member.type = tarfile.REGTYPE
    status, reason, _ = failing_restore(tmp_path, stored=archive_with(member))

    assert status != HTTPStatus.OK
    assert "absolute path" in reason


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (tarfile.SYMTYPE, "a symbolic link"),
        (tarfile.LNKTYPE, "a hard link"),
        (tarfile.CHRTYPE, "a device node"),
        (tarfile.FIFOTYPE, "a FIFO"),
    ],
)
def test_a_member_this_runtime_will_not_restore_is_refused(
    tmp_path: Path, kind: bytes, expected: str
) -> None:
    """The archive escape this closes is documented in `runtime.restore`."""
    member = tarfile.TarInfo("link")
    member.type = kind
    member.linkname = "/etc"
    status, reason, _ = failing_restore(tmp_path, stored=archive_with(member))

    assert status != HTTPStatus.OK
    assert f"[{RestoreCause.MEMBER_REFUSED}]" in reason
    assert expected in reason
    assert not (tmp_path / "link").exists()


def test_a_runtime_with_no_configured_root_refuses_to_restore(tmp_path: Path) -> None:
    status, reason, phase = failing_restore(
        tmp_path, stored=archive({"a.txt": b"a"}), with_root=False
    )

    assert status != HTTPStatus.OK
    assert "no configured filesystem root" in reason
    assert phase is RuntimePhase.FAILED


def test_a_failed_restoration_leaves_the_handler_closed_with_the_same_reason(
    tmp_path: Path,
) -> None:
    """The gate holds the reason, so a request arriving afterwards is told what happened."""
    client, gate, lifecycle, ports = build(
        tmp_path, state_store=RecordingStateStore({})
    )

    started = client.post(
        f"{HOOK_PATH_PREFIX}/run",
        content=document(
            ports=(8080,), template=TEMPLATE, restore={"reference": REFERENCE}
        ),
    )

    assert started.status_code != HTTPStatus.OK
    assert gate.phase is RuntimePhase.FAILED
    # Nothing was applied: the port set is still empty even though the document declared one,
    # because the publish happens after the restore and not alongside it.
    assert ports.declared == frozenset()
    assert lifecycle.configuration is None
    refused = client.post(PROTOCOL_PATH, content=b"\x00")
    assert refused.status_code == HTTPStatus.GONE
    assert RESTORE_FAILURE_PREFIX in refused.text


def test_the_restore_request_carries_what_the_writer_recorded() -> None:
    """The two optional fields are what separate a truncated transfer from a corrupt one."""
    parsed = parse_configuration(
        json.dumps(
            {
                "restore": {
                    "reference": REFERENCE,
                    "sizeBytes": 10,
                    "sha256": "a" * 64,
                }
            }
        ).encode()
    )

    assert parsed.restore == RestoreRequest(
        reference=REFERENCE, size_bytes=10, sha256="a" * 64
    )
