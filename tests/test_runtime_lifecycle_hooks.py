# kiro-classification: public
"""The `/suspend`, `/resume` and `/terminate` hook bodies: quiesce, refresh, and the artifact write.

Every test here is deterministic and none uses Hypothesis. The two properties over this surface —
suspend and resume state preservation, and artifact persistence round-trip with restoration failure
reporting — are numbered properties with tasks of their own; what is asserted here is the behaviour
those properties generalise, on named examples.

Both State_Store seams are recording stand-ins, and so is the egress identity source. That is not a
shortcut: the offline suite denies outbound network access, neither the artifact bucket nor the
Egress_Controller's signing endpoint exists yet, and the seams are one method each precisely so that
a stand-in like these is the whole of what a test needs. No bucket, no endpoint and no key material
here is real, and the certificates are obviously-fake byte strings.

The strongest assertion in the module is the round trip: an archive `runtime.persist` produced,
restored by `runtime.restore` through the `RestoreRequest` the artifact itself derives, compared
against the tree it came from. That is one check over both sides of the format, which is worth more
than two checks each asserting one side agrees with a literal.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tarfile
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from protocol.schema import load_catalogue
from runtime.app import HOOK_PATH_PREFIX, create_app
from runtime.egress_identity import (
    EgressIdentity,
    EgressIdentityManager,
    EgressRefreshFailure,
)
from runtime.filesystem import ConfinedRoot
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.persist import (
    ARTIFACT_STATUS_MEMBER,
    ArtifactPersistFailure,
    PersistedArtifact,
    SkippedMember,
    StateStoreWriter,
    StateWriteFailure,
    WriteDenied,
    persist_state,
)
from runtime.ports import ExposedPorts
from runtime.process import ProcessManager, argv_of, register_process_operations
from runtime.quiesce import (
    OutboundConnections,
    QuiesceFailure,
    QuiesceReport,
    quiesce,
)
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.restore import restore_state
from runtime.run_config import (
    DEFAULT_PERSIST_DEADLINE_MS,
    MAX_PERSIST_DEADLINE_MS,
    ConfigurationError,
    PersistRequest,
    ReferenceNotFound,
    RunConfiguration,
    parse_configuration,
)

CATALOGUE = load_catalogue()

#: Obviously fake. A reference is opaque to the runtime, so the only thing that matters about this
#: string is that the same one comes back out.
REFERENCE = "tenants/tnt-fake/sessions/ses-fake/1/state.tar"

#: An obviously-fake certificate. Not PEM, not DER, not anything a parser would accept: the runtime
#: never parses it, and a plausible-looking one would invite a reader to think it did.
CERTIFICATE = b"not-a-real-certificate"
NOT_AFTER = 4_102_444_800

#: The interpreter running the suite, as a byte string, because `argv` is byte-typed.
PYTHON = os.fsencode(sys.executable)

#: A bound on every wait here. Present so a regression is a failure rather than a hang.
_WAIT_SECONDS = 20.0


# --- The stand-ins for the three seams -----------------------------------------------------


class RecordingWriter:
    """The State_Store write seam, recording every artifact instead of storing one."""

    def __init__(self, *, failure: Exception | None = None, delay: float = 0.0) -> None:
        self._failure = failure
        self._delay = delay
        self.written: list[PersistedArtifact] = []

    async def write(self, artifact: PersistedArtifact) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._failure is not None:
            raise self._failure
        self.written.append(artifact)

    @property
    def only(self) -> PersistedArtifact:
        assert len(self.written) == 1, self.written
        return self.written[0]


class RecordingReader:
    """The State_Store read seam, answering from whatever the writer recorded."""

    def __init__(self, writer: RecordingWriter) -> None:
        self._writer = writer

    async def read(self, reference: str) -> bytes:
        for artifact in self._writer.written:
            if artifact.reference == reference:
                return artifact.body
        raise ReferenceNotFound(f"no object is stored at {reference}")


class RecordingSource:
    """The Family B signing exchange, recording the key it was handed instead of signing with it."""

    def __init__(
        self,
        *,
        failure: Exception | None = None,
        delay: float = 0.0,
        certificate: bytes = CERTIFICATE,
    ) -> None:
        #: Public and mutable, so a test can make an established source start failing part-way
        #: through a suspend and resume cycle without reaching into a private attribute.
        self.failure = failure
        self._delay = delay
        self._certificate = certificate
        self.keys: list[bytes] = []

    async def refresh(self, private_key: bytes) -> EgressIdentity:
        self.keys.append(private_key)
        if self._delay:
            await asyncio.sleep(self._delay)
        if self.failure is not None:
            raise self.failure
        return EgressIdentity(
            certificate=self._certificate + b"-" + str(len(self.keys)).encode("ascii"),
            not_after_epoch_seconds=NOT_AFTER,
        )


class RecordingOutbound:
    """A holder of connections out of the MicroVM, recording the close instead of performing one."""

    def __init__(self, *, failure: Exception | None = None, delay: float = 0.0) -> None:
        self._failure = failure
        self._delay = delay
        self.closes = 0

    async def close_outbound(self) -> None:
        self.closes += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._failure is not None:
            raise self._failure


class RefusingOutbound(RecordingOutbound):
    """A holder whose close fails, so that `/suspend` has something real to refuse over."""

    def __init__(self) -> None:
        super().__init__(failure=OSError("the connector is already gone"))


# --- The application under test ------------------------------------------------------------


@dataclass(slots=True)
class Runtime:
    """One started application and everything a test needs to look inside it."""

    client: TestClient
    gate: ReadinessGate
    lifecycle: SandboxLifecycle
    root: Path
    writer: RecordingWriter
    source: RecordingSource
    outbound: tuple[RecordingOutbound, ...]
    processes: ProcessManager


def build(
    tmp_path: Path,
    *,
    outbound: tuple[RecordingOutbound, ...] = (),
    source: RecordingSource | None = None,
    with_egress: bool = True,
    with_writer: bool = True,
    writer: RecordingWriter | None = None,
    egress_deadline_seconds: float = 5.0,
) -> Runtime:
    """The real application, with the real gate, ports, process manager and lifecycle actions."""
    root = tmp_path / "work"
    root.mkdir(exist_ok=True)
    gate = ReadinessGate()
    ports = ExposedPorts(catalogue=CATALOGUE)
    resolved_writer = writer if writer is not None else RecordingWriter()
    resolved_source = source if source is not None else RecordingSource()
    operations = OperationRegistry(catalogue=CATALOGUE)
    processes = register_process_operations(
        operations, manager=ProcessManager(catalogue=CATALOGUE)
    )
    ports.register(operations)
    lifecycle = SandboxLifecycle(
        ports=ports,
        filesystem_root=ConfinedRoot(root),
        state_store=RecordingReader(resolved_writer),
        state_writer=resolved_writer if with_writer else None,
        egress_identity=(
            EgressIdentityManager(
                resolved_source, deadline_seconds=egress_deadline_seconds
            )
            if with_egress
            else None
        ),
        outbound=outbound,
        running_work=(processes,),
    )
    client = TestClient(
        create_app(
            actions=lifecycle, operations=operations, gate=gate, catalogue=CATALOGUE
        )
    )
    # Entered here and left by `close`, because a Starlette test client used outside a context
    # manager runs each request on a fresh event loop, and the task reaping a background child
    # belongs to the loop that started it. One entered client is one loop, which is also what the
    # deployed runtime is.
    client.__enter__()
    return Runtime(
        client=client,
        gate=gate,
        lifecycle=lifecycle,
        root=root,
        writer=resolved_writer,
        source=resolved_source,
        outbound=outbound,
        processes=processes,
    )


def close(runtime: Runtime) -> None:
    """Terminate and leave the client, so no test leaves a child behind."""
    if runtime.gate.phase is not RuntimePhase.TERMINATED:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")
    runtime.client.__exit__(None, None, None)


def document(**sections: object) -> bytes:
    return json.dumps(sections).encode()


def persist_section(
    *,
    reference: str = REFERENCE,
    paths: list[str] | None = None,
    deadline_ms: int | None = None,
    compress: bool | None = None,
) -> dict[str, object]:
    section: dict[str, object] = {"reference": reference}
    if paths is not None:
        section["paths"] = paths
    if deadline_ms is not None:
        section["deadlineMs"] = deadline_ms
    if compress is not None:
        section["compress"] = compress
    return section


def tree_of(root: Path) -> dict[str, bytes]:
    """Every regular file below `root`, by relative path. The comparison a round trip is judged on."""
    found: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            found[str(path.relative_to(root))] = path.read_bytes()
    return found


def read_status(artifact: PersistedArtifact) -> dict[str, object]:
    """The reserved status member, decoded straight from the archive stream."""
    with tarfile.open(fileobj=io.BytesIO(artifact.body), mode="r:*") as stream:
        member = stream.extractfile(ARTIFACT_STATUS_MEMBER)
        assert member is not None, "every archive carries the status member"
        with member:
            decoded = json.loads(member.read())
    assert isinstance(decoded, dict)
    return decoded


def member_names(artifact: PersistedArtifact) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(artifact.body), mode="r:*") as stream:
        return stream.getnames()


def crowd(root: Path, count: int) -> None:
    """Fill `root` with enough small files that a one-millisecond deadline cannot outrun them.

    The tests that assert on truncation need the deadline to expire, and a handful of files can be
    archived faster than the smallest deadline the document admits. This makes the outcome a
    property of the tree rather than of how fast the machine happens to be.
    """
    for index in range(count):
        (root / f"file-{index:03d}.txt").write_bytes(b"x" * 512)


def restore_into_fresh(
    artifact: PersistedArtifact, destination: Path
) -> dict[str, bytes]:
    """Restore an artifact into an empty root through `runtime.restore`, and read the result.

    The `RestoreRequest` comes from the artifact rather than being written out by hand, so the size
    and digest `runtime.restore` verifies are the ones the write side recorded. That is what makes
    those checks load-bearing instead of vestigial.
    """
    destination.mkdir(parents=True, exist_ok=True)
    asyncio.run(
        restore_state(
            artifact.as_restore_request(),
            root=ConfinedRoot(destination),
            source=RecordingReader(_writer_holding(artifact)),
        )
    )
    return tree_of(destination)


def _writer_holding(artifact: PersistedArtifact) -> RecordingWriter:
    writer = RecordingWriter()
    writer.written.append(artifact)
    return writer


# --- R7.9: `/suspend` flushes and closes, and stops nothing ---------------------------------


def test_suspend_flushes_and_closes_every_outbound_holder(tmp_path: Path) -> None:
    first, second = RecordingOutbound(), RecordingOutbound()
    runtime = build(tmp_path, outbound=(first, second))
    try:
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK
        (runtime.root / "notes.txt").write_bytes(b"work in progress")

        suspended = runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")

        assert suspended.status_code == HTTPStatus.OK
        assert runtime.gate.phase is RuntimePhase.SUSPENDED
        report = runtime.lifecycle.quiesced
        assert report == QuiesceReport(flushed_root=True, synced=True, closed=2)
        assert (first.closes, second.closes) == (1, 1)
    finally:
        close(runtime)


def test_suspend_leaves_the_sessions_processes_running(tmp_path: Path) -> None:
    """R10.5 and R13.2: a suspended Sandbox resumes, so killing its children would be wrong."""
    runtime = build(tmp_path)
    try:
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK
        handle = _start_background(runtime, seconds=_WAIT_SECONDS)

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == HTTPStatus.OK

        assert handle in runtime.processes.handles
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK
        # Still the same process, still running, after a full suspend and resume cycle.
        assert handle in runtime.processes.handles
    finally:
        close(runtime)


def test_an_outbound_close_that_fails_makes_suspend_a_non_200(tmp_path: Path) -> None:
    """A connection held across a snapshot hangs on resume, so a failed close is not absorbed."""
    refusing, healthy = RefusingOutbound(), RecordingOutbound()
    runtime = build(tmp_path, outbound=(refusing, healthy))
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")

        with pytest.raises(QuiesceFailure, match="RefusingOutbound"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")

        # The holder after the failing one was still attempted, which is the whole reason the
        # failures are accumulated rather than raised at the first.
        assert healthy.closes == 1
        assert runtime.gate.phase is RuntimePhase.SUSPENDED
        assert runtime.lifecycle.quiesced is None
    finally:
        close(runtime)


def test_a_slow_outbound_close_is_bounded(tmp_path: Path) -> None:
    """Every wait in the hook is bounded, so a client that never returns is a failure not a hang."""
    slow = RecordingOutbound(delay=_WAIT_SECONDS)

    async def scenario() -> None:
        with pytest.raises(QuiesceFailure, match="did not complete within"):
            await quiesce(outbound=(slow,), deadline_seconds=0.05)

    asyncio.run(asyncio.wait_for(scenario(), timeout=_WAIT_SECONDS))


def test_a_runtime_with_no_configured_root_still_flushes(tmp_path: Path) -> None:
    """`flushed_root` is False and `synced` is True: a truthful report, not a skipped flush."""
    report = asyncio.run(quiesce())

    assert report == QuiesceReport(flushed_root=False, synced=True, closed=0)


def test_suspend_is_repeatable_because_a_hook_may_be_delivered_twice(
    tmp_path: Path,
) -> None:
    holder = RecordingOutbound()
    runtime = build(tmp_path, outbound=(holder,))
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == HTTPStatus.OK
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == HTTPStatus.OK

        # The gate absorbs the second transition; the flush and the close happen again, which is
        # what a repeated delivery of a hook that promises durability should do.
        assert holder.closes == 2
    finally:
        close(runtime)


# --- R7.10: `/resume` refreshes the Family B identity before the handler reopens -------------


def test_resume_refreshes_the_identity_over_the_key_run_generated(tmp_path: Path) -> None:
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
        values = runtime.lifecycle.values
        assert values is not None
        runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK

        # The key the signing exchange was handed is the per-Session one generated inside `/run`,
        # not a value that could have been captured at image build time (R7.12).
        assert runtime.source.keys == [values.egress_private_key]
        identity = runtime.lifecycle.egress_identity
        assert identity is not None
        assert identity.not_after_epoch_seconds == NOT_AFTER
        assert runtime.gate.phase is RuntimePhase.SERVING
    finally:
        close(runtime)


def test_each_resume_refreshes_again(tmp_path: Path) -> None:
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
        for _ in range(2):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")
            assert runtime.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK

        first = runtime.lifecycle.egress_identity
        assert first is not None
        assert len(runtime.source.keys) == 2
        # The certificate changed, so the identity in effect is the one this resume produced rather
        # than one left over from the previous cycle.
        assert first.certificate.endswith(b"-2")
    finally:
        close(runtime)


def test_a_failed_refresh_leaves_the_handler_closed_and_the_previous_identity(
    tmp_path: Path,
) -> None:
    """R7.10's ordering: no request is served against a stale egress identity."""
    source = RecordingSource()
    runtime = build(tmp_path, source=source)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
        runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK
        established = runtime.lifecycle.egress_identity
        runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")

        source.failure = OSError("the signing endpoint refused the connection")
        with pytest.raises(EgressRefreshFailure, match="OSError"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/resume")

        assert runtime.gate.phase is RuntimePhase.SUSPENDED
        assert runtime.lifecycle.egress_identity is established
    finally:
        close(runtime)


def test_a_resume_before_any_run_cannot_refresh_anything(tmp_path: Path) -> None:
    """The gate would refuse the transition, but the refresh runs first, so it refuses too."""
    runtime = build(tmp_path)
    try:
        with pytest.raises(EgressRefreshFailure, match="no per-Session egress private key"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/resume")

        assert runtime.gate.phase is RuntimePhase.CLOSED
        assert runtime.source.keys == []
    finally:
        close(runtime)


def test_a_runtime_with_no_egress_identity_refuses_to_resume(tmp_path: Path) -> None:
    """R7.10 is unconditional, so a runtime with nothing to refresh is misconfigured."""
    runtime = build(tmp_path, with_egress=False)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
        runtime.client.post(f"{HOOK_PATH_PREFIX}/suspend")

        with pytest.raises(ConfigurationError, match="no egress identity manager"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/resume")

        assert runtime.gate.phase is RuntimePhase.SUSPENDED
        assert runtime.lifecycle.egress_identity is None
    finally:
        close(runtime)


def test_a_slow_signing_exchange_is_bounded() -> None:
    manager = EgressIdentityManager(
        RecordingSource(delay=_WAIT_SECONDS), deadline_seconds=0.05
    )

    async def scenario() -> None:
        with pytest.raises(EgressRefreshFailure, match="did not complete within"):
            await manager.refresh(private_key=b"fake-key-material")

    asyncio.run(asyncio.wait_for(scenario(), timeout=_WAIT_SECONDS))
    assert manager.identity is None
    assert manager.refresh_count == 0


@pytest.mark.parametrize(
    ("certificate", "not_after"),
    [(b"", NOT_AFTER), (CERTIFICATE, 0), (CERTIFICATE, -1)],
)
def test_an_identity_that_could_authenticate_nothing_is_refused(
    certificate: bytes, not_after: int
) -> None:
    with pytest.raises(ValueError, match="egress identity"):
        EgressIdentity(certificate=certificate, not_after_epoch_seconds=not_after)


# --- R13.3: `/terminate` writes the configured artifacts, and ends the running work ----------


def test_the_persisted_archive_round_trips_through_restore(tmp_path: Path) -> None:
    """The strongest assertion here: what this side writes is what `runtime.restore` reads."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(
            f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section())
        )
        written = {
            "notes.txt": b"a line\n",
            "nested/deeper/data.bin": bytes(range(256)),
            "empty.txt": b"",
        }
        for name, content in written.items():
            target = runtime.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        artifact = runtime.writer.only
        assert artifact.reference == REFERENCE
        assert artifact.truncated is False
        restored = restore_into_fresh(artifact, tmp_path / "restored")
        assert {
            name: content
            for name, content in restored.items()
            if name != ARTIFACT_STATUS_MEMBER
        } == written
    finally:
        close(runtime)


def test_a_compressed_archive_round_trips_too(tmp_path: Path) -> None:
    """`runtime.restore` opens `r:*`, so both forms are one code path on the way back."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(
            f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section(compress=True))
        )
        (runtime.root / "notes.txt").write_bytes(b"compressible " * 100)

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        artifact = runtime.writer.only
        # Gzip's own magic, which is the observable difference between the two forms.
        assert artifact.body[:2] == b"\x1f\x8b"
        restored = restore_into_fresh(artifact, tmp_path / "restored")
        assert restored["notes.txt"] == b"compressible " * 100
    finally:
        close(runtime)


def test_the_recorded_size_and_digest_are_the_ones_restore_verifies(
    tmp_path: Path,
) -> None:
    """Recorded on the write side so the reader's checks guard something (R13.4's two fields)."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        (runtime.root / "notes.txt").write_bytes(b"a line\n")
        runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")

        artifact = runtime.writer.only
        request = artifact.as_restore_request()

        assert request.reference == REFERENCE
        assert request.size_bytes == len(artifact.body)
        assert request.sha256 == artifact.sha256
        # And a document composed from it parses back to the same request, which is the shape the
        # next generation's `/run` payload carries.
        composed = parse_configuration(
            document(
                restore={
                    "reference": request.reference,
                    "sizeBytes": request.size_bytes,
                    "sha256": request.sha256,
                }
            )
        )
        assert composed.restore == request
    finally:
        close(runtime)


def test_only_the_configured_paths_are_persisted(tmp_path: Path) -> None:
    runtime = build(tmp_path)
    try:
        runtime.client.post(
            f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section(paths=["keep"]))
        )
        (runtime.root / "keep").mkdir()
        (runtime.root / "keep" / "wanted.txt").write_bytes(b"wanted")
        (runtime.root / "discard.txt").write_bytes(b"not asked for")

        runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")

        restored = restore_into_fresh(runtime.writer.only, tmp_path / "restored")
        assert set(restored) == {"keep/wanted.txt", ARTIFACT_STATUS_MEMBER}
    finally:
        close(runtime)


def test_a_configured_path_that_does_not_exist_is_skipped_not_fatal(
    tmp_path: Path,
) -> None:
    """A Session that produced no `out/` is an ordinary outcome, not a lost artifact."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(
            f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section(paths=["kept.txt", "out"]))
        )
        (runtime.root / "kept.txt").write_bytes(b"kept")

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        artifact = runtime.writer.only
        assert artifact.truncated is False
        assert [skipped.path for skipped in artifact.skipped] == ["out"]
        assert read_status(artifact)["skipped"] == [
            {"path": "out", "reason": "No such file or directory"}
        ]
    finally:
        close(runtime)


@pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks and FIFOs need a POSIX filesystem"
)
def test_a_member_restore_would_refuse_is_skipped_and_named(tmp_path: Path) -> None:
    """`runtime.restore` fails a whole archive over one symlink, so one must never be persisted."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        (runtime.root / "real.txt").write_bytes(b"real")
        (runtime.root / "link").symlink_to("real.txt")
        os.mkfifo(runtime.root / "pipe")

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        artifact = runtime.writer.only
        assert set(artifact.skipped) == {
            SkippedMember("link", "a symbolic link, which is never persisted or restored"),
            SkippedMember("pipe", "a FIFO, which is never persisted or restored"),
        }
        # And the proof that skipping was the right call: the archive restores, which it could not
        # have done with either member in it.
        restored = restore_into_fresh(artifact, tmp_path / "restored")
        assert set(restored) == {"real.txt", ARTIFACT_STATUS_MEMBER}
    finally:
        close(runtime)


def test_the_reserved_status_name_is_not_overwritten_by_the_sessions_own_file(
    tmp_path: Path,
) -> None:
    """Two members with one name is an archive whose restored content depends on member order."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        (runtime.root / ARTIFACT_STATUS_MEMBER).write_bytes(b"the Session's own file")

        runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")

        artifact = runtime.writer.only
        assert member_names(artifact).count(ARTIFACT_STATUS_MEMBER) == 1
        assert artifact.skipped == (
            SkippedMember(
                ARTIFACT_STATUS_MEMBER,
                "the name is reserved for the artifact status member",
            ),
        )
        assert read_status(artifact)["complete"] is True
    finally:
        close(runtime)


def test_a_complete_archive_says_so_in_the_status_member(tmp_path: Path) -> None:
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        (runtime.root / "notes.txt").write_bytes(b"a line\n")
        runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")

        status = read_status(runtime.writer.only)

        assert status["complete"] is True
        assert status["memberCount"] == 1
        assert status["deadlineMs"] == DEFAULT_PERSIST_DEADLINE_MS
        assert "truncatedAt" not in status
    finally:
        close(runtime)


def test_a_deadline_that_has_already_expired_truncates_and_says_so(
    tmp_path: Path,
) -> None:
    """The marker exists in both places, so a truncated artifact cannot pass for a complete one."""
    runtime = build(tmp_path)
    try:
        # One millisecond, of which the reserve leaves the collection three quarters. `crowd` puts
        # more files in the tree than that can reach, so the expiry is a property of the tree.
        runtime.client.post(
            f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section(deadline_ms=1))
        )
        crowd(runtime.root, 400)

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        artifact = runtime.writer.only
        assert artifact.truncated is True
        assert len(artifact.members) < 400
        status = read_status(artifact)
        assert status["complete"] is False
        assert str(status["truncatedAt"]).startswith("file-")
        assert status["memberCount"] == len(artifact.members)
        # The truncated archive is still an archive: what it did capture restores, byte for byte.
        restored = restore_into_fresh(artifact, tmp_path / "restored")
        assert set(restored) - {ARTIFACT_STATUS_MEMBER} == set(artifact.members)
    finally:
        close(runtime)


def test_a_truncated_member_is_absent_rather_than_short(tmp_path: Path) -> None:
    """Half a file restored under its own name is corrupt data presented as data."""
    root = tmp_path / "work"
    root.mkdir()
    crowd(root, 400)
    writer = RecordingWriter()

    artifact = asyncio.run(
        persist_state(
            PersistRequest(reference=REFERENCE, deadline_ms=1),
            root=ConfinedRoot(root),
            destination=writer,
        )
    )

    assert artifact.truncated is True
    restored = restore_into_fresh(artifact, tmp_path / "restored")
    assert restored, "some members survived, or this asserts nothing"
    for name, content in restored.items():
        if name == ARTIFACT_STATUS_MEMBER:
            continue
        # Every member that survived is the whole file, never a prefix of it.
        assert content == (root / name).read_bytes()


def test_terminate_ends_the_sessions_background_processes(tmp_path: Path) -> None:
    """The 8.2 note: these have to be reaped inside the application's own event loop."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        handle = _start_background(runtime, seconds=_WAIT_SECONDS)
        assert handle in runtime.processes.handles

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        assert runtime.processes.handles == frozenset()
        assert runtime.lifecycle.shutdown_overran == ()
    finally:
        close(runtime)


def test_terminate_with_no_configured_artifacts_still_ends_the_running_work(
    tmp_path: Path,
) -> None:
    """R13.3 is about the *configured* artifacts; a Session that configured none has none."""
    runtime = build(tmp_path)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}")
        handle = _start_background(runtime, seconds=_WAIT_SECONDS)

        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        assert handle not in runtime.processes.handles
        assert runtime.writer.written == []
        assert runtime.lifecycle.persisted is None
    finally:
        close(runtime)


def test_terminate_on_a_sandbox_that_never_ran_writes_nothing(tmp_path: Path) -> None:
    """The gate admits `CLOSED -> TERMINATED`: the disposal path for an unused Sandbox."""
    runtime = build(tmp_path)
    try:
        assert runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK

        assert runtime.gate.phase is RuntimePhase.TERMINATED
        assert runtime.writer.written == []
    finally:
        close(runtime)


def test_a_write_the_state_store_refuses_is_reported(tmp_path: Path) -> None:
    writer = RecordingWriter(
        failure=WriteDenied("the Sandbox execution role may not write this prefix")
    )
    runtime = build(tmp_path, writer=writer)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))
        (runtime.root / "notes.txt").write_bytes(b"a line\n")

        with pytest.raises(ArtifactPersistFailure, match="may not write this prefix"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")

        assert runtime.lifecycle.persisted is None
    finally:
        runtime.client.__exit__(None, None, None)


def test_a_store_write_that_outlives_its_share_of_the_deadline_fails(
    tmp_path: Path,
) -> None:
    """A write that did not complete is not a truncation: there is no artifact to mark."""
    root = tmp_path / "work"
    root.mkdir()
    (root / "notes.txt").write_bytes(b"a line\n")
    writer = RecordingWriter(delay=_WAIT_SECONDS)

    async def scenario() -> None:
        with pytest.raises(ArtifactPersistFailure, match="did not complete within"):
            await persist_state(
                PersistRequest(reference=REFERENCE, deadline_ms=20),
                root=ConfinedRoot(root),
                destination=writer,
            )

    asyncio.run(asyncio.wait_for(scenario(), timeout=_WAIT_SECONDS))
    assert writer.written == []


def test_a_runtime_that_cannot_write_refuses_a_configuration_that_asks_it_to(
    tmp_path: Path,
) -> None:
    runtime = build(tmp_path, with_writer=False)
    try:
        runtime.client.post(f"{HOOK_PATH_PREFIX}/run", content=document(persist=persist_section()))

        with pytest.raises(ConfigurationError, match="no State_Store writer"):
            runtime.client.post(f"{HOOK_PATH_PREFIX}/terminate")
    finally:
        runtime.client.__exit__(None, None, None)


def test_a_configured_path_that_leaves_the_root_is_refused(tmp_path: Path) -> None:
    """The Control_Plane composed it, so a path outside the root is a defect, not a skip."""
    root = tmp_path / "work"
    root.mkdir()

    async def scenario() -> None:
        with pytest.raises(ArtifactPersistFailure, match="resolves outside"):
            await persist_state(
                PersistRequest(reference=REFERENCE, paths=("../escape",)),
                root=ConfinedRoot(root),
                destination=RecordingWriter(),
            )

    asyncio.run(asyncio.wait_for(scenario(), timeout=_WAIT_SECONDS))


def test_the_artifact_repr_withholds_the_body() -> None:
    """A `repr` reaches a traceback, and megabytes of `tar` in one hides what is being reported."""
    artifact = PersistedArtifact(
        reference=REFERENCE,
        body=b"a whole tar stream",
        sha256="0" * 64,
        truncated=False,
        members=("notes.txt",),
        skipped=(),
    )

    rendered = repr(artifact)

    assert "a whole tar stream" not in rendered
    assert "size_bytes=18" in rendered
    assert REFERENCE in rendered


# --- The `persist` section of the configuration document ------------------------------------


def test_the_minimum_persist_section_is_a_reference() -> None:
    parsed = parse_configuration(document(persist={"reference": REFERENCE}))

    assert parsed == RunConfiguration(
        persist=PersistRequest(
            reference=REFERENCE,
            paths=(),
            deadline_ms=DEFAULT_PERSIST_DEADLINE_MS,
            compress=False,
        )
    )


def test_persist_paths_are_sorted_and_deduplicated_so_the_order_cannot_matter() -> None:
    parsed = parse_configuration(
        document(persist=persist_section(paths=["out", "work", "out"]))
    )

    assert parsed.persist is not None
    assert parsed.persist.paths == ("out", "work")


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'{"persist": "somewhere"}', "must be an object"),
        (b'{"persist": {}}', "non-empty State_Store reference"),
        (b'{"persist": {"reference": "r", "unknown": 1}}', "does not understand"),
        (b'{"persist": {"reference": "r", "paths": "out"}}', "must be a list of paths"),
        (b'{"persist": {"reference": "r", "paths": [""]}}', "which is not a path"),
        (b'{"persist": {"reference": "r", "paths": ["/etc"]}}', "absolute path"),
        (b'{"persist": {"reference": "r", "deadlineMs": 0}}', "positive number of"),
        (b'{"persist": {"reference": "r", "deadlineMs": true}}', "positive number of"),
        (b'{"persist": {"reference": "r", "compress": "yes"}}', "must be true or false"),
    ],
)
def test_a_malformed_persist_section_is_refused(payload: bytes, expected: str) -> None:
    with pytest.raises(ConfigurationError, match=expected):
        parse_configuration(payload)


def test_a_deadline_longer_than_this_runtime_will_hold_a_sandbox_is_refused() -> None:
    """Refused rather than clamped: clamping applies a deadline nobody composed."""
    with pytest.raises(ConfigurationError, match="exceeds the"):
        parse_configuration(
            document(persist=persist_section(deadline_ms=MAX_PERSIST_DEADLINE_MS + 1))
        )


# --- The seams are satisfied structurally ---------------------------------------------------


def test_the_stand_ins_satisfy_the_seams_they_stand_in_for() -> None:
    """`isinstance` against the runtime-checkable Protocols, which is what `create_app` relies on."""
    writer = RecordingWriter()

    assert isinstance(writer, StateStoreWriter)
    assert isinstance(RecordingOutbound(), OutboundConnections)


def test_a_write_failure_carries_its_reason() -> None:
    failure = StateWriteFailure("the bucket refused the object")

    assert failure.reason == "the bucket refused the object"
    assert isinstance(WriteDenied("denied"), StateWriteFailure)


# --- Starting a background process, which two tests need -----------------------------------


def _start_background(runtime: Runtime, *, seconds: float) -> bytes:
    """Start a sleeping background process through `proc.start` and return its handle."""
    from protocol.codec.messages import decode, encode
    from protocol.schema import (
        ENVELOPE_KEY_BODY,
        ENVELOPE_KEY_ID,
        ENVELOPE_KEY_TYPE,
        ENVELOPE_KEY_VERSION,
    )
    from runtime.app import PROTOCOL_PATH
    from runtime.process import PROC_START

    message = CATALOGUE.messages[PROC_START]
    request = encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: PROC_START,
            ENVELOPE_KEY_ID: b"cid",
            ENVELOPE_KEY_BODY: {
                message.field_by_name("argv").key: list(
                    argv_of([PYTHON, "-c", f"import time; time.sleep({seconds})"])
                ),
                message.field_by_name("cwd").key: b"",
                message.field_by_name("env").key: {},
            },
        },
        catalogue=CATALOGUE,
    )
    response = runtime.client.post(PROTOCOL_PATH, content=request)
    assert response.status_code == HTTPStatus.OK, response.text
    reply = decode(response.content, catalogue=CATALOGUE)
    body = reply[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    handle = body[CATALOGUE.messages["proc.handle"].field_by_name("handle").key]
    assert isinstance(handle, bytes)
    return handle
