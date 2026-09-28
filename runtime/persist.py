# kiro-classification: public
"""The `/terminate` hook's body: write the configured artifacts under a bounded deadline (R13.3).

R13.3 asks for the configured Session output artifacts to be written to the State_Store during
`/terminate`, and the design attaches the bound and the failure behaviour: "Artifact writing is
bounded by a configured deadline; on deadline expiry the Runtime records a truncation marker in the
artifact index rather than blocking teardown, because a hung terminate hook would leave a billable
Sandbox allocated." Those two clauses are what this module is shaped by, and they pull in opposite
directions: the artifact has to be as complete as it can be, and the hook has to end.

`runtime.hooks` owns the ordering. The readiness gate is closed for good and drained before this
runs, which is why the tree being read is not moving underneath the reader on the protocol's
account. It can still be moving on the *Sandbox's* account, which is what `runtime.lifecycle` ends
the Session's processes for before calling in here.

## The archive is the one `runtime.restore` reads, and that is a hard constraint

Persisted state is a `tar` stream, optionally gzip-compressed, carrying **regular files and
directories and nothing else**. That is not a choice made here — `runtime.restore` refuses every
other member type to close the archive-escape class, and it refuses them by *failing the whole
restore*. So an archive containing one unrestorable member is not a slightly lossy archive, it is an
archive that restores nothing at all, and the next generation of the Session would meet
`member-refused` on a symlink the previous one happened to leave in its work tree.

Therefore anything in the tree that is not a regular file or a directory is **skipped, and named in
the status member**. Skipping silently would produce a restored tree that is not the tree that was
persisted while reporting success, which is the failure mode `runtime.restore` calls out on its own
side; naming it is what keeps the omission discoverable. Symlinks, hardlinks, devices, FIFOs and
sockets all land here, and so does a path the configuration named that does not exist — a Session
configured to persist `out/` that never produced one is an ordinary outcome, not a reason to lose
the rest of its artifacts.

Member names are the paths below the configured root, encoded exactly as the filesystem gave them.
`tarfile` types a member name as `str`, so the name goes in through `os.fsdecode` and comes back out
of `runtime.restore` through `os.fsencode`; because CPython decodes filesystem names with
`surrogateescape` (PEP 383), that pair is exact even for a name that is not valid UTF-8. A file the
Sandbox created with a name no decoder accepts survives a persist and a restore, which is the same
byte-typing stance `runtime.filesystem` takes and the reason it is worth taking.

## Truncation drops whole members and says so, in two places

The deadline is checked before each member and between the chunks of a file's read. When it expires
the member being worked on is **abandoned entirely** rather than written short. That is the single
most important decision in this module: a member that is present is byte-exact, and a member that
could not be captured is absent. Half a file restored under its own name is corrupt data presented
as data, and nothing downstream could tell it from the real thing.

The marker is written in two places because it answers two different readers:

- **In the archive**, as `.sandbox-artifact-status.json`, which is written last and
  **unconditionally** — for a complete archive as well as a truncated one. Presence is mandatory and
  the content carries the claim, so the two cases are distinguished by what the marker *says* rather
  than by whether it is there. That is what makes the archive self-describing: an archive with no
  status member is not a complete archive, it is not one this runtime wrote. A reader that never
  looks would be able to mistake a truncated archive for a complete one if the only marker were
  out-of-band metadata that had been separated from it.
- **On the write seam**, as `PersistedArtifact.truncated`, which is the design's artifact-index
  marker. The State_Store side already has the field for it —
  `control_plane.state.records.ArtifactIndexEntry.truncated`, mirrored through
  `ArtifactStore.put_artifact(..., truncated=...)` — so an operator listing a Session's artifacts
  sees the flag beside the size without fetching the object.

The status member's name is reserved. A file of that name in the persisted tree is skipped and the
skip recorded, rather than being written and then shadowed by the marker: two members with one name
is an archive whose restored content depends on member order, which is not a thing to leave to
chance.

## Where the deadline is split, and why the write gets a share of it

One configured number bounds the hook, so the bound is a statement about `/terminate` and not about
one step inside it. It is split: collection stops at a fixed fraction of the deadline and the store
write gets whatever is left, never less than the reserved remainder. Giving collection the whole
deadline would leave the write nothing, and a bounded collection followed by an unbounded write is
not a bounded hook — it is the hang the design is guarding against, moved one step later.

A write that exceeds its share **fails**. It is not a truncation: truncation is an artifact that
exists and is short, and a write that did not complete is an artifact that does not exist. Reporting
it as a truncation would put a `truncated` marker in an index beside an object that is not there.

## The archive is built in memory, and the seam is a seam

`runtime.restore` holds the whole archive in memory so that the digest is verified before a byte is
written; this side holds it in memory for the symmetric reason — the digest and the size are computed
over the finished object, and the seam takes `bytes`. For a working set that fits a MicroVM's disk
that is the simpler and safer shape, and a future streaming writer is a change to the seam and to
this module's last step, not to its traversal.

`StateStoreWriter` is the write half of `runtime.run_config.StateStoreReader`: one method, and the
failures a writer can distinguish from the outside as distinct types. It lives here rather than
beside the reader because the reader is part of the run hook's *document* — that module is about what
`/run` was handed — while this is the terminate hook's output. `runtime/` imports nothing from
`control_plane/`, here as everywhere: this code runs inside the untrusted MicroVM, and the
`ArtifactStore` that will implement this seam runs outside it under credentials this process must
never hold. No bucket is named here and none should be.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import stat
import tarfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from runtime.bodies import OperationRefusal
from runtime.filesystem import ConfinedRoot
from runtime.run_config import PersistRequest, RestoreRequest

__all__ = [
    "ARTIFACT_STATUS_MEMBER",
    "ArtifactPersistFailure",
    "PersistedArtifact",
    "SkippedMember",
    "StateStoreWriter",
    "StateWriteFailure",
    "WriteDenied",
    "persist_state",
]

#: The reserved archive member carrying the completeness claim. Written last and always. Dot-
#: prefixed and named for the project so that it is recognisable in a restored tree and unlikely to
#: collide with anything a Session produced; a collision is refused rather than resolved.
ARTIFACT_STATUS_MEMBER: Final = ".sandbox-artifact-status.json"

#: The fraction of the configured deadline held back for the store write. A quarter, because the
#: write is one round trip against an object store and the collection is an unbounded amount of
#: local IO: the split favours the step whose duration is a property of the Session's own output.
_WRITE_RESERVE: Final = 0.25

#: The floor on the store write's budget, for the case where collection overran its share — which
#: it can, by the length of one chunk read. A write granted zero seconds has not been bounded, it
#: has been cancelled. So the hook is bounded by the configured deadline *or* by this floor,
#: whichever is larger, and a document asking for a millisecond gets a second: the overshoot is
#: stated rather than hidden, because the alternative is a configured deadline that guarantees the
#: artifact is never written at all.
_MINIMUM_WRITE_SECONDS: Final = 1.0

#: Permission bits carried into the archive. The same mask `runtime.restore` applies on the way
#: back, so a mode that survives one direction survives both. Set-user-ID, set-group-ID and the
#: sticky bit are outside it: a persisted working set has no business carrying a setuid binary
#: across a Session boundary, and dropping them here means the reader never has to.
_MODE_MASK: Final = 0o777

#: Descending one directory component: the same flags `runtime.restore` descends with and for the
#: same reason. `O_NOFOLLOW` is the confinement, `O_DIRECTORY` makes a non-directory fail the open
#: rather than be opened and rejected, `O_CLOEXEC` keeps a descriptor to the inside of the root out
#: of anything spawned meanwhile.
_DESCEND_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ROOT_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC

#: `O_NONBLOCK` so that something planted at the path between the `stat` and the open — a FIFO with
#: no writer — fails the open or the `fstat` check instead of blocking the collection until the
#: deadline expires and taking the whole artifact down with it.
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

#: One read of a regular file, in chunks, because `os.read` may return less than it was asked for
#: and because the deadline is checked between chunks: a single enormous file cannot run past the
#: bound on the strength of being one member.
_CHUNK: Final = 1 << 20


class StateWriteFailure(Exception):
    """Writing an object to the State_Store failed.

    Raised by a `StateStoreWriter` implementation. The mirror of
    `runtime.run_config.StateReadFailure`, and like it the reason names what could not be written
    rather than restating that something went wrong.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class WriteDenied(StateWriteFailure):
    """The Sandbox execution role may not write the reference.

    The write-side counterpart of `runtime.run_config.ReadDenied`, and distinct for the same reason:
    a reference outside this Session's artifact prefix is refused by IAM rather than by a check in
    this runtime, because the per-Session execution role is confined to that prefix and the
    authority on it is the credential. There is no write analogue of `ReferenceNotFound` — an object
    that is not there is what a write is for.
    """


class ArtifactPersistFailure(Exception):
    """The configured artifacts could not be written during `/terminate`.

    Not the same event as a truncation. A truncated artifact was written and says it is short; this
    is an artifact that does not exist, and the reason names the reference so that an operator
    looking for it learns why nothing is there.
    """


@dataclass(frozen=True, slots=True)
class SkippedMember:
    """Something under a configured path that was not persisted, and why.

    Recorded rather than dropped. Every reason here is one `runtime.restore` would refuse the whole
    archive for, or a path that was not there to read, so the skip is what makes the archive
    restorable — which makes "what did it cost" a question with an answer in the artifact itself.
    """

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class PersistedArtifact:
    """One written archive, and everything the reader of it will need.

    `sha256` and `size_bytes` are recorded because `runtime.restore` verifies both before it writes
    a byte, against the values the *writer* recorded — so if this side did not produce them those
    checks would be unreachable code guarding nothing. `as_restore_request` closes that loop: the
    document the Control_Plane composes for the next generation is derivable from this object rather
    than assembled by hand from it.
    """

    reference: str
    body: bytes
    sha256: str
    truncated: bool
    members: tuple[str, ...]
    skipped: tuple[SkippedMember, ...]

    @property
    def size_bytes(self) -> int:
        """The size the reader checks the transfer against."""
        return len(self.body)

    def as_restore_request(self) -> RestoreRequest:
        """The `restore` this artifact is restorable by, for the next generation's document."""
        return RestoreRequest(
            reference=self.reference, size_bytes=self.size_bytes, sha256=self.sha256
        )

    def __repr__(self) -> str:
        """Report the shape and withhold the body.

        The default dataclass `repr` would render the whole archive, and a `repr` reaches an
        unhandled exception's traceback and a test failure report. Megabytes of `tar` in either is
        noise that hides the thing being reported.
        """
        return (
            f"PersistedArtifact(reference={self.reference!r}, "
            f"size_bytes={self.size_bytes}, sha256={self.sha256!r}, "
            f"truncated={self.truncated}, members={len(self.members)}, "
            f"skipped={len(self.skipped)})"
        )


@runtime_checkable
class StateStoreWriter(Protocol):
    """Writes one object into the State_Store under an opaque reference.

    One method, because that is the entire dependency: the runtime holds a reference it never
    parses and an archive it built, and the deployment holds the bucket, the encryption key, the
    credentials and the artifact index the `truncated` marker is mirrored onto.
    """

    async def write(self, artifact: PersistedArtifact) -> None:
        """Store `artifact.body` under `artifact.reference`.

        Raises:
            WriteDenied: the Sandbox may not write it.
            StateWriteFailure: the write failed for any other reason.
        """
        ...


async def persist_state(
    request: PersistRequest,
    *,
    root: ConfinedRoot,
    destination: StateStoreWriter,
) -> PersistedArtifact:
    """Archive the configured paths and write them to the State_Store (R13.3).

    Raises:
        ArtifactPersistFailure: the archive could not be written. A *truncated* archive is not a
            failure and is returned, carrying its marker.
    """
    started = time.monotonic()
    budget = request.deadline_ms / 1000
    collection_deadline = started + budget * (1 - _WRITE_RESERVE)

    try:
        artifact = await asyncio.to_thread(_build, root, request, collection_deadline)
    except OSError as exc:
        raise ArtifactPersistFailure(
            f"building the artifact archive for {request.reference!r} failed: {exc}"
        ) from exc
    except tarfile.TarError as exc:
        raise ArtifactPersistFailure(
            f"building the artifact archive for {request.reference!r} failed: {exc}"
        ) from exc

    remaining = max(
        budget - (time.monotonic() - started), budget * _WRITE_RESERVE
    )
    write_budget = max(remaining, _MINIMUM_WRITE_SECONDS)
    try:
        async with asyncio.timeout(write_budget):
            await destination.write(artifact)
    except TimeoutError as exc:
        raise ArtifactPersistFailure(
            f"writing the artifact to {request.reference!r} did not complete within "
            f"{write_budget:g}s of the {request.deadline_ms}ms deadline"
        ) from exc
    except StateWriteFailure as exc:
        raise ArtifactPersistFailure(
            f"writing the artifact to {request.reference!r} failed: {exc.reason}"
        ) from exc
    return artifact


# --- Building the archive, on a worker thread ---------------------------------------------
#
# Every function below runs on the worker thread `persist_state` hands the traversal to. The
# traversal is a blocking sequence of syscalls over a whole tree, and the event loop it would
# otherwise occupy is the one that has to finish answering `/terminate`.


@dataclass(slots=True)
class _Outcome:
    """What the traversal found, accumulated as it goes."""

    members: list[str]
    skipped: list[SkippedMember]
    #: The member the deadline expired on, and the signal that collection stopped early. Set once:
    #: every caller checks it before doing more work, so the first expiry is the one reported.
    truncated_at: str | None = None

    def skip(self, path: bytes, reason: str) -> None:
        self.skipped.append(SkippedMember(path=os.fsdecode(path), reason=reason))

    def truncate(self, path: bytes) -> None:
        self.truncated_at = os.fsdecode(path)


class _DeadlineReached(Exception):
    """Internal: the collection deadline expired part-way through reading a member."""


def _build(
    root: ConfinedRoot, request: PersistRequest, deadline: float
) -> PersistedArtifact:
    """Archive the configured paths, append the status member, and describe the result."""
    outcome = _Outcome(members=[], skipped=[])
    buffer = io.BytesIO()
    # The two modes are two `with` statements rather than one over a variable mode, because
    # `tarfile.open` is overloaded on a literal mode and the compressed and uncompressed forms take
    # different keyword sets. `runtime.restore` opens `r:*` and reads either.
    if request.compress:
        with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
            _fill(stream, root, request, deadline, outcome)
    else:
        with tarfile.open(fileobj=buffer, mode="w") as stream:
            _fill(stream, root, request, deadline, outcome)
    body = buffer.getvalue()
    return PersistedArtifact(
        reference=request.reference,
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        truncated=outcome.truncated_at is not None,
        members=tuple(outcome.members),
        skipped=tuple(outcome.skipped),
    )


def _fill(
    stream: tarfile.TarFile,
    root: ConfinedRoot,
    request: PersistRequest,
    deadline: float,
    outcome: _Outcome,
) -> None:
    """Add the configured tree and then the status member, in that order."""
    _collect(stream, root, request, deadline, outcome)
    # Unconditional, and last. See the module docstring: the marker's presence is mandatory and its
    # content is the claim, which is what stops a truncated archive from being indistinguishable
    # from a complete one to a reader who only looks at the members.
    _put_file(
        stream,
        os.fsencode(ARTIFACT_STATUS_MEMBER),
        _status_document(request, outcome),
        mode=0o600,
        mtime=0,
    )


def _status_document(request: PersistRequest, outcome: _Outcome) -> bytes:
    """The reserved member's content: the completeness claim, and what it cost.

    `complete` is the field a reader checks, spelled positively so that the safe reading of a
    malformed or absent status is not "complete". Sorted keys and a fixed separator so that two
    archives of the same tree differ only where the tree did.
    """
    document: dict[str, object] = {
        "complete": outcome.truncated_at is None,
        "memberCount": len(outcome.members),
        "deadlineMs": request.deadline_ms,
        "configuredPaths": list(request.paths),
        "skipped": [
            {"path": member.path, "reason": member.reason} for member in outcome.skipped
        ],
    }
    if outcome.truncated_at is not None:
        document["truncatedAt"] = outcome.truncated_at
    return json.dumps(document, sort_keys=True).encode()


def _collect(
    stream: tarfile.TarFile,
    root: ConfinedRoot,
    request: PersistRequest,
    deadline: float,
    outcome: _Outcome,
) -> None:
    """Add every configured path, stopping at the first one the deadline runs out on."""
    descriptor = os.open(root.root, _ROOT_FLAGS)
    try:
        # An empty path set is the whole root, which is the components tuple `()` — the same
        # spelling `ConfinedRoot.components` gives for the root itself, so the two cases meet
        # immediately rather than each having their own traversal.
        targets: tuple[tuple[bytes, ...], ...] = (
            tuple(_components_of(root, path) for path in request.paths)
            if request.paths
            else ((),)
        )
        for components in targets:
            if outcome.truncated_at is not None:
                return
            _add_target(stream, descriptor, components, deadline, outcome)
    finally:
        os.close(descriptor)


def _components_of(root: ConfinedRoot, path: str) -> tuple[bytes, ...]:
    """Resolve one configured path against the root, or refuse it.

    A path that leaves the root is a defect in the configuration rather than something to skip: the
    Control_Plane composed it, and persisting a tree from outside the Sandbox's own root is not a
    lesser version of what was asked for.
    """
    encoded = os.fsencode(path)
    try:
        return root.components(encoded)
    except OperationRefusal as refusal:
        raise ArtifactPersistFailure(
            f"the configured path {path!r} {refusal.detail}"
        ) from refusal


def _add_target(
    stream: tarfile.TarFile,
    root_fd: int,
    components: tuple[bytes, ...],
    deadline: float,
    outcome: _Outcome,
) -> None:
    """Add one configured path: the root's whole contents, or one entry and what is under it."""
    if not components:
        # The root itself. It is not added as a member: `runtime.restore` returns without acting
        # on a member describing the root, because the root already exists and its mode is the
        # deployment's rather than the archive's.
        _add_contents(stream, root_fd, b"", deadline, outcome)
        return
    with _descend(root_fd, components[:-1]) as parent:
        _add_entry(
            stream, parent, components[-1], b"/".join(components), deadline, outcome
        )


def _add_entry(
    stream: tarfile.TarFile,
    parent: int,
    name: bytes,
    relative: bytes,
    deadline: float,
    outcome: _Outcome,
) -> None:
    """Add one entry, recursing into it when it is a directory."""
    if outcome.truncated_at is not None:
        return
    if relative == os.fsencode(ARTIFACT_STATUS_MEMBER):
        outcome.skip(relative, "the name is reserved for the artifact status member")
        return
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        # A configured path that is not there, or an entry that vanished between the directory
        # scan and this `stat`. Both are ordinary: a Session that produced no `out/` is not a
        # Session whose other artifacts should be lost over it.
        outcome.skip(relative, _strerror(exc))
        return

    if stat.S_ISDIR(info.st_mode):
        _put_directory(stream, relative, info)
        outcome.members.append(os.fsdecode(relative))
        with _descend(parent, (name,)) as directory:
            _add_contents(stream, directory, relative, deadline, outcome)
        return

    if not stat.S_ISREG(info.st_mode):
        outcome.skip(relative, _describe_kind(info.st_mode))
        return

    if time.monotonic() >= deadline:
        outcome.truncate(relative)
        return
    try:
        content = _read_file(parent, name, deadline)
    except _DeadlineReached:
        # Abandoned whole rather than written short. The single most consequential line in the
        # module: a member that is present is byte-exact.
        outcome.truncate(relative)
        return
    except OSError as exc:
        outcome.skip(relative, _strerror(exc))
        return
    _put_file(
        stream,
        relative,
        content,
        mode=info.st_mode & _MODE_MASK,
        mtime=int(info.st_mtime),
    )
    outcome.members.append(os.fsdecode(relative))


def _add_contents(
    stream: tarfile.TarFile,
    directory: int,
    prefix: bytes,
    deadline: float,
    outcome: _Outcome,
) -> None:
    """Add every entry of an open directory, in name order.

    The scan is drained into a list before anything recurses, so the number of descriptors and
    scan handles held at once is the depth of the tree rather than its size.
    """
    with os.scandir(directory) as scan:
        # `os.fsencode` of a name CPython decoded with `surrogateescape` restores the original
        # bytes. `os.scandir` on a descriptor has no bytes-returning form, which is the same one
        # place `runtime.filesystem` converts.
        children = sorted(os.fsencode(entry.name) for entry in scan)
    for child in children:
        if outcome.truncated_at is not None:
            return
        relative = child if not prefix else prefix + b"/" + child
        _add_entry(stream, directory, child, relative, deadline, outcome)


@contextlib.contextmanager
def _descend(parent: int, components: tuple[bytes, ...]) -> Iterator[int]:
    """Yield a descriptor for the directory `components` names below `parent`.

    Every level is opened relative to the descriptor above it and never re-resolved from a string,
    which is what makes the confinement unraceable: a descriptor names an inode, and replacing the
    name it came from cannot change what it refers to. A symlink anywhere on the way down fails the
    open, so a link planted mid-traversal cannot redirect the archive at a tree outside the root.
    """
    opened: list[int] = []
    current = parent
    try:
        for component in components:
            current = os.open(component, _DESCEND_FLAGS, dir_fd=current)
            opened.append(current)
        yield current
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _read_file(parent: int, name: bytes, deadline: float) -> bytes:
    """Read one regular file whole, checking the deadline between chunks.

    Raises:
        _DeadlineReached: the deadline expired mid-read. Nothing is returned, because a partial
            read is not a shorter version of the file.
    """
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            # Replaced between the `stat` above and this open. The `fstat` is on the descriptor
            # rather than on the name, so it describes what will actually be read.
            raise OSError(f"{os.fsdecode(name)} is no longer a regular file")
        chunks: list[bytes] = []
        while True:
            if time.monotonic() >= deadline:
                raise _DeadlineReached
            chunk = os.read(descriptor, _CHUNK)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def _put_directory(
    stream: tarfile.TarFile, relative: bytes, info: os.stat_result
) -> None:
    member = _member(relative, mode=info.st_mode & _MODE_MASK, mtime=int(info.st_mtime))
    member.type = tarfile.DIRTYPE
    stream.addfile(member)


def _put_file(
    stream: tarfile.TarFile, relative: bytes, content: bytes, *, mode: int, mtime: int
) -> None:
    member = _member(relative, mode=mode, mtime=mtime)
    member.type = tarfile.REGTYPE
    member.size = len(content)
    stream.addfile(member, io.BytesIO(content))


def _member(relative: bytes, *, mode: int, mtime: int) -> tarfile.TarInfo:
    """One member header.

    The owner fields are left at `TarInfo`'s defaults rather than taken from the filesystem. They
    are not information `runtime.restore` uses — it restores mode and content and nothing else —
    and a persisted artifact leaving the MicroVM with the image's user and group map in it would be
    disclosing the inside of the Sandbox for no reader's benefit.
    """
    member = tarfile.TarInfo(os.fsdecode(relative))
    member.mode = mode
    member.mtime = mtime
    return member


def _describe_kind(mode: int) -> str:
    """What an unpersistable entry is, in the words the skip records.

    Every one of these is a member type `runtime.restore` refuses, so including one would make the
    archive unrestorable in its entirety rather than merely odd.
    """
    if stat.S_ISLNK(mode):
        return "a symbolic link, which is never persisted or restored"
    if stat.S_ISFIFO(mode):
        return "a FIFO, which is never persisted or restored"
    if stat.S_ISSOCK(mode):
        return "a socket, which is never persisted or restored"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "a device node, which is never persisted or restored"
    return "not a regular file or directory, which is never persisted or restored"


def _strerror(exc: OSError) -> str:
    return os.strerror(exc.errno) if exc.errno is not None else str(exc)
