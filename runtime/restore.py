# kiro-classification: public
"""Restoring previously persisted state into the Sandbox filesystem, before readiness (R13.4).

R13.4 fixes the ordering and R13.7 fixes the failure: the state named by the run hook payload is
restored during `/run` and before HTTP 200, and a restoration that fails produces a non-200 whose
reason identifies the restoration failure. The ordering is not this module's to enforce —
`runtime.hooks` applies the configuration while the readiness gate is still closed and opens it
last, so nothing this module writes can be observed half-written by a protocol request. What is
this module's is the restore itself, and the vocabulary the failure is reported in.

## Why the reason is a closed set and not a sentence

"A reason identifying the restoration failure" is a requirement about *identification*, and a
free-text sentence identifies a failure only to a person reading it. The Control_Plane records the
reason against the Session, an operator reads it there, and the same string is what a test asserts
on. So every failure carries one member of `RestoreCause` — a closed, kebab-case set, the same
shape the design's blocked-attempt audit uses — followed by the detail that makes it actionable.

The set distinguishes the failure modes that have different causes and different responses:

- `reference-absent` and `read-denied` come from the State_Store reader rather than from anything
  here. A reference belonging to a different Session lands in `read-denied`, because the
  per-Session execution role is confined to its own artifact prefix and IAM is the authority on
  that. This module does not parse a reference to work out whose it is.
- `truncated-transfer` and `digest-mismatch` are distinct: a short read and a corrupt read fail
  differently and are both invisible in the archive itself, which is why the configuration
  document carries the size and digest the writer recorded.
- `archive-unreadable` is a payload that is not an archive, or is one that is damaged beyond its
  header. A **compressed** archive that stops short or decompresses wrongly is here and not in
  `truncated-transfer`, which is worth stating because "truncated" describes both. The distinction
  is who noticed: `truncated-transfer` is the size the writer recorded disagreeing with the number
  of bytes that arrived, and that comparison needs a recorded size, which the configuration
  document makes optional. A damaged compressed stream is noticed by the reader regardless, so it
  is reported as the unreadable archive it is rather than as a claim about a size nobody stated.
  That is the shape a partially transferred artifact has, so it is the case R13.7's identification
  most needs to cover.

  Reaching it takes more than catching `tarfile.TarError`, which is the failure `tarfile`
  documents. `tarfile` translates the decompression layer's own exceptions only while it is
  *opening* a stream, and `gzopen` does not translate `EOFError` even there, so a damaged
  compressed archive surfaces as an `EOFError` (the stream ended before its end-of-stream marker),
  a `zlib.error` or a `gzip.BadGzipFile` (an invalid deflate block, or a checksum mismatch), or an
  `lzma.LZMAError`. Each is named in `_extract`. They are named rather than caught as `Exception`,
  because an `Exception` arm would report a defect in this module as a corrupt payload — and one
  gap is left open deliberately for the same reason: `bz2` reports a damaged stream as a plain
  `OSError`, and catching `OSError` here would swallow every filesystem defect this module could
  have. Nothing this runtime writes is bzip2 (`runtime.persist` writes `w` or `w:gz`), and a bzip2
  payload that fails while *opening* is already a `TarError`, so what is left uncovered is a
  mid-stream failure in a compression this runtime never produces.
- `member-refused` is a member this runtime will not restore. See below; this is the security-
  relevant one.
- `write-failed` is the filesystem refusing — no space, a permission, a path that is already a
  directory.

## What an archive may contain

An archive is a `tar` stream, optionally compressed, and it may contain **regular files and
directories and nothing else**. Every other member type is refused by name rather than skipped
silently, because skipping would restore a tree that is not the tree that was persisted and
report success.

That restriction is not tidiness. A symlink member is the classic archive escape: extract
`work/link -> /etc`, then extract `work/link/passwd`, and a writer that resolves paths as it goes
has written outside the root while every individual member looked relative. Refusing symlink
members removes the first half of that sequence, and refusing to *follow* one removes the second:
every directory this module opens on the way down is opened with `O_NOFOLLOW` relative to the
descriptor above it, which is the same discipline `runtime.filesystem` uses and for the same
reason — a check followed by an open can be raced, and an `openat` cannot.

Hardlink members are refused for a related reason: a hardlink's target is a path, so restoring one
means resolving a path that a later member could change. Device nodes and FIFOs are refused
because a persisted-state archive containing one is not describing a working set of files, and a
FIFO restored into the root is a path that blocks any later reader of it forever.

Member names are resolved through `ConfinedRoot`, so `..` and any name that lands outside the root
are refused by the same code that refuses them for `fs.read`. Absolute names are refused outright:
persisted state is relative to the root it was captured from, and an absolute name that happened
to begin with the root's own path would be accepted by a lexical resolution while meaning
something quite different on a Sandbox whose root is configured elsewhere.

## The transfer is a seam, and the archive is held in memory

The bytes arrive through `runtime.run_config.StateStoreReader`, the same one-method seam the
oversized configuration path uses. There is one reader because there is one State_Store and one
credential; there is no concrete implementation here because neither the bucket nor the Sandbox
execution role exists yet.

The archive is read into memory before extraction rather than streamed. For a working set that
fits a MicroVM's disk this is the simpler and safer choice — the digest is verified over the whole
object before a single byte is written, so a corrupt archive cannot leave a partially restored
tree behind — and the seam returns `bytes`, so a future streaming reader is a change to the seam
and to this module's fetch step, not to its extraction.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import gzip
import hashlib
import io
import lzma
import os
import tarfile
import zlib
from collections.abc import Iterator
from typing import Final

from runtime.bodies import OperationRefusal
from runtime.filesystem import ConfinedRoot
from runtime.hooks import RestorationFailure
from runtime.run_config import (
    ReadDenied,
    ReferenceNotFound,
    RestoreRequest,
    StateReadFailure,
    StateStoreReader,
)

__all__ = [
    "RESTORE_FAILURE_PREFIX",
    "RestoreCause",
    "restore_failure_reason",
    "restore_state",
]

#: How every restoration failure reason begins, so the Control_Plane records one recognisable
#: family of reasons rather than a different phrasing per cause (R13.7).
RESTORE_FAILURE_PREFIX: Final = "state restoration failed"

#: Descending one directory component: `O_NOFOLLOW` is the confinement, `O_DIRECTORY` makes a
#: non-directory component fail the open rather than be opened and then rejected, and `O_CLOEXEC`
#: keeps a descriptor to the inside of the root out of any process spawned meanwhile. The same
#: flags `runtime.filesystem` descends with, spelled here rather than imported from its privates.
_DESCEND_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ROOT_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_WRITE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
)

#: The mode a directory this module creates on the way to a member gets when the archive does not
#: describe that directory itself: owner-only, because a permissive default on an intermediate
#: directory would widen access to everything restored beneath it.
_IMPLICIT_DIRECTORY_MODE: Final = 0o700

#: Permission bits taken from an archive member. Set-user-ID, set-group-ID and the sticky bit are
#: dropped: a persisted working set has no business carrying a setuid binary back into a Sandbox,
#: and the archive is composed outside this runtime.
_MODE_MASK: Final = 0o777


class RestoreCause(enum.StrEnum):
    """Why a restoration failed. Closed, so a reason can be matched rather than only read."""

    #: Nothing is stored under the reference.
    REFERENCE_ABSENT = "reference-absent"
    #: The Sandbox execution role may not read the reference. A reference belonging to another
    #: Session arrives here, refused by IAM rather than by this runtime.
    READ_DENIED = "read-denied"
    #: The read failed for any other reason the transport reported.
    TRANSFER_FAILED = "transfer-failed"
    #: Fewer or more bytes arrived than the writer recorded.
    TRUNCATED_TRANSFER = "truncated-transfer"
    #: The right number of the wrong bytes arrived.
    DIGEST_MISMATCH = "digest-mismatch"
    #: The bytes are not a readable archive.
    ARCHIVE_UNREADABLE = "archive-unreadable"
    #: A member this runtime will not restore: a symlink, a hardlink, a device, a FIFO, or a name
    #: that resolves outside the configured root.
    MEMBER_REFUSED = "member-refused"
    #: The filesystem refused a write.
    WRITE_FAILED = "write-failed"


def restore_failure_reason(cause: RestoreCause, detail: str, reference: str) -> str:
    """The reason a non-200 carries: the fixed prefix, the closed-set cause, and the detail."""
    return f"{RESTORE_FAILURE_PREFIX} [{cause}]: {detail} (reference {reference!r})"


async def restore_state(
    request: RestoreRequest,
    *,
    root: ConfinedRoot,
    source: StateStoreReader,
) -> None:
    """Restore the state `request` names into `root`, or raise (R13.4, R13.7).

    Raises:
        RestorationFailure: carrying the identifying reason, for every failure mode.
    """
    archive = await _fetch(request, source)
    _verify(request, archive)
    # The extraction is a blocking sequence of syscalls, and the event loop it would otherwise
    # run on is the one serving the protocol. It is not serving anything yet — the gate is closed
    # until this returns — but a `/terminate` arriving mid-restore still has to be answered.
    await asyncio.to_thread(_extract, root, archive, request.reference)


async def _fetch(request: RestoreRequest, source: StateStoreReader) -> bytes:
    """Read the archive, translating the reader's failures into identified causes."""
    reference = request.reference
    try:
        return await source.read(reference)
    except ReferenceNotFound as exc:
        raise _failure(RestoreCause.REFERENCE_ABSENT, exc.reason, reference) from exc
    except ReadDenied as exc:
        raise _failure(RestoreCause.READ_DENIED, exc.reason, reference) from exc
    except StateReadFailure as exc:
        raise _failure(RestoreCause.TRANSFER_FAILED, exc.reason, reference) from exc


def _verify(request: RestoreRequest, archive: bytes) -> None:
    """Check the archive against what the writer recorded, before anything is written."""
    if request.size_bytes is not None and len(archive) != request.size_bytes:
        raise _failure(
            RestoreCause.TRUNCATED_TRANSFER,
            f"the writer recorded {request.size_bytes} bytes and {len(archive)} arrived",
            request.reference,
        )
    if request.sha256 is not None:
        digest = hashlib.sha256(archive).hexdigest()
        if digest != request.sha256:
            raise _failure(
                RestoreCause.DIGEST_MISMATCH,
                f"the writer recorded {request.sha256} and the bytes hash to {digest}",
                request.reference,
            )


def _failure(cause: RestoreCause, detail: str, reference: str) -> RestorationFailure:
    """The one constructor for every failure this module raises."""
    return RestorationFailure(restore_failure_reason(cause, detail, reference))


def _extract(root: ConfinedRoot, archive: bytes, reference: str) -> None:
    """Restore every member, refusing any this runtime will not write."""
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as stream:
            for member in stream.getmembers():
                _restore_member(root, stream, member, reference)
    except tarfile.TarError as exc:
        raise _failure(RestoreCause.ARCHIVE_UNREADABLE, str(exc), reference) from exc
    except EOFError as exc:
        # A compressed stream that stops before its end-of-stream marker: the decompressor ran
        # out of input with a member still to come, which is the shape a partially transferred
        # artifact has. `EOFError` is neither an `OSError` nor a `TarError`, so it arrives here
        # rather than at the arm above. See the module docstring on why this is
        # `archive-unreadable` and not `truncated-transfer`.
        raise _failure(
            RestoreCause.ARCHIVE_UNREADABLE,
            f"the compressed stream ended before its end-of-stream marker: {exc}",
            reference,
        ) from exc
    except (zlib.error, gzip.BadGzipFile, lzma.LZMAError) as exc:
        # A compressed stream that is damaged rather than short: an invalid deflate block, or a
        # checksum over the decompressed bytes that does not match the one the stream recorded.
        raise _failure(
            RestoreCause.ARCHIVE_UNREADABLE,
            f"the compressed stream is damaged: {type(exc).__name__}: {exc}",
            reference,
        ) from exc


def _restore_member(
    root: ConfinedRoot,
    stream: tarfile.TarFile,
    member: tarfile.TarInfo,
    reference: str,
) -> None:
    """Restore one member: a directory, or a regular file, or nothing at all."""
    components = _components_of(root, member, reference)
    mode = member.mode & _MODE_MASK
    if member.isdir():
        if not components:
            # The archive describes the root itself. It already exists, and its mode is the
            # deployment's rather than the archive's.
            return
        with _walk(root, components[:-1], reference) as parent:
            os.close(
                _open_directory(parent, components[-1], mode, reference, described=True)
            )
        return
    if not member.isfile():
        raise _failure(
            RestoreCause.MEMBER_REFUSED,
            f"member {member.name!r} is {_describe_kind(member)}, which is never restored",
            reference,
        )
    if not components:
        raise _failure(
            RestoreCause.MEMBER_REFUSED,
            f"member {member.name!r} is the filesystem root, which is a directory",
            reference,
        )
    extracted = stream.extractfile(member)
    if extracted is None:  # pragma: no cover - `isfile` members always extract
        raise _failure(
            RestoreCause.ARCHIVE_UNREADABLE,
            f"member {member.name!r} carries no readable content",
            reference,
        )
    with extracted:
        content = extracted.read()
    with _walk(root, components[:-1], reference) as parent:
        _write_at(parent, components[-1], content, mode, reference)


def _components_of(
    root: ConfinedRoot, member: tarfile.TarInfo, reference: str
) -> tuple[bytes, ...]:
    """The member's path components below the root, refusing any name that leaves it."""
    name = os.fsencode(member.name)
    if name.startswith(b"/"):
        raise _failure(
            RestoreCause.MEMBER_REFUSED,
            f"member {member.name!r} is an absolute path; persisted state is relative to "
            f"the configured root",
            reference,
        )
    try:
        return root.components(name)
    except OperationRefusal as refusal:
        raise _failure(
            RestoreCause.MEMBER_REFUSED,
            f"member {member.name!r} {refusal.detail}",
            reference,
        ) from refusal


@contextlib.contextmanager
def _walk(
    root: ConfinedRoot, components: tuple[bytes, ...], reference: str
) -> Iterator[int]:
    """Yield a descriptor for the directory `components` names, creating what is missing.

    Every level is opened relative to the descriptor above it and never re-resolved from a
    string, which is what makes the confinement unraceable: once a descriptor is held it names an
    inode, and replacing the name it came from cannot change what it refers to.

    The walk *invents* directories rather than describing them, so it passes `described=False`:
    one it creates is created owner-only, and one that is already there is left exactly as it is.
    That second half is what keeps a restored directory's mode the archive's — the directory a
    `DIRTYPE` member restored a moment ago is on the path to that member's first child, and a
    walk that re-applied `_IMPLICIT_DIRECTORY_MODE` on the way past would undo the mode the
    member had just set. Order does not matter either way: reached first by a walk the directory
    is owner-only until its own member arrives, and reached first by its member it keeps the
    archive's mode when a walk passes through.
    """
    descriptors = [os.open(root.root, _ROOT_FLAGS)]
    try:
        for component in components:
            descriptors.append(
                _open_directory(
                    descriptors[-1],
                    component,
                    _IMPLICIT_DIRECTORY_MODE,
                    reference,
                    described=False,
                )
            )
        yield descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_directory(
    parent: int, component: bytes, mode: int, reference: str, *, described: bool
) -> int:
    """Open `component` below `parent` as a directory, creating it when it is not there.

    `mkdir` first and tolerate `FileExistsError`, rather than testing for existence and then
    creating: the test-then-act form has a window in which something else creates the name, and
    the whole point of doing this with descriptors is not to have such windows.

    `described` says whether `mode` is a mode the *archive* stated for this directory or a
    default this module chose on the way down to something else, and the two cannot be treated
    alike:

    - **A described directory's mode is applied whichever way the open went.** It is the archive's
      mode, and R13.4's restore means the directory comes back as it was persisted whether or not
      the image already shipped a directory at that path.
    - **An invented directory's mode is applied only when this call created it.** Applying it
      unconditionally would chmod a directory that something else established — including one an
      earlier `DIRTYPE` member restored with the archive's mode — so a directory's restored mode
      would depend on whether any member happened to be restored below it.

    `fchmod` rather than trusting `mkdir`'s mode argument in either case, because that argument is
    masked by the process umask: an invented directory has to be `0o700` exactly, not `0o700`
    minus whatever the umask removes, and a described one has to be the archive's mode exactly.
    """
    created = True
    try:
        os.mkdir(component, mode, dir_fd=parent)
    except FileExistsError:
        created = False
    except OSError as exc:
        raise _write_failed(component, exc, reference) from exc
    try:
        descriptor = os.open(component, _DESCEND_FLAGS, dir_fd=parent)
    except OSError as exc:
        raise _write_failed(component, exc, reference) from exc
    if not (described or created):
        return descriptor
    try:
        os.fchmod(descriptor, mode)
    except OSError as exc:
        os.close(descriptor)
        raise _write_failed(component, exc, reference) from exc
    return descriptor


def _write_at(
    parent: int, name: bytes, content: bytes, mode: int, reference: str
) -> None:
    """Write one restored file below `parent`, never following a symlink at its name."""
    try:
        descriptor = os.open(name, _WRITE_FLAGS, mode, dir_fd=parent)
    except OSError as exc:
        raise _write_failed(name, exc, reference) from exc
    try:
        # Unconditionally, because the mode argument to `open` applies only when the file is
        # created and is masked by the process umask, and a restored file's mode is the archive's
        # whether or not the image already shipped a file at that path.
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
    except OSError as exc:
        raise _write_failed(name, exc, reference) from exc
    finally:
        os.close(descriptor)


def _write_failed(name: bytes, exc: OSError, reference: str) -> RestorationFailure:
    return _failure(
        RestoreCause.WRITE_FAILED,
        f"{os.fsdecode(name)!r}: {_strerror(exc)}",
        reference,
    )


def _strerror(exc: OSError) -> str:
    return os.strerror(exc.errno) if exc.errno is not None else str(exc)


def _describe_kind(member: tarfile.TarInfo) -> str:
    """What an unrestorable member is, in the words the refusal reports."""
    if member.issym():
        return "a symbolic link"
    if member.islnk():
        return "a hard link"
    if member.ischr() or member.isblk():
        return "a device node"
    if member.isfifo():
        return "a FIFO"
    return "not a regular file or directory"
