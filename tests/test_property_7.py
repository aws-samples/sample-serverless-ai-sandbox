# kiro-classification: public
"""Property 7: artifact persistence round-trip, and restoration failure reporting.

Two conjuncts over one drawn example each time. The first terminates a Session with a configured
artifact set and then creates a Session restoring what that produced, and compares the two trees
byte for byte. The second drives one restoration failure and asserts the `/run` hook reports the
*right* cause out of a closed set. The deterministic tests in `test_runtime_lifecycle_hooks.py`
and `test_runtime_run_hook.py` are the examples underneath both halves; what is generalised here
is the domain, and the domain is chosen so the property can fail.

## The round trip is closed by the artifact, not by the test

The `RestoreRequest` handed to the second Session comes from
`PersistedArtifact.as_restore_request()` and travels through a real configuration document, so the
size and the digest `runtime.restore` verifies are the ones `runtime.persist` recorded. A test that
wrote those two fields out by hand would be asserting that two literals agree with each other,
and both checks in `runtime.restore._verify` would be guarding nothing.

The comparison is against the *source tree read back off the filesystem* rather than against the
dictionary the example drew. That matters on a case-insensitive or normalisation-insensitive
filesystem, where two drawn names can land on one inode: what was persisted is what the filesystem
held, so that is what the restored tree has to equal. It also means the modes are compared, which
`runtime.persist` and `runtime.restore` both claim to carry.

## What the format constrains, and what that costs to reach

Every example carries nested paths, an empty file and an empty directory at fixed names, because
those three are cases the archive format has to be right about rather than cases worth sampling.
Around them the tree is drawn: names from `path_component()` and contents from `output_bytes()`,
so content and filenames that are not valid UTF-8 are the ordinary case rather than the exception —
that is where a round-trip claim breaks, and `os.fsencode`/`os.fsdecode` either survive it or they
do not.

Members `runtime.restore` would refuse are planted in the tree, because 8.8's reasoning is that one
such member costs the *whole* archive: `runtime.restore` fails a restore over a single symlink, so
an archive containing one restores nothing at all. The strong assertion is therefore not that the
skip was recorded but that the archive still restores, which it could not have done with the member
in it.

A **hardlink** is deliberately not among the planted kinds. A hardlink to a regular file *is* a
regular file — `os.stat` cannot tell them apart, and `runtime.persist` skips on `st_mode` — so
planting one produces a second regular member, which the comparison covers as an ordinary file.
The refusal of a `LNKTYPE` *member* is real and is reached from the other side, in the failure half,
by a crafted archive. **Device nodes** are the same shape of problem for the opposite reason:
`mknod` needs privilege this suite does not have, so a device member is also reached as a crafted
member rather than as a planted file.

## Truncation, and why the tree is crowded

A deadline of one millisecond leaves collection three quarters of one, and a handful of files can be
archived inside that on a fast machine — so the truncation half would be a test of machine speed.
`crowd()` puts more files under the configured path set than the smallest deadline the document
admits can reach, which is the same device `test_runtime_lifecycle_hooks.py` uses and for the same
reason: the outcome becomes a property of the tree. What is then asserted is the consequential
half of 8.8's decision — every member that survived is byte-identical to its source and never a
prefix of it.

## Drawn filenames are asked of the filesystem, never predicted

`usable_name` probes the real filesystem with `O_CREAT | O_EXCL` and substitutes only on an actual
`OSError`. A predicate over the bytes is not the question: APFS refuses valid encodings of
*unassigned* code points, so `b"\\xd7\\x88"` (U+05C8) is refused exactly as `b"\\xff"` is, and
Property 5's guard was wrong until it stopped guessing. The reasoning is `test_property_5.py`'s and
this module reuses it rather than restating it.

Note the asymmetry the format has and the configuration document does not: `PersistRequest.paths`
are JSON `str`, so a path that is not valid UTF-8 cannot be *named* in the document, while an
archive member name goes through `os.fsencode`/`os.fsdecode` and is exact. So the configured path
set is drawn from expressible ASCII names and everything below it is drawn bytes, which is what
makes a byte-exact name inside a named subtree an assertion rather than a contradiction.

## Both State_Store seams are faked, and neither is a shortcut

The offline suite denies outbound network access and neither the artifact bucket nor the Sandbox
execution role exists yet. `FakeStateStore` is one dictionary behind both one-method seams, and it
is where `read-denied` comes from: the per-Session execution role is confined to its own artifact
prefix, so a reference belonging to another Session is refused by the credential rather than by a
string comparison inside the runtime. Every reference here is obviously fake.

## Two things this property found, and what it asserts now that both are fixed

Both were defects in `runtime/restore.py`, reported rather than encoded here — a property that
asserts the current behaviour of the code it is testing has stopped being a property — and both
have since been fixed. Each accommodation this module made for them has been removed, because a
property that still accommodates a fixed defect is asserting less than it could.

1. **A restored directory's mode was not the archive's whenever anything was restored below it.**
   `_open_directory` applied its `mode` argument unconditionally, including to a directory that
   already existed, and `_walk` descended with `_IMPLICIT_DIRECTORY_MODE`, so a directory member
   restored with `0o755` was chmodded back to `0o700` by the walk that reached its first child while
   an empty directory kept `0o755` — the restored mode depended on whether anything followed.
   `_open_directory` now distinguishes a directory the archive described, whose mode is applied
   either way, from one the walk invented on the way down, which is created owner-only and left
   alone when it is already there. So directories are compared here **with their modes**, exactly as
   files are, which is the design's byte-for-byte claim stated whole.

2. **A truncated compressed artifact was not identified.** `_extract` caught `tarfile.TarError`, but
   a gzip stream that ends before its end-of-stream marker makes the decompressor raise `EOFError`,
   which is neither an `OSError` nor a `TarError`. That escaped to the fail-closed arm in
   `runtime.hooks` — so the gate failed and the Sandbox was `FAILED`, correctly — but the reason was
   a bare `EOFError` message carrying no member of `RestoreCause` and not even the
   `RESTORE_FAILURE_PREFIX` that R13.7's identification is built on. It is exactly the shape a
   partially transferred compressed artifact has, and `sizeBytes` and `sha256` are optional in the
   document, so the checks that would otherwise have caught it may not be there. `_extract` now
   names `EOFError` alongside `TarError` — and, in the same family, the compression layer's own
   error types, which are not `TarError` either — and reports `archive-unreadable`. The
   `archive-unreadable` generator therefore draws the whole family: truncated and damaged
   *compressed* payloads as well as payloads that are not an archive at all.

## Budget

`MINIMUM_EXAMPLES`, the design's floor. Each example builds two applications, materialises a tree,
builds a real `tar` stream and extracts it, and drives four hook requests; the truncating examples
additionally write `_CROWD_FILES` small files. That is real filesystem work, so the drawn tree is
kept to a handful of small files and every example's roots are removed as it finishes. Nothing here
waits on anything, so there is no wait to bound: the only clock is the artifact deadline, which is
what the truncation case is about.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import socket
import stat
import struct
import sys
import tarfile
import tempfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from starlette.testclient import TestClient

from protocol.generators import output_bytes, path_component
from protocol.schema import load_catalogue
from runtime.app import HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.filesystem import ConfinedRoot
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.persist import ARTIFACT_STATUS_MEMBER, PersistedArtifact
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.restore import RESTORE_FAILURE_PREFIX, RestoreCause
from runtime.run_config import (
    ReadDenied,
    ReferenceNotFound,
    StateReadFailure,
)
from tests.harness import MINIMUM_EXAMPLES

CATALOGUE = load_catalogue()

#: Obviously fake, and opaque to the runtime: the only thing that matters about a reference is
#: that the same string comes back out and that it appears in a failure reason.
SESSION_PREFIX: Final = "tenants/tnt-fake/sessions/ses-fake/"

#: Another Session's prefix. The `read-denied` case, because the Sandbox execution role is
#: confined to its own prefix and IAM is the authority on that.
FOREIGN_PREFIX: Final = "tenants/tnt-fake/sessions/ses-other/"

#: The one configured path the document can name. ASCII, because `PersistRequest.paths` are JSON
#: strings; everything below it is drawn bytes.
SELECTED: Final = b"selected"

#: The reserved status member, as bytes, which is how a byte-typed tree comparison sees it.
STATUS_MEMBER: Final = os.fsencode(ARTIFACT_STATUS_MEMBER)

#: Fixed names for the three cases the archive format constrains rather than samples: an empty
#: file, an empty directory, and a nested path. Inside `SELECTED`, so they are reached whether or
#: not the example configures a path set.
EMPTY_FILE: Final = b"empty.bin"
EMPTY_DIRECTORY: Final = b"empty.dir"
NESTED_DIRECTORY: Final = b"nested"

#: A deadline that has already expired by the time the traversal starts, and the deadline of a
#: Session that is not being truncated. One millisecond is the smallest the document admits.
EXPIRED_DEADLINE_MS: Final = 1
AMPLE_DEADLINE_MS: Final = 20_000

#: Enough small files under the configured path set that the expired deadline cannot outrun them,
#: so truncation is a property of the tree and not of how fast the machine happens to be. The same
#: numbers `test_runtime_lifecycle_hooks.py`'s `crowd()` uses.
_CROWD_FILES: Final = 400
_CROWD_BYTES: Final = 512

#: Ceilings on the drawn tree. Small on purpose: every example writes this tree, archives it and
#: extracts it again, and the axis this property is about is the *shape* of what is carried, not
#: its size. The full length domain is already swept by the codec properties.
_MAX_FILES: Final = 3
_MAX_DEPTH: Final = 3
_CONTENT_BYTES: Final = 1024
_NAME_BYTES: Final = 32

#: Modes a drawn file is created with. Persisted and restored through `_MODE_MASK` on both sides,
#: so a mode that survives one direction has to survive both.
_MODES: Final = (0o600, 0o644, 0o755)

#: The probe's flags, and the reasoning behind them, are `test_property_5.py`'s: `O_EXCL` so the
#: probe can never truncate a file that is already there, `O_NOFOLLOW` and `O_CLOEXEC` for the
#: reasons `runtime.filesystem` uses them on the write this stands in for.
_PROBE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
)

_POSIX: Final = sys.platform != "win32"

#: Somewhere short enough to bind a Unix socket in. `tempfile.gettempdir()` is the long
#: `/var/folders` path on macOS, which `sun_path` will not hold together with a name, so `/tmp` is
#: preferred where it exists. Nothing is left behind in it; see `_put_socket_at`.
_SHORT_TEMP_ROOT: Final = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()  # nosec B108


# --- The State_Store, faked behind both of its one-method seams ------------------------------


class FakeStateStore:
    """One dictionary behind `StateStoreWriter` and `StateStoreReader`.

    The prefix confinement is the interesting part: a reference outside this Session's own prefix
    is refused, which is where `RestoreCause.READ_DENIED` comes from. `runtime.restore` never
    parses a reference to work out whose it is, and neither does this.
    """

    def __init__(
        self,
        *,
        objects: dict[str, bytes] | None = None,
        prefix: str = SESSION_PREFIX,
        read_failure: Exception | None = None,
    ) -> None:
        self.objects = dict(objects or {})
        self.written: list[PersistedArtifact] = []
        self._prefix = prefix
        self._read_failure = read_failure

    async def write(self, artifact: PersistedArtifact) -> None:
        self.objects[artifact.reference] = artifact.body
        self.written.append(artifact)

    async def read(self, reference: str) -> bytes:
        if not reference.startswith(self._prefix):
            raise ReadDenied(
                f"the Sandbox execution role may not read {reference}, which is outside "
                f"its own artifact prefix"
            )
        if self._read_failure is not None:
            raise self._read_failure
        stored = self.objects.get(reference)
        if stored is None:
            raise ReferenceNotFound(f"no object is stored at {reference}")
        return stored

    @property
    def only(self) -> PersistedArtifact:
        assert len(self.written) == 1, self.written
        return self.written[0]


# --- The drawn artifact set ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Entry:
    """One regular file to materialise: its path components below the root, and its bytes."""

    components: tuple[bytes, ...]
    content: bytes
    mode: int


@dataclass(frozen=True, slots=True)
class ArtifactSet:
    """One configured artifact set, and how the Session that produces it is configured.

    `inside` lives under `SELECTED` and `outside` does not, both non-empty, so an example that
    configures a path set always has content that must survive and content that must not — the
    same device the design's Property 8 generator uses, applied to the persisted path set.
    """

    inside: tuple[Entry, ...]
    outside: tuple[Entry, ...]
    refused_kinds: tuple[str, ...]
    select_paths: bool
    compress: bool
    truncate: bool

    @property
    def paths(self) -> tuple[str, ...]:
        """The configured path set: one named subtree, or empty for the whole root."""
        return (os.fsdecode(SELECTED),) if self.select_paths else ()

    @property
    def deadline_ms(self) -> int:
        return EXPIRED_DEADLINE_MS if self.truncate else AMPLE_DEADLINE_MS

    def selects(self, relative: bytes) -> bool:
        """Whether a path below the root is inside the configured set."""
        if not self.select_paths:
            return True
        return relative == SELECTED or relative.startswith(SELECTED + b"/")


#: The member kinds that can be *planted in a tree* and that `runtime.restore` refuses, with the
#: words `runtime.persist` records the skip in. A hardlink and a device node are absent by
#: construction and the module docstring says why.
_PLANTABLE: Final = {
    "symlink": "a symbolic link, which is never persisted or restored",
    "fifo": "a FIFO, which is never persisted or restored",
    "socket": "a socket, which is never persisted or restored",
}


def name_component() -> SearchStrategy[bytes]:
    """One drawn filesystem name, from the adversarial byte domain."""
    return path_component(max_size=_NAME_BYTES)


@st.composite
def _entry(draw: st.DrawFn, *, prefix: bytes | None) -> Entry:
    """One drawn file, at a drawn depth, optionally below a fixed prefix."""
    drawn = draw(
        st.lists(name_component(), min_size=1, max_size=_MAX_DEPTH).map(tuple)
    )
    components = drawn if prefix is None else (prefix, *drawn)
    return Entry(
        components=components,
        content=draw(output_bytes(max_size=_CONTENT_BYTES)),
        mode=draw(st.sampled_from(_MODES)),
    )


def artifact_set() -> SearchStrategy[ArtifactSet]:
    """A configured artifact set: a tree that straddles the path set, and how it is written.

    `refused_kinds` is drawn from what this platform can actually plant, so the conjunct that
    asserts a refused member is skipped and named is reached wherever it is meaningful and the
    module is not skipped whole where it is not.
    """
    plantable = sorted(_PLANTABLE) if _POSIX else []
    return st.builds(
        ArtifactSet,
        inside=st.lists(_entry(prefix=SELECTED), min_size=1, max_size=_MAX_FILES).map(
            tuple
        ),
        outside=st.lists(_entry(prefix=None), min_size=1, max_size=_MAX_FILES).map(
            tuple
        ),
        refused_kinds=(
            st.lists(st.sampled_from(plantable), unique=True).map(tuple)
            if plantable
            else st.just(())
        ),
        select_paths=st.booleans(),
        compress=st.booleans(),
        truncate=st.booleans(),
    )


# --- The drawn restoration failure ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RestoreFailureCase:
    """One way a restoration fails, and the cause its reason has to identify.

    `detail` is the substring that makes the assertion about *this* cause rather than about any
    reason at all; it is None only for `archive-unreadable`, whose detail is the archive reader's
    own message and not this suite's to predict.
    """

    cause: RestoreCause
    reference: str
    stored: bytes | None = None
    read_failure: Exception | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    detail: str | None = None
    #: Something to put in the destination root before `/run`, so a write has something to fail
    #: against: a regular file or a directory at this relative name.
    obstruction: tuple[str, bytes] | None = None
    #: A name that must not appear beside the destination root afterwards. The archive-escape
    #: guard, asserted where the member named a way out.
    escape_probe: bytes | None = None


def one_member_archive(name: bytes = b"a.bin", content: bytes = b"a") -> bytes:
    """A readable `tar` stream carrying one regular file, for the cases that need bytes."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        member = tarfile.TarInfo(os.fsdecode(name))
        member.type = tarfile.REGTYPE
        member.mode = 0o600
        member.size = len(content)
        stream.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def crafted_member_archive(member: tarfile.TarInfo) -> bytes:
    """A `tar` stream carrying exactly one member, however unrestorable."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        member.size = 0
        stream.addfile(member)
    return buffer.getvalue()


def absent_reference(suffix: str) -> RestoreFailureCase:
    """Nothing is stored under the reference."""
    return RestoreFailureCase(
        cause=RestoreCause.REFERENCE_ABSENT,
        reference=SESSION_PREFIX + suffix,
        detail="no object is stored",
    )


def foreign_reference(suffix: str) -> RestoreFailureCase:
    """A reference belonging to a different Session, refused by the credential."""
    return RestoreFailureCase(
        cause=RestoreCause.READ_DENIED,
        reference=FOREIGN_PREFIX + suffix,
        detail="may not read",
    )


def transport_failure(suffix: str) -> RestoreFailureCase:
    """The read failed for a reason the transport reported."""
    return RestoreFailureCase(
        cause=RestoreCause.TRANSFER_FAILED,
        reference=SESSION_PREFIX + suffix,
        read_failure=StateReadFailure("the transfer was reset by the peer"),
        detail="reset by the peer",
    )


def truncated_transfer(suffix: str, content: bytes, delta: int) -> RestoreFailureCase:
    """Fewer or more bytes arrived than the writer recorded."""
    stored = one_member_archive(content=content)
    return RestoreFailureCase(
        cause=RestoreCause.TRUNCATED_TRANSFER,
        reference=SESSION_PREFIX + suffix,
        stored=stored,
        size_bytes=len(stored) + delta,
        detail="arrived",
    )


def digest_mismatch(suffix: str, content: bytes) -> RestoreFailureCase:
    """The right number of the wrong bytes arrived."""
    stored = one_member_archive(content=content)
    return RestoreFailureCase(
        cause=RestoreCause.DIGEST_MISMATCH,
        reference=SESSION_PREFIX + suffix,
        stored=stored,
        sha256=hashlib.sha256(stored + b"not these bytes").hexdigest(),
        detail="hash to",
    )


#: The ways a stored payload is not a readable archive. `not-an-archive` is the plain case; the two
#: compressed ones are a *partially transferred* compressed artifact, which is the shape that
#: matters most — `sizeBytes` and `sha256` are optional in the configuration document, so the
#: checks that would otherwise catch a short transfer may be absent and the reader is then the only
#: thing that can notice. Both were excluded from this generator until `runtime.restore` identified
#: them; the module docstring records what changed.
_UNREADABLE_ARCHIVES: Final = (
    "not-an-archive",
    "compressed-header-only",
    "compressed-truncated",
    "compressed-damaged",
)


def compressed_archive(content: bytes) -> bytes:
    """A readable `w:gz` stream carrying one regular file, for the truncation cases."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
        member = tarfile.TarInfo("compressed.bin")
        member.type = tarfile.REGTYPE
        member.mode = 0o600
        member.size = len(content)
        stream.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def damaged_compressed_archive(content: bytes) -> bytes:
    """A compressed archive whose recorded checksum does not describe its own bytes.

    Framed by hand rather than by damaging a `w:gz` stream, because where the damage lands decides
    which layer notices it and that is not something to leave to chance here. A wrong CRC32 in the
    gzip trailer is the one corruption the format itself is specified to catch, and the `tar` inside
    carries no end-of-archive blocks so that the reader reads to the end of the compressed stream
    and therefore reaches the check.
    """
    member = tarfile.TarInfo("damaged.bin")
    member.type = tarfile.REGTYPE
    member.mode = 0o644
    member.size = len(content)
    raw = member.tobuf() + content + b"\x00" * (-len(content) % tarfile.BLOCKSIZE)
    deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = deflate.compress(raw) + deflate.flush()
    header = b"\x1f\x8b\x08\x00" + b"\x00" * 4 + b"\x00\xff"
    trailer = struct.pack("<II", zlib.crc32(raw) ^ 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    return header + body + trailer


def unreadable_archive(suffix: str, kind: str, payload: bytes) -> RestoreFailureCase:
    """Bytes that are not a readable archive, in one of four ways.

    `not-an-archive` is a short prefix that is none of the compression magics followed by drawn
    bytes, so the total is under one `tar` block and cannot be a header whatever was drawn.
    Deterministic, rather than hoping drawn bytes are not accidentally an archive.

    The three compressed kinds are the family a partially transferred or corrupted compressed
    artifact belongs to: `compressed-header-only` is the magic and nothing else,
    `compressed-truncated` is a real archive of drawn content cut in half, and
    `compressed-damaged` decompresses to a `tar` under a checksum that does not match it. Which
    layer notices — the gzip header read, the deflate body, the trailer's CRC, or the `tar` reader
    behind all three — varies with the kind and with the drawn content, and that is deliberate: the
    assertion is that every one of them is reported as `archive-unreadable` with the standard
    prefix, not that a particular one raises a particular exception.
    """
    if kind == "compressed-header-only":
        stored = b"\x1f\x8b\x08\x00" + payload
    elif kind == "compressed-truncated":
        whole = compressed_archive(b"restored content " * 64 + payload)
        stored = whole[: len(whole) // 2]
    elif kind == "compressed-damaged":
        stored = damaged_compressed_archive(b"restored content " * 8 + payload)
    else:
        stored = b"not an archive at all" + payload
    return RestoreFailureCase(
        cause=RestoreCause.ARCHIVE_UNREADABLE,
        reference=SESSION_PREFIX + suffix,
        stored=stored,
    )


#: The member kinds and names `runtime.restore` refuses, each with the words its refusal uses.
#: The two link types and the two device types are reachable only from this side: neither can be
#: planted in a tree by an unprivileged process, and a hardlink to a regular file is a regular
#: file.
_REFUSED_MEMBERS: Final = (
    "escaping",
    "nested-escaping",
    "absolute",
    "symlink",
    "hardlink",
    "character-device",
    "block-device",
    "fifo",
)


def refused_member(suffix: str, kind: str, name: bytes) -> RestoreFailureCase:
    """A member this runtime will not restore, or a name that leaves the root."""
    member = tarfile.TarInfo(os.fsdecode(name))
    member.type = tarfile.REGTYPE
    detail = "resolves outside"
    escape: bytes | None = None
    if kind == "escaping":
        member.name = os.fsdecode(b"../" + name)
        escape = name
    elif kind == "nested-escaping":
        member.name = os.fsdecode(b"below/../../" + name)
        escape = name
    elif kind == "absolute":
        member.name = os.fsdecode(b"/" + name)
        detail = "absolute path"
    else:
        member.linkname = "elsewhere"
        member.type, detail = {
            "symlink": (tarfile.SYMTYPE, "a symbolic link"),
            "hardlink": (tarfile.LNKTYPE, "a hard link"),
            "character-device": (tarfile.CHRTYPE, "a device node"),
            "block-device": (tarfile.BLKTYPE, "a device node"),
            "fifo": (tarfile.FIFOTYPE, "a FIFO"),
        }[kind]
    return RestoreFailureCase(
        cause=RestoreCause.MEMBER_REFUSED,
        reference=SESSION_PREFIX + suffix,
        stored=crafted_member_archive(member),
        detail=detail,
        escape_probe=escape,
    )


#: How the filesystem is made to refuse a write: something of the wrong kind is already at the
#: path the archive names.
_OBSTRUCTIONS: Final = ("file-in-the-way", "directory-in-the-way")


def write_failed(suffix: str, kind: str) -> RestoreFailureCase:
    """The filesystem refused the write, because the path is already something else."""
    if kind == "file-in-the-way":
        # A regular file where the member's parent directory has to be created.
        stored = one_member_archive(name=b"blocked/inner.bin")
        obstruction = ("file", b"blocked")
    else:
        # A directory where the member's own file has to be opened.
        stored = one_member_archive(name=b"blocked")
        obstruction = ("directory", b"blocked")
    return RestoreFailureCase(
        cause=RestoreCause.WRITE_FAILED,
        reference=SESSION_PREFIX + suffix,
        stored=stored,
        detail="blocked",
        obstruction=obstruction,
    )


def _suffixes() -> SearchStrategy[str]:
    """The varying tail of a reference. Opaque to the runtime, so only its identity matters."""
    return st.integers(min_value=1, max_value=99).map(lambda n: f"{n}/state.tar")


def restore_failure() -> SearchStrategy[RestoreFailureCase]:
    """One restoration failure mode, over every member of the closed cause set.

    The design's generator names absent reference, corrupt archive, permission denied, truncated
    transfer, and a reference belonging to a different Session. The last two of those are the same
    case here — a foreign reference is refused by the credential, which is `read-denied` — and the
    set is extended to the rest of `RestoreCause`, because the claim is that the reported cause is
    the *right* one and a cause no example reaches is a claim about nothing.
    """
    suffix = _suffixes()
    return st.one_of(
        st.builds(absent_reference, suffix=suffix),
        st.builds(foreign_reference, suffix=suffix),
        st.builds(transport_failure, suffix=suffix),
        st.builds(
            truncated_transfer,
            suffix=suffix,
            content=output_bytes(max_size=64),
            delta=st.integers(min_value=1, max_value=512).flatmap(
                lambda size: st.sampled_from((size, -size))
            ),
        ),
        st.builds(digest_mismatch, suffix=suffix, content=output_bytes(max_size=64)),
        st.builds(
            unreadable_archive,
            suffix=suffix,
            kind=st.sampled_from(_UNREADABLE_ARCHIVES),
            payload=output_bytes(max_size=64),
        ),
        st.builds(
            refused_member,
            suffix=suffix,
            kind=st.sampled_from(_REFUSED_MEMBERS),
            name=name_component(),
        ),
        st.builds(write_failed, suffix=suffix, kind=st.sampled_from(_OBSTRUCTIONS)),
    )


# --- The workspace: fresh roots, and one probe directory -------------------------------------


@dataclass(slots=True)
class Workspace:
    """Somewhere to build roots, and the facts about this filesystem the examples need."""

    base: Path
    probe: Path
    sockets_bindable: bool
    served: int = 0

    def fresh(self, label: str) -> Path:
        """A directory no previous example has touched, holding one root of its own.

        Nested one level down so that "nothing was written beside the root" is a question with an
        answer: the holder contains the root and nothing else until something escapes it.
        """
        self.served += 1
        holder = self.base / f"{label}-{self.served:05d}"
        (holder / "root").mkdir(parents=True)
        return holder


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Workspace]:
    """One base directory for the module, module-scoped because it holds no state.

    Every example takes fresh roots out of it and removes them again, so nothing an example does
    is observable by the next one. Module-scoped so that Hypothesis is not handed a
    function-scoped fixture, which it is right to complain about.
    """
    base = tmp_path_factory.mktemp("property-7")
    probe = base / "probe"
    probe.mkdir()
    yield Workspace(base=base, probe=probe, sockets_bindable=_sockets_bindable(probe))


def _sockets_bindable(directory: Path) -> bool:
    """Whether a socket can be put in `directory`, established by trying it.

    Asked once per run, so the answer is the same for every example, and it is a fact about where
    the suite is running rather than about the code under test.
    """
    probe = os.fsencode(directory / "probe.sock")
    if not _put_socket_at(probe):
        return False
    os.unlink(probe)
    return True


def _put_socket_at(path: bytes) -> bool:
    """Put a Unix socket at `path`, or answer False where this platform will not.

    `sun_path` is about a hundred bytes and a pytest temporary directory is longer than that on its
    own, so the socket is bound at a short path and renamed into place: a rename moves the inode and
    only the name changes, so what ends up at `path` is a socket bound the ordinary way. Both steps
    can fail for reasons that are facts about the machine — no `AF_UNIX` at all, or a filesystem
    boundary between the two directories — and the answer is then False and the kind is not planted
    rather than the example failing over the platform.
    """
    if not hasattr(socket, "AF_UNIX"):
        return False
    scratch = tempfile.mkdtemp(prefix="p7-", dir=_SHORT_TEMP_ROOT)
    staged = os.path.join(os.fsencode(scratch), b"s")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(os.fsdecode(staged))
        os.rename(staged, path)
    except OSError:
        return False
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return True


def usable_name(workspace: Workspace, drawn: bytes) -> bytes:
    """The drawn name, or its hex rendering on a filesystem that will not hold it.

    The question is asked of the filesystem rather than predicted from the bytes, for the reasons
    `test_property_5.py`'s `usable_name` sets out: APFS refuses valid encodings of unassigned code
    points, so no predicate over bytes is the rule. Only a refusal from the filesystem substitutes,
    the substitute is derived from the drawn bytes and so is injective, and it is neither empty nor
    a reserved component.
    """
    if _filesystem_holds(workspace.probe, drawn):
        return drawn
    return os.fsencode(drawn.hex())


def _filesystem_holds(directory: Path, name: bytes) -> bool:
    """Whether this filesystem will hold `name` in `directory`, established by trying it.

    Byte-typed throughout, and in a directory on the same filesystem as the roots the examples
    build, because representability is a property of the name and the filesystem. The probe is
    removed the moment it succeeds.
    """
    probe = os.path.join(os.fsencode(directory), name)
    try:
        descriptor = os.open(probe, _PROBE_FLAGS, 0o600)
    except FileExistsError:
        # Representable; something already holds it. Nothing to create and nothing to remove.
        return True
    except OSError:
        return False
    os.close(descriptor)
    os.unlink(probe)
    return True


# --- Materialising a drawn tree ---------------------------------------------------------------


def materialise(root: bytes, artifacts: ArtifactSet, workspace: Workspace) -> None:
    """Write the drawn tree, plus the three cases the format constrains.

    Drawn paths can collide — one example's file is another's directory — and a collision is
    resolved by leaving the first writer's entry in place rather than by drawing again. That is
    safe because everything downstream compares against the tree as the filesystem actually holds
    it, not against what was drawn.
    """
    selected = root + b"/" + SELECTED
    os.mkdir(selected, 0o755)
    # An empty file, an empty directory, and a nested path: reached by every example, because the
    # format has to be right about them rather than usually right.
    _write_file(selected + b"/" + EMPTY_FILE, b"", 0o644)
    os.mkdir(selected + b"/" + EMPTY_DIRECTORY, 0o755)
    os.mkdir(selected + b"/" + NESTED_DIRECTORY, 0o755)
    _write_file(selected + b"/" + NESTED_DIRECTORY + b"/deeper.bin", b"nested", 0o600)

    for entry in (*artifacts.inside, *artifacts.outside):
        components = tuple(
            usable_name(workspace, component) for component in entry.components
        )
        _write_entry(root, components, entry)

    if artifacts.truncate:
        crowd(selected)


def _write_entry(root: bytes, components: tuple[bytes, ...], entry: Entry) -> None:
    """Write one drawn file, or leave a colliding path as whatever already holds it."""
    path = root + b"/" + b"/".join(components)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        return
    if os.path.lexists(path):
        return
    try:
        _write_file(path, entry.content, entry.mode)
    except (IsADirectoryError, NotADirectoryError, FileExistsError):
        return


def _write_file(path: bytes, content: bytes, mode: int) -> None:
    """Write one file with an exact mode.

    `fchmod` after the open, because the mode argument is masked by the process umask and the
    comparison this feeds is about the mode the file actually has.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, content)
    finally:
        os.close(descriptor)


def crowd(directory: bytes) -> None:
    """Fill `directory` with more files than the smallest deadline can reach.

    `test_runtime_lifecycle_hooks.py`'s helper, and its reasoning: a handful of files can be
    archived inside one millisecond, so a truncation assertion over a small tree would be an
    assertion about the machine. Written inside the configured path set, so it is reached whether
    or not the example names one.
    """
    for index in range(_CROWD_FILES):
        _write_file(
            directory + b"/" + f"crowd-{index:04d}.bin".encode("ascii"),
            b"x" * _CROWD_BYTES,
            0o600,
        )


def plant_refused_members(
    root: bytes, artifacts: ArtifactSet, workspace: Workspace
) -> dict[bytes, str]:
    """Plant the drawn member kinds `runtime.restore` refuses, and say what was planted.

    Inside the configured path set, so the traversal reaches them either way. Each is something
    one archive member of which would cost the whole restore, which is what makes the skip the
    right outcome rather than a lossy one.
    """
    planted: dict[bytes, str] = {}
    selected = root + b"/" + SELECTED
    for kind in artifacts.refused_kinds:
        name = f"refused-{kind}".encode("ascii")
        path = selected + b"/" + name
        if kind == "symlink":
            os.symlink(b"deeper.bin", path)
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
        elif not workspace.sockets_bindable or not _put_socket_at(path):
            continue
        planted[SELECTED + b"/" + name] = _PLANTABLE[kind]
    return planted


# --- Reading a tree back, byte-typed ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tree:
    """A filesystem tree as the comparison sees it: content and mode, by relative path."""

    files: dict[bytes, tuple[bytes, int]]
    directories: dict[bytes, int]
    others: set[bytes]

    @property
    def members(self) -> set[bytes]:
        """Every path in the tree that an archive would carry as a member."""
        return set(self.files) | set(self.directories)


def read_tree(root: bytes) -> Tree:
    """Every regular file and directory below `root`, by relative path.

    Byte-typed and never following a symlink, because a name on a Linux filesystem is a byte
    sequence and because what is being compared is what `runtime.persist` walks: regular files and
    directories, with everything else recorded separately so its absence from an archive is
    assertable rather than assumed.
    """
    files: dict[bytes, tuple[bytes, int]] = {}
    directories: dict[bytes, int] = {}
    others: set[bytes] = set()

    def walk(current: bytes, prefix: bytes) -> None:
        for name in sorted(os.listdir(current)):
            path = current + b"/" + name
            relative = name if not prefix else prefix + b"/" + name
            info = os.lstat(path)
            if stat.S_ISDIR(info.st_mode):
                directories[relative] = info.st_mode & 0o777
                walk(path, relative)
            elif stat.S_ISREG(info.st_mode):
                with open(path, "rb") as handle:
                    files[relative] = (handle.read(), info.st_mode & 0o777)
            else:
                others.add(relative)

    walk(root, b"")
    return Tree(files=files, directories=directories, others=others)


def member_names(artifact: PersistedArtifact) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(artifact.body), mode="r:*") as stream:
        return stream.getnames()


def read_status(artifact: PersistedArtifact) -> dict[str, object]:
    """The reserved status member, decoded straight out of the archive stream."""
    with tarfile.open(fileobj=io.BytesIO(artifact.body), mode="r:*") as stream:
        member = stream.extractfile(ARTIFACT_STATUS_MEMBER)
        assert member is not None, "every archive carries the status member"
        with member:
            decoded = json.loads(member.read())
    assert isinstance(decoded, dict)
    return decoded


# --- Driving the two Sessions -----------------------------------------------------------------


def run_payload(**sections: object) -> bytes:
    return json.dumps(sections).encode()


@dataclass(slots=True)
class Sandbox:
    """One application, its gate, and the lifecycle it drives."""

    client: TestClient
    gate: ReadinessGate
    lifecycle: SandboxLifecycle


def sandbox(root: Path, store: FakeStateStore) -> Sandbox:
    """The real application over a real confined root, with the State_Store faked."""
    gate = ReadinessGate()
    lifecycle = SandboxLifecycle(
        filesystem_root=ConfinedRoot(root),
        state_store=store,
        state_writer=store,
    )
    client = TestClient(
        create_app(
            actions=lifecycle,
            operations=OperationRegistry(catalogue=CATALOGUE),
            gate=gate,
            catalogue=CATALOGUE,
        )
    )
    return Sandbox(client=client, gate=gate, lifecycle=lifecycle)


def terminate_a_session(
    root: Path, artifacts: ArtifactSet, store: FakeStateStore, reference: str
) -> PersistedArtifact:
    """Run a Session configured to persist `artifacts`, then terminate it (R13.3)."""
    session = sandbox(root, store)
    persist: dict[str, object] = {
        "reference": reference,
        "deadlineMs": artifacts.deadline_ms,
        "compress": artifacts.compress,
    }
    if artifacts.paths:
        persist["paths"] = list(artifacts.paths)
    started = session.client.post(f"{HOOK_PATH_PREFIX}/run", content=run_payload(persist=persist))
    assert started.status_code == HTTPStatus.OK, started.text
    terminated = session.client.post(f"{HOOK_PATH_PREFIX}/terminate")
    assert terminated.status_code == HTTPStatus.OK, terminated.text
    assert session.gate.phase is RuntimePhase.TERMINATED
    written = session.lifecycle.persisted
    assert written is not None, "a configured artifact set was not written"
    return written


def create_a_session_restoring(
    root: Path, artifact: PersistedArtifact, store: FakeStateStore
) -> None:
    """Create a Session restoring `artifact`, and assert it became ready (R13.4).

    The `restore` section is composed from `as_restore_request()` rather than written out here, so
    the size and the digest `runtime.restore` verifies are the ones the write side recorded.
    """
    request = artifact.as_restore_request()
    assert request.size_bytes == len(artifact.body)
    assert request.sha256 == artifact.sha256
    session = sandbox(root, store)
    started = session.client.post(
        f"{HOOK_PATH_PREFIX}/run",
        content=run_payload(
            restore={
                "reference": request.reference,
                "sizeBytes": request.size_bytes,
                "sha256": request.sha256,
            }
        ),
    )
    assert started.status_code == HTTPStatus.OK, started.text
    assert session.gate.phase is RuntimePhase.SERVING


# --- The two conjuncts ------------------------------------------------------------------------


def assert_the_artifact_set_round_trips(
    workspace: Workspace, artifacts: ArtifactSet
) -> None:
    """R13.3 and R13.4: what `/terminate` wrote is what the next `/run` restores, byte for byte."""
    source_holder = workspace.fresh("source")
    destination_holder = workspace.fresh("restored")
    source = source_holder / "root"
    destination = destination_holder / "root"
    reference = SESSION_PREFIX + f"{workspace.served}/state.tar"
    try:
        encoded_source = os.fsencode(source)
        materialise(encoded_source, artifacts, workspace)
        planted = plant_refused_members(encoded_source, artifacts, workspace)

        store = FakeStateStore()
        artifact = terminate_a_session(source, artifacts, store, reference)

        assert artifact.reference == reference
        assert artifact.truncated is artifacts.truncate, (
            f"a {artifacts.deadline_ms}ms deadline reported truncated="
            f"{artifact.truncated}"
        )
        assert_the_refused_members_were_skipped_and_named(artifact, planted, artifacts)
        assert_the_status_member_states_the_outcome(artifact, artifacts)
        assert (artifact.body[:2] == b"\x1f\x8b") is artifacts.compress, (
            "the archive form is not the one the configuration asked for"
        )

        # The proof that skipping was the right call, and the whole round trip in one step: the
        # archive restores, which it could not have done with a refused member in it.
        create_a_session_restoring(destination, artifact, store)

        assert_the_restored_tree_reproduces_the_source(
            read_tree(encoded_source),
            read_tree(os.fsencode(destination)),
            artifacts,
            artifact,
        )
        assert list(destination_holder.iterdir()) == [destination], (
            "the restore wrote something beside the configured root"
        )
    finally:
        shutil.rmtree(source_holder, ignore_errors=True)
        shutil.rmtree(destination_holder, ignore_errors=True)


def assert_the_refused_members_were_skipped_and_named(
    artifact: PersistedArtifact, planted: dict[bytes, str], artifacts: ArtifactSet
) -> None:
    """Every member `runtime.restore` would refuse is absent from the archive, and recorded.

    The *naming* is asserted only where the traversal reached the member: a truncated collection
    stops at the member the deadline expired on, and a skip it never got to is an omission it never
    made. The absence from the archive is asserted either way, because that is the half that would
    cost the whole restore.
    """
    skipped = {os.fsencode(member.path): member.reason for member in artifact.skipped}
    names = {os.fsencode(name) for name in member_names(artifact)}
    for relative, reason in planted.items():
        if not artifacts.truncate:
            assert skipped.get(relative) == reason, (
                f"{relative!r} was not skipped and named: {artifact.skipped}"
            )
        assert relative not in names, (
            f"{relative!r} is in the archive, which would cost the whole restore"
        )


def assert_the_status_member_states_the_outcome(
    artifact: PersistedArtifact, artifacts: ArtifactSet
) -> None:
    """The reserved member is present either way, and says which case this is."""
    status = read_status(artifact)
    assert status["complete"] is (not artifacts.truncate)
    assert status["memberCount"] == len(artifact.members)
    assert status["deadlineMs"] == artifacts.deadline_ms
    assert status["configuredPaths"] == list(artifacts.paths)
    assert status["skipped"] == [
        {"path": member.path, "reason": member.reason} for member in artifact.skipped
    ]
    if artifacts.truncate:
        assert "truncatedAt" in status
    else:
        assert "truncatedAt" not in status


def assert_the_restored_tree_reproduces_the_source(
    source: Tree, restored: Tree, artifacts: ArtifactSet, artifact: PersistedArtifact
) -> None:
    """The comparison: only the configured paths, byte for byte, and never a prefix."""
    expected_files = {
        relative: value
        for relative, value in source.files.items()
        if artifacts.selects(relative) and relative != STATUS_MEMBER
    }
    # Directories are compared with their modes, exactly as files are. They were compared by name
    # alone until `runtime.restore._open_directory` stopped applying `_IMPLICIT_DIRECTORY_MODE` to a
    # directory the archive had already described, which made a directory's restored mode depend on
    # whether any member happened to follow it; the module docstring records the defect and the fix.
    # This is the assertion that would catch it coming back, and it is the design's byte-for-byte
    # claim in full rather than the weaker half of it.
    expected_directories = {
        relative: mode
        for relative, mode in source.directories.items()
        if artifacts.selects(relative)
    }
    restored_files = {
        relative: value
        for relative, value in restored.files.items()
        if relative != STATUS_MEMBER
    }

    assert STATUS_MEMBER in restored.files, "the status member did not survive the trip"
    assert restored.others == set(), (
        f"the restore produced something that is not a file or a directory: "
        f"{restored.others}"
    )
    # What the write side recorded is what came back, which is the other half of the marker being
    # trustworthy: `members` is what an operator reading the artifact index is told is in there.
    assert restored.members - {STATUS_MEMBER} == {
        os.fsencode(name) for name in artifact.members
    }

    if not artifacts.truncate:
        assert restored_files == expected_files
        assert restored.directories == expected_directories
        return

    # A truncated archive drops whole members rather than writing one short, so what came back is
    # a subset of the source and every element of it is the whole file.
    assert set(restored_files) <= set(expected_files), (
        f"the restore produced paths the source did not hold: "
        f"{set(restored_files) - set(expected_files)}"
    )
    # Modes included even here: truncation loses whole members, so a directory that *did* survive
    # survived as its own member and came back with the archive's mode.
    assert restored.directories.items() <= expected_directories.items(), (
        f"a restored directory disagrees with its source: "
        f"{restored.directories.items() - expected_directories.items()}"
    )
    for relative, value in restored_files.items():
        assert value == expected_files[relative], (
            f"{relative!r} came back as {len(value[0])} bytes of the source's "
            f"{len(expected_files[relative][0])}"
        )


def _obstructed(failure: RestoreFailureCase) -> set[bytes]:
    """What the destination root holds after a failure: the obstruction, and nothing else.

    Every failure case here carries at most one bad member, so a restore that failed should have
    written nothing at all — which is the archive-escape guard stated positively.
    """
    return set() if failure.obstruction is None else {failure.obstruction[1]}


def assert_a_failed_restoration_names_its_cause(
    workspace: Workspace, failure: RestoreFailureCase
) -> None:
    """R13.7: a non-200, a `FAILED` phase, and a reason that identifies *this* cause."""
    holder = workspace.fresh("failure")
    root = holder / "root"
    try:
        if failure.obstruction is not None:
            kind, name = failure.obstruction
            if kind == "file":
                _write_file(os.fsencode(root) + b"/" + name, b"in the way", 0o600)
            else:
                os.mkdir(os.fsencode(root) + b"/" + name, 0o755)

        objects = (
            {} if failure.stored is None else {failure.reference: failure.stored}
        )
        store = FakeStateStore(objects=objects, read_failure=failure.read_failure)
        session = sandbox(root, store)

        restore: dict[str, object] = {"reference": failure.reference}
        if failure.size_bytes is not None:
            restore["sizeBytes"] = failure.size_bytes
        if failure.sha256 is not None:
            restore["sha256"] = failure.sha256
        response = session.client.post(f"{HOOK_PATH_PREFIX}/run", content=run_payload(restore=restore))

        assert response.status_code != HTTPStatus.OK
        reason = response.text
        assert reason.startswith(RESTORE_FAILURE_PREFIX), reason
        assert f"[{failure.cause}]" in reason, (
            f"a {failure.cause} failure reported {reason}"
        )
        assert failure.reference in reason
        if failure.detail is not None:
            assert failure.detail in reason, (
                f"the reason does not name what failed: {reason}"
            )
        assert session.gate.phase is RuntimePhase.FAILED

        # The reason is recorded rather than only returned: a request arriving afterwards is told
        # what happened, which is what the Control_Plane records against the Session.
        refused = session.client.post(PROTOCOL_PATH, content=b"\x00")
        assert refused.status_code == HTTPStatus.GONE
        assert RESTORE_FAILURE_PREFIX in refused.text

        if failure.escape_probe is not None:
            escaped = os.fsencode(holder) + b"/" + failure.escape_probe
            assert not os.path.lexists(escaped), (
                f"a refused member wrote {escaped!r} outside the root"
            )
        assert os.listdir(holder) == ["root"], (
            "a failed restoration wrote something beside the configured root"
        )
        assert read_tree(os.fsencode(root)).members == _obstructed(failure), (
            "a failed restoration left content behind in the root"
        )
    finally:
        shutil.rmtree(holder, ignore_errors=True)


# Feature: aws-serverless-agent-sandbox, Property 7: For all configured artifact sets,
# terminating a Session and then creating a Session with a reference to the persisted state
# reproduces the artifact tree byte-for-byte; and for all restoration failure modes, the `/run`
# hook returns a non-200 response and the recorded Session lifecycle state is `FAILED` with a
# reason identifying the restoration failure.
@given(artifacts=artifact_set(), failure=restore_failure())
@settings(max_examples=MINIMUM_EXAMPLES)
def test_artifacts_round_trip_and_a_failed_restoration_identifies_its_cause(
    workspace: Workspace, artifacts: ArtifactSet, failure: RestoreFailureCase
) -> None:
    assert_the_artifact_set_round_trips(workspace, artifacts)
    assert_a_failed_restoration_names_its_cause(workspace, failure)


# --- The oracles, checked once and drawing nothing ---------------------------------------------


#: One case per failure-mode builder, with fixed arguments. The same builders the strategy draws
#: from, so the coverage claim below is about what the property actually reaches.
def every_failure_mode() -> tuple[RestoreFailureCase, ...]:
    return (
        absent_reference("1/state.tar"),
        foreign_reference("1/state.tar"),
        transport_failure("1/state.tar"),
        truncated_transfer("1/state.tar", b"a", 7),
        digest_mismatch("1/state.tar", b"a"),
        *(
            unreadable_archive("1/state.tar", kind, b"not deflate")
            for kind in _UNREADABLE_ARCHIVES
        ),
        *(
            refused_member("1/state.tar", kind, b"member.bin")
            for kind in _REFUSED_MEMBERS
        ),
        *(write_failed("1/state.tar", kind) for kind in _OBSTRUCTIONS),
    )


def test_every_restoration_failure_cause_is_reached_by_a_drawn_mode() -> None:
    """Not a property and it draws nothing: what makes the failure half non-vacuous.

    `RestoreCause` is closed, and a property asserting "the reported cause is the right one" says
    nothing about a cause no example can produce. So the modes the strategy draws from are
    enumerated here and their causes are compared against the whole set: a cause added to
    `runtime.restore` without a mode to reach it fails this test rather than quietly narrowing the
    property.
    """
    reached = {case.cause for case in every_failure_mode()}

    assert reached == set(RestoreCause), (
        f"causes no drawn failure mode reaches: {set(RestoreCause) - reached}"
    )


def test_each_failure_mode_is_distinguishable_from_the_others(
    workspace: Workspace,
) -> None:
    """Every mode reports its own cause, and no two modes report the same detail by accident.

    The property samples this domain; this is the per-mode evidence that each one is reachable and
    that its `detail` is present in the reason it produces. Without it a mode that had stopped
    failing — a stored object that is accidentally valid, an obstruction that is not in the way —
    would be invisible, because the property would simply draw a different mode next time.
    """
    for case in every_failure_mode():
        assert_a_failed_restoration_names_its_cause(workspace, case)


#: Names the substitution oracle puts through `usable_name`, fixed so it draws nothing. Each is a
#: name `path_component()` can draw, and each is awkward in a different way. Which of them a given
#: filesystem holds is exactly what is not assumed.
_AWKWARD_NAMES: Final = (
    b"ordinary.bin",
    b"\xd7\x88",
    b"\xff",
    b"na\xffme.bin",
    b"\xed\xa0\x80",
    b"\xc0\xaf",
    b"\xe2\x82",
)


def test_a_usable_name_is_always_one_this_filesystem_will_hold(
    workspace: Workspace,
) -> None:
    """The one weakening in the module, asserted directly rather than only through its consumer.

    `b"\\xd7\\x88"` is in the list because it is the name a predicate over bytes gets wrong: U+05C8
    is valid UTF-8 and APFS refuses it anyway. On a filesystem that holds every one of these the
    test still says something — that none of them was substituted needlessly.
    """
    answers: dict[bytes, bytes] = {}
    for drawn in _AWKWARD_NAMES:
        substitute = os.fsencode(drawn.hex())
        assert _filesystem_holds(workspace.probe, substitute), (
            f"the substitute {substitute!r} is itself a name this filesystem refuses"
        )

        name = usable_name(workspace, drawn)

        assert name in (drawn, substitute), f"usable_name invented {name!r}"
        assert _filesystem_holds(workspace.probe, name)
        assert (name == drawn) == _filesystem_holds(workspace.probe, drawn), (
            f"{drawn!r} was substituted although it is representable, or the other way about"
        )
        answers[drawn] = name

    assert len(set(answers.values())) == len(answers), "usable_name is not injective"
    assert os.listdir(workspace.probe) == [], "a probe was left behind"


@pytest.mark.skipif(
    not _POSIX, reason="symlinks, FIFOs and sockets need a POSIX filesystem"
)
def test_every_plantable_kind_is_something_the_archive_could_not_have_carried(
    workspace: Workspace,
) -> None:
    """The skip is about something real: each planted kind is neither a file nor a directory.

    Which is what makes "skipped and named" the right outcome rather than a lossy one — and it is
    why a hardlink is not among them. A hardlink to a regular file *is* a regular file, so planting
    one would assert nothing; the `LNKTYPE` member refusal is reached from the archive side, in
    `_REFUSED_MEMBERS`.
    """
    holder = workspace.fresh("plantable")
    root = os.fsencode(holder / "root")
    try:
        os.mkdir(root + b"/" + SELECTED, 0o755)
        kinds = tuple(
            kind
            for kind in sorted(_PLANTABLE)
            if kind != "socket" or workspace.sockets_bindable
        )
        planted = plant_refused_members(
            root,
            ArtifactSet(
                inside=(),
                outside=(),
                refused_kinds=kinds,
                select_paths=False,
                compress=False,
                truncate=False,
            ),
            workspace,
        )

        assert set(planted) == {
            SELECTED + b"/" + f"refused-{kind}".encode("ascii") for kind in kinds
        }
        for relative in planted:
            mode = os.lstat(root + b"/" + relative).st_mode
            assert not stat.S_ISREG(mode) and not stat.S_ISDIR(mode), (
                f"{relative!r} was planted as something the archive would have carried"
            )
        assert read_tree(root).others == set(planted)
    finally:
        shutil.rmtree(holder, ignore_errors=True)
