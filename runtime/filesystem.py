# kiro-classification: public
"""Filesystem operations, confined to a configured root and honest about byte-typed names.

This is the `Filesystem operations` node of the design's Sandbox_Runtime drawing: the four
operations R7.4 names — read a file, write a file, list a directory, delete a path — wired into
`runtime.operations` against the `fs.*` types the catalogue declares. Two things about it are not
incidental, and both are the reason the task exists rather than being a wrapper over `pathlib`.

## A filename is not text

Every `carries: name` field in the catalogue is a byte string, and that is a statement about
Linux rather than a preference about encodings: a name on a Linux filesystem is a sequence of
bytes with two forbidden values, `/` and NUL, and nothing requires the rest to be valid UTF-8. A
real filesystem hands back names that are not. So nothing here decodes a path in order to work
with it. Paths are `bytes` end to end, `os.stat` and `os.open` are given `bytes`, and the one
place a name arrives as `str` — `os.scandir` on a directory descriptor, which has no bytes form —
is converted back with `os.fsencode`. That round trip is exact and not approximate: CPython
decodes filesystem names with the `surrogateescape` error handler (PEP 383), so a byte that is
not valid UTF-8 is carried as a lone surrogate and `os.fsencode` restores the original byte.

The consequence worth stating: a name that cannot be decoded still lists, still reads and still
deletes, which is what makes the byte typing of `fs.listing`'s `name` field mean something rather
than merely being permissive.

## Confinement is done with descriptors, not with string comparisons

R7.4 confines these operations to a configured root, and the obvious implementation — resolve the
path, compare it against the root, then open it — is wrong in a way that matters here more than
in most programs. Between the comparison and the open, a component of the path can be replaced by
a symlink pointing anywhere, and the open follows it. That window is normally hard to hit; in a
Sandbox it is trivial, because the attacker is a process running on the same filesystem with a
loop and as much time as it likes. A check followed by an open is not a confinement mechanism.

So the decision and the access are the same act:

1. The requested path is normalised **lexically** — `.` and empty components dropped, `..`
   applied by popping, with `/..` staying at `/` as POSIX has it. A path that is not absolute is
   taken as relative to the root; an absolute path is a path in the Sandbox filesystem and must
   land inside the root. Lexical `..` is exactly equivalent to filesystem `..` here *because* of
   step 2, which is the only reason it is sound to do it this way round.
2. The remaining components are walked one at a time with `openat` and `O_NOFOLLOW`, each open
   relative to the descriptor of the directory above it. A symlink anywhere on the path fails the
   open. Nothing is ever re-resolved from a string, so there is no second lookup to race: once a
   descriptor is held it names an inode, and renaming or replacing the path it came from cannot
   change what it refers to.
3. Every operation then acts through that descriptor — `os.stat(..., dir_fd=)`,
   `os.open(..., dir_fd=)`, `os.unlink(..., dir_fd=)` — never through a reassembled path.

**Symlinks are never followed, including ones that point inside the root.** The narrower rule —
follow a symlink and then check where it landed — is the check-then-use pattern again, one level
down, and it also has to answer what happens when a link's target is itself a link, and how many
times. Refusing the first one has no such questions. The cost is real and accepted: a Sandbox
whose image ships `/work/data -> /srv/data` cannot read through that link, and a caller that
wants the target reads the target's own path. Symlinks remain *visible*: `fs.listing` reports
them with kind `symlink` and the catalogue has that value precisely so they can be reported
rather than hidden. Refusing to traverse is not the same as pretending they are absent.

**Non-regular files are refused for read and write.** A FIFO opened for reading blocks until a
writer arrives, and blocking a request forever is a denial of service reachable by any code in
the Sandbox creating one file. `O_NONBLOCK` on the open plus an `fstat` check makes it a refusal.

## What this does and does not protect against

It confines a *well-behaved caller of these operations* to the root: a client speaking the
Sandbox_Protocol cannot read `/etc/shadow`, cannot escape by `..`, and cannot escape by planting
a symlink, whether the plant races the request or precedes it.

It is not a containment boundary for the Sandbox. Code running inside the MicroVM has its own
filesystem access and does not go through this module at all — it opens files directly. The
design says this in terms that leave no room for a different reading: the Sandbox_Runtime is not
a security control, and every guarantee about what a Sandbox cannot do is enforced outside the
MicroVM. So this confinement is defence in depth against a *protocol* caller — including the
Client_SDK of a caller who has the Session credential but should not be reading the image's
system files — and it is worth having for that. It is not what stops the code in the Sandbox from
reading its own root filesystem, and nothing here should be described as if it were.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import stat
from collections.abc import Iterator
from typing import Final

from protocol.codec.values import Message
from protocol.codec.values import Value as ProtocolValue
from protocol.schema import Catalogue, load_catalogue
from runtime.bodies import (
    OperationRefusal,
    as_bool,
    as_bytes,
    as_uint,
    named_body,
    refusal_reply,
    request_fields,
)
from runtime.operations import OperationRegistry, OperationReply

__all__ = [
    "FS_ACK",
    "FS_CONTENT",
    "FS_DELETE",
    "FS_LIST",
    "FS_LISTING",
    "FS_READ",
    "FS_WRITE",
    "ConfinedRoot",
    "FilesystemOperations",
    "PathEscapesRoot",
]

#: The catalogue's filesystem types. The four the runtime receives, and the three it answers with.
FS_READ: Final = "fs.read"
FS_CONTENT: Final = "fs.content"
FS_WRITE: Final = "fs.write"
FS_LIST: Final = "fs.list"
FS_LISTING: Final = "fs.listing"
FS_DELETE: Final = "fs.delete"
FS_ACK: Final = "fs.ack"

#: The field every refusal in this module names, because it is the field every one of these
#: operations is refusing about.
_PATH: Final = "path"

#: Opening a directory to descend through. `O_NOFOLLOW` is the confinement; `O_DIRECTORY` means a
#: non-directory component fails the open rather than being opened and then rejected; `O_CLOEXEC`
#: keeps a descriptor to the inside of the root out of any process the process manager spawns.
_DESCEND_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

#: Opening the root itself, which is trusted configuration rather than caller input, so it may
#: legitimately be reached through a symlink. Everything below it may not.
_ROOT_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC

#: `O_NONBLOCK` so that a FIFO planted at the requested path fails the open or the `fstat` check
#: instead of blocking the request until a peer appears.
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_WRITE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
)

#: One read of a regular file, in chunks, because `os.read` is permitted to return less than it
#: was asked for and a single call is not a read of the file.
_CHUNK: Final = 1 << 20

#: The `kind` values `fs.listing` declares.
_KIND_FILE: Final = "file"
_KIND_DIRECTORY: Final = "directory"
_KIND_SYMLINK: Final = "symlink"
_KIND_OTHER: Final = "other"


class PathEscapesRoot(OperationRefusal):
    """A requested path resolves outside the configured root.

    A distinct type rather than a detail string because it is the one refusal in this module with
    a security meaning, so a test asserts on it by type and a reader greps for it. It is refused
    and never clamped: silently rewriting `/etc/passwd` to `<root>/etc/passwd` would answer a
    request the caller did not make, and answering it successfully would teach them that the path
    they asked for is the path they got.
    """

    def __init__(self) -> None:
        super().__init__(_PATH, "resolves outside the configured filesystem root")


class ConfinedRoot:
    """A configured root, and the resolution of requested paths against it.

    Separate from the operations because it is the whole of the confinement decision and nothing
    else, so it can be asserted on directly rather than through four operations that each happen
    to call it.
    """

    def __init__(self, root: bytes | str | os.PathLike[str]) -> None:
        """Resolve and fix the root.

        The root is resolved once, here, with symlinks followed: it is deployment configuration
        and not caller input, so a deployment that mounts the Sandbox work area at a symlinked
        path is making a legitimate choice. Everything *below* the resolved root is caller input
        and gets no such treatment.
        """
        resolved = os.path.realpath(os.fsencode(root))
        mode = os.stat(resolved).st_mode
        if not stat.S_ISDIR(mode):
            raise NotADirectoryError(
                f"the configured filesystem root {resolved!r} is not a directory"
            )
        self._root = resolved

    @property
    def root(self) -> bytes:
        """The resolved root, as bytes."""
        return self._root

    def components(self, path: bytes) -> tuple[bytes, ...]:
        """The path's components below the root, or `()` for the root itself.

        Raises:
            PathEscapesRoot: the normalised path is not the root and not below it.
            OperationRefusal: the path contains a NUL byte, which no filesystem name may.
        """
        if b"\x00" in path:
            raise OperationRefusal(
                _PATH, "contains a NUL byte, which no name may contain"
            )
        normalised = self._normalise(path)
        if normalised == self._root:
            return ()
        prefix = self._root if self._root.endswith(b"/") else self._root + b"/"
        if not normalised.startswith(prefix):
            raise PathEscapesRoot
        return tuple(normalised[len(prefix) :].split(b"/"))

    def _normalise(self, path: bytes) -> bytes:
        """Collapse `.`, empty components and `..` lexically, against an absolute path."""
        absolute = path if path.startswith(b"/") else self._root + b"/" + path
        parts: list[bytes] = []
        for component in absolute.split(b"/"):
            if component in (b"", b"."):
                continue
            if component == b"..":
                # `/..` is `/`, so popping nothing is correct rather than an error here. A path
                # that climbed out this way no longer starts with the root, and the caller of
                # this method is what refuses it.
                if parts:
                    parts.pop()
                continue
            parts.append(component)
        return b"/" + b"/".join(parts)

    @contextlib.contextmanager
    def walk_to_parent(self, path: bytes) -> Iterator[tuple[int, bytes | None]]:
        """Open the directory holding `path` and yield it with the final component's name.

        The name is None when `path` is the root itself, which has no parent inside the root and
        is therefore the one path an operation has to handle separately rather than uniformly.

        Every descriptor opened on the way down is held until the block exits, which costs one
        descriptor per path component. A path deep enough to exhaust the process's descriptor
        limit fails with that OS error; it does not escape, because the failure is an open that
        did not happen rather than a check that was skipped.
        """
        descriptors = [os.open(self._root, _ROOT_FLAGS)]
        try:
            components = self.components(path)
            for component in components[:-1]:
                descriptors.append(_descend(descriptors[-1], component))
            yield descriptors[-1], components[-1] if components else None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


def _descend(parent: int, component: bytes) -> int:
    """Open one directory component below `parent`, refusing symlinks."""
    try:
        return os.open(component, _DESCEND_FLAGS, dir_fd=parent)
    except OSError as exc:
        raise OperationRefusal(_PATH, _describe(parent, component, exc)) from exc


def _describe(parent: int, component: bytes, exc: OSError) -> str:
    """Explain why an open failed, without letting the explanation become the decision.

    The refusal has already happened — `O_NOFOLLOW` made it, authoritatively, at open time. This
    runs afterwards and only to produce a better sentence than `strerror` alone, which is why a
    stat here is not the check-then-use pattern the module docstring rejects: nothing is opened
    on the strength of what it finds, and if the entry has changed again in the meantime the
    worst outcome is a less apt message.
    """
    with contextlib.suppress(OSError):
        mode = os.stat(component, dir_fd=parent, follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            return "traverses a symlink, which is never followed"
        if not stat.S_ISDIR(mode):
            return "traverses something that is not a directory"
    return os.strerror(exc.errno) if exc.errno is not None else str(exc)


class FilesystemOperations:
    """The four R7.4 operations, bound to one confined root.

    Each operation performs its syscalls on a worker thread. Reading a large file or deleting a
    deep tree is a blocking sequence of syscalls, and the event loop this runs on is also serving
    the streaming operations R7.2 and R7.5 need; a synchronous read here would stall a pseudo-
    terminal's output for as long as it took. The syscalls themselves are unchanged by the move,
    and the confinement is unaffected because the whole walk-and-act sequence happens inside one
    thread and shares no descriptor with anything else.
    """

    def __init__(
        self,
        root: ConfinedRoot | bytes | str | os.PathLike[str],
        *,
        catalogue: Catalogue | None = None,
    ) -> None:
        self._root = root if isinstance(root, ConfinedRoot) else ConfinedRoot(root)
        self._catalogue = catalogue if catalogue is not None else load_catalogue()

    @property
    def confined_root(self) -> ConfinedRoot:
        """The root every operation resolves against."""
        return self._root

    def register(self, registry: OperationRegistry) -> None:
        """Route the four inbound `fs.*` types onto these operations."""
        registry.register(FS_READ, self.read)
        registry.register(FS_WRITE, self.write)
        registry.register(FS_LIST, self.list)
        registry.register(FS_DELETE, self.delete)

    # --- Operations ------------------------------------------------------------------------

    async def read(self, request: Message) -> OperationReply:
        """`fs.read` -> `fs.content`: the file's bytes, verbatim."""
        fields = request_fields(self._catalogue, request)
        path = as_bytes(fields[_PATH], _PATH)
        try:
            data = await asyncio.to_thread(_read_file, self._root, path)
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)
        return OperationReply(
            t=FS_CONTENT, body=named_body(self._catalogue, FS_CONTENT, {"data": data})
        )

    async def write(self, request: Message) -> OperationReply:
        """`fs.write` -> `fs.ack`: replace the file's contents and set its mode."""
        fields = request_fields(self._catalogue, request)
        path = as_bytes(fields[_PATH], _PATH)
        data = as_bytes(fields["data"], "data")
        mode = as_uint(fields["mode"], "mode")
        try:
            await asyncio.to_thread(_write_file, self._root, path, data, mode)
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)
        return OperationReply(t=FS_ACK, body={})

    async def list(self, request: Message) -> OperationReply:
        """`fs.list` -> `fs.listing`: one entry per name, with its kind and size."""
        fields = request_fields(self._catalogue, request)
        path = as_bytes(fields[_PATH], _PATH)
        try:
            entries = await asyncio.to_thread(
                _list_directory, self._root, self._catalogue, path
            )
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)
        return OperationReply(
            t=FS_LISTING,
            body=named_body(self._catalogue, FS_LISTING, {"entries": entries}),
        )

    async def delete(self, request: Message) -> OperationReply:
        """`fs.delete` -> `fs.ack`: remove the path, and its contents when asked to."""
        fields = request_fields(self._catalogue, request)
        path = as_bytes(fields[_PATH], _PATH)
        recursive = as_bool(fields["recursive"], "recursive")
        try:
            await asyncio.to_thread(_delete_path, self._root, path, recursive=recursive)
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)
        return OperationReply(t=FS_ACK, body={})


# --- The syscall sequences, each run on a worker thread ----------------------------------
#
# Module-level rather than methods, because `FilesystemOperations.list` shadows the builtin
# `list` inside the class body and these are the functions that return one. Keeping the
# operation named for the catalogue's `fs.list` is worth more than keeping its helpers nearby.


def _read_file(root: ConfinedRoot, path: bytes) -> bytes:
    with root.walk_to_parent(path) as (parent, name):
        if name is None:
            raise OperationRefusal(
                _PATH, "is the filesystem root, which is a directory"
            )
        descriptor = _open_at(parent, name, _READ_FLAGS)
        try:
            _require_regular_file(descriptor)
            return _read_all(descriptor)
        finally:
            os.close(descriptor)


def _write_file(root: ConfinedRoot, path: bytes, data: bytes, mode: int) -> None:
    with root.walk_to_parent(path) as (parent, name):
        if name is None:
            raise OperationRefusal(
                _PATH, "is the filesystem root, which is a directory"
            )
        descriptor = _open_at(parent, name, _WRITE_FLAGS, mode)
        try:
            _require_regular_file(descriptor)
            # `mode` is applied unconditionally rather than left to the open, because the mode
            # argument to `open` applies only when the file is created and is masked by the
            # process umask. R7.4's write is the same operation whether the file existed or
            # not, so the mode it lands with has to be as well.
            os.fchmod(descriptor, mode)
            _write_all(descriptor, data)
        finally:
            os.close(descriptor)


def _list_directory(
    root: ConfinedRoot, catalogue: Catalogue, path: bytes
) -> list[ProtocolValue]:
    with root.walk_to_parent(path) as (parent, name):
        descriptor = parent if name is None else _descend(parent, name)
        try:
            return _entries(catalogue, descriptor)
        finally:
            if name is not None:
                os.close(descriptor)


def _entries(catalogue: Catalogue, descriptor: int) -> list[ProtocolValue]:
    struct = catalogue.messages[FS_LISTING].field_by_name("entries").spec.items
    if struct is None:  # pragma: no cover - the catalogue declares `entries` as a list
        raise TypeError("fs.listing entries is not a list of structs")
    keys = {field.name: field.key for field in struct.fields}
    listing: list[ProtocolValue] = []
    with os.scandir(descriptor) as scan:
        for entry in scan:
            info = entry.stat(follow_symlinks=False)
            item: dict[ProtocolValue, ProtocolValue] = {
                # `os.fsencode` of a name CPython decoded with `surrogateescape` restores the
                # original bytes, including bytes that are not valid UTF-8. This is the only
                # point in the module where a name is not already bytes, and it is here
                # because a directory descriptor has no bytes-returning scan.
                keys["name"]: os.fsencode(entry.name),
                keys["kind"]: _kind_of(info.st_mode),
                keys["size"]: max(info.st_size, 0),
            }
            listing.append(item)
    return listing


def _delete_path(root: ConfinedRoot, path: bytes, *, recursive: bool) -> None:
    with root.walk_to_parent(path) as (parent, name):
        if name is None:
            raise OperationRefusal(
                _PATH, "is the filesystem root, which is not the runtime's to delete"
            )
        try:
            mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
        except OSError as exc:
            raise OperationRefusal(_PATH, _describe(parent, name, exc)) from exc
        if not stat.S_ISDIR(mode):
            # A symlink is unlinked, not followed: the link goes and its target stays, wherever
            # the target is. That is the only reading consistent with never following one.
            _unlink_at(parent, name)
            return
        if not recursive:
            _rmdir_at(parent, name)
            return
        _delete_tree(parent, name)


def _delete_tree(parent: int, name: bytes) -> None:
    """Remove a directory and everything below it, descending only through real directories."""
    descriptor = _descend(parent, name)
    try:
        with os.scandir(descriptor) as scan:
            children = [
                (os.fsencode(e.name), e.is_dir(follow_symlinks=False)) for e in scan
            ]
        for child, is_directory in children:
            if is_directory:
                _delete_tree(descriptor, child)
            else:
                _unlink_at(descriptor, child)
    finally:
        os.close(descriptor)
    _rmdir_at(parent, name)


def _open_at(parent: int, name: bytes, flags: int, mode: int = 0o600) -> int:
    try:
        return os.open(name, flags, mode, dir_fd=parent)
    except OSError as exc:
        raise OperationRefusal(_PATH, _describe(parent, name, exc)) from exc


def _unlink_at(parent: int, name: bytes) -> None:
    try:
        os.unlink(name, dir_fd=parent)
    except OSError as exc:
        raise OperationRefusal(_PATH, _describe(parent, name, exc)) from exc


def _rmdir_at(parent: int, name: bytes) -> None:
    try:
        os.rmdir(name, dir_fd=parent)
    except OSError as exc:
        detail = os.strerror(exc.errno) if exc.errno is not None else str(exc)
        raise OperationRefusal(_PATH, detail) from exc


def _require_regular_file(descriptor: int) -> None:
    """Refuse anything that is not a regular file, before a byte is read or written."""
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise OperationRefusal(_PATH, "is not a regular file")


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, _CHUNK)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all(descriptor: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        written += os.write(descriptor, data[written:])


def _kind_of(mode: int) -> str:
    """Map a stat mode onto `fs.listing`'s closed `kind` enum."""
    if stat.S_ISLNK(mode):
        return _KIND_SYMLINK
    if stat.S_ISDIR(mode):
        return _KIND_DIRECTORY
    if stat.S_ISREG(mode):
        return _KIND_FILE
    return _KIND_OTHER
