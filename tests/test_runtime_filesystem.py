# kiro-classification: public
"""The four R7.4 filesystem operations: byte fidelity, and confinement to the configured root.

Every test is deterministic and every path lives under `tmp_path`, so nothing reaches outside the
test's own directory and nothing needs the network. The property that quantifies over paths and
contents is Property 5, which belongs to a later task; these are the specific cases — the byte
sequences a real filesystem returns, and the specific escapes a caller really attempts.

The confinement tests are the reason this file is as long as it is. "Confined to a root" is four
separate claims, not one: a path outside the root, a path that climbs out with `..`, a symlink
planted inside the root, and the root itself. Each is denied by its own test, named after the
shape of the escape, so a regression says which claim stopped holding.
"""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import Coroutine
from pathlib import Path

import pytest

from protocol.codec.messages import decode, encode
from protocol.codec.values import Message
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.bodies import OperationRefusal
from runtime.filesystem import (
    FS_ACK,
    FS_CONTENT,
    FS_DELETE,
    FS_LIST,
    FS_LISTING,
    FS_READ,
    FS_WRITE,
    ConfinedRoot,
    FilesystemOperations,
    PathEscapesRoot,
)
from runtime.operations import OperationRegistry, OperationReply
from runtime.protocol_handler import SandboxProtocolHandler
from runtime.readiness import ReadinessGate

CATALOGUE = load_catalogue()

#: A byte sequence that is not valid UTF-8, used as file content throughout. `\xff` cannot begin
#: a UTF-8 sequence and `\xed\xa0\x80` is an encoded surrogate, so a runtime that decoded content
#: anywhere on the path would either raise or substitute here rather than round-tripping.
INVALID_UTF8 = b"\x00\xff\xfe\xed\xa0\x80binary\n"


def run[T](coroutine: Coroutine[object, object, T]) -> T:
    """Drive one operation to completion on its own loop."""
    return asyncio.run(coroutine)


def files(root: Path) -> FilesystemOperations:
    return FilesystemOperations(root, catalogue=CATALOGUE)


def request(t: str, **fields: object) -> Message:
    """A decoded request for `t`, with its body keyed as the catalogue keys it."""
    message = CATALOGUE.messages[t]
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: b"cid",
        ENVELOPE_KEY_BODY: {
            message.field_by_name(name).key: value  # type: ignore[misc]
            for name, value in fields.items()
        },
    }


def body(reply: OperationReply) -> dict[str, object]:
    """A reply's body, keyed by the catalogue's field names."""
    return {
        field.name: reply.body[field.key]
        for field in CATALOGUE.messages[reply.t].body
        if field.key in reply.body
    }


def entries(reply: OperationReply) -> dict[bytes, tuple[str, int]]:
    """An `fs.listing` reply as name -> (kind, size)."""
    assert reply.t == FS_LISTING
    struct = CATALOGUE.messages[FS_LISTING].field_by_name("entries").spec.items
    assert struct is not None
    keys = {field.name: field.key for field in struct.fields}
    listing = body(reply)["entries"]
    assert isinstance(listing, list)
    out: dict[bytes, tuple[str, int]] = {}
    for entry in listing:
        assert isinstance(entry, dict)
        out[entry[keys["name"]]] = (entry[keys["kind"]], entry[keys["size"]])
    return out


def refusal(reply: OperationReply) -> str:
    """The detail of an `error.decode` reply, having asserted it names the `path` field."""
    assert reply.t == "error.decode"
    fields = body(reply)
    assert fields["field"] == "path"
    detail = fields["detail"]
    assert isinstance(detail, str)
    return detail


# --- Byte fidelity -------------------------------------------------------------------------


def test_a_written_file_reads_back_byte_identically(tmp_path: Path) -> None:
    fs = files(tmp_path)
    written = run(
        fs.write(request(FS_WRITE, path=b"data.bin", data=INVALID_UTF8, mode=0o644))
    )
    assert written.t == FS_ACK

    read = run(fs.read(request(FS_READ, path=b"data.bin")))
    assert read.t == FS_CONTENT
    assert body(read)["data"] == INVALID_UTF8


def test_a_written_file_appears_in_its_listing_with_its_kind_and_size(
    tmp_path: Path,
) -> None:
    fs = files(tmp_path)
    run(fs.write(request(FS_WRITE, path=b"data.bin", data=INVALID_UTF8, mode=0o600)))
    (tmp_path / "sub").mkdir()

    listing = entries(run(fs.list(request(FS_LIST, path=b"."))))
    assert listing[b"data.bin"] == ("file", len(INVALID_UTF8))
    assert listing[b"sub"][0] == "directory"


def test_a_name_that_is_not_valid_utf8_survives_a_listing_and_a_read(
    tmp_path: Path,
) -> None:
    """Why `carries: name` fields are byte-typed, exercised against a real filesystem.

    Skipped where the filesystem itself refuses the name — APFS and HFS+ reject a name that is
    not valid UTF-8 at the system-call boundary, so on macOS there is no such file to list. The
    claim is about the runtime not narrowing what the filesystem allows, and a filesystem that
    allows less has nothing to say about it.
    """
    name = b"na\xffme.bin"
    try:
        (tmp_path / os.fsdecode(name)).write_bytes(INVALID_UTF8)
    except OSError as exc:
        pytest.skip(f"this filesystem refuses names that are not valid UTF-8: {exc}")

    fs = files(tmp_path)
    listing = entries(run(fs.list(request(FS_LIST, path=b"."))))
    # The exact bytes: not a replacement character, and not a surrogate escape leaking out.
    assert name in listing

    read = run(fs.read(request(FS_READ, path=name)))
    assert body(read)["data"] == INVALID_UTF8


def test_write_applies_the_mode_even_when_the_file_already_existed(
    tmp_path: Path,
) -> None:
    target = tmp_path / "script.sh"
    target.write_bytes(b"old")
    target.chmod(0o600)

    run(
        files(tmp_path).write(
            request(FS_WRITE, path=b"script.sh", data=b"new", mode=0o755)
        )
    )

    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert target.read_bytes() == b"new"


# --- Listing kinds -------------------------------------------------------------------------


def test_the_listing_reports_each_of_the_four_declared_kinds(tmp_path: Path) -> None:
    (tmp_path / "a-file").write_bytes(b"x")
    (tmp_path / "a-directory").mkdir()
    (tmp_path / "a-symlink").symlink_to(tmp_path / "a-file")
    os.mkfifo(tmp_path / "a-fifo")

    listing = entries(run(files(tmp_path).list(request(FS_LIST, path=b"."))))
    assert {name: kind for name, (kind, _) in listing.items()} == {
        b"a-file": "file",
        b"a-directory": "directory",
        # Reported rather than hidden, even though it is never traversed.
        b"a-symlink": "symlink",
        b"a-fifo": "other",
    }


# --- Confinement ---------------------------------------------------------------------------


def test_an_absolute_path_outside_the_root_is_refused(tmp_path: Path) -> None:
    reply = run(files(tmp_path).read(request(FS_READ, path=b"/etc/passwd")))
    assert "outside the configured filesystem root" in refusal(reply)


def test_a_path_that_climbs_out_with_dotdot_is_refused(tmp_path: Path) -> None:
    """Both spellings: relative to the root, and absolute through the root."""
    (tmp_path / "outside.txt").write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    fs = files(root)

    relative = run(fs.read(request(FS_READ, path=b"../outside.txt")))
    assert "outside the configured filesystem root" in refusal(relative)

    absolute = run(
        fs.read(request(FS_READ, path=os.fsencode(root) + b"/../outside.txt"))
    )
    assert "outside the configured filesystem root" in refusal(absolute)


def test_dotdot_inside_the_root_is_resolved_rather_than_refused(tmp_path: Path) -> None:
    """Confinement rejects an escape; it does not reject `..` as a character sequence."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "target.txt").write_bytes(b"inside")

    reply = run(files(tmp_path).read(request(FS_READ, path=b"sub/../target.txt")))
    assert body(reply)["data"] == b"inside"


def test_a_symlink_pointing_outside_the_root_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    (root / "escape").symlink_to(outside)
    (root / "direct").symlink_to(outside / "secret.txt")
    fs = files(root)

    through_a_directory = run(fs.read(request(FS_READ, path=b"escape/secret.txt")))
    assert "symlink, which is never followed" in refusal(through_a_directory)

    at_the_leaf = run(fs.read(request(FS_READ, path=b"direct")))
    assert "symlink, which is never followed" in refusal(at_the_leaf)


def test_a_symlink_pointing_inside_the_root_is_also_not_followed(
    tmp_path: Path,
) -> None:
    """The stated decision: the first link is refused, so there is no target to re-check."""
    (tmp_path / "real.txt").write_bytes(b"inside")
    (tmp_path / "alias").symlink_to(tmp_path / "real.txt")

    reply = run(files(tmp_path).read(request(FS_READ, path=b"alias")))
    assert "symlink, which is never followed" in refusal(reply)


def test_a_symlink_is_unlinked_rather_than_followed_by_delete(tmp_path: Path) -> None:
    (tmp_path / "outside.txt").write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path / "outside.txt")

    reply = run(files(root).delete(request(FS_DELETE, path=b"escape", recursive=False)))
    assert reply.t == FS_ACK
    assert not (root / "escape").is_symlink()
    # The link went; the file it named did not.
    assert (tmp_path / "outside.txt").read_bytes() == b"secret"


def test_the_root_itself_is_neither_read_nor_deleted(tmp_path: Path) -> None:
    fs = files(tmp_path)
    read = run(fs.read(request(FS_READ, path=b".")))
    assert "filesystem root" in refusal(read)

    deleted = run(fs.delete(request(FS_DELETE, path=b".", recursive=True)))
    assert "not the runtime's to delete" in refusal(deleted)
    assert tmp_path.is_dir()


def test_a_path_containing_a_nul_byte_is_refused(tmp_path: Path) -> None:
    reply = run(files(tmp_path).read(request(FS_READ, path=b"we\x00ird")))
    assert "NUL byte" in refusal(reply)


# --- Non-regular files, and paths that are not there ---------------------------------------


def test_reading_a_fifo_is_refused_rather_than_blocking(tmp_path: Path) -> None:
    """A FIFO with no writer would block a read forever, so it is refused before the read.

    The assertion that matters is that this test returns at all: `pytest-timeout` fails the
    suite at 300 s, so a runtime that opened the FIFO and waited would not merely be slow here.
    """
    os.mkfifo(tmp_path / "pipe")
    reply = run(files(tmp_path).read(request(FS_READ, path=b"pipe")))
    assert refusal(reply)


def test_reading_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    reply = run(files(tmp_path).read(request(FS_READ, path=b"sub")))
    assert refusal(reply)


def test_reading_an_absent_path_is_refused_naming_the_field(tmp_path: Path) -> None:
    reply = run(files(tmp_path).read(request(FS_READ, path=b"missing.txt")))
    assert "No such file" in refusal(reply)


def test_writing_below_an_absent_directory_is_refused(tmp_path: Path) -> None:
    """`fs.write` writes a file. It does not create the directories above it."""
    reply = run(
        files(tmp_path).write(
            request(FS_WRITE, path=b"absent/file.txt", data=b"x", mode=0o644)
        )
    )
    assert "No such file" in refusal(reply)


# --- Delete --------------------------------------------------------------------------------


def test_delete_removes_a_file_and_the_listing_no_longer_carries_it(
    tmp_path: Path,
) -> None:
    (tmp_path / "gone.txt").write_bytes(b"x")
    fs = files(tmp_path)

    removed = run(fs.delete(request(FS_DELETE, path=b"gone.txt", recursive=False)))
    assert removed.t == FS_ACK
    assert entries(run(fs.list(request(FS_LIST, path=b".")))) == {}


def test_a_non_empty_directory_is_refused_unless_recursive_was_asked_for(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nested").mkdir()
    (tree / "nested" / "leaf.bin").write_bytes(INVALID_UTF8)
    fs = files(tmp_path)

    refused = run(fs.delete(request(FS_DELETE, path=b"tree", recursive=False)))
    assert refusal(refused)
    assert (tree / "nested" / "leaf.bin").exists()

    removed = run(fs.delete(request(FS_DELETE, path=b"tree", recursive=True)))
    assert removed.t == FS_ACK
    assert not tree.exists()


def test_a_recursive_delete_does_not_descend_through_a_symlinked_directory(
    tmp_path: Path,
) -> None:
    """The bug this denies: a link inside the tree turning a delete into a delete elsewhere."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"keep")
    root = tmp_path / "root"
    root.mkdir()
    tree = root / "tree"
    tree.mkdir()
    (tree / "link").symlink_to(outside)

    reply = run(files(root).delete(request(FS_DELETE, path=b"tree", recursive=True)))
    assert reply.t == FS_ACK
    assert not tree.exists()
    assert (outside / "keep.txt").read_bytes() == b"keep"


# --- ConfinedRoot, on its own ---------------------------------------------------------------


def test_the_root_is_resolved_once_and_a_symlink_to_it_is_permitted(
    tmp_path: Path,
) -> None:
    """The root is trusted configuration; a deployment may mount it at a symlinked path."""
    real = tmp_path / "real-root"
    real.mkdir()
    (tmp_path / "link-root").symlink_to(real)

    root = ConfinedRoot(tmp_path / "link-root")
    assert root.root == os.fsencode(real.resolve())
    assert root.components(b"a/b") == (b"a", b"b")


def test_a_root_that_is_not_a_directory_is_refused_at_construction(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "not-a-directory"
    plain.write_bytes(b"x")
    with pytest.raises(NotADirectoryError):
        ConfinedRoot(plain)


def test_components_normalise_before_they_decide(tmp_path: Path) -> None:
    root = ConfinedRoot(tmp_path)
    # The configured root itself, by three relative spellings, is no components at all.
    assert root.components(b"") == ()
    assert root.components(b".") == ()
    assert root.components(b"./") == ()
    # And by its own absolute path, which is what a caller of these operations actually sends.
    assert root.components(os.fsencode(tmp_path)) == ()

    assert root.components(b"./a//b/./c") == (b"a", b"b", b"c")
    assert root.components(b"a/b/../c") == (b"a", b"c")
    assert root.components(os.fsencode(tmp_path) + b"/a/b") == (b"a", b"b")


def test_an_escape_is_a_refusal_and_not_a_clamp(tmp_path: Path) -> None:
    """`/etc/passwd` is refused rather than rewritten to `<root>/etc/passwd`.

    `/` is in this list, and that is the decision worth naming: an absolute path is a path in the
    Sandbox filesystem, not a path relative to the root, which is what makes the design's own
    `sandbox.files.write("/work/main.py")` mean what it looks like. `/` is therefore the
    filesystem root and is outside any configured root that is not itself `/`. A caller reaches
    the configured root by its own absolute path, or relatively as `.`.
    """
    root = ConfinedRoot(tmp_path)
    for escape in (b"../elsewhere", b"/etc/passwd", b"a/../../elsewhere", b"/..", b"/"):
        with pytest.raises(PathEscapesRoot):
            root.components(escape)
    # A refusal, so the operations catch it by one type rather than two.
    assert isinstance(PathEscapesRoot(), OperationRefusal)


def test_a_sibling_directory_sharing_the_roots_prefix_is_not_inside_it(
    tmp_path: Path,
) -> None:
    """The prefix comparison is on components, not characters: `/work2` is not under `/work`."""
    root = tmp_path / "work"
    root.mkdir()
    sibling = tmp_path / "work2"
    sibling.mkdir()
    (sibling / "secret.txt").write_bytes(b"secret")

    with pytest.raises(PathEscapesRoot):
        ConfinedRoot(root).components(os.fsencode(sibling / "secret.txt"))


def test_a_name_round_trips_through_the_conversion_the_listing_relies_on() -> None:
    """The mechanism behind the byte fidelity claim, asserted where every platform can run it.

    `os.scandir` on a directory descriptor has no bytes-returning form, so the listing converts
    with `os.fsencode`. That conversion is exact for arbitrary bytes because CPython decodes
    filesystem names with the `surrogateescape` handler (PEP 383). This is the same assertion the
    skipped test above makes against a real filesystem, minus the filesystem.
    """
    for name in (b"na\xffme.bin", b"\x80\x81\x82", b"\xed\xa0\x80", b"plain.txt"):
        assert os.fsencode(os.fsdecode(name)) == name


# --- Through the protocol handler ------------------------------------------------------------


def test_the_operations_encode_against_the_catalogue_end_to_end(tmp_path: Path) -> None:
    """Every reply body here is built from field names; this is what checks it against the schema.

    The unit tests above read a reply straight off the operation, which never encodes it. A body
    keyed wrongly, or carrying a value outside its field's declared type, would pass all of them
    and fail on the wire. So one test goes through the real handler, which encodes with the real
    codec, and a schema violation becomes a failure here rather than in an integration test.
    """

    async def scenario() -> None:
        gate = ReadinessGate()
        registry = OperationRegistry(catalogue=CATALOGUE)
        files(tmp_path).register(registry)
        handler = SandboxProtocolHandler(
            gate=gate, operations=registry, catalogue=CATALOGUE
        )
        await gate.begin_start()
        await gate.finish_start()

        async def exchange(t: str, **fields: object) -> Message:
            reply = await handler.handle(
                encode(request(t, **fields), catalogue=CATALOGUE)
            )
            assert reply.wire is not None, reply.reason
            return decode(reply.wire, catalogue=CATALOGUE)

        written = await exchange(
            FS_WRITE, path=b"data.bin", data=INVALID_UTF8, mode=0o644
        )
        assert written[ENVELOPE_KEY_TYPE] == FS_ACK

        read = await exchange(FS_READ, path=b"data.bin")
        assert read[ENVELOPE_KEY_TYPE] == FS_CONTENT

        listed = await exchange(FS_LIST, path=b".")
        assert listed[ENVELOPE_KEY_TYPE] == FS_LISTING

        # And a refusal is a real `error.decode` message on the wire, not a 500.
        refused = await exchange(FS_READ, path=b"/etc/passwd")
        assert refused[ENVELOPE_KEY_TYPE] == "error.decode"

        deleted = await exchange(FS_DELETE, path=b"data.bin", recursive=False)
        assert deleted[ENVELOPE_KEY_TYPE] == FS_ACK

    run(scenario())


# --- Registration --------------------------------------------------------------------------


def test_the_four_inbound_filesystem_types_are_routed_and_no_others(
    tmp_path: Path,
) -> None:
    registry = OperationRegistry(catalogue=CATALOGUE)
    files(tmp_path).register(registry)
    assert registry.routed() == {FS_READ, FS_WRITE, FS_LIST, FS_DELETE}
    # The three reply types are outbound, so the registry would refuse them anyway; asserting
    # they are absent records that this module does not try.
    for outbound in (FS_CONTENT, FS_LISTING, FS_ACK):
        assert outbound not in registry.routed()
