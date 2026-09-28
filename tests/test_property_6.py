# kiro-classification: public
"""Property 6: suspend and resume preserve filesystem and memory state (R7.9, R13.2).

The design's statement has three conjuncts and they are asserted over one drawn example each
time: a filesystem tree written before the suspension comes back byte-for-byte, a byte sequence
held only in the memory of a running process comes back unchanged, and every write issued before
the suspension is readable after the resumption. `test_runtime_lifecycle_hooks.py` holds the
deterministic examples underneath the first and third — one file, one background handle, one
outbound holder — and what is generalised here is the *domain*: several files at several depths,
contents that are not valid UTF-8, a real background process, a real pseudo-terminal, and more
than one cycle.

## What "memory state" means here, and what it cannot mean

R13.2 says a suspended Sandbox retains its filesystem *and memory* state and restores both on
resume. The memory half of that sentence is, in the deployed system, a MicroVM snapshot: the
provider stops the virtual CPUs, writes the guest's pages to snapshot storage, and restores them.
**No in-process test can assert that.** There is no MicroVM here, nothing is paged out, and a test
that claimed to have verified a snapshot would be verifying that the machine it ran on has memory.

What the *runtime* is responsible for is the complement: not destroying the state it holds, so
that there is something for the provider to snapshot. That is a real and falsifiable obligation,
and it is what the 8.8 report identifies as the substantive difference between `/suspend` and
`/terminate` — `/suspend` flushes and closes connections and ends nothing, because R10.5's
auto-resume can be triggered by a request arriving at the endpoint and a `/suspend` that killed
the agent's long-running build would make auto-resume a promise about a Sandbox that had been
quietly emptied. So the memory half is reached as three things a `/suspend` must leave alone:

1. A background process started before the suspension is **still the same process** after the
   resumption — the handle still resolves, `proc.status` still reports `running`, and the process
   identifier it reports for itself afterwards is the one `proc.start` reported before.
2. That process's **own memory contents survive**: the drawn byte sequence is embedded in the
   child's source, held in a local variable, and emitted only when the test triggers it after the
   last resumption. The property asserts the emitted bytes equal the drawn ones, and asserts
   before triggering that the emission path does not exist — so the value provably was not on
   disk at any point during the cycles, which is what stops this being a restatement of the
   filesystem half.
3. An **open pseudo-terminal survives**: the same terminal, the same shell, still echoing after
   the cycle.

Stated plainly: this establishes that the runtime preserves process and terminal state across
`/suspend` and `/resume`. It does not establish that a provider's snapshot restores guest memory,
and nothing here should be read as if it did.

## The pseudo-terminal is driven over the transport, which it once could not be

This module was first written with the terminal opened on the `TerminalManager` directly, on the
application's own event loop through the test client's portal, because a `pty.open` served through
the protocol handler held one *in-flight* readiness admission for as long as the terminal was open
and `ReadinessGate.suspend` waited for the in-flight count to reach zero. A `/suspend` issued while
a protocol-driven terminal was open therefore did not return until the peer hung up, and
`/terminate` did not return at all, because the shutdown that closes terminals ran behind its own
wait. The workaround removed the transport's admission and nothing else.

The gate now carries two admission classes and the drain covers one of them: an admission enters
the in-flight class and is reclassified to long-lived once the decoded route says it is one, which
`pty.open` is. So the workaround is gone and the terminal here is opened over the WebSocket
transport, admission included. That is the stronger arrangement rather than merely a tidier one:
the conjunct is now asserted against the path a caller actually takes, and the fact that a
suspension proceeds with a terminal open is the same fact R13.2 and R10.5 rely on — the terminal's
descriptors and shell state are memory, memory survives suspension, and the caller's next keystroke
is a request arriving at a suspended Session.

`tests/test_runtime_admission_classes.py` is where the two hooks are asserted to *return* with a
transport terminal open, bounded so a regression fails rather than hangs. What this module adds on
top of that is the terminal surviving the cycle byte-exactly, which is Property 6's own conjunct.

## Non-vacuity

Four things make the conjuncts able to fail rather than merely able to pass:

- The in-flight request. Each cycle opens a WebSocket, starts a streamed command that announces
  itself, writes a file and only then exits, and issues `/suspend` while that command is still
  running. `gate.in_flight` is asserted to be 1 immediately before the hook and 0 at the moment
  the flush begins, and the file the command wrote during the drain is asserted readable after the
  resumption. Without it, "the flush happens after in-flight requests drain" would be true of a
  runtime that never drained anything, because nothing would ever have been in flight.
- The ordering probes. A `ConfinedRoot` whose `root` property records what was true when
  `runtime.quiesce` read it observes the instant *before* the flush; an `OutboundConnections`
  holder observes the instant *after* it. Both attempt a real protocol request and both must be
  refused `503`, which is what "no protocol request is served between the gate closing and the
  flush completing" reduces to at two points inside the window.
- The absence assertion on the memory value's emission path, described above.
- `test_every_named_adversarial_class_survives_a_suspend_and_resume`, which carries each byte
  class the design names through a cycle by name rather than by sampling.

## Budget

100 examples, the design's floor. Each one spawns three real children — the background process,
the terminal's shell, and the in-flight command — opens one pseudo-terminal, writes and reads a
drawn tree twice over, and calls `os.sync` once per cycle. The two costs that dominate are the
per-cycle 0.12-second window during which the in-flight command is deliberately still running, and
`os.sync` at roughly 40 milliseconds a call; everything else is microseconds. One application, one
event loop and one confined root are built once for the module, with each example working inside
its own subdirectory and deleting it afterwards, so the root does not accumulate dirty pages that
a later example's flush would pay for. Every wait is bounded, because the suite fails a hang. The
whole module runs in about 45 seconds, against the suite's 300-second ceiling.

## POSIX only

`runtime.terminal` imports `pty`, `termios` and `fcntl`, so the terminal conjunct cannot be
asserted where those do not exist and the module is skipped there rather than failing — the same
module-level `importorskip` before the import that `test_runtime_terminal.py` and
`test_property_5.py` use.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import Final, cast

import pytest

pytest.importorskip(
    "termios", reason="a pseudo-terminal needs the POSIX termios module"
)

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from starlette.testclient import TestClient, WebSocketTestSession

from protocol.codec.messages import decode, encode
from protocol.codec.values import Message, Value
from protocol.generators import (
    ADVERSARIAL_BYTE_CLASSES,
    output_bytes,
    path_component,
)
from protocol.generators.byte_domains import RESERVED_PATH_COMPONENTS
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.egress_identity import EgressIdentity, EgressIdentityManager
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
)
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.process import (
    EXEC_CHUNK,
    EXEC_REQUEST,
    PROC_HANDLE,
    PROC_START,
    PROC_STATUS,
    ProcessManager,
    register_process_operations,
)
from runtime.protocol_handler import ERROR_DECODE, SandboxProtocolHandler
from runtime.quiesce import QuiesceReport
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.terminal import (
    PTY_DATA,
    PTY_OPEN,
    TerminalManager,
    register_terminal_operations,
)
from tests.harness import MINIMUM_EXAMPLES

CATALOGUE = load_catalogue()

#: The interpreter running the suite, as a byte string, because `argv` is byte-typed.
PYTHON: Final = os.fsencode(sys.executable)

#: A bound on every wait in the module. Present so a regression is a failure and not a hang.
_WAIT_SECONDS: Final = 30.0

#: How often the two polling waits look again. Short enough that the wait is not itself the cost.
_POLL_SECONDS: Final = 0.005

#: How long the in-flight command stays running after it has announced itself. The `/suspend`
#: that must drain it is issued inside this window from the test thread, so it has to be long
#: enough that a thread hand-off cannot outrun it and short enough to pay for 100 examples: at
#: two cycles an example this is the largest single line in the module's runtime.
_IN_FLIGHT_SECONDS: Final = 0.12

#: What the in-flight command writes to its standard output before it starts waiting. Read by the
#: test as the signal that the stream has been admitted, which is what makes `in_flight == 1`
#: an observation rather than a race.
_ANNOUNCE: Final = b"GO"

#: Ceilings on the two drawn byte sequences. File contents are the axis this property is about
#: and get the larger one; the memory value is carried in the child's argument vector, which the
#: kernel bounds, and its `repr` is about four bytes of ASCII per byte of value.
_MAX_CONTENT: Final = 8192
_MAX_MEMORY_BYTES: Final = 2048

#: Ceilings on the drawn tree. Small on purpose: what the property needs is *several* files at
#: *several* depths, and a wider tree would buy no new failure mode for a linear cost.
_MAX_TREE_FILES: Final = 4
_MAX_TREE_DEPTH: Final = 3
_MAX_NAME_BYTES: Final = 24

#: How many suspend and resume cycles one example performs. More than one because a lifecycle
#: hook may be delivered twice: the gate absorbs the repeated transition, and the flush and the
#: outbound close happen again.
_MAX_CYCLES: Final = 2

#: A hang guard on the WebSocket frame loop, not an assertion.
_FRAME_BUDGET: Final = 10_000

#: An obviously-fake certificate. `/resume` refreshes the Family B identity and the runtime never
#: parses what comes back, so a plausible-looking one would invite a reader to think it did.
_CERTIFICATE: Final = b"not-a-real-certificate"
_NOT_AFTER: Final = 4_102_444_800

#: Where an example's drawn tree lives, and where its control files live. Two subdirectories
#: rather than one, so every directory inside the drawn tree contains only drawn content and the
#: listing conjunct can be an exact set comparison rather than a containment.
_TREE: Final = b"tree"
_CONTROL: Final = b"control"

#: The child that holds the drawn byte sequence in memory and emits it when triggered.
#:
#: Every path is a byte string and every write is `os.write`, for the same reasons as the rest of
#: the runtime: a filesystem name is bytes, and a buffered stream would emit when it felt like it
#: rather than when the program says. The value is written to a partial name and renamed, so the
#: emission path either does not exist or holds the whole value — which is what lets the property
#: assert the value's absence before the trigger without racing the child, and what makes the
#: assertion meaningful for a drawn value that happens to be empty.
_MEMORY_PROGRAM: Final = """
import os, time
held = {held!r}
deadline = time.monotonic() + {budget!r}
while time.monotonic() < deadline:
    if os.path.exists({trigger!r}):
        fd = os.open({pid!r}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        fd = os.open({partial!r}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        written = 0
        while written < len(held):
            written += os.write(fd, held[written:])
        os.close(fd)
        os.rename({partial!r}, {value!r})
        break
    time.sleep({poll!r})
"""

#: The command that is still running when `/suspend` arrives. It announces itself, waits, writes
#: its file and exits, so the write it issues lands *during* the gate's drain — which is the one
#: arrangement in which "the flush happens after in-flight requests drain" can be observed by
#: reading the file back afterwards.
_IN_FLIGHT_PROGRAM: Final = """
import os, time
os.write(1, {announce!r})
time.sleep({seconds!r})
fd = os.open({path!r}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
data = {data!r}
written = 0
while written < len(data):
    written += os.write(fd, data[written:])
os.close(fd)
"""

#: A program that echoes its terminal verbatim, once it has put the terminal into raw mode.
#: `tty.setraw` is what makes the echo a claim about bytes rather than a test of `termios`
#: defaults: it clears `ICRNL`, `IXON`, `ISIG`, `IEXTEN`, `ISTRIP` and `OPOST`, so a `\r`, a
#: `0x03` and a `0x11` are data. The echo is the program's own `os.write`, because `ECHO` is off.
_PTY_READY: Final = b"READY"
_PTY_ECHO_PROGRAM: Final = f"""
import os, tty
tty.setraw(0)
os.write(1, {_PTY_READY!r})
while True:
    data = os.read(0, 65536)
    if not data:
        break
    os.write(1, data)
"""


# --- The drawn domains ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DrawnTree:
    """A directory chain and the files hung off it, before any name has met a filesystem.

    `directories` is a chain rather than a set of siblings because depth is what the property
    needs — a preservation claim that only ever saw files in one directory would pass against a
    runtime that lost everything below the first level. `files` places each file at a drawn depth
    along that chain, so a single example covers the root of the tree and its interior.
    """

    directories: tuple[bytes, ...]
    files: tuple[tuple[int, bytes, bytes], ...]


@st.composite
def file_tree(draw: st.DrawFn) -> DrawnTree:
    """Directory structures with names from `path_component()` and contents from `output_bytes()`.

    Defined here rather than in `protocol/generators/`, which is where the design's Testing
    Strategy names it, for one reason: Properties 7 and 8 also draw from `file_tree()`, they are
    other tasks, and a generator promoted by whichever of the three lands first is a generator
    two later tasks inherit without having agreed to its shape. It belongs beside them once all
    three exist.
    """
    directories = draw(
        st.lists(
            path_component(max_size=_MAX_NAME_BYTES),
            max_size=_MAX_TREE_DEPTH,
        )
    )
    files = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=len(directories)),
                path_component(max_size=_MAX_NAME_BYTES),
                output_bytes(max_size=_MAX_CONTENT),
            ),
            min_size=1,
            max_size=_MAX_TREE_FILES,
        )
    )
    return DrawnTree(directories=tuple(directories), files=tuple(files))


def memory_value() -> SearchStrategy[bytes]:
    """A byte sequence the test holds in a background process and never writes to disk.

    The same adversarial domain as process output, bounded by what an argument vector will carry:
    the value reaches the child as part of its `-c` source, and `repr` of a byte string is ASCII
    whatever the bytes are, so a value that is not valid UTF-8 crosses `execve` intact.
    """
    return output_bytes(max_size=_MAX_MEMORY_BYTES)


# --- The instruments that observe R7.9's ordering from inside the hook -----------------------


@dataclass(frozen=True, slots=True)
class Observation:
    """What was true at one instant inside a `/suspend`, from inside the hook."""

    phase: RuntimePhase
    in_flight: int
    refused: int


@dataclass(slots=True)
class Instruments:
    """The two probe points inside one quiesce, and what they need to probe with.

    `handler` and `loop` are filled in after the application is built, because the handler is the
    application's and the loop is the test client's. Until then the probes record nothing, which
    is what keeps the module importable and the fixture buildable in one pass.
    """

    gate: ReadinessGate
    handler: SandboxProtocolHandler | None = None
    loop: asyncio.AbstractEventLoop | None = None
    at_flush: list[Observation] = field(default_factory=list)
    at_close: list[Observation] = field(default_factory=list)

    def arm(self) -> None:
        """Forget the previous suspension's observations, so each cycle is judged on its own."""
        self.at_flush.clear()
        self.at_close.clear()

    @property
    def ready(self) -> bool:
        return self.handler is not None and self.loop is not None

    async def probe(self) -> Observation:
        """Read the gate, then attempt a real protocol request against it, on the loop.

        The phase and the in-flight count are read *before* the attempt, because an attempt that
        were admitted would itself be in flight and would report the count it had just changed.
        """
        assert self.handler is not None
        phase, in_flight = self.gate.phase, self.gate.in_flight
        reply = await self.handler.handle(_PROBE_WIRE)
        return Observation(phase=phase, in_flight=in_flight, refused=reply.status)

    def probe_from_thread(self) -> Observation:
        """The same probe, from the worker thread `runtime.quiesce` runs its flush on."""
        assert self.loop is not None
        return asyncio.run_coroutine_threadsafe(self.probe(), self.loop).result(
            timeout=_WAIT_SECONDS
        )


class ObservingRoot(ConfinedRoot):
    """A confined root that records what was true when the quiesce read it.

    `runtime.quiesce` reads `root` once, to open the directory it `fsync`s, and that read is the
    first thing the flush does — so overriding this property is a probe positioned at the instant
    *before* the flush and after the gate has closed and drained, which is the ordering R7.9
    fixes. Nothing else reads it: `runtime.filesystem` walks from the private attribute this
    class inherits, so the instrumentation cannot reach the operations the property is asserting
    about.
    """

    def __init__(
        self, path: bytes | str | os.PathLike[str], instruments: Instruments
    ) -> None:
        super().__init__(path)
        self._instruments = instruments

    @property
    def root(self) -> bytes:
        if self._instruments.ready:
            self._instruments.at_flush.append(self._instruments.probe_from_thread())
        return super().root


class ObservingOutbound:
    """An `OutboundConnections` holder that records what was true when its close ran.

    The closes happen after the flush, so this is the probe at the other end of the window. It
    also counts, because a hook delivered twice must flush and close again rather than be
    absorbed, and the count is what says so.
    """

    def __init__(self, instruments: Instruments) -> None:
        self._instruments = instruments
        self.closes = 0

    async def close_outbound(self) -> None:
        self.closes += 1
        if self._instruments.ready:
            self._instruments.at_close.append(await self._instruments.probe())


class RecordingSource:
    """The Family B signing exchange, recording the key it was handed instead of signing with it.

    `/resume` refreshes the egress identity before it reopens the gate (R7.10), and a runtime with
    nothing to refresh refuses to resume at all — so a property about resumption needs one of
    these. No key material here is real and the offline suite has no signing endpoint to reach.
    """

    def __init__(self) -> None:
        self.keys: list[bytes] = []

    async def refresh(self, private_key: bytes) -> EgressIdentity:
        self.keys.append(private_key)
        return EgressIdentity(
            certificate=_CERTIFICATE + b"-" + str(len(self.keys)).encode("ascii"),
            not_after_epoch_seconds=_NOT_AFTER,
        )


# --- The application under test, built once for the module ----------------------------------


@dataclass(slots=True)
class Runtime:
    """One started Sandbox_Runtime and everything an example needs to look inside it."""

    client: TestClient
    gate: ReadinessGate
    lifecycle: SandboxLifecycle
    instruments: Instruments
    outbound: ObservingOutbound
    processes: ProcessManager
    terminals: TerminalManager
    root: Path
    served: int = 0

    def next_example(self) -> bytes:
        """A fresh subdirectory name, so no two examples can see each other's filesystem."""
        self.served += 1
        return b"ex-" + str(self.served).encode("ascii")


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Runtime]:
    """A started runtime with the filesystem, process and terminal operations wired in.

    Module-scoped, as Property 5's is and for the same reasons: the application holds no state an
    example can observe, and three real children an example already pays for are enough without
    also rebuilding an event loop each time. What is per-example — the working subdirectory, the
    background handle, the terminal, the correlation identifiers — is fresh every time, so a
    shrunk counterexample is reproducible rather than contaminated by its predecessors.

    One entered client is one event loop, which is what a background process and a pseudo-terminal
    both need: the task that reaps a child belongs to the loop that started it.
    """
    root = tmp_path_factory.mktemp("property-6-root")
    gate = ReadinessGate()
    instruments = Instruments(gate=gate)
    confined = ObservingRoot(root, instruments)
    outbound = ObservingOutbound(instruments)

    operations = OperationRegistry(catalogue=CATALOGUE)
    processes = register_process_operations(
        operations, manager=ProcessManager(catalogue=CATALOGUE)
    )
    FilesystemOperations(confined, catalogue=CATALOGUE).register(operations)
    # Registered, not merely constructed: the terminal conjunct is driven over the transport now,
    # so `pty.open` has to be a routed type rather than a manager the test calls directly.
    terminals = register_terminal_operations(
        operations,
        manager=TerminalManager(
            catalogue=CATALOGUE,
            command=(PYTHON, b"-u", b"-c", _PTY_ECHO_PROGRAM.encode("utf-8")),
        ),
    )

    lifecycle = SandboxLifecycle(
        filesystem_root=confined,
        egress_identity=EgressIdentityManager(RecordingSource()),
        outbound=(outbound,),
        running_work=(processes,),
    )
    app = create_app(
        actions=lifecycle, operations=operations, gate=gate, catalogue=CATALOGUE
    )
    client = TestClient(app)
    client.__enter__()

    instruments.handler = cast("SandboxProtocolHandler", app.state.handler)
    instruments.loop = _loop_of(client)

    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK
    yield Runtime(
        client=client,
        gate=gate,
        lifecycle=lifecycle,
        instruments=instruments,
        outbound=outbound,
        processes=processes,
        terminals=terminals,
        root=root,
    )
    # `/terminate` ends the background processes; the terminals are closed by each example, and
    # the assertion below is what says so rather than leaving a shell behind for the next module.
    assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK
    assert processes.handles == frozenset()
    assert terminals.sessions == frozenset()
    client.__exit__(None, None, None)


def _loop_of(client: TestClient) -> asyncio.AbstractEventLoop:
    """The event loop the entered client serves every request on."""

    async def running() -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()

    portal = client.portal
    assert portal is not None, "the test client has to be entered before it has a loop"
    return cast("asyncio.AbstractEventLoop", portal.call(running))


# --- Messages -------------------------------------------------------------------------------


def body_for(t: str, **fields: object) -> dict[Value, Value]:
    """A body keyed by the catalogue's field numbers, built from field names."""
    message = CATALOGUE.messages[t]
    return {
        message.field_by_name(name).key: cast("Value", value)
        for name, value in fields.items()
    }


def envelope(t: str, body: dict[Value, Value], correlation: bytes) -> Message:
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: correlation,
        ENVELOPE_KEY_BODY: body,
    }


def wire(t: str, body: dict[Value, Value], correlation: bytes) -> bytes:
    return encode(envelope(t, body, correlation), catalogue=CATALOGUE)


#: The request the two ordering probes attempt. A real inbound message that a serving gate would
#: answer, so a `503` is the gate refusing rather than the message being unroutable.
_PROBE_WIRE: Final = wire(FS_LIST, body_for(FS_LIST, path=b"."), b"ordering-probe")

#: The correlation identifier every unary request in this module carries. Fixed, unlike the
#: terminals': `pty.open` keys a terminal by it and two terminals must not collide, but nothing in
#: the filesystem or process operations reads it, so a fresh one per request would be noise.
_UNARY_CORRELATION: Final = b"unary"


def type_of(message: Message) -> str:
    t = message[ENVELOPE_KEY_TYPE]
    assert isinstance(t, str)
    return t


def fields_of(message: Message) -> dict[str, Value]:
    """A message's body, keyed by the field names of its own type."""
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    return {
        field_.name: body[field_.key]
        for field_ in CATALOGUE.messages[type_of(message)].body
        if field_.key in body
    }


def bytes_field(fields: dict[str, Value], name: str) -> bytes:
    value = fields[name]
    assert isinstance(value, bytes), f"{name} came back as {type(value).__name__}"
    return value


def int_field(fields: dict[str, Value], name: str) -> int:
    value = fields[name]
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def unary(sandbox: Runtime, t: str, body: dict[Value, Value]) -> Message:
    """One request over `POST /protocol`, decoded. Answers the reply whatever its type."""
    response = sandbox.client.post(
        PROTOCOL_PATH, content=wire(t, body, _UNARY_CORRELATION)
    )
    assert response.status_code == HTTPStatus.OK, response.text
    return decode(response.content, catalogue=CATALOGUE)


# --- Filesystem names, asked of the filesystem rather than predicted ------------------------

#: The probe's flags. `O_EXCL` so it can never truncate a file that is already there, which is
#: also what makes `FileExistsError` an answer of *yes*; `O_NOFOLLOW` and `O_CLOEXEC` for the same
#: reasons `runtime.filesystem` uses them on the write this stands in for.
_PROBE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
)


def _filesystem_holds(directory: bytes, name: bytes) -> bool:
    """Whether this filesystem will hold `name` directly in `directory`, established by trying it.

    The question is asked of the filesystem rather than predicted from the bytes, and that is a
    platform lesson rather than a preference: a predicate testing `bytes.decode("utf-8")` is wrong
    on APFS, which refuses names that are not valid *assigned* Unicode, so `b"\\xd7\\x88"` — a
    well-formed encoding of the unassigned U+05C8 — is rejected at the system-call boundary
    exactly as `b"\\xff"` is. A predicate can only ever be as complete as its author's reading of
    one platform's rule; an attempt *is* the rule, whatever the platform's rule happens to be.

    The same approach as `usable_name` in `test_property_5.py`, restated here rather than imported
    from it: importing one test module into another couples two properties' fixtures, and the
    shared home for it would be `tests/harness/`, which this task may not modify.
    """
    probe = os.path.join(directory, name)
    try:
        descriptor = os.open(probe, _PROBE_FLAGS, 0o600)
    except FileExistsError:
        # Representable; something already holds it. The caller's `taken` set is what reacts.
        return True
    except OSError:
        return False
    os.close(descriptor)
    os.unlink(probe)
    return True


def _candidates(drawn: bytes) -> Iterator[bytes]:
    """The drawn name, then derived names that are ASCII and therefore holdable anywhere.

    Total: the hex rendering of any byte string is a non-empty ASCII name that is neither `.` nor
    `..`, and the numbered suffixes make the sequence infinite, so the loop in `usable_name`
    always terminates. Injective in the drawn bytes, so two files cannot collide on one name.
    """
    yield drawn
    hexed = os.fsencode(drawn.hex())
    yield hexed
    suffix = 1
    while True:
        yield hexed + b"-" + str(suffix).encode("ascii")
        suffix += 1


def usable_name(directory: bytes, drawn: bytes, taken: set[bytes]) -> bytes:
    """The drawn name, or a derived one where this filesystem or this directory will not take it.

    Only a refusal from the filesystem, or a name already claimed in the same directory,
    substitutes. A name the filesystem accepted and nothing else holds is passed through
    untouched, so an `fs.write` the runtime refuses for a name the filesystem would have held is
    still a failure of the property rather than something this helper absorbs.
    """
    for candidate in _candidates(drawn):
        if candidate in taken:
            continue
        if _filesystem_holds(directory, candidate):
            taken.add(candidate)
            return candidate
    raise AssertionError(  # pragma: no cover - `_candidates` is infinite and ends in ASCII
        f"no usable name for {drawn!r} in {directory!r}"
    )


# --- Materialising a drawn tree -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Materialised:
    """A drawn tree with every name resolved against the real filesystem.

    `files` is keyed by path relative to the confined root, which is what `fs.*` requests carry.
    `entries` is the listing each directory of the tree must report, exactly — the drawn tree gets
    a subdirectory of its own precisely so that this can be an equality.
    """

    files: dict[bytes, bytes]
    entries: dict[bytes, dict[bytes, tuple[str, int]]]


def materialise(root: Path, base: bytes, drawn: DrawnTree) -> Materialised:
    """Create the drawn directory chain under `base` and resolve every file name in it.

    The directories are created directly rather than through the protocol because the catalogue
    declares no `fs.mkdir`: `fs.write` walks to an existing parent and refuses to invent one. That
    is the runtime's surface and not a gap in this test, so the directories are set up out of band
    and every *file* — which is what the property is about — is written through `fs.write`.
    """
    encoded_root = os.fsencode(root)
    chain: list[bytes] = []
    taken: dict[bytes, set[bytes]] = {}
    entries: dict[bytes, dict[bytes, tuple[str, int]]] = {base: {}}

    for drawn_directory in drawn.directories:
        parent_relative = _join(base, chain)
        parent = os.path.join(encoded_root, parent_relative)
        name = usable_name(parent, drawn_directory, taken.setdefault(parent, set()))
        os.mkdir(os.path.join(parent, name))
        # Size zero rather than the directory's own: `assert_tree_is_preserved` compares sizes for
        # files only, because a directory's size is the filesystem's bookkeeping and not content
        # this property has anything to say about.
        entries[parent_relative][name] = ("directory", 0)
        chain.append(name)
        entries[_join(base, chain)] = {}

    files: dict[bytes, bytes] = {}
    for depth, drawn_name, content in drawn.files:
        parent_relative = _join(base, chain[:depth])
        parent = os.path.join(encoded_root, parent_relative)
        name = usable_name(parent, drawn_name, taken.setdefault(parent, set()))
        files[parent_relative + b"/" + name] = content
        entries[parent_relative][name] = ("file", len(content))
    return Materialised(files=files, entries=entries)


def _join(base: bytes, components: list[bytes]) -> bytes:
    return b"/".join([base, *components])


# --- The conjuncts --------------------------------------------------------------------------


def write_tree(sandbox: Runtime, tree: Materialised) -> None:
    """Write every file of the tree through `fs.write`, which is the write R13.2 is about."""
    for path, content in tree.files.items():
        reply = unary(
            sandbox, FS_WRITE, body_for(FS_WRITE, path=path, data=content, mode=0o600)
        )
        assert type_of(reply) == FS_ACK, f"fs.write {path!r} answered {fields_of(reply)}"


def assert_tree_is_preserved(sandbox: Runtime, tree: Materialised) -> None:
    """R13.2's filesystem half: every file byte-identical, and every listing in agreement."""
    for path, content in tree.files.items():
        reply = unary(sandbox, FS_READ, body_for(FS_READ, path=path))
        assert type_of(reply) == FS_CONTENT, (
            f"fs.read {path!r} answered {fields_of(reply)} after a suspend and resume"
        )
        reread = bytes_field(fields_of(reply), "data")
        assert len(reread) == len(content), (
            f"{path!r} read back {len(reread)} bytes, not {len(content)}"
        )
        assert reread == content, f"{path!r} was altered across a suspend and resume"

    for directory, expected in tree.entries.items():
        listed = listing_of(sandbox, directory)
        assert {name: kind for name, (kind, _) in listed.items()} == {
            name: kind for name, (kind, _) in expected.items()
        }, f"the listing of {directory!r} disagrees after a suspend and resume"
        for name, (kind, size) in expected.items():
            if kind == "file":
                assert listed[name] == (kind, size), (
                    f"{name!r} in {directory!r} is listed as {listed[name]}, not "
                    f"{(kind, size)}"
                )


def listing_of(sandbox: Runtime, path: bytes) -> dict[bytes, tuple[str, int]]:
    """One directory as name -> (kind, size), through `fs.list`."""
    reply = unary(sandbox, FS_LIST, body_for(FS_LIST, path=path))
    assert type_of(reply) == FS_LISTING, f"fs.list answered {fields_of(reply)}"
    struct = CATALOGUE.messages[FS_LISTING].field_by_name("entries").spec.items
    assert struct is not None
    keys = {field_.name: field_.key for field_ in struct.fields}
    entries = fields_of(reply)["entries"]
    assert isinstance(entries, list)
    listed: dict[bytes, tuple[str, int]] = {}
    for entry in entries:
        assert isinstance(entry, dict)
        name = entry[keys["name"]]
        kind = entry[keys["kind"]]
        size = entry[keys["size"]]
        assert isinstance(name, bytes) and isinstance(kind, str)
        assert isinstance(size, int)
        listed[name] = (kind, size)
    return listed


def assert_ordering_held(sandbox: Runtime, *, quiesces: int) -> None:
    """R7.9's ordering, from the two probe points inside each quiesce since the last arming.

    `quiesces` is how many `/suspend` hooks have run in this window, and asserting the probe
    counts against it is what says a hook delivered twice flushed and closed twice: the gate
    absorbs the repeated transition, and the durability work does not get absorbed with it.
    """
    instruments = sandbox.instruments
    assert len(instruments.at_flush) == quiesces, (
        f"the quiesce flushed {len(instruments.at_flush)} times, not {quiesces}"
    )
    assert len(instruments.at_close) == quiesces, (
        f"the quiesce closed an outbound holder {len(instruments.at_close)} times, "
        f"not {quiesces}"
    )
    observations = [(observed, "before the flush") for observed in instruments.at_flush]
    observations += [(observed, "after the flush") for observed in instruments.at_close]
    for observed, when in observations:
        assert observed.phase is RuntimePhase.SUSPENDED, (
            f"the gate was {observed.phase} {when}, not suspended"
        )
        assert observed.in_flight == 0, (
            f"{observed.in_flight} protocol requests were still in flight {when}"
        )
        assert observed.refused == HTTPStatus.SERVICE_UNAVAILABLE, (
            f"a protocol request {when} was answered {observed.refused}, not 503"
        )


# --- The background process that holds the drawn value in its memory ------------------------


@dataclass(frozen=True, slots=True)
class HeldMemory:
    """A background process holding a byte sequence, and where it will put it when triggered."""

    handle: bytes
    pid: int
    value: bytes
    value_path: bytes
    pid_path: bytes
    trigger_path: bytes


def start_holder(sandbox: Runtime, control: bytes, value: bytes) -> HeldMemory:
    """Start a background process holding `value` in memory and nowhere else."""
    root = os.fsencode(sandbox.root)
    value_path = control + b"/value"
    pid_path = control + b"/pid"
    trigger_path = control + b"/trigger"
    source = _MEMORY_PROGRAM.format(
        held=value,
        budget=_WAIT_SECONDS,
        trigger=os.path.join(root, trigger_path),
        pid=os.path.join(root, pid_path),
        partial=os.path.join(root, control + b"/value.part"),
        value=os.path.join(root, value_path),
        poll=_POLL_SECONDS,
    )
    reply = unary(
        sandbox,
        PROC_START,
        body_for(
            PROC_START,
            argv=[PYTHON, b"-u", b"-c", source.encode("utf-8")],
            cwd=b"",
            env={},
        ),
    )
    assert type_of(reply) == PROC_HANDLE, f"proc.start answered {fields_of(reply)}"
    fields = fields_of(reply)
    return HeldMemory(
        handle=bytes_field(fields, "handle"),
        pid=int_field(fields, "pid"),
        value=value,
        value_path=value_path,
        pid_path=pid_path,
        trigger_path=trigger_path,
    )


def assert_holder_is_the_same_running_process(
    sandbox: Runtime, held: HeldMemory
) -> None:
    """The process that will emit the value is the one started before the suspension."""
    assert held.handle in sandbox.processes.handles, (
        "the background handle stopped resolving across a suspend and resume"
    )
    reply = unary(
        sandbox, PROC_STATUS, body_for(PROC_STATUS, handle=held.handle, state="running")
    )
    fields = fields_of(reply)
    assert fields["state"] == "running", (
        f"the background process is {fields['state']!r} after a resume, not running"
    )


def assert_the_value_is_not_on_disk(sandbox: Runtime, held: HeldMemory) -> None:
    """The non-vacuity guard for the memory half: nothing has written the value out yet.

    Without this, a child that had emitted the value before the first suspension would satisfy the
    assertion below by way of the filesystem, and the memory half would be a restatement of the
    filesystem half — which is the failure mode the design's note about `memory_value()` names.
    """
    reply = unary(sandbox, FS_READ, body_for(FS_READ, path=held.value_path))
    assert type_of(reply) == ERROR_DECODE, (
        f"{held.value_path!r} exists before the trigger, so the value reached disk "
        f"during the cycles: {fields_of(reply)}"
    )


def assert_the_held_value_survived(sandbox: Runtime, held: HeldMemory) -> None:
    """The memory half: trigger the emission and compare what a live process remembered."""
    written = unary(
        sandbox,
        FS_WRITE,
        body_for(FS_WRITE, path=held.trigger_path, data=b"now", mode=0o600),
    )
    assert type_of(written) == FS_ACK, f"the trigger write answered {fields_of(written)}"

    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        reply = unary(sandbox, FS_READ, body_for(FS_READ, path=held.value_path))
        if type_of(reply) == FS_CONTENT:
            emitted = bytes_field(fields_of(reply), "data")
            assert len(emitted) == len(held.value), (
                f"the held value came back as {len(emitted)} bytes, not "
                f"{len(held.value)}"
            )
            assert emitted == held.value, "the held value was altered across the cycles"
            _assert_the_emitter_was_the_process_that_started(sandbox, held)
            return
        time.sleep(_POLL_SECONDS)
    raise AssertionError(
        "the background process never emitted the value it held in memory"
    )


def _assert_the_emitter_was_the_process_that_started(
    sandbox: Runtime, held: HeldMemory
) -> None:
    """The process that emitted after the resumption is the one `proc.start` reported before.

    The handle would say almost as much — handles are unguessable and never reused — but the
    process identifier is the kernel's own answer to "is this the same process", read out of the
    child by the child, and it is what turns "still running" into "still the same".
    """
    reply = unary(sandbox, FS_READ, body_for(FS_READ, path=held.pid_path))
    assert type_of(reply) == FS_CONTENT, f"fs.read of the pid answered {fields_of(reply)}"
    reported = int(bytes_field(fields_of(reply), "data").decode("ascii"))
    assert reported == held.pid, (
        f"the value was emitted by process {reported}, not by {held.pid}, which is the "
        f"process proc.start reported before the suspension"
    )


# --- The pseudo-terminal, held across the cycles off the readiness gate ---------------------


class HeldTerminal:
    """One open pseudo-terminal, opened and driven over the WebSocket transport.

    Over the transport rather than on the `TerminalManager` directly, which is what this module did
    while a protocol-driven terminal held an in-flight admission; the module docstring records what
    changed. Everything the terminal conjunct is about is on this path — `openpty`, the child, the
    reader callback, the write path — and the readiness admission is on it too, which is the part
    that could not straddle a suspension before.

    Its own connection, separate from the one the in-flight command uses, because the two are
    independent claims: the command's stream has to be drained by the suspension and the terminal's
    has to survive it, and sharing a connection would mean one peer hanging up ended both.
    """

    def __init__(self, sandbox: Runtime, correlation: bytes) -> None:
        self._sandbox = sandbox
        self._correlation = correlation
        self._session = sandbox.client.websocket_connect(PROTOCOL_PATH)
        self._websocket = self._session.__enter__()
        self._websocket.send_bytes(
            wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24), correlation)
        )
        ready = self._read(len(_PTY_READY))
        assert ready == _PTY_READY, (
            f"the terminal's program never became ready: {ready!r}"
        )

    @property
    def is_open(self) -> bool:
        return self._correlation in self._sandbox.terminals.sessions

    def echo(self, payload: bytes) -> bytes:
        """Write `payload` into the terminal and answer what came back."""
        if not payload:
            return b""
        self._websocket.send_bytes(
            wire(PTY_DATA, body_for(PTY_DATA, data=payload), self._correlation)
        )
        return self._read(len(payload))

    def close(self) -> None:
        """End the terminal by hanging up, which is how a caller ends one.

        The transport's own `finally` cancels the frame task, which finalises the `pty.open`
        generator, which kills the shell and closes the descriptor. `is_open` asserted `False`
        afterwards by the fixture's teardown is what says that happened.
        """
        self._session.__exit__(None, None, None)

    def _read(self, count: int) -> bytes:
        """Accumulate terminal output until at least `count` bytes have arrived.

        Accumulated rather than read frame by frame, because a terminal delivers whatever the
        kernel had ready: a read boundary is not a record boundary. `_FRAME_BUDGET` is the guard
        here, as it is for the in-flight command's announcement, and for the same reason: a
        `receive_bytes` that never answers is a frame the runtime never sent.
        """
        accumulated = bytearray()
        for _ in range(_FRAME_BUDGET):
            if len(accumulated) >= count:
                return bytes(accumulated)
            message = decode(self._websocket.receive_bytes(), catalogue=CATALOGUE)
            assert type_of(message) == PTY_DATA, (
                f"the terminal answered {type_of(message)}"
            )
            accumulated += bytes_field(fields_of(message), "data")
        raise AssertionError(  # pragma: no cover - `_FRAME_BUDGET` is a hang guard
            f"the terminal sent fewer than {count} bytes"
        )


# --- The in-flight request that makes the drain observable ----------------------------------


def suspend_with_a_request_in_flight(
    sandbox: Runtime, path: bytes, content: bytes
) -> QuiesceReport:
    """Issue `/suspend` while a streamed command is still running, and answer what it flushed.

    The command announces itself on standard output, waits, writes `content` to `path` and exits.
    Reading the announcement is what makes the stream provably admitted, so `in_flight == 1`
    immediately afterwards is an observation rather than a hope; the wait is what keeps the
    command running while `/suspend` closes the gate, so the drain has something to drain and the
    write it issues lands inside the window the flush must cover.
    """
    source = _IN_FLIGHT_PROGRAM.format(
        announce=_ANNOUNCE,
        seconds=_IN_FLIGHT_SECONDS,
        path=os.path.join(os.fsencode(sandbox.root), path),
        data=content,
    )
    request = wire(
        EXEC_REQUEST,
        body_for(
            EXEC_REQUEST,
            argv=[PYTHON, b"-u", b"-c", source.encode("utf-8")],
            cwd=b"",
            env={},
            timeoutMs=0,
            stream=True,
        ),
        b"in-flight",
    )
    sandbox.instruments.arm()
    with sandbox.client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(request)
        _await_announcement(websocket)
        assert sandbox.gate.in_flight == 1, (
            f"{sandbox.gate.in_flight} requests are in flight, not the one that has "
            f"announced itself and not yet exited"
        )
        response = sandbox.client.post(f"{HOOK_PATH_PREFIX}/suspend")
    assert response.status_code == HTTPStatus.OK, response.text
    assert sandbox.gate.phase is RuntimePhase.SUSPENDED
    report = sandbox.lifecycle.quiesced
    assert report is not None, "/suspend returned 200 having recorded no quiesce"
    return report


def _await_announcement(websocket: WebSocketTestSession) -> None:
    """Read `exec.chunk` frames until the command has said it is running."""
    for _ in range(_FRAME_BUDGET):
        message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert type_of(message) == EXEC_CHUNK, (
            f"the in-flight command answered {type_of(message)} before announcing"
        )
        if _ANNOUNCE in bytes_field(fields_of(message), "data"):
            return
    raise AssertionError(  # pragma: no cover - `_FRAME_BUDGET` is a hang guard
        "the in-flight command never announced itself"
    )


def resume(sandbox: Runtime) -> None:
    assert sandbox.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK
    assert sandbox.gate.phase is RuntimePhase.SERVING


# --- One example -----------------------------------------------------------------------------


def run_cycles(
    sandbox: Runtime,
    *,
    drawn: DrawnTree,
    held_value: bytes,
    during_suspend: bytes,
    keystrokes: bytes,
    cycles: int,
    redelivered: bool,
) -> None:
    """Write the tree, hold a process and a terminal, and cycle the Session `cycles` times."""
    base = sandbox.next_example()
    root = os.fsencode(sandbox.root)
    control = base + b"/" + _CONTROL
    os.makedirs(os.path.join(root, base + b"/" + _TREE))
    os.makedirs(os.path.join(root, control))

    tree = materialise(sandbox.root, base + b"/" + _TREE, drawn)
    write_tree(sandbox, tree)
    held = start_holder(sandbox, control, held_value)
    terminal = HeldTerminal(sandbox, b"pty-" + base)
    try:
        for cycle in range(cycles):
            drained_path = control + b"/in-flight-" + str(cycle).encode("ascii")
            report = suspend_with_a_request_in_flight(
                sandbox, drained_path, during_suspend
            )
            assert report == QuiesceReport(flushed_root=True, synced=True, closed=1)
            assert_ordering_held(sandbox, quiesces=1)
            if redelivered:
                # A lifecycle hook may be delivered more than once. The gate absorbs the
                # repeated transition and stays suspended; the flush and the outbound close
                # happen again, which is what a repeated promise about durability should do.
                redelivery = sandbox.client.post(f"{HOOK_PATH_PREFIX}/suspend")
                assert redelivery.status_code == HTTPStatus.OK, redelivery.text
                assert sandbox.gate.phase is RuntimePhase.SUSPENDED
                assert_ordering_held(sandbox, quiesces=2)
            resume(sandbox)

            assert_tree_is_preserved(sandbox, tree)
            assert_holder_is_the_same_running_process(sandbox, held)
            assert terminal.is_open, "the pseudo-terminal did not survive the cycle"
            echoed = terminal.echo(keystrokes)
            assert echoed == keystrokes, (
                f"the terminal altered its input across the cycle: "
                f"{keystrokes.hex()} became {echoed.hex()}"
            )
            # The write the in-flight command issued during the drain, read back after the
            # resumption: R7.9's "the flush happens after in-flight requests drain", observed
            # through the bytes rather than only through the gate's counter.
            drained = unary(sandbox, FS_READ, body_for(FS_READ, path=drained_path))
            assert type_of(drained) == FS_CONTENT, (
                f"the file the draining request wrote is not readable: "
                f"{fields_of(drained)}"
            )
            assert bytes_field(fields_of(drained), "data") == during_suspend

        assert_the_value_is_not_on_disk(sandbox, held)
        assert_the_held_value_survived(sandbox, held)
    finally:
        try:
            terminal.close()
        finally:
            _restore(sandbox)
            _discard(sandbox, base)


def _restore(sandbox: Runtime) -> None:
    """Leave the gate serving, whatever the example did.

    An example that fails part-way through a cycle leaves the runtime `SUSPENDED`, and every
    example after it would then fail on its first `fs.write` for a reason that has nothing to do
    with what it drew — which would also send the shrinker looking for a smaller version of the
    wrong failure. Restoring the phase is fixture hygiene, not an assertion being softened: the
    cycle's own `resume` above is what the property checks, and it has already either happened or
    not by the time this runs.
    """
    if sandbox.gate.phase is RuntimePhase.SUSPENDED:
        sandbox.client.post(f"{HOOK_PATH_PREFIX}/resume")


def _discard(sandbox: Runtime, base: bytes) -> None:
    """Delete the example's subdirectory, so a later example's flush is not paying for it."""
    unary(sandbox, FS_DELETE, body_for(FS_DELETE, path=base, recursive=True))


# Feature: aws-serverless-agent-sandbox, Property 6: For all filesystem trees written before
# suspension and for all values held only in the memory of a running process, suspending and
# then resuming a Session yields the same tree byte-for-byte and the same in-memory value, and
# every write issued before suspension is readable after resumption.
@given(
    drawn=file_tree(),
    held_value=memory_value(),
    during_suspend=output_bytes(max_size=_MAX_CONTENT),
    keystrokes=output_bytes(max_size=_MAX_MEMORY_BYTES),
    cycles=st.integers(min_value=1, max_value=_MAX_CYCLES),
    redelivered=st.booleans(),
)
@settings(max_examples=MINIMUM_EXAMPLES)
def test_suspend_and_resume_preserve_filesystem_and_memory_state(
    sandbox: Runtime,
    drawn: DrawnTree,
    held_value: bytes,
    during_suspend: bytes,
    keystrokes: bytes,
    cycles: int,
    redelivered: bool,
) -> None:
    run_cycles(
        sandbox,
        drawn=drawn,
        held_value=held_value,
        during_suspend=during_suspend,
        keystrokes=keystrokes,
        cycles=cycles,
        redelivered=redelivered,
    )


# --- The oracles, checked once and drawing nothing ------------------------------------------


def test_every_named_adversarial_class_survives_a_suspend_and_resume(
    sandbox: Runtime,
) -> None:
    """Each byte class the design names, carried through a cycle by name rather than by chance.

    The property above samples the same domain, but a sampler is not a promise that each class was
    reached, and a preservation claim breaks first on content that is not valid UTF-8 — a runtime
    that decoded anywhere on the write or read path would lose exactly these.
    """
    base = sandbox.next_example()
    directory = base + b"/" + _TREE
    os.makedirs(os.path.join(os.fsencode(sandbox.root), directory))
    written = {
        os.fsencode(name).replace(b"-", b"_"): b"".join(sequences)
        for name, sequences in ADVERSARIAL_BYTE_CLASSES.items()
    }
    for name, content in written.items():
        reply = unary(
            sandbox,
            FS_WRITE,
            body_for(
                FS_WRITE, path=directory + b"/" + name, data=content, mode=0o600
            ),
        )
        assert type_of(reply) == FS_ACK

    assert sandbox.client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == HTTPStatus.OK
    resume(sandbox)

    for name, content in written.items():
        reply = unary(
            sandbox, FS_READ, body_for(FS_READ, path=directory + b"/" + name)
        )
        assert type_of(reply) == FS_CONTENT
        assert bytes_field(fields_of(reply), "data") == content, (
            f"{name.decode('ascii')} was altered across a suspend and resume"
        )
    _discard(sandbox, base)


def test_a_usable_name_is_always_one_the_filesystem_will_hold(sandbox: Runtime) -> None:
    """`usable_name` is the only weakening in the module, so what it answers is checked directly.

    `b"\\xd7\\x88"` is in the list because it is the name a "is this valid UTF-8" predicate gets
    wrong: U+05C8 is well-formed UTF-8 and APFS refuses it anyway. On a filesystem that holds
    every one of these the test still says something — that none of them was substituted
    needlessly.
    """
    awkward = (
        b"ordinary.bin",
        b"\xd7\x88",
        b"\xff",
        b"na\xffme.bin",
        b"\xed\xa0\x80",
        b"\xc0\xaf",
        b"\xe2\x82",
    )
    base = sandbox.next_example()
    directory = os.path.join(os.fsencode(sandbox.root), base)
    os.makedirs(directory)
    taken: set[bytes] = set()
    answers: dict[bytes, bytes] = {}
    for drawn in awkward:
        holdable = _filesystem_holds(directory, drawn)
        name = usable_name(directory, drawn, taken)
        assert name not in RESERVED_PATH_COMPONENTS
        assert _filesystem_holds(directory, name), (
            f"usable_name answered {name!r}, which this filesystem will not hold"
        )
        assert (name == drawn) == holdable, (
            f"{drawn!r} was substituted although it is representable, or the reverse"
        )
        answers[drawn] = name

    assert len(set(answers.values())) == len(answers), (
        f"usable_name is not injective over {list(answers)}"
    )
    assert listing_of(sandbox, base) == {}, "a probe was left behind"
    _discard(sandbox, base)


def test_the_memory_program_writes_nothing_until_it_is_triggered() -> None:
    """The other half of the memory conjunct's non-vacuity, asserted without the runtime.

    The property asserts the emission path is absent before the trigger, which is a statement
    about one drawn value at one moment. This is the statement about the program: rendered for a
    value, it contains no write that is not behind the trigger check, so there is no ordering in
    which the value could reach disk earlier.
    """
    rendered = _MEMORY_PROGRAM.format(
        held=b"\xff\x00held",
        budget=1.0,
        trigger=b"/tmp/trigger",
        pid=b"/tmp/pid",
        partial=b"/tmp/value.part",
        value=b"/tmp/value",
        poll=0.001,
    )
    lines = [line for line in rendered.splitlines() if line.strip()]
    guard = next(
        index for index, line in enumerate(lines) if "os.path.exists" in line
    )
    assert all("os.open" not in line for line in lines[:guard])
    assert all("os.rename" not in line for line in lines[:guard])
    # And the value only ever appears as a literal and in the write loop, never in a path.
    assert rendered.count("held = ") == 1
