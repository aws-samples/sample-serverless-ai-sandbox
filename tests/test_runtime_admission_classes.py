# kiro-classification: public
"""The two admission classes, and the `/suspend` and `/terminate` deadlock they retire.

The defect these tests are about had one shape and two symptoms. `runtime.protocol_handler` holds
one readiness admission for the whole of a stream, so a protocol-driven pseudo-terminal was one
in-flight request from `pty.open` until the peer hung up — potentially hours. `/suspend` closed the
gate and waited for the in-flight count to reach zero, and closes nothing itself, so only the peer
hanging up released it. `/terminate` was worse: its wait sat *in front of* the shutdown that closes
terminals, so it could not be released at all, and it held a billable Sandbox while not being
released.

So the tests here come in three groups, and each group asserts a different half of the fix:

- **The gate.** Two classes, one drained. `admit` reads the phase and nothing else, and an
  admission is reclassified after the route is decoded rather than before it is admitted, because
  an admission decision that consulted the body would have parsed attacker-supplied bytes in a
  phase where nothing has been configured (R7.8).
- **The hooks, over the real transport.** A pseudo-terminal opened over the WebSocket — the path
  the deadlock was on — and then `/suspend`, and then `/terminate`, each of which has to *return*.
  Every wait is bounded and runs the hook on a worker thread, so the old behaviour fails these in
  a second or two instead of hanging until `pyproject.toml`'s 300-second ceiling.
- **The declared ordering.** `runtime.hooks` declares what each step of each hook awaits and
  releases and checks the design's rule over that declaration at import. These assert the checker
  catches the violation rather than trusting that it would, since the check passing on the one
  sequence that exists says nothing about a sequence that does not.

## POSIX only

`runtime.terminal` imports `pty`, `termios` and `fcntl`, so the transport half of this module needs
a platform that has them and is skipped where it does not, the same module-level `importorskip`
before the import that `test_runtime_terminal.py` and `test_property_6.py` use. The gate and the
ordering groups need no terminal, but they are cheap and there is no reason to split the module for
a platform the deployment and CI both are.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
from collections.abc import AsyncGenerator, Iterator
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Final, cast

import pytest

pytest.importorskip(
    "termios", reason="a pseudo-terminal needs the POSIX termios module"
)

from starlette.testclient import TestClient

from protocol.codec.messages import decode, encode
from protocol.codec.values import Message, Value
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.egress_identity import EgressIdentity, EgressIdentityManager
from runtime.filesystem import ConfinedRoot
from runtime.hooks import (
    SUSPEND_SEQUENCE,
    TERMINATE_SEQUENCE,
    DrainOrdering,
    HookStep,
    drain_ordering_violations,
)
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry, OperationReply
from runtime.readiness import (
    DRAINED_CLASSES,
    AdmissionClass,
    ReadinessGate,
    RuntimePhase,
)
from runtime.terminal import (
    PTY_DATA,
    PTY_OPEN,
    TerminalManager,
    register_terminal_operations,
)

CATALOGUE = load_catalogue()

#: The interpreter running the suite, as a byte string, because `argv` is byte-typed.
PYTHON: Final = os.fsencode(sys.executable)

#: A bound on every wait here. Generous enough that a loaded machine does not fail the test, short
#: enough that the old behaviour — an unbounded wait — fails it promptly rather than at the
#: suite's 300-second ceiling.
_WAIT_SECONDS: Final = 20.0

#: A shorter bound for the two hook calls specifically. A hook that has to drain nothing answers in
#: milliseconds, so this is two orders of magnitude of headroom and still 60 times faster to fail
#: than a hang.
_HOOK_SECONDS: Final = 5.0

#: What the terminal's program writes before it starts echoing. Read by the test as the signal that
#: `pty.open` has been admitted, routed and reclassified, which is what makes the class assertions
#: an observation rather than a race with the event loop.
_READY: Final = b"READY"

#: A program that echoes its terminal verbatim and never exits on its own, which is the point: the
#: terminal's end has to be somebody's decision, and in the deployed system it is the caller's.
_ECHO_PROGRAM: Final = f"""
import os, tty
tty.setraw(0)
os.write(1, {_READY!r})
while True:
    data = os.read(0, 65536)
    if not data:
        break
    os.write(1, data)
"""

#: An obviously-fake certificate. `/resume` refreshes the Family B identity and the runtime never
#: parses what comes back, so a plausible-looking one would invite a reader to think it did.
_CERTIFICATE: Final = b"not-a-real-certificate"
_NOT_AFTER: Final = 4_102_444_800

#: A hang guard on the WebSocket frame loop, not an assertion.
_FRAME_BUDGET: Final = 1_000


# --- Messages -------------------------------------------------------------------------------


def body_for(t: str, **fields: object) -> dict[Value, Value]:
    message = CATALOGUE.messages[t]
    return {
        message.field_by_name(name).key: cast("Value", value)
        for name, value in fields.items()
    }


def wire(t: str, body: dict[Value, Value], correlation: bytes) -> bytes:
    envelope: Message = {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: t,
        ENVELOPE_KEY_ID: correlation,
        ENVELOPE_KEY_BODY: body,
    }
    return encode(envelope, catalogue=CATALOGUE)


def type_of(message: Message) -> str:
    t = message[ENVELOPE_KEY_TYPE]
    assert isinstance(t, str)
    return t


def data_of(message: Message) -> bytes:
    key = CATALOGUE.messages[type_of(message)].field_by_name("data").key
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    value = body[key]
    assert isinstance(value, bytes)
    return value


# --- The application under test ---------------------------------------------------------------


class RecordingSource:
    """The Family B signing exchange, recording the key rather than signing with it.

    Present because `/resume` refuses to run without an egress identity manager, and one of the
    tests resumes to show the Session is still usable after the suspension it no longer blocks.
    """

    def __init__(self) -> None:
        self.keys: list[bytes] = []

    async def refresh(self, private_key: bytes) -> EgressIdentity:
        self.keys.append(private_key)
        return EgressIdentity(
            certificate=_CERTIFICATE, not_after_epoch_seconds=_NOT_AFTER
        )


@dataclass(slots=True)
class Runtime:
    """One started Sandbox_Runtime, with the terminal operations wired in over the transport."""

    client: TestClient
    gate: ReadinessGate
    terminals: TerminalManager


@pytest.fixture
def sandbox(tmp_path: Path) -> Iterator[Runtime]:
    """A runtime whose `/terminate` really does end the Session's terminals.

    `running_work` carries the terminal manager, which is what makes the `/terminate` test a test
    of the ordering rule rather than of an empty sequence: the shutdown that closes an open
    pseudo-terminal is a step of the hook, it runs after the drain, and the drain must therefore
    not be waiting for it.

    Function-scoped rather than module-scoped, unlike Property 6's: each test here terminates or
    suspends the runtime it was given, and a shared one would carry a terminal phase into the next.
    """
    gate = ReadinessGate()
    operations = OperationRegistry(catalogue=CATALOGUE)
    terminals = register_terminal_operations(
        operations,
        manager=TerminalManager(
            catalogue=CATALOGUE,
            command=(PYTHON, b"-u", b"-c", _ECHO_PROGRAM.encode("utf-8")),
        ),
    )
    lifecycle = SandboxLifecycle(
        filesystem_root=ConfinedRoot(tmp_path),
        egress_identity=EgressIdentityManager(RecordingSource()),
        running_work=(terminals,),
    )
    app = create_app(
        actions=lifecycle, operations=operations, gate=gate, catalogue=CATALOGUE
    )
    with TestClient(app) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == HTTPStatus.OK
        yield Runtime(client=client, gate=gate, terminals=terminals)


# --- Driving a terminal over the transport, and bounding every wait --------------------------


class TransportTerminal:
    """One pseudo-terminal opened over the WebSocket transport, which is the path that deadlocked.

    Deliberately *not* driven on the `TerminalManager` directly. The manager works either way; the
    admission is the thing under test, and only the transport takes one.
    """

    def __init__(self, sandbox: Runtime, correlation: bytes = b"pty") -> None:
        self._sandbox = sandbox
        self._correlation = correlation
        self._session = sandbox.client.websocket_connect(PROTOCOL_PATH)
        self._websocket = self._session.__enter__()
        self._websocket.send_bytes(
            wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24), correlation)
        )
        assert self._read(len(_READY)) == _READY, "the terminal never became ready"

    @property
    def is_open(self) -> bool:
        return self._correlation in self._sandbox.terminals.sessions

    def echo(self, payload: bytes) -> bytes:
        """Write into the terminal over the transport and answer what came back."""
        self._websocket.send_bytes(
            wire(PTY_DATA, body_for(PTY_DATA, data=payload), self._correlation)
        )
        return self._read(len(payload))

    def hang_up(self) -> None:
        """Close the WebSocket, which is the peer decision the terminal's end depends on."""
        self._session.__exit__(None, None, None)

    def _read(self, count: int) -> bytes:
        accumulated = bytearray()
        for _ in range(_FRAME_BUDGET):
            if len(accumulated) >= count:
                return bytes(accumulated)
            message = decode(self._websocket.receive_bytes(), catalogue=CATALOGUE)
            assert type_of(message) == PTY_DATA, (
                f"the terminal answered {type_of(message)}"
            )
            accumulated += data_of(message)
        raise AssertionError(  # pragma: no cover - `_FRAME_BUDGET` is a hang guard
            f"the terminal sent fewer than {count} bytes"
        )


def hook_answers_within(client: TestClient, path: str, seconds: float) -> int:
    """POST a lifecycle hook and fail if it has not answered inside `seconds`.

    The bound is the whole point of this helper, and so is the worker thread: the hook is called
    off the test thread so that a hook which never returns leaves this function rather than the
    suite, and the assertion names the hang instead of the run dying at the 300-second ceiling. The
    thread is a daemon because a deadlocked hook would otherwise keep the interpreter alive after
    the test that diagnosed it has already failed.
    """
    answered: list[int] = []
    failed: list[BaseException] = []

    def call() -> None:
        try:
            answered.append(client.post(path).status_code)
        except BaseException as exc:  # noqa: BLE001 - carried to the test thread, not swallowed
            failed.append(exc)

    worker = threading.Thread(target=call, name=f"hook{path}", daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), (
        f"POST {path} had not returned after {seconds} seconds, so it is waiting on a drain "
        f"nothing is going to satisfy"
    )
    if failed:
        raise failed[0]
    return answered[0]


# --- The gate: two classes, one drained ------------------------------------------------------


def test_an_admission_starts_in_flight_and_admit_reads_only_the_phase() -> None:
    """R7.8's prohibition is why: an admission decision cannot depend on the request's content."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()
        async with gate.admit() as admission:
            assert admission.admission_class is AdmissionClass.IN_FLIGHT
            assert gate.in_flight == 1
            assert gate.long_lived == 0
        assert gate.in_flight == 0

    asyncio.run(scenario())


def test_reclassifying_moves_an_admission_out_of_the_drained_class() -> None:
    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()
        async with gate.admit() as admission:
            await admission.becomes_long_lived()
            assert admission.admission_class is AdmissionClass.LONG_LIVED
            assert gate.in_flight == 0
            assert gate.long_lived == 1
            # Idempotent: a transport may say the same true thing twice.
            await admission.becomes_long_lived()
            assert gate.long_lived == 1
        assert gate.long_lived == 0

    asyncio.run(scenario())


def test_a_long_lived_admission_does_not_hold_suspend_or_terminate() -> None:
    """The gate-level statement of the defect: the drain covers one class, and this is the other."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()
        async with gate.admit() as admission:
            await admission.becomes_long_lived()
            await asyncio.wait_for(gate.suspend(), timeout=_WAIT_SECONDS)
            assert gate.phase is RuntimePhase.SUSPENDED
            await gate.resume()
            await asyncio.wait_for(gate.terminate(), timeout=_WAIT_SECONDS)
            assert gate.phase is RuntimePhase.TERMINATED
            assert gate.long_lived == 1

    asyncio.run(scenario())


def test_an_in_flight_admission_still_holds_the_drain() -> None:
    """The other side of it. Widening the classes would have made the fix vacuous."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()
        admitted = asyncio.Event()
        release = asyncio.Event()

        async def request() -> None:
            async with gate.admit():
                admitted.set()
                await release.wait()

        task = asyncio.create_task(request())
        await admitted.wait()
        suspend = asyncio.create_task(gate.suspend())
        for _ in range(10):
            await asyncio.sleep(0)
        assert not suspend.done(), (
            "suspend returned while a request was still in flight"
        )
        release.set()
        await asyncio.wait_for(suspend, timeout=_WAIT_SECONDS)
        await task

    asyncio.run(scenario())


def test_the_drained_classes_are_the_in_flight_ones() -> None:
    """Stated as a value so that `runtime.hooks` can check its ordering against it."""
    assert DRAINED_CLASSES == frozenset({AdmissionClass.IN_FLIGHT})
    assert AdmissionClass.LONG_LIVED not in DRAINED_CLASSES


# --- The hooks, over the transport that deadlocked -------------------------------------------


def test_suspend_returns_while_a_transport_pseudo_terminal_is_open(
    sandbox: Runtime,
) -> None:
    """The first symptom, on the path it appeared on. Fails against the old single-class drain.

    Before the fix this `POST /suspend` never returned: `pty.open` held an in-flight admission for
    as long as the terminal was open, and nothing in `/suspend` closes a terminal, so only the peer
    hanging up released it. The bounded wait is what turns that into a failed assertion.
    """
    terminal = TransportTerminal(sandbox)
    try:
        assert sandbox.gate.long_lived == 1, (
            "an open transport terminal is not counted as a long-lived admission"
        )
        assert sandbox.gate.in_flight == 0, (
            "an open transport terminal is still counted against the drain"
        )
        assert (
            hook_answers_within(sandbox.client, f"{HOOK_PATH_PREFIX}/suspend", _HOOK_SECONDS)
            == HTTPStatus.OK
        )
        assert sandbox.gate.phase is RuntimePhase.SUSPENDED
        # R13.2 and R10.5: the suspension ended nothing, so the terminal is still there to be
        # resumed into. This is the reason closing terminals on suspend was not the answer.
        assert terminal.is_open, "the suspension closed the caller's pseudo-terminal"
        assert sandbox.client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK
        assert terminal.echo(b"\x03\r\xffabc") == b"\x03\r\xffabc"
    finally:
        terminal.hang_up()


def test_terminate_returns_while_a_transport_pseudo_terminal_is_open(
    sandbox: Runtime,
) -> None:
    """The second and sharper symptom: the releaser sat behind the wait, so it was a deadlock.

    `/terminate`'s drain runs before the artifact step, and the artifact step is where the terminal
    manager is shut down. With a single-class drain this hook could not complete at all, and it
    held a billable Sandbox while not completing.
    """
    terminal = TransportTerminal(sandbox)
    try:
        assert sandbox.gate.long_lived == 1
        assert (
            hook_answers_within(sandbox.client, f"{HOOK_PATH_PREFIX}/terminate", _HOOK_SECONDS)
            == HTTPStatus.OK
        )
        assert sandbox.gate.phase is RuntimePhase.TERMINATED
        # And the step behind the drain did its work: `/terminate` ends everything.
        assert sandbox.terminals.sessions == frozenset(), (
            "/terminate returned without closing the Session's pseudo-terminals"
        )
    finally:
        terminal.hang_up()


def test_a_streamed_command_still_holds_suspend_until_it_exits(
    sandbox: Runtime, tmp_path: Path
) -> None:
    """The classification is not "streams are exempt": `exec.request` is drained, terminals are not.

    Asserted through the registry rather than by timing a command, because what the drain waits for
    is the declared class and the declaration is the thing that could regress.
    """
    operations = OperationRegistry(catalogue=CATALOGUE)
    register_terminal_operations(
        operations, manager=TerminalManager(catalogue=CATALOGUE)
    )

    async def streamed(request: Message) -> AsyncGenerator[OperationReply]:
        yield OperationReply(t="pty.close", body={})  # pragma: no cover - never entered

    operations.register_stream("session.quiesce", streamed)

    assert operations.admission_class_for(PTY_OPEN) is AdmissionClass.LONG_LIVED
    for ordinary in (PTY_DATA, "pty.resize", "pty.close", "session.quiesce"):
        assert operations.admission_class_for(ordinary) is AdmissionClass.IN_FLIGHT, (
            f"{ordinary} is not counted against the drain"
        )
    # A type nothing routes, and a unary type, are both in-flight: neither can outlast a reply.
    assert operations.admission_class_for("exec.request") is AdmissionClass.IN_FLIGHT


# --- The declared ordering, and the check over it ---------------------------------------------


def test_the_declared_terminate_sequence_satisfies_the_ordering_rule() -> None:
    """What `runtime.hooks` enforces at import, restated where a reader can see it hold."""
    assert drain_ordering_violations(TERMINATE_SEQUENCE) == ()
    assert drain_ordering_violations(SUSPEND_SEQUENCE) == ()
    drain, work = TERMINATE_SEQUENCE
    assert drain.awaits == DRAINED_CLASSES
    assert work.releases == frozenset({AdmissionClass.LONG_LIVED})


def test_a_drain_in_front_of_its_releaser_is_a_violation() -> None:
    """The defect as a declaration: the single-class drain `/terminate` used to perform.

    Without this the checker could be vacuous — passing on the one sequence that exists says
    nothing about the sequence the defect was.
    """
    deadlocking = (
        HookStep(
            "close the handler for good and wait for every admission",
            awaits=frozenset(AdmissionClass),
        ),
        HookStep(
            "end the Session's running work and write the artifacts",
            releases=frozenset({AdmissionClass.LONG_LIVED}),
        ),
    )
    violations = drain_ordering_violations(deadlocking)
    assert len(violations) == 1
    assert "long-lived" in violations[0]
    assert "end the Session's running work" in violations[0]


def test_a_release_before_the_drain_is_not_a_violation() -> None:
    """The rule is about order, not about overlap: a releaser that runs first is the fix."""
    reordered = (
        HookStep(
            "end the Session's running work",
            releases=frozenset({AdmissionClass.LONG_LIVED}),
        ),
        HookStep("wait for every admission", awaits=frozenset(AdmissionClass)),
    )
    assert drain_ordering_violations(reordered) == ()


def test_the_ordering_error_names_the_hook_and_the_violations() -> None:
    """The exception a violating declaration would stop the runtime with."""
    error = DrainOrdering(
        "/terminate", ("the drain awaits what the shutdown releases",)
    )
    assert error.hook == "/terminate"
    assert "the drain awaits what the shutdown releases" in str(error)
