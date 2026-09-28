"""The runtime side of the duration-ceiling handoff: `session.quiesce` (R10.11).

Deterministic throughout, and example-based: what the orchestrator's one message does to the
readiness gate, what it answers, and the one ordering that matters — that it does not wait for a
drain it is itself counted in. The two transports and the reply-count mapping are
`test_runtime_streaming`'s; here the operation is the real one.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from http import HTTPStatus

from starlette.testclient import TestClient

from protocol.codec.messages import encode
from protocol.codec.values import Message, Value
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.continuation import (
    SESSION_QUIESCE,
    SessionQuiesce,
    register_continuation_operations,
)
from runtime.hooks import QUIESCE_SEQUENCE, HookStep, drain_ordering_violations
from runtime.operations import OperationRegistry
from runtime.readiness import (
    DRAINED_CLASSES,
    AdmissionClass,
    ReadinessGate,
    RuntimePhase,
)

CATALOGUE = load_catalogue()

#: A second inbound type, so a test can put a request in flight that is not the quiesce itself.
#: Declared both ways and carries no field, which is all these tests need of it.
OTHER = "pty.close"

#: A bound on every wait here. The suite fails a hang rather than hanging.
_WAIT_SECONDS = 10.0


def run[T](coroutine: Coroutine[object, object, T]) -> T:
    """Drive one coroutine to completion on its own loop. See `test_runtime_readiness.run`."""
    return asyncio.run(coroutine)


class RecordingActions:
    """The four hook bodies, recording which of them ran.

    `quiesce_and_flush` is here for one assertion: `session.quiesce` is not `/suspend`, and the
    R7.9 flush belongs to the hook rather than to the message.
    """

    def __init__(self) -> None:
        self.called: list[str] = []

    async def apply_configuration(self, payload: bytes) -> None:
        self.called.append("apply_configuration")

    async def quiesce_and_flush(self) -> None:
        self.called.append("quiesce_and_flush")

    async def refresh_egress_identity(self) -> None:
        self.called.append("refresh_egress_identity")

    async def persist_artifacts(self) -> None:
        self.called.append("persist_artifacts")


def wire(t: str, body: dict[Value, Value] | None = None) -> bytes:
    """One encoded request frame."""
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: b"one",
            ENVELOPE_KEY_BODY: body or {},
        },
        catalogue=CATALOGUE,
    )


def started() -> tuple[TestClient, ReadinessGate, RecordingActions]:
    """An application with the continuation operation wired in and `/run` already completed."""
    gate = ReadinessGate()
    operations = OperationRegistry(catalogue=CATALOGUE)
    register_continuation_operations(operations, gate=gate)
    actions = RecordingActions()
    client = TestClient(
        create_app(
            actions=actions, operations=operations, gate=gate, catalogue=CATALOGUE
        )
    )
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config").status_code == HTTPStatus.OK
    return client, gate, actions


# --- The message reaches an operation, and stops new work ----------------------------------


def test_session_quiesce_is_routed_rather_than_falling_through_to_501() -> None:
    """The gap this closes: the catalogue declared it and nothing served it."""
    operations = OperationRegistry(catalogue=CATALOGUE)
    assert SESSION_QUIESCE in set(operations.unrouted_inbound())

    register_continuation_operations(operations, gate=ReadinessGate())
    assert operations.routed() == {SESSION_QUIESCE}
    assert SESSION_QUIESCE not in set(operations.unrouted_inbound())
    # In the drained class, which is what `runtime.readiness`'s admission table declares for it.
    assert operations.admission_class_for(SESSION_QUIESCE) is AdmissionClass.IN_FLIGHT


def test_a_quiesce_frame_is_acknowledged_and_stops_new_work() -> None:
    """The design's sequence: quiesce, then a request at the ceiling is refused cleanly."""
    client, gate, actions = started()

    response = client.post(PROTOCOL_PATH, content=wire(SESSION_QUIESCE))
    assert response.status_code == HTTPStatus.NO_CONTENT
    assert response.content == b""
    assert gate.phase is RuntimePhase.SUSPENDED

    refused = client.post(PROTOCOL_PATH, content=wire(OTHER))
    # 503 and not 410: the Session is coming back at the next generation, so time is the
    # recovery rather than re-resolving a Sandbox that is still there.
    assert refused.status_code == HTTPStatus.SERVICE_UNAVAILABLE

    # Not the `/suspend` hook. Nothing was flushed, because the archive is `/terminate`'s.
    assert actions.called == ["apply_configuration"]


def test_a_repeated_quiesce_meets_the_gate_it_already_closed() -> None:
    """Redelivery is refused at admission rather than served, and changes nothing.

    The gate no longer admits any protocol request, this message included, so the second
    delivery is `503` and not `204`. That is the consequence of quiesce being an ordinary
    admitted request, and it is a truthful answer to the ask: the Sandbox is not accepting new
    work. The orchestrator seam reports a failed quiesce rather than raising one, so a redelivery
    reading as unacknowledged does not abandon the handoff.
    """
    client, gate, _actions = started()

    assert (
        client.post(PROTOCOL_PATH, content=wire(SESSION_QUIESCE)).status_code
        == HTTPStatus.NO_CONTENT
    )
    again = client.post(PROTOCOL_PATH, content=wire(SESSION_QUIESCE))
    assert again.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert gate.phase is RuntimePhase.SUSPENDED


def test_terminate_still_runs_after_a_quiesce() -> None:
    """The handoff's next step. A quiesced gate is closed, not terminal."""
    client, gate, actions = started()
    assert (
        client.post(PROTOCOL_PATH, content=wire(SESSION_QUIESCE)).status_code
        == HTTPStatus.NO_CONTENT
    )

    assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.TERMINATED
    assert "persist_artifacts" in actions.called


# --- The drain ordering --------------------------------------------------------------------


def test_quiesce_does_not_wait_for_the_drain_it_is_counted_in() -> None:
    """The deadlock this avoids: the message holds an in-flight admission of its own.

    A second request is held open for the whole scenario, so a quiesce that awaited
    `DRAINED_CLASSES` would not return even without counting itself.
    """

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()
        operation = SessionQuiesce(gate=gate)

        held = asyncio.Event()
        async with gate.admit() as other:
            assert other.admission_class is AdmissionClass.IN_FLIGHT
            assert gate.in_flight == 1

            async def quiesce() -> None:
                async for _reply in operation.quiesce(wire_request()):
                    pass  # pragma: no cover - this operation yields nothing
                held.set()

            async with asyncio.timeout(_WAIT_SECONDS):
                await asyncio.create_task(quiesce())
            assert held.is_set()

        assert gate.phase is RuntimePhase.SUSPENDED
        # The other request was neither waited for nor cut short.
        assert gate.in_flight == 0

    run(scenario())


def test_the_quiesce_sequence_refuses_a_close_step_that_awaits_the_drained_class() -> (
    None
):
    """The emptiness of the first step's `awaits` is checked, not merely commented."""
    assert drain_ordering_violations(QUIESCE_SEQUENCE) == ()

    close, acknowledge = QUIESCE_SEQUENCE
    widened = (HookStep(close.name, awaits=DRAINED_CLASSES), acknowledge)
    violations = drain_ordering_violations(widened)
    assert len(violations) == 1
    assert acknowledge.name in violations[0]


def wire_request() -> Message:
    """The decoded `session.quiesce` request. Empty body, so there is nothing to compose."""
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: SESSION_QUIESCE,
        ENVELOPE_KEY_ID: b"one",
        ENVELOPE_KEY_BODY: {},
    }
