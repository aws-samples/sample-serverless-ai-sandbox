# kiro-classification: public
"""The streaming extension to the operations seam, with stub operations rather than processes.

Task 8.1 left the seam unary and said so: one request, one reply. R7.2 and R7.5 need one request
to produce many frames, and R7.5 needs one to produce none, so the seam grew a second
registration form. These are the tests of that form on its own — what a reply count of zero, one
and many means on each transport, that the unary form is unchanged, and that the WebSocket
transport reads the next frame without waiting for the previous one to finish.

Stub operations throughout, deliberately. The process manager and the pseudo-terminal are tested
against real subprocesses in their own modules; here the operation is a list of replies, so a
failure is a failure of the seam and cannot be a failure of a subprocess.

Deterministic. No generated inputs: the property that quantifies over commands and output byte
sequences is Property 5, which is task 8.4.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from http import HTTPStatus
from pathlib import Path

import pytest
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
from runtime.operations import (
    OperationRegistry,
    OperationReply,
    UnroutableMessageType,
)

CATALOGUE = load_catalogue()

#: Two inbound types with empty bodies, so a test can name an operation without composing a
#: request body for it. `session.quiesce` is orchestrator-to-runtime and `pty.close` is declared
#: both ways; neither carries a field, which is the only property these tests need of them.
QUIESCE = "session.quiesce"
CLOSE = "pty.close"

#: The reply these stubs answer with. `fs.ack` has an empty body, so a reply is a type and
#: nothing else, which keeps the assertions about counts rather than about contents.
ACK = "fs.ack"

#: A bound on every wait in this module. The suite fails a hang rather than hanging, and these
#: waits exist to make an ordering observable, not to measure anything.
_WAIT_SECONDS = 10.0
_POLL_SECONDS = 0.005


class NoActions:
    """The four lifecycle hook bodies, which nothing here exercises."""

    async def apply_configuration(self, payload: bytes) -> None:
        return

    async def quiesce_and_flush(self) -> None:
        return

    async def refresh_egress_identity(self) -> None:
        return

    async def persist_artifacts(self) -> None:
        return


def ack() -> OperationReply:
    """One reply. `fs.ack` carries no field, so a reply is a type and nothing else."""
    return OperationReply(t=ACK, body={})


def wire(
    t: str, body: dict[Value, Value] | None = None, correlation: bytes = b"one"
) -> bytes:
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: correlation,
            ENVELOPE_KEY_BODY: body or {},
        },
        catalogue=CATALOGUE,
    )


def started(operations: OperationRegistry) -> TestClient:
    """An application with `operations` wired in and `/run` already completed."""
    client = TestClient(
        create_app(actions=NoActions(), operations=operations, catalogue=CATALOGUE)
    )
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config").status_code == HTTPStatus.OK
    return client


def replying(count: int) -> OperationRegistry:
    """A registry whose one streaming operation answers with exactly `count` replies."""

    async def operation(request: Message) -> AsyncGenerator[OperationReply]:
        for _ in range(count):
            yield ack()

    operations = OperationRegistry(catalogue=CATALOGUE)
    operations.register_stream(QUIESCE, operation)
    return operations


# --- The reply count, on the request/response transport ------------------------------------


def test_a_streaming_operation_that_answers_once_is_served_like_a_unary_one() -> None:
    """This is what keeps `exec.request` with `stream` false working over `POST /protocol`."""
    response = started(replying(1)).post(PROTOCOL_PATH, content=wire(QUIESCE))
    assert response.status_code == HTTPStatus.OK
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == ACK
    assert reply[ENVELOPE_KEY_ID] == b"one"


def test_a_streaming_operation_that_answers_with_nothing_is_204() -> None:
    """A terminal input frame: the effect happened and there is no message, not a missing one."""
    response = started(replying(0)).post(PROTOCOL_PATH, content=wire(QUIESCE))
    assert response.status_code == HTTPStatus.NO_CONTENT
    assert response.content == b""


def test_a_streaming_operation_that_answers_many_times_asks_for_the_other_transport() -> (
    None
):
    """426, which is none of the statuses the Client_SDK reads as a signal to recover."""
    response = started(replying(3)).post(PROTOCOL_PATH, content=wire(QUIESCE))
    assert response.status_code == HTTPStatus.UPGRADE_REQUIRED
    assert "WebSocket" in response.text


def test_a_streamed_operation_is_abandoned_at_the_second_reply(tmp_path: Path) -> None:
    """The rest of the stream is not run: nothing is produced that nothing can read."""
    produced = tmp_path / "produced"

    async def operation(request: Message) -> AsyncGenerator[OperationReply]:
        yield ack()
        yield ack()
        produced.write_bytes(b"third")
        yield ack()

    operations = OperationRegistry(catalogue=CATALOGUE)
    operations.register_stream(QUIESCE, operation)

    response = started(operations).post(PROTOCOL_PATH, content=wire(QUIESCE))
    assert response.status_code == HTTPStatus.UPGRADE_REQUIRED
    assert not produced.exists()


# --- The unary form, unchanged --------------------------------------------------------------


def test_the_unary_registration_form_still_answers_once() -> None:
    """8.3 is registering unary operations against this seam concurrently; it did not move."""

    async def operation(request: Message) -> OperationReply:
        return ack()

    operations = OperationRegistry(catalogue=CATALOGUE)
    operations.register(QUIESCE, operation)

    response = started(operations).post(PROTOCOL_PATH, content=wire(QUIESCE))
    assert response.status_code == HTTPStatus.OK
    assert decode(response.content, catalogue=CATALOGUE)[ENVELOPE_KEY_TYPE] == ACK


def test_one_type_cannot_be_routed_in_both_forms() -> None:
    """Two registrations means two modules believe they own it, whichever forms they used."""

    async def unary(request: Message) -> OperationReply:
        return ack()

    async def streaming(request: Message) -> AsyncGenerator[OperationReply]:
        yield ack()

    operations = OperationRegistry(catalogue=CATALOGUE)
    operations.register(QUIESCE, unary)
    assert operations.stream_for(QUIESCE) is None
    with pytest.raises(UnroutableMessageType, match="already routed"):
        operations.register_stream(QUIESCE, streaming)
    assert operations.routed() == {QUIESCE}


# --- The WebSocket transport ---------------------------------------------------------------


def test_every_reply_of_a_stream_becomes_one_frame() -> None:
    client = started(replying(4))
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(QUIESCE, correlation=b"many"))
        for _ in range(4):
            reply = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
            assert reply[ENVELOPE_KEY_TYPE] == ACK
            assert reply[ENVELOPE_KEY_ID] == b"many"


def test_a_stream_that_answers_with_nothing_sends_no_frame_and_stays_open() -> None:
    """Silence, not a status: over this transport a zero-reply operation has nothing to say."""
    operations = replying(0)

    async def one(request: Message) -> OperationReply:
        return ack()

    operations.register(CLOSE, one)

    client = started(operations)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(QUIESCE, correlation=b"silent"))
        websocket.send_bytes(wire(CLOSE, correlation=b"audible"))
        reply = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        # The first frame received is the answer to the *second* request sent.
        assert reply[ENVELOPE_KEY_ID] == b"audible"


def test_a_frame_is_read_while_the_previous_one_is_still_streaming(
    tmp_path: Path,
) -> None:
    """R7.5's requirement on the transport: input reaches a terminal that is producing output.

    The slow stream yields once, then blocks until a file appears. A second request is sent and
    answered in the meantime, which could not happen if the reading loop waited for the first
    stream to finish. Both waits are bounded, so a regression is a failure rather than a hang.
    """
    proceed = tmp_path / "proceed"

    async def slow(request: Message) -> AsyncGenerator[OperationReply]:
        yield ack()
        deadline = time.monotonic() + _WAIT_SECONDS
        while not proceed.exists() and time.monotonic() < deadline:
            await asyncio.sleep(_POLL_SECONDS)
        yield ack()

    async def quick(request: Message) -> OperationReply:
        return ack()

    operations = OperationRegistry(catalogue=CATALOGUE)
    operations.register_stream(QUIESCE, slow)
    operations.register(CLOSE, quick)

    client = started(operations)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(QUIESCE, correlation=b"slow"))
        assert (
            decode(websocket.receive_bytes(), catalogue=CATALOGUE)[ENVELOPE_KEY_ID]
            == b"slow"
        )

        websocket.send_bytes(wire(CLOSE, correlation=b"quick"))
        interleaved = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert interleaved[ENVELOPE_KEY_ID] == b"quick"

        proceed.write_bytes(b"go")
        assert (
            decode(websocket.receive_bytes(), catalogue=CATALOGUE)[ENVELOPE_KEY_ID]
            == b"slow"
        )
