# kiro-classification: public
"""The interactive pseudo-terminal against a real `openpty` and a real child: R7.5.

POSIX only, and skipped rather than failed elsewhere. `pty`, `termios` and `fcntl` are POSIX
modules, so on a platform without them `runtime.terminal` cannot be imported at all — which is
why it is a separate module from `runtime.process`, and why the skip here is a module-level one
placed before the import. CI runs on `ubuntu-24.04` and the MicroVM image is Amazon Linux 2023,
so the tested and the deployed configurations both have all three; the skip exists so a developer
on a platform that does not is told that rather than shown an import error.

Every wait is bounded and every assertion is about bytes that a program in the terminal was asked
to produce, never about timing. The child is `sys.executable` rather than a shell, so nothing here
depends on which shell the machine has or on what it prints at a prompt.
"""

from __future__ import annotations

import os
import sys
from http import HTTPStatus
from typing import cast

import pytest

pytest.importorskip(
    "termios", reason="a pseudo-terminal needs the POSIX termios module"
)

from starlette.testclient import (
    TestClient,
    WebSocketTestSession,
)

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
from runtime.operations import OperationRegistry
from runtime.terminal import (
    PTY_CLOSE,
    PTY_DATA,
    PTY_OPEN,
    PTY_RESIZE,
    TerminalManager,
    register_terminal_operations,
)

CATALOGUE = load_catalogue()

#: A program that behaves like an interactive one: for every line it is given it reports the
#: terminal's window size, which is the only way to observe R7.5's window-size control from
#: outside. Unbuffered, so a report reaches the master as soon as it is written.
_REPORTER = """
import os, sys
for line in sys.stdin:
    size = os.get_terminal_size(0)
    sys.stdout.write(f"<{size.columns}x{size.lines}>")
    sys.stdout.flush()
"""

#: A program that writes bytes no decoder would survive, and no newline, so nothing the terminal
#: line discipline rewrites is in the payload. `ONLCR` turns a newline into carriage return plus
#: newline on the way out, which is a terminal doing its job rather than the runtime decoding.
HOSTILE = b"\xff\xfe\xed\xa0\x80\xc0\x80"
_EMITTER = f"import os\nos.write(1, {HOSTILE!r})\nos.read(0, 1)\n"

#: How many frames a test will read before giving up looking for what it expects. A bound, so a
#: regression fails instead of blocking on `receive_bytes` until the suite's own timeout.
_FRAME_BUDGET = 200


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


def build(source: str) -> tuple[TestClient, TerminalManager]:
    """A started application whose terminals run `sys.executable -u -c source`."""
    operations = OperationRegistry(catalogue=CATALOGUE)
    manager = register_terminal_operations(
        operations,
        manager=TerminalManager(
            catalogue=CATALOGUE,
            command=(os.fsencode(sys.executable), b"-u", b"-c", source.encode("utf-8")),
        ),
    )
    client = TestClient(
        create_app(actions=NoActions(), operations=operations, catalogue=CATALOGUE)
    )
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config").status_code == HTTPStatus.OK
    return client, manager


def body_for(t: str, **fields: object) -> dict[Value, Value]:
    """A body keyed by the catalogue's field numbers. See the same helper in the process tests."""
    message = CATALOGUE.messages[t]
    return {
        message.field_by_name(name).key: cast("Value", value)
        for name, value in fields.items()
    }


def wire(t: str, body: dict[Value, Value], correlation: bytes = b"term") -> bytes:
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: correlation,
            ENVELOPE_KEY_BODY: body,
        },
        catalogue=CATALOGUE,
    )


def data_of(message: Message) -> bytes:
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    data = body[CATALOGUE.messages[PTY_DATA].field_by_name("data").key]
    assert isinstance(data, bytes)
    return data


def read_until(websocket: WebSocketTestSession, marker: bytes) -> bytes:
    """Accumulate terminal output until `marker` appears, within the frame budget.

    A terminal delivers its output in whatever pieces the kernel had ready, so a test cannot ask
    for "the frame containing X" — it accumulates and looks for X in the whole, which is the same
    thing a terminal emulator does.
    """
    accumulated = b""
    for _ in range(_FRAME_BUDGET):
        message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        if message[ENVELOPE_KEY_TYPE] == PTY_CLOSE:
            raise AssertionError(f"the terminal closed before producing {marker!r}")
        accumulated += data_of(message)
        if marker in accumulated:
            return accumulated
    raise AssertionError(f"{marker!r} never appeared in {accumulated!r}")


# --- R7.5: an interactive terminal ---------------------------------------------------------


def test_a_terminal_carries_input_in_and_output_back() -> None:
    client, manager = build(_REPORTER)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=100, rows=40)))
        websocket.send_bytes(wire(PTY_DATA, body_for(PTY_DATA, data=b"\n")))
        assert b"<100x40>" in read_until(websocket, b"<100x40>")
        # Asserted after output has arrived, not after the frame was sent: the registration
        # happens in the application's task, and a check before then would be a race.
        assert manager.sessions == frozenset({b"term"})

        websocket.send_bytes(wire(PTY_CLOSE, {}))
        _drain_to_close(websocket)
    assert manager.sessions == frozenset()


def test_the_window_size_can_be_changed_while_the_terminal_is_open() -> None:
    """R7.5's window-size control, observed where it matters: inside the terminal."""
    client, _ = build(_REPORTER)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24)))
        websocket.send_bytes(wire(PTY_DATA, body_for(PTY_DATA, data=b"\n")))
        read_until(websocket, b"<80x24>")

        websocket.send_bytes(wire(PTY_RESIZE, body_for(PTY_RESIZE, cols=132, rows=50)))
        websocket.send_bytes(wire(PTY_DATA, body_for(PTY_DATA, data=b"\n")))
        read_until(websocket, b"<132x50>")

        websocket.send_bytes(wire(PTY_CLOSE, {}))
        _drain_to_close(websocket)


def test_terminal_output_that_is_not_text_survives_unchanged() -> None:
    """Nothing between `os.read` and `pty.data` decodes: these bytes have no valid reading."""
    client, _ = build(_EMITTER)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24)))
        assert HOSTILE in read_until(websocket, HOSTILE)

        websocket.send_bytes(wire(PTY_CLOSE, {}))
        _drain_to_close(websocket)


def test_a_terminal_whose_program_exits_ends_its_own_stream() -> None:
    """End of file on the master is the end of the stream, and it emits exactly one close."""
    client, manager = build("import os\nos.write(1, b'done')\n")
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24)))
        read_until(websocket, b"done")
        closed = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert closed[ENVELOPE_KEY_TYPE] == PTY_CLOSE
        assert closed[ENVELOPE_KEY_ID] == b"term"
    assert manager.sessions == frozenset()


def test_a_second_terminal_under_one_correlation_identifier_is_refused() -> None:
    client, _ = build(_REPORTER)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24)))
        websocket.send_bytes(wire(PTY_DATA, body_for(PTY_DATA, data=b"\n")))
        read_until(websocket, b"<80x24>")

        websocket.send_bytes(wire(PTY_OPEN, body_for(PTY_OPEN, cols=80, rows=24)))
        refusal = _read_error(websocket)
        assert refusal == "id"

        websocket.send_bytes(wire(PTY_CLOSE, {}))
        _drain_to_close(websocket)


def test_two_terminals_are_told_apart_by_their_correlation_identifier() -> None:
    client, manager = build(_REPORTER)
    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(
            wire(PTY_OPEN, body_for(PTY_OPEN, cols=10, rows=11), correlation=b"a")
        )
        websocket.send_bytes(
            wire(PTY_OPEN, body_for(PTY_OPEN, cols=20, rows=21), correlation=b"b")
        )
        websocket.send_bytes(
            wire(PTY_DATA, body_for(PTY_DATA, data=b"\n"), correlation=b"b")
        )

        # Only the terminal addressed produced output, and it reports its own window size.
        message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert message[ENVELOPE_KEY_ID] == b"b"
        assert manager.sessions == frozenset({b"a", b"b"})

        websocket.send_bytes(wire(PTY_CLOSE, {}, correlation=b"a"))
        websocket.send_bytes(wire(PTY_CLOSE, {}, correlation=b"b"))


def test_input_for_a_terminal_that_is_not_open_names_the_correlation_identifier() -> (
    None
):
    """The envelope's `id` is the terminal's identity here, so it is the field that is wrong."""
    client, _ = build(_REPORTER)
    response = client.post(
        PROTOCOL_PATH, content=wire(PTY_DATA, body_for(PTY_DATA, data=b"x"))
    )
    assert response.status_code == HTTPStatus.OK
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    body = reply[ENVELOPE_KEY_BODY]
    assert isinstance(body, dict)
    field = CATALOGUE.messages["error.decode"].field_by_name("field").key
    assert body[field] == "id"


# --- Helpers -------------------------------------------------------------------------------


def _drain_to_close(websocket: WebSocketTestSession) -> None:
    """Read frames until the terminal's single closing frame arrives, within the budget."""
    for _ in range(_FRAME_BUDGET):
        message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        if message[ENVELOPE_KEY_TYPE] == PTY_CLOSE:
            return
    raise AssertionError("the terminal never closed")


def _read_error(websocket: WebSocketTestSession) -> str:
    """Read frames until an `error.decode` arrives, and return the field it names."""
    for _ in range(_FRAME_BUDGET):
        message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        if message[ENVELOPE_KEY_TYPE] == "error.decode":
            body = message[ENVELOPE_KEY_BODY]
            assert isinstance(body, dict)
            named = body[CATALOGUE.messages["error.decode"].field_by_name("field").key]
            assert isinstance(named, str)
            return named
    raise AssertionError("no error.decode arrived")
