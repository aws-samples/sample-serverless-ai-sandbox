# kiro-classification: public
"""The process manager against real subprocesses: R7.1, R7.2 and R7.3.

Real children, no mocks. A mocked subprocess would assert that this module calls asyncio the way
this module calls asyncio, which is the one thing these requirements do not say. What they say is
about exit codes, output bytes and when a chunk arrives, and only a real process produces those.

Every subprocess is `sys.executable -c ...`. That is deliberate on two counts: the suite denies
outbound network access and these children must not reach for it, and a shell utility would make
the tests depend on which coreutils the machine has rather than on the runtime.

Deterministic throughout, including the streaming test: "before the process exits" is established
by a child that blocks on a file appearing, not by a sleep that might be long enough. Every wait
is bounded, because the suite fails a hang.

The property that quantifies over commands, exit codes and output byte sequences is Property 5,
which is task 8.4. These are the examples and edge cases underneath it.
"""

from __future__ import annotations

import os
import sys
import time
from http import HTTPStatus
from pathlib import Path
from typing import cast

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
from runtime.operations import OperationRegistry
from runtime.process import (
    EXEC_CHUNK,
    EXEC_REQUEST,
    EXEC_RESULT,
    EXIT_CODE_NOT_FOUND,
    PROC_START,
    PROC_STATUS,
    ProcessManager,
    register_process_operations,
)

CATALOGUE = load_catalogue()

#: The interpreter running the suite, as a byte string, because `argv` is byte-typed.
PYTHON = os.fsencode(sys.executable)

#: A bound on every wait here. Present so a regression is a failure rather than a hang.
_WAIT_SECONDS = 20.0
_POLL_SECONDS = 0.01

#: Bytes no decoder would survive: a lone `0xff`, a truncated sequence, the CESU-8 encoding of a
#: lone surrogate, an overlong NUL, and an embedded NUL. Property 3 proves the codec carries
#: these; this module's job is to prove nothing between the pipe and the codec touches them.
HOSTILE = b"\xff\xfe\xed\xa0\x80\xc0\x80\x00tail"


class ShutdownOnTerminate:
    """The four lifecycle hook bodies, with the one that has real work here doing it.

    `persist_artifacts` is where `/terminate` reaches, and shutting the process manager down from
    there is not a testing convenience: background children have to be reaped inside the
    application's own event loop, because that is the loop their reaping tasks are attached to.
    Driving `manager.shutdown()` from a fresh loop instead would fail on exactly that, which is
    also the reason the task that implements these hook bodies will call it from here.
    """

    def __init__(self, manager: ProcessManager) -> None:
        self._manager = manager

    async def apply_configuration(self, payload: bytes) -> None:
        return

    async def quiesce_and_flush(self) -> None:
        return

    async def refresh_egress_identity(self) -> None:
        return

    async def persist_artifacts(self) -> None:
        await self._manager.shutdown()


def build(*, chunk_bytes: int = 65536) -> tuple[TestClient, ProcessManager]:
    """A started application with the process manager wired in."""
    operations = OperationRegistry(catalogue=CATALOGUE)
    manager = register_process_operations(
        operations,
        manager=ProcessManager(catalogue=CATALOGUE, chunk_bytes=chunk_bytes),
    )
    client = TestClient(
        create_app(
            actions=ShutdownOnTerminate(manager),
            operations=operations,
            catalogue=CATALOGUE,
        )
    )
    # Entered here and left in `shut_down`, because a Starlette test client used outside a
    # context manager runs *each* request on a fresh event loop. That is invisible to a stateless
    # operation and fatal to a background process: the task reaping the child is attached to the
    # loop that started it, so the next request would find that loop closed. One entered client
    # is one loop, which is also what the deployed runtime is.
    client.__enter__()
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config").status_code == HTTPStatus.OK
    return client, manager


def body_for(t: str, **fields: object) -> dict[Value, Value]:
    """A body keyed by the catalogue's field numbers, built from field names.

    `object` and one cast, rather than `Value` and a cast at every call site: a list of byte
    strings is a `Value` but `list` is invariant, so `list[bytes]` is not assignable to it.
    """
    message = CATALOGUE.messages[t]
    return {
        message.field_by_name(name).key: cast("Value", value)
        for name, value in fields.items()
    }


def status_query(handle: bytes) -> dict[Value, Value]:
    """A `proc.status` *query*, which has to carry a `state` it does not know.

    `proc.status` is declared `both` in the catalogue and its `state` field is not optional, so
    the same schema describes the question and the answer and a caller cannot ask without
    asserting something. The runtime reads `handle` and ignores the rest, and the value sent here
    is deliberately the wrong one — the process under test has exited — so that a test would fail
    if the runtime ever echoed the query's `state` back instead of reporting the real one.
    """
    return body_for(PROC_STATUS, handle=handle, state="running")


def wire(t: str, body: dict[Value, Value], correlation: bytes = b"cid") -> bytes:
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: correlation,
            ENVELOPE_KEY_BODY: body,
        },
        catalogue=CATALOGUE,
    )


def exec_body(
    *script: bytes,
    cwd: bytes = b"",
    env: dict[Value, Value] | None = None,
    timeout_ms: int = 0,
    stream: bool = False,
) -> dict[Value, Value]:
    return body_for(
        EXEC_REQUEST,
        argv=list(script),
        cwd=cwd,
        env=env or {},
        timeoutMs=timeout_ms,
        stream=stream,
    )


def python_argv(source: str) -> list[bytes]:
    """`sys.executable -c source`, unbuffered so a flush reaches the pipe immediately."""
    return [PYTHON, b"-u", b"-c", source.encode("utf-8")]


def fields_of(message: Message) -> dict[str, Value]:
    t = message[ENVELOPE_KEY_TYPE]
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(t, str)
    assert isinstance(body, dict)
    return {
        field.name: body[field.key]
        for field in CATALOGUE.messages[t].body
        if field.key in body
    }


def run(client: TestClient, t: str, body: dict[Value, Value]) -> dict[str, Value]:
    """One request over `POST /protocol`, decoded to its body fields."""
    response = client.post(PROTOCOL_PATH, content=wire(t, body))
    assert response.status_code == HTTPStatus.OK, response.text
    return fields_of(decode(response.content, catalogue=CATALOGUE))


def shut_down(client: TestClient) -> None:
    """Terminate, which reaps every background child inside the application's own loop."""
    assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK
    client.__exit__(None, None, None)


# --- R7.1: the exit code and both streams --------------------------------------------------


def test_a_command_reports_its_exit_code_and_both_streams() -> None:
    client, _ = build()
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(
            *python_argv(
                "import sys\n"
                "sys.stdout.buffer.write(b'to stdout')\n"
                "sys.stderr.buffer.write(b'to stderr')\n"
                "raise SystemExit(7)\n"
            )
        ),
    )
    assert result == {"exitCode": 7, "stdout": b"to stdout", "stderr": b"to stderr"}
    shut_down(client)


def test_output_that_is_not_text_survives_unchanged() -> None:
    """R8.9's premise: nothing between the pipe and the message body decodes anything."""
    client, _ = build()
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(*python_argv(f"import sys\nsys.stdout.buffer.write({HOSTILE!r})\n")),
    )
    assert result["stdout"] == HOSTILE
    shut_down(client)


def test_a_termination_by_signal_is_reported_as_a_negative_exit_code() -> None:
    client, _ = build()
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(
            *python_argv("import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
        ),
    )
    assert result["exitCode"] == -9
    shut_down(client)


def test_a_command_that_does_not_exist_is_an_ordinary_result_not_a_protocol_error() -> (
    None
):
    """127, as a shell reports it. The catalogue affords no "spawn failed" message type."""
    client, _ = build()
    result = run(client, EXEC_REQUEST, exec_body(b"/nonexistent/definitely-not-here"))
    assert result["exitCode"] == EXIT_CODE_NOT_FOUND
    assert result["stdout"] == b""
    assert result["stderr"] != b""
    shut_down(client)


def test_an_empty_argument_vector_names_nothing_to_run() -> None:
    client, _ = build()
    response = client.post(PROTOCOL_PATH, content=wire(EXEC_REQUEST, exec_body()))
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    assert fields_of(reply)["field"] == "argv"
    shut_down(client)


def test_no_shell_reinterprets_an_argument() -> None:
    """The argument vector is handed to `execvp`, so shell syntax is data and stays data."""
    client, _ = build()
    hostile_argument = b"; rm -rf / && echo pwned > /tmp/x"
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(
            *python_argv("import os, sys\nos.write(1, os.fsencode(sys.argv[1]))\n"),
            hostile_argument,
        ),
    )
    assert result["stdout"] == hostile_argument
    assert result["exitCode"] == 0
    shut_down(client)


def test_the_working_directory_and_environment_are_the_ones_requested(
    tmp_path: Path,
) -> None:
    client, _ = build()
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(
            *python_argv(
                "import os\nos.write(1, os.getcwdb() + b'|' + os.environb[b'MARKER'])\n"
            ),
            cwd=os.fsencode(tmp_path),
            env={b"MARKER": b"\xff not text"},
        ),
    )
    stdout = result["stdout"]
    assert isinstance(stdout, bytes)
    reported_cwd, marker = stdout.split(b"|")
    assert Path(os.fsdecode(reported_cwd)).resolve() == tmp_path.resolve()
    assert marker == b"\xff not text"
    shut_down(client)


# --- R7.2: chunks before the exit -----------------------------------------------------------


def test_output_reaches_the_caller_before_the_command_exits(tmp_path: Path) -> None:
    """The requirement's actual claim, and the reason the seam had to grow a streaming form.

    The child writes, flushes, and then blocks until a file appears. Receiving that chunk is
    therefore proof that it arrived before the process exited: the process cannot have exited,
    because the file that lets it finish has not been created yet.
    """
    gate = tmp_path / "gate"
    client, _ = build()

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(
            wire(
                EXEC_REQUEST,
                exec_body(
                    *python_argv(
                        "import pathlib, sys, time\n"
                        "sys.stdout.buffer.write(b'first')\n"
                        "sys.stdout.flush()\n"
                        f"gate = pathlib.Path({str(gate)!r})\n"
                        f"deadline = time.monotonic() + {_WAIT_SECONDS}\n"
                        "while not gate.exists() and time.monotonic() < deadline:\n"
                        f"    time.sleep({_POLL_SECONDS})\n"
                        "sys.stdout.buffer.write(b'second')\n"
                    ),
                    stream=True,
                ),
                correlation=b"streamed",
            )
        )

        first = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert first[ENVELOPE_KEY_TYPE] == EXEC_CHUNK
        assert fields_of(first) == {"stream": 0, "data": b"first"}
        assert not gate.exists()

        gate.write_bytes(b"go")
        received = [first]
        while True:
            message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
            received.append(message)
            if message[ENVELOPE_KEY_TYPE] == EXEC_RESULT:
                break

    chunks = [m for m in received if m[ENVELOPE_KEY_TYPE] == EXEC_CHUNK]
    result = fields_of(received[-1])
    assert b"".join(_data_of(chunk) for chunk in chunks) == result["stdout"]
    assert result["stdout"] == b"firstsecond"
    assert result["exitCode"] == 0
    shut_down(client)


def test_chunk_boundaries_fall_wherever_they_fall_and_rejoin_losslessly() -> None:
    """A three-byte read splits every multi-byte sequence in `HOSTILE` across two chunks.

    Which is the point: the concatenation is byte-identical to the captured output because
    nothing decoded a chunk, so no boundary could land inside a character and corrupt it.
    """
    client, _ = build(chunk_bytes=3)

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(
            wire(
                EXEC_REQUEST,
                exec_body(
                    *python_argv(f"import sys\nsys.stdout.buffer.write({HOSTILE!r})\n"),
                    stream=True,
                ),
            )
        )
        chunks: list[bytes] = []
        while True:
            message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
            if message[ENVELOPE_KEY_TYPE] == EXEC_RESULT:
                result = fields_of(message)
                break
            chunks.append(_data_of(message))

    assert len(chunks) > 1, "a three-byte read should not have produced one chunk"
    assert b"".join(chunks) == HOSTILE
    assert result["stdout"] == HOSTILE
    shut_down(client)


def test_both_streams_are_carried_and_tagged_separately() -> None:
    client, _ = build()

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(
            wire(
                EXEC_REQUEST,
                exec_body(
                    *python_argv(
                        "import sys\n"
                        "sys.stderr.buffer.write(b'E')\n"
                        "sys.stderr.flush()\n"
                        "sys.stdout.buffer.write(b'O')\n"
                    ),
                    stream=True,
                ),
            )
        )
        seen: dict[int, bytes] = {}
        while True:
            message = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
            if message[ENVELOPE_KEY_TYPE] == EXEC_RESULT:
                result = fields_of(message)
                break
            fields = fields_of(message)
            stream_id = fields["stream"]
            assert isinstance(stream_id, int)
            seen[stream_id] = seen.get(stream_id, b"") + _data_of(message)

    assert seen == {0: b"O", 1: b"E"}
    assert result["stdout"] == b"O"
    assert result["stderr"] == b"E"
    shut_down(client)


def test_a_streamed_request_over_the_unary_transport_asks_for_the_websocket() -> None:
    client, _ = build()
    response = client.post(
        PROTOCOL_PATH,
        content=wire(
            EXEC_REQUEST,
            exec_body(
                *python_argv("import sys\nsys.stdout.buffer.write(b'x')\n"), stream=True
            ),
        ),
    )
    assert response.status_code == HTTPStatus.UPGRADE_REQUIRED
    shut_down(client)


def test_a_command_that_outlives_its_timeout_is_killed_and_its_output_kept(
    tmp_path: Path,
) -> None:
    client, _ = build()
    result = run(
        client,
        EXEC_REQUEST,
        exec_body(
            *python_argv(
                "import sys, time\n"
                "sys.stdout.buffer.write(b'partial')\n"
                "sys.stdout.flush()\n"
                f"time.sleep({_WAIT_SECONDS})\n"
            ),
            timeout_ms=200,
        ),
    )
    assert result["stdout"] == b"partial"
    exit_code = result["exitCode"]
    assert isinstance(exit_code, int)
    assert exit_code < 0, "a killed process reports termination by signal"
    shut_down(client)


# --- R7.3: a handle, and a status against it ------------------------------------------------


def test_a_background_process_gets_a_handle_and_reports_running_then_exited() -> None:
    client, manager = build()
    started = run(
        client,
        PROC_START,
        body_for(
            PROC_START,
            argv=python_argv(
                "import pathlib, sys, time\n"
                f"deadline = time.monotonic() + {_WAIT_SECONDS}\n"
                "while not pathlib.Path(sys.argv[1]).exists() and time.monotonic() < deadline:\n"
                f"    time.sleep({_POLL_SECONDS})\n"
                "raise SystemExit(4)\n"
            ),
            cwd=b"",
            env={},
        ),
    )
    assert set(started) == {"handle", "pid"}
    handle = started["handle"]
    assert isinstance(handle, bytes)
    pid = started["pid"]
    assert isinstance(pid, int)
    assert pid > 1
    assert manager.handles == {handle}

    # The process is blocked on a file that does not exist, so `running` is not a race.
    status = run(client, PROC_STATUS, status_query(handle))
    assert status == {"handle": handle, "state": "running"}
    shut_down(client)


def test_a_handle_is_unguessable_and_distinct_per_process() -> None:
    client, _ = build()
    body = body_for(
        PROC_START,
        argv=python_argv(f"import time\ntime.sleep({_WAIT_SECONDS})\n"),
        cwd=b"",
        env={},
    )
    first = run(client, PROC_START, body)["handle"]
    second = run(client, PROC_START, body)["handle"]
    assert isinstance(first, bytes)
    assert first != second
    assert len(first) == 32, "16 random bytes rendered as hex"
    shut_down(client)


def test_an_exited_background_process_reports_its_exit_code() -> None:
    client, _ = build()
    handle = run(
        client,
        PROC_START,
        body_for(
            PROC_START,
            argv=python_argv("raise SystemExit(4)\n"),
            cwd=b"",
            env={},
        ),
    )["handle"]
    assert isinstance(handle, bytes)

    status = _await_exit(client, handle)
    assert status == {"handle": handle, "state": "exited", "exitCode": 4}
    shut_down(client)


def test_a_status_query_does_not_consume_the_status() -> None:
    """The point of the design's `WNOWAIT`: a second query answers the same thing as the first."""
    client, _ = build()
    handle = run(
        client,
        PROC_START,
        body_for(
            PROC_START, argv=python_argv("raise SystemExit(5)\n"), cwd=b"", env={}
        ),
    )["handle"]
    assert isinstance(handle, bytes)

    first = _await_exit(client, handle)
    second = run(client, PROC_STATUS, status_query(handle))
    assert first == second
    shut_down(client)


def test_a_handle_no_process_answers_to_names_the_offending_field() -> None:
    client, _ = build()
    response = client.post(
        PROTOCOL_PATH,
        content=wire(PROC_STATUS, status_query(b"not a handle")),
    )
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    assert fields_of(reply)["field"] == "handle"
    shut_down(client)


def test_shutdown_empties_the_registry_and_leaves_no_child_running() -> None:
    client, manager = build()
    run(
        client,
        PROC_START,
        body_for(
            PROC_START,
            argv=python_argv(f"import time\ntime.sleep({_WAIT_SECONDS})\n"),
            cwd=b"",
            env={},
        ),
    )
    assert len(manager.handles) == 1
    shut_down(client)
    assert manager.handles == frozenset()


# --- Helpers -------------------------------------------------------------------------------


def _data_of(chunk: Message) -> bytes:
    data = fields_of(chunk)["data"]
    assert isinstance(data, bytes)
    return data


def _await_exit(client: TestClient, handle: bytes) -> dict[str, Value]:
    """Poll `proc.status` until it stops saying `running`, within the bound."""
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        status = run(client, PROC_STATUS, status_query(handle))
        if status["state"] != "running":
            return status
        time.sleep(_POLL_SECONDS)
    raise AssertionError("the background process never reported an exit")
