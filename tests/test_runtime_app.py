# kiro-classification: public
"""The ASGI application, driven in-process: the hooks, the two transports, and the gate.

No socket and no deployed resource. Starlette's test client speaks ASGI directly, which is what
the offline suite's loopback-only rule asks for and also what makes the readiness assertions
exact: the request reaches the application without a server in between that might answer for it.

`RecordingActions` stands in for the run, suspend, resume and terminate hook bodies, which are
later tasks. It is not a stand-in for anything asserted here — the gate, the transports and the
handler are the real modules — and it records the phase it observed on each call, because two of
the design's orderings are only checkable from inside the action.
"""

from __future__ import annotations

from http import HTTPStatus

import pytest
from starlette.testclient import TestClient

from protocol.codec.messages import decode, encode
from protocol.codec.profile import encode_value
from protocol.codec.values import Message
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import (
    CBOR_MEDIA_TYPE,
    HOOK_PATH_PREFIX,
    PROTOCOL_PATH,
    WS_CLOSE_GONE,
    WS_CLOSE_TRY_AGAIN_LATER,
    WS_CLOSE_UNSUPPORTED_DATA,
    create_app,
)
from runtime.hooks import RestorationFailure
from runtime.operations import OperationRegistry, OperationReply
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.server import DEFAULT_HOST, DEFAULT_PORT, build_server

CATALOGUE = load_catalogue()

#: An orchestrator-to-runtime type with an empty body, used wherever a test needs a valid
#: request and does not care what it asks for.
QUIESCE = "session.quiesce"


class RecordingActions:
    """The four hook bodies, recorded rather than performed."""

    def __init__(
        self, gate: ReadinessGate, *, restoration_failure: str | None = None
    ) -> None:
        self._gate = gate
        self._restoration_failure = restoration_failure
        #: Each call, as (action name, phase observed while it ran).
        self.calls: list[tuple[str, RuntimePhase]] = []
        self.payloads: list[bytes] = []
        #: Every request that reached a registered operation. Kept here rather than on the
        #: operation so that a test holding the actions can assert the operation was not run.
        self.operation_requests: list[Message] = []

    def _record(self, name: str) -> None:
        self.calls.append((name, self._gate.phase))

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self.calls]

    async def apply_configuration(self, payload: bytes) -> None:
        self._record("apply_configuration")
        self.payloads.append(payload)
        if self._restoration_failure is not None:
            raise RestorationFailure(self._restoration_failure)

    async def quiesce_and_flush(self) -> None:
        self._record("quiesce_and_flush")

    async def refresh_egress_identity(self) -> None:
        self._record("refresh_egress_identity")

    async def persist_artifacts(self) -> None:
        self._record("persist_artifacts")


def build(
    *, route_quiesce: bool = False, restoration_failure: str | None = None
) -> tuple[TestClient, ReadinessGate, RecordingActions]:
    gate = ReadinessGate()
    actions = RecordingActions(gate, restoration_failure=restoration_failure)

    async def acknowledge(request: Message) -> OperationReply:
        """A registered operation, standing in for the process manager and filesystem."""
        actions.operation_requests.append(request)
        return OperationReply(t="fs.ack", body={})

    operations = OperationRegistry(catalogue=CATALOGUE)
    if route_quiesce:
        operations.register(QUIESCE, acknowledge)
    app = create_app(
        actions=actions, operations=operations, gate=gate, catalogue=CATALOGUE
    )
    return TestClient(app), gate, actions


def request_wire(t: str = QUIESCE, correlation: bytes = b"cid") -> bytes:
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: correlation,
            ENVELOPE_KEY_BODY: {},
        },
        catalogue=CATALOGUE,
    )


def body_of(message: Message) -> dict[object, object]:
    """A decoded message's body, keyed by the catalogue's field names."""
    t = message[ENVELOPE_KEY_TYPE]
    body = message[ENVELOPE_KEY_BODY]
    assert isinstance(t, str) and isinstance(body, dict)
    fields = CATALOGUE.messages[t].body
    return {field.name: body[field.key] for field in fields if field.key in body}


# --- Readiness -----------------------------------------------------------------------------


def test_no_protocol_request_succeeds_before_the_run_hook() -> None:
    """The readiness gate, from outside: 503, no protocol message, and no operation reached."""
    client, gate, actions = build(route_quiesce=True)
    response = client.post(PROTOCOL_PATH, content=request_wire())

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert CBOR_MEDIA_TYPE not in response.headers.get("content-type", "")
    assert "closed" in response.text
    assert gate.phase is RuntimePhase.CLOSED
    # Nothing ran: not a hook action, and not the operation the request named. The gate is
    # checked before the representation is decoded, so a closed runtime does no work at all.
    assert actions.names == []
    assert actions.operation_requests == []


def test_the_run_hook_returns_200_and_the_handler_then_serves() -> None:
    client, gate, actions = build(route_quiesce=True)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=b"per-session-configuration")
    assert started.status_code == HTTPStatus.OK
    assert gate.phase is RuntimePhase.SERVING
    assert actions.payloads == [b"per-session-configuration"]
    # The configuration was applied while the handler was still closed (R7.8).
    assert actions.calls == [("apply_configuration", RuntimePhase.STARTING)]

    served = client.post(PROTOCOL_PATH, content=request_wire())
    assert served.status_code == HTTPStatus.OK
    assert served.headers["content-type"].startswith(CBOR_MEDIA_TYPE)


def test_an_operation_that_is_not_wired_in_yet_is_reported_as_such() -> None:
    """A routable type with nothing behind it is 501, not a fabricated protocol error."""
    client, _, _ = build(route_quiesce=False)
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"").status_code == HTTPStatus.OK

    response = client.post(PROTOCOL_PATH, content=request_wire())
    assert response.status_code == HTTPStatus.NOT_IMPLEMENTED
    assert QUIESCE in response.text
    assert CBOR_MEDIA_TYPE not in response.headers.get("content-type", "")


def test_a_second_run_hook_is_refused_and_applies_nothing() -> None:
    client, gate, actions = build()
    assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"first").status_code == HTTPStatus.OK

    second = client.post(f"{HOOK_PATH_PREFIX}/run", content=b"second")
    assert second.status_code == HTTPStatus.CONFLICT
    assert actions.payloads == [b"first"]
    assert gate.phase is RuntimePhase.SERVING


def test_a_restoration_failure_is_a_non_200_naming_the_reason() -> None:
    """R13.7: the Control_Plane records `FAILED` with the reason this response carries."""
    reason = "restore of /work failed: artifact digest mismatch"
    client, gate, _ = build(route_quiesce=True, restoration_failure=reason)

    started = client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")
    assert started.status_code != HTTPStatus.OK
    assert started.text == reason
    assert gate.phase is RuntimePhase.FAILED

    # And the handler never opens, with the same reason rather than a bare "not ready".
    refused = client.post(PROTOCOL_PATH, content=request_wire())
    assert refused.status_code == HTTPStatus.GONE
    assert reason in refused.text


def test_suspend_closes_the_handler_before_flushing_and_resume_reopens_it() -> None:
    client, gate, actions = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    assert client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == HTTPStatus.OK
    # R7.9's ordering, observed from inside the action: already closed when the flush ran.
    assert ("quiesce_and_flush", RuntimePhase.SUSPENDED) in actions.calls
    suspended = client.post(PROTOCOL_PATH, content=request_wire())
    assert suspended.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert actions.operation_requests == []

    assert client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == HTTPStatus.OK
    # R7.10's ordering: the egress identity was refreshed while the handler was still closed.
    assert ("refresh_egress_identity", RuntimePhase.SUSPENDED) in actions.calls
    assert gate.phase is RuntimePhase.SERVING
    assert (
        client.post(PROTOCOL_PATH, content=request_wire()).status_code == HTTPStatus.OK
    )


def test_terminate_closes_the_handler_before_writing_artifacts() -> None:
    client, gate, actions = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == HTTPStatus.OK
    assert ("persist_artifacts", RuntimePhase.TERMINATED) in actions.calls
    assert gate.phase is RuntimePhase.TERMINATED

    gone = client.post(PROTOCOL_PATH, content=request_wire())
    # 410 rather than 503, because re-resolution and not a retry is the caller's recovery.
    assert gone.status_code == HTTPStatus.GONE


# --- The protocol handler ------------------------------------------------------------------


def test_a_served_request_is_answered_with_the_request_correlation_identifier() -> None:
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    response = client.post(PROTOCOL_PATH, content=request_wire(correlation=b"\x00\xff"))
    reply = decode(response.content, catalogue=CATALOGUE)

    assert reply[ENVELOPE_KEY_VERSION] == CATALOGUE.protocol_version
    assert reply[ENVELOPE_KEY_TYPE] == "fs.ack"
    # Echoed verbatim, including bytes that are not valid UTF-8.
    assert reply[ENVELOPE_KEY_ID] == b"\x00\xff"


def test_an_unreadable_representation_is_a_decode_error_naming_a_field() -> None:
    """R8.6, via the codec's Phase 0: no version to report, so field `1` is named."""
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    # A map whose first key is not the version key.
    response = client.post(
        PROTOCOL_PATH, content=encode_value({ENVELOPE_KEY_TYPE: QUIESCE})
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    assert body_of(reply)["field"] == str(ENVELOPE_KEY_VERSION)


def test_a_schema_violation_is_a_decode_error_naming_the_offending_field() -> None:
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    undeclared = encode_value(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: "nope.nope",
            ENVELOPE_KEY_ID: b"cid",
            ENVELOPE_KEY_BODY: {},
        }
    )
    response = client.post(PROTOCOL_PATH, content=undeclared)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    assert body_of(reply)["field"] == "t"


def test_an_unsupported_version_is_a_version_error_reporting_both_bounds() -> None:
    """R8.7: the received version and the supported range, read off the catalogue."""
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    unsupported = CATALOGUE.supported_max + 1
    response = client.post(
        PROTOCOL_PATH,
        content=encode_value(
            {
                ENVELOPE_KEY_VERSION: unsupported,
                ENVELOPE_KEY_TYPE: QUIESCE,
                ENVELOPE_KEY_ID: b"cid",
                ENVELOPE_KEY_BODY: {},
            }
        ),
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.version"
    assert body_of(reply) == {
        "received": unsupported,
        "supportedMin": CATALOGUE.supported_min,
        "supportedMax": CATALOGUE.supported_max,
    }


def test_a_message_the_runtime_only_sends_is_refused_naming_the_type() -> None:
    """`exec.result` conforms to its schema but the catalogue declares it runtime-to-client."""
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    outbound = encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: "exec.result",
            ENVELOPE_KEY_ID: b"cid",
            ENVELOPE_KEY_BODY: {1: 0, 2: b"", 3: b""},
        },
        catalogue=CATALOGUE,
    )
    response = client.post(PROTOCOL_PATH, content=outbound)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    reply = decode(response.content, catalogue=CATALOGUE)
    assert reply[ENVELOPE_KEY_TYPE] == "error.decode"
    assert body_of(reply)["field"] == "t"


def test_the_gate_is_checked_before_the_representation_is_decoded() -> None:
    """Refusing first is the point: unreadable bytes are not parsed by a closed runtime."""
    client, _, _ = build(route_quiesce=True)
    response = client.post(PROTOCOL_PATH, content=b"\xff\xff not cbor at all")
    # 503 and not the 400 the same bytes would earn from a serving runtime.
    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE


# --- The WebSocket transport ---------------------------------------------------------------


def test_a_websocket_frame_is_answered_with_one_reply_frame() -> None:
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(request_wire(correlation=b"ws"))
        reply = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert reply[ENVELOPE_KEY_TYPE] == "fs.ack"
        assert reply[ENVELOPE_KEY_ID] == b"ws"


def test_a_websocket_peer_arriving_before_readiness_is_told_to_retry() -> None:
    """1013 and not an HTTP 403, which would send the SDK to refresh a credential instead."""
    client, _, _ = build(route_quiesce=True)

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(request_wire())
        closed = websocket.receive()
    assert closed["type"] == "websocket.close"
    assert closed["code"] == WS_CLOSE_TRY_AGAIN_LATER


def test_a_websocket_peer_arriving_after_termination_is_told_the_runtime_is_gone() -> (
    None
):
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")
    client.post(f"{HOOK_PATH_PREFIX}/terminate")

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(request_wire())
        closed = websocket.receive()
    assert closed["code"] == WS_CLOSE_GONE


def test_a_text_frame_is_not_a_sandbox_protocol_message() -> None:
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_text(request_wire().decode("latin-1"))
        closed = websocket.receive()
    assert closed["code"] == WS_CLOSE_UNSUPPORTED_DATA


def test_a_decode_error_over_the_websocket_is_still_a_protocol_message() -> None:
    """The connection stays open: a malformed frame is reported, not fatal to the session."""
    client, _, _ = build(route_quiesce=True)
    client.post(f"{HOOK_PATH_PREFIX}/run", content=b"config")

    with client.websocket_connect(PROTOCOL_PATH) as websocket:
        websocket.send_bytes(encode_value({ENVELOPE_KEY_TYPE: QUIESCE}))
        reply = decode(websocket.receive_bytes(), catalogue=CATALOGUE)
        assert reply[ENVELOPE_KEY_TYPE] == "error.decode"

        # Still serving, on the same connection.
        websocket.send_bytes(request_wire())
        assert (
            decode(websocket.receive_bytes(), catalogue=CATALOGUE)[ENVELOPE_KEY_TYPE]
            == "fs.ack"
        )


# --- The application object and the server ------------------------------------------------


def test_the_application_starts_closed_and_publishes_its_gate() -> None:
    gate = ReadinessGate()
    app = create_app(actions=RecordingActions(gate), gate=gate, catalogue=CATALOGUE)
    assert app.state.gate is gate
    assert gate.phase is RuntimePhase.CLOSED


def test_the_application_defaults_to_an_empty_routing_table() -> None:
    gate = ReadinessGate()
    app = create_app(actions=RecordingActions(gate), gate=gate, catalogue=CATALOGUE)
    operations = app.state.operations
    assert isinstance(operations, OperationRegistry)
    assert operations.routed() == frozenset()


def test_the_hook_and_protocol_routes_are_the_ones_the_design_names() -> None:
    gate = ReadinessGate()
    client = TestClient(
        create_app(actions=RecordingActions(gate), gate=gate, catalogue=CATALOGUE)
    )
    # GET is not a protocol transport, and no hook is reachable by it.
    for path in (
        f"{HOOK_PATH_PREFIX}/run",
        f"{HOOK_PATH_PREFIX}/suspend",
        f"{HOOK_PATH_PREFIX}/resume",
        f"{HOOK_PATH_PREFIX}/terminate",
        PROTOCOL_PATH,
    ):
        assert client.get(path).status_code == HTTPStatus.METHOD_NOT_ALLOWED
    assert client.post("/nonexistent").status_code == HTTPStatus.NOT_FOUND


def test_the_server_binds_loopback_with_one_worker() -> None:
    """The two settings with consequences, asserted without opening a socket."""
    gate = ReadinessGate()
    app = create_app(actions=RecordingActions(gate), gate=gate, catalogue=CATALOGUE)
    server = build_server(app)

    assert server.config.host == DEFAULT_HOST == "127.0.0.1"
    assert server.config.port == DEFAULT_PORT
    assert server.config.workers == 1


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_the_bind_address_is_overridable_for_a_provider_that_needs_it(
    host: str,
) -> None:
    gate = ReadinessGate()
    app = create_app(actions=RecordingActions(gate), gate=gate, catalogue=CATALOGUE)
    assert build_server(app, host=host, port=9001).config.host == host
