# kiro-classification: public
"""The ASGI application: the two transports, routed onto the hooks and the protocol handler.

This is the `ASGI server` node of the design's Sandbox_Runtime drawing, minus the server
itself, which is `runtime.server`. The application is a plain ASGI callable so that it can be
driven in-process by the offline suite, with no socket and no deployed resource; the server is a
separate concern that binds it to a port.

Two transports reach one handler, because the protocol has two shapes and one grammar:

- `POST /protocol` carries one CBOR item in a request body and one in the response body. This
  is every operation whose reply is a single message.
- `WS /protocol` carries one CBOR item per binary frame, which is the framing the design fixes
  ("one WebSocket binary frame carries one item", RFC 8742 sequences). Streaming operations
  need it, and the unary ones work over it unchanged, which is why the two share a handler
  rather than each having their own.

Neither path is a free choice about *what* it accepts. All Sandbox_Protocol messages are CBOR
byte strings, so a WebSocket text frame is not a message with a different encoding, it is not a
message; it is closed with `1003 Unsupported Data` rather than decoded and reported as a schema
violation, because there is nothing to name a field of.

**What authenticates a request here: nothing, deliberately.** The design settles this in
Session credentials and it is not an omission to be corrected in a later task of this
component. The endpoint in front of the Sandbox authenticates every request against a
Sandbox-scoped, port-scoped, expiring credential, and there is no unauthenticated route to this
application. The reason the check is not *also* performed here is that this process is untrusted
code's neighbour: a validator inside the MicroVM can be bypassed by the code it is meant to
constrain, so it would be decorative, and the design rejects it in those terms. The permission
to mint that credential is held by the Control_Plane execution role alone. Nothing in this
module should ever grow a token check, an allowlist or a shared secret.
"""

from __future__ import annotations

import asyncio
from contextlib import aclosing, suppress
from http import HTTPStatus
from typing import Final

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

from protocol.schema import Catalogue, load_catalogue
from runtime.hooks import LifecycleActions, LifecycleHooks
from runtime.observability import SessionLogEmitter
from runtime.operations import OperationRegistry
from runtime.protocol_handler import ProtocolReply, SandboxProtocolHandler
from runtime.readiness import ReadinessGate

__all__ = [
    "CBOR_MEDIA_TYPE",
    "HOOK_PATH_PREFIX",
    "PROTOCOL_PATH",
    "WS_CLOSE_GONE",
    "WS_CLOSE_TRY_AGAIN_LATER",
    "WS_CLOSE_UNSUPPORTED_DATA",
    "create_app",
]

#: The Lambda MicroVMs runtime hook path prefix.
HOOK_PATH_PREFIX: Final = "/aws/lambda-microvms/runtime/v1"

#: Where both transports live. One path, two schemes, one grammar.
PROTOCOL_PATH: Final = "/protocol"

#: RFC 8949's media type. Set on responses that carry a message and on nothing else.
CBOR_MEDIA_TYPE: Final = "application/cbor"

#: RFC 6455 close codes, named rather than spelled inline at the call site.
#:
#: `1013` is the readiness refusal: the peer arrived before `/run` completed, or while the
#: Sandbox is suspended, and retrying is the correct response. `1001` is the terminal refusal.
#: `1003` is a frame that is not a CBOR item at all.
WS_CLOSE_TRY_AGAIN_LATER: Final = 1013
WS_CLOSE_GONE: Final = 1001
WS_CLOSE_UNSUPPORTED_DATA: Final = 1003

#: Close reasons are capped by RFC 6455 at 123 bytes of UTF-8; anything longer is truncated
#: here rather than by the WebSocket implementation, which would cut mid-character.
_MAX_CLOSE_REASON_BYTES: Final = 123


def create_app(
    *,
    actions: LifecycleActions,
    operations: OperationRegistry | None = None,
    gate: ReadinessGate | None = None,
    catalogue: Catalogue | None = None,
    emitter: SessionLogEmitter | None = None,
) -> Starlette:
    """Build the Sandbox_Runtime ASGI application.

    `actions` is required and has no default. A runtime whose hooks do nothing would return 200
    from `/run` having applied no configuration, which is a false statement about readiness and
    exactly the claim R7.8 exists to make true, so there is no default that could be right.

    `operations` defaults to an empty registry, which is a true statement rather than a
    convenient one: a runtime with no operations wired in serves the protocol's error and
    readiness behaviour and answers every operation `501`.

    `emitter` carries the Session-identifying log destination (R14.1) and defaults to None,
    which is a runtime that emits no lifecycle records. It is not defaulted to one built from the
    environment, because that would make importing this module in a process with no Sandbox
    environment either fail or invent a Session; a deployment builds it from
    `runtime.observability.SessionIdentity.from_environment` and passes it in.

    The application starts `CLOSED`. Nothing serves the protocol until `/run` says so.
    """
    resolved_catalogue = catalogue if catalogue is not None else load_catalogue()
    resolved_gate = gate if gate is not None else ReadinessGate()
    resolved_operations = (
        operations
        if operations is not None
        else OperationRegistry(catalogue=resolved_catalogue)
    )

    hooks = LifecycleHooks(gate=resolved_gate, actions=actions, emitter=emitter)
    handler = SandboxProtocolHandler(
        gate=resolved_gate,
        operations=resolved_operations,
        catalogue=resolved_catalogue,
    )

    async def ready_probe(request: Request) -> Response:
        """``/ready``: the MicroVM image-build probe. Returns 200 unconditionally."""
        return PlainTextResponse("ok", status_code=HTTPStatus.OK)

    async def protocol_over_http(request: Request) -> Response:
        return _as_response(await handler.handle(await request.body()))

    async def protocol_over_websocket(websocket: WebSocket) -> None:
        await _serve_websocket(websocket, handler)

    app = Starlette(
        routes=[
            Route(f"{HOOK_PATH_PREFIX}/ready", ready_probe, methods=["POST"]),
            Route(f"{HOOK_PATH_PREFIX}/run", hooks.run, methods=["POST"]),
            Route(f"{HOOK_PATH_PREFIX}/suspend", hooks.suspend, methods=["POST"]),
            Route(f"{HOOK_PATH_PREFIX}/resume", hooks.resume, methods=["POST"]),
            Route(f"{HOOK_PATH_PREFIX}/terminate", hooks.terminate, methods=["POST"]),
            Route(PROTOCOL_PATH, protocol_over_http, methods=["POST"]),
            WebSocketRoute(PROTOCOL_PATH, protocol_over_websocket),
        ]
    )
    # Held on the application so that a caller holding only the ASGI object can read the phase
    # and reach the routing table, which is what the server entrypoint and the suite both need.
    app.state.gate = resolved_gate
    app.state.operations = resolved_operations
    app.state.handler = handler
    app.state.emitter = emitter
    return app


def _as_response(reply: ProtocolReply) -> Response:
    """Render a handler reply as an HTTP response.

    A reply carrying a message is CBOR with the media type; one that does not is the plain
    reason, because there is no protocol message type for the condition and a CBOR body that
    was not a message would be worse than no body. `204` is the exception to even that: RFC 9110
    forbids a body on it, so the reason is dropped rather than sent as one.
    """
    if reply.status == HTTPStatus.NO_CONTENT:
        return Response(status_code=reply.status)
    if reply.wire is None:
        return PlainTextResponse(reply.reason, status_code=reply.status)
    return Response(
        content=reply.wire,
        status_code=reply.status,
        media_type=CBOR_MEDIA_TYPE,
    )


async def _serve_websocket(
    websocket: WebSocket, handler: SandboxProtocolHandler
) -> None:
    """Accept a protocol connection and serve one item per binary frame.

    The handshake is accepted before a readiness refusal is sent, rather than rejected. That is
    not politeness: an ASGI `close` before `accept` is delivered to the peer as an HTTP `403`,
    and a `403` is the Client_SDK's signal to refresh its credential and retry (R9.5) — the one
    recovery that cannot help a Sandbox that is merely not ready yet. Accepting and then closing
    with `1013` says what is actually true.

    **Each frame is served in its own task, and the reading loop does not wait for it.** That is
    what R7.5 costs: an interactive pseudo-terminal has output arriving while input is being
    sent, so a loop that read a frame, served it to completion and only then read again could
    not deliver a keystroke into a terminal that was producing output. It has the same
    consequence for R7.2 — a second command can be issued while the first is still streaming.

    Concurrency does not make the replies ambiguous. Every reply carries the correlation
    identifier of the request that caused it, which is what the envelope's `id` is for, so
    interleaved streams are separable by the peer without this transport imposing an order.
    Sends are serialised by a lock because a WebSocket frame must not be interleaved with
    another on the wire; that is a framing constraint, not an ordering guarantee.
    """
    await websocket.accept()
    connection = _Connection(websocket)
    tasks: set[asyncio.Task[None]] = set()
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            frame = message.get("bytes")
            if frame is None:
                await connection.close(
                    WS_CLOSE_UNSUPPORTED_DATA,
                    "Sandbox_Protocol frames are CBOR byte strings, not text",
                )
                return
            task = asyncio.create_task(connection.serve(handler, frame))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            if connection.is_closed:  # nosemgrep: is-function-without-parentheses — @property
                return
    finally:
        # A peer that hangs up mid-stream leaves operations running: a command still producing
        # output, a terminal still open. Cancelling here is what finalises those generators, and
        # what releases the readiness admission each of them holds, so a later `/suspend` drains
        # instead of waiting on a stream nobody is reading.
        outstanding = tuple(tasks)
        for task in outstanding:
            task.cancel()
        for task in outstanding:
            with suppress(asyncio.CancelledError):
                await task


class _Connection:
    """One accepted WebSocket, with serialised sends and a close that happens once.

    Held per connection rather than per frame because both of those are shared state across the
    concurrent frame tasks: two tasks must not interleave sends, and two tasks that both meet a
    readiness refusal must not both send a close.
    """

    def __init__(self, websocket: WebSocket) -> None:
        self._websocket = websocket
        self._send_lock = asyncio.Lock()
        self._closed = False

    @property
    def is_closed(self) -> bool:
        """Whether this connection has been closed from our side."""
        return self._closed

    async def serve(self, handler: SandboxProtocolHandler, frame: bytes) -> None:
        """Serve one request frame, sending every reply it produces."""
        async with aclosing(handler.stream(frame)) as replies:
            async for reply in replies:
                if self._closed:
                    return
                if reply.wire is not None:
                    async with self._send_lock:
                        await self._websocket.send_bytes(reply.wire)
                    continue
                await self.close(_close_code(reply.status), reply.reason)
                return

    async def close(self, code: int, reason: str) -> None:
        """Close once, with a reason truncated to what RFC 6455 admits."""
        if self._closed:
            return
        self._closed = True
        async with self._send_lock:
            await self._websocket.close(code=code, reason=_close_reason(reason))


def _close_code(status: int) -> int:
    """The RFC 6455 close code for a reply that carries no protocol message."""
    if status == HTTPStatus.SERVICE_UNAVAILABLE:
        return WS_CLOSE_TRY_AGAIN_LATER
    if status == HTTPStatus.GONE:
        return WS_CLOSE_GONE
    # A routable type with no operation behind it yet. Closing rather than staying open and
    # silent, so the peer learns the outcome instead of waiting for a frame that is never
    # coming. `204` never reaches here: a stream that produced no reply produced nothing to
    # send, and over this transport that is simply silence rather than a status.
    return WS_CLOSE_UNSUPPORTED_DATA


def _close_reason(reason: str) -> str:
    """Truncate a close reason to RFC 6455's 123 bytes without splitting a character."""
    encoded = reason.encode("utf-8")
    if len(encoded) <= _MAX_CLOSE_REASON_BYTES:
        return reason
    return encoded[:_MAX_CLOSE_REASON_BYTES].decode("utf-8", errors="ignore")
