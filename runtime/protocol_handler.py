# kiro-classification: public
"""The Sandbox_Protocol handler: the gate, then the shared codec, then an operation.

One method does the whole of it, and the order of its steps is the content of this module:

1. **Admission.** `ReadinessGate.admit` first, before the body is looked at. Refusing before
   decoding is not an optimisation; it is what makes R7.8's prohibition true. A handler that
   decoded and then refused would have parsed attacker-supplied bytes in a phase where the
   design says nothing has been configured yet. The cost of that order is that the admission's
   *class* cannot be known here — see step 4a.
2. **Decode.** `protocol.codec.decode`, the same function the Python Client_SDK calls. Nothing
   here re-implements a phase of the decode algorithm or touches CBOR: the three phases, their
   order and their two error shapes are the codec's, and this module's whole involvement in
   R8.6, R8.7 and R8.8 is to render the exception the codec raised into the message type the
   catalogue declares for it.
3. **Direction.** The catalogue says who sends each type. A client that sends `exec.result` has
   sent a schema-conforming map that the schema nonetheless does not permit in that direction,
   so it gets `error.decode` naming `t`.
4. **Route.** The registry. An inbound type nothing routes yet is 501 and not an error message,
   for the reason given below.
4a. **Reclassify, where the route is a long-lived one.** The registry declares an admission class
   per streaming type, and a route declared `LONG_LIVED` moves the admission out of the drained
   class before the operation is entered. Every admission starts in-flight because step 1 cannot
   see the body; a pseudo-terminal is the one route whose end is a caller decision, so leaving it
   counted as in-flight is what made `/suspend` wait for a shell to exit and `/terminate` deadlock
   against the shutdown that would have closed it.
5. **Encode.** The operation returns a type and a body; the envelope — version and correlation
   identifier — is built here.

**Why some refusals are not protocol messages.** The catalogue declares exactly two error
types, `error.decode` and `error.version`, and neither describes "not ready yet", "gone" or
"not implemented". Inventing a third would be a change to `protocol/messages.yaml`, which is
the schema both codecs and the vector corpus are built from — a protocol change made to
improve an error message. So those three conditions are reported at the transport instead, as a
status code with a plain reason, and the protocol carries only what the protocol declares.

**Why the status codes are the ones they are.** Two of the three are constrained by the
Client_SDK's documented recovery paths rather than free choices. A `401` or `403` sends the SDK
to the Control_Plane to refresh a credential and retry once (R9.5); a `404` or `410` sends it
to re-resolve the Affinity_Key (R9.12). A readiness refusal must therefore be neither: it is
`503`, because time alone fixes it and nothing about the credential or the Session is wrong. A
terminal refusal is `410`, because the Sandbox really is gone and re-resolution really is the
recovery — the gate and the SDK agree on that by construction rather than by coincidence.

**Two shapes, one grammar.** `handle` serves one request and answers once; `stream` serves one
request and yields every reply it produces. They share the whole of the admitted path — gate,
decode, direction, routing — and differ only in what they do with a streaming operation's
replies, because the request/response transport can carry exactly one message and the WebSocket
transport can carry many.

So a streaming operation reached over `POST /protocol` is answered by its reply *count*, which
is the one thing the transport can act on:

- **No replies** is a request whose whole effect was a side effect, which is what a terminal
  input frame is: `204 No Content`, because there is no message and none is missing.
- **One reply** is indistinguishable from a unary operation and is served identically, which is
  what keeps `exec.request` with `stream` false working over the unary transport.
- **More than one** cannot be carried: `426 Upgrade Required`, and the operation is abandoned at
  the second reply rather than run to completion, so nothing is produced that nothing can read.
  `426` is chosen for the same reason as the other two — it is outside every status the
  Client_SDK treats as a signal to refresh a credential, re-resolve, or back off and retry, so
  it reads as "ask again over the other transport" and cannot be mistaken for anything else.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import aclosing
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final

from protocol.codec.errors import DecodeError, VersionError
from protocol.codec.messages import decode, encode
from protocol.codec.values import Message, Value
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    Catalogue,
    load_catalogue,
)
from runtime.operations import (
    OperationRegistry,
    OperationReply,
    ProtocolOperation,
    StreamingOperation,
    is_inbound,
)
from runtime.readiness import Admission, AdmissionClass, NotServing, ReadinessGate

__all__ = [
    "ERROR_DECODE",
    "ERROR_VERSION",
    "ProtocolReply",
    "SandboxProtocolHandler",
]

#: The two error types the catalogue declares (R8.6, R8.7).
ERROR_DECODE: Final = "error.decode"
ERROR_VERSION: Final = "error.version"

#: The identity reported when a message is well formed and schema-conforming but travels the
#: wrong way. The offending field is the type discriminator, named as the catalogue names it.
_TYPE_IDENTITY: Final = "t"

#: An empty correlation identifier, used when the request could not be decoded far enough to
#: have one. A byte string because the envelope's `id` is byte-typed; empty rather than
#: invented, because a fabricated identifier would correlate a reply to a request that never
#: carried it.
_NO_CORRELATION: Final = b""

#: The two reasons a streaming operation can give the request/response transport, neither of
#: which is a protocol message: see the module docstring on reply counts.
_UPGRADE_REASON: Final = (
    "this operation answers with more than one Sandbox_Protocol message; "
    "send it over the WebSocket transport on the same path"
)
_NO_CONTENT_REASON: Final = (
    "accepted; this operation answers with no Sandbox_Protocol message"
)


@dataclass(frozen=True, slots=True)
class ProtocolReply:
    """What the handler produces, in a form both transports can carry.

    `wire` is an encoded Sandbox_Protocol message, or None where the condition has no message
    type to be expressed in. `status` is for the request/response transport; the WebSocket
    transport reads `wire` and, where there is none, `reason`.
    """

    status: int
    wire: bytes | None
    reason: str

    @property
    def is_protocol_message(self) -> bool:
        """Whether there is a Sandbox_Protocol message to send back."""
        return self.wire is not None


@dataclass(frozen=True, slots=True)
class _UnaryRoute:
    """A decoded, direction-checked request and the unary operation that will serve it."""

    request: Message
    correlation: bytes
    operation: ProtocolOperation


@dataclass(frozen=True, slots=True)
class _StreamRoute:
    """A decoded, direction-checked request and the streaming operation that will serve it.

    Two route types rather than one with two optional fields, so that "exactly one of them is
    set" is the type rather than an invariant restated at every use.

    `admission` is the class the registry declares for this type. It is on the route rather than
    read again at each use because it is part of what resolving the request established, and
    because the one thing that must happen before the operation is entered is the reclassification
    it implies.
    """

    request: Message
    correlation: bytes
    operation: StreamingOperation
    admission: AdmissionClass


class SandboxProtocolHandler:
    """Serves one Sandbox_Protocol message, given a readiness gate and a routing table."""

    def __init__(
        self,
        *,
        gate: ReadinessGate,
        operations: OperationRegistry,
        catalogue: Catalogue | None = None,
    ) -> None:
        self._gate = gate
        self._operations = operations
        self._catalogue = catalogue if catalogue is not None else load_catalogue()

    @property
    def catalogue(self) -> Catalogue:
        """The catalogue this handler validates and encodes against."""
        return self._catalogue

    async def handle(self, wire: bytes) -> ProtocolReply:
        """Serve one request, and never raise.

        Every failure mode is a reply rather than an exception, because both transports need to
        answer something: a request/response caller needs a status and a WebSocket peer needs a
        frame or a close code. A handler that raised would leave that decision to whatever
        catches it, in two places, differently.
        """
        try:
            async with self._gate.admit() as admission:
                return await self._serve(wire, admission)
        except NotServing as refusal:
            return self._refuse(refusal)

    async def stream(self, wire: bytes) -> AsyncGenerator[ProtocolReply]:
        """Serve one request and yield every reply it produces, and never raise.

        A unary route yields exactly one reply, so a transport can drive every operation through
        this method and the streaming ones are not a special case at the call site.

        Admission is held for the whole stream rather than reacquired per reply, because the
        stream *is* one admitted request: R7.9's drain has to wait for a command that is still
        producing output, and a per-reply admission would let `/suspend` return while a
        subprocess was still writing.

        Which drain it has to wait for is the admission's *class*, and that is settled after the
        route is known rather than at admission: see `_reclassified`. A command stream stays in the
        drained class and ends when the command exits; a pseudo-terminal leaves it, because it ends
        on `pty.close`, on end of file, or when the transport abandons the generator, and none of
        those is a moment the Runtime can bring about.
        """
        try:
            async with self._gate.admit() as admission:
                async for reply in self._serve_stream(wire, admission):
                    yield reply
        except NotServing as refusal:
            yield self._refuse(refusal)

    async def _serve(self, wire: bytes, admission: Admission) -> ProtocolReply:
        """The admitted request/response path: decode, check direction, route, encode."""
        route = self._resolve(wire)
        if isinstance(route, ProtocolReply):
            return route
        if isinstance(route, _UnaryRoute):
            return self._encoded(
                await route.operation(route.request), route.correlation
            )
        await self._reclassified(route, admission)
        return await self._collapse(route)

    async def _serve_stream(
        self, wire: bytes, admission: Admission
    ) -> AsyncGenerator[ProtocolReply]:
        """The admitted streaming path. See `stream`."""
        route = self._resolve(wire)
        if isinstance(route, ProtocolReply):
            yield route
            return
        if isinstance(route, _UnaryRoute):
            yield self._encoded(await route.operation(route.request), route.correlation)
            return
        await self._reclassified(route, admission)
        # `aclosing` rather than a bare `async for`: if the consumer stops early the generator
        # has to be finalised here, while this task still exists, so that whatever the operation
        # holds open — a subprocess, a terminal file descriptor — is released deterministically
        # rather than whenever the interpreter next collects an abandoned async generator.
        async with aclosing(route.operation(route.request)) as replies:
            async for reply in replies:
                yield self._encoded(reply, route.correlation)

    async def _reclassified(self, route: _StreamRoute, admission: Admission) -> None:
        """Move the admission into the long-lived class where the route says it belongs.

        Before the operation is entered, and that placement is the whole of the mechanism: once
        `pty.open` is running, the next thing that happens is a wait on a descriptor the caller
        owns, so an admission still counted as in-flight at that point is one a drain would wait
        behind. Doing it here and not in `admit` is what keeps the admission decision
        content-blind — the class comes from the *decoded* route, which is exactly the thing
        admission may not consult.

        Both transports go through this. A `pty.open` sent over the request/response transport is
        abandoned at its second reply and answered `426`, but it can wait indefinitely for its
        first, and an admission that is unbounded in one transport is unbounded in both.
        """
        if route.admission is AdmissionClass.LONG_LIVED:
            await admission.becomes_long_lived()

    async def _collapse(self, route: _StreamRoute) -> ProtocolReply:
        """Answer a streaming operation over a transport that carries one message.

        Reads at most two replies. The second is read in order to *detect* that there is one and
        is then discarded with the rest of the stream unread, so a caller that asked for a
        streamed command over the request/response transport is told to upgrade rather than made
        to wait for a command to finish whose output nothing will receive.
        """
        first: OperationReply | None = None
        overflowed = False
        async with aclosing(route.operation(route.request)) as replies:
            async for reply in replies:
                if first is None:
                    first = reply
                    continue
                overflowed = True
                break

        if overflowed:
            return ProtocolReply(
                status=HTTPStatus.UPGRADE_REQUIRED,
                wire=None,
                reason=_UPGRADE_REASON,
            )
        if first is None:
            return ProtocolReply(
                status=HTTPStatus.NO_CONTENT,
                wire=None,
                reason=_NO_CONTENT_REASON,
            )
        return self._encoded(first, route.correlation)

    def _resolve(self, wire: bytes) -> _UnaryRoute | _StreamRoute | ProtocolReply:
        """Decode, check direction and route, or report why none of that was possible.

        Shared by both shapes so that a malformed frame, a wrong-direction type and an unrouted
        type are reported identically whichever transport asked.
        """
        try:
            request = decode(wire, catalogue=self._catalogue)
        except VersionError as exc:
            return self._version_error(exc)
        except DecodeError as exc:
            return self._decode_error(
                exc.field, exc.detail, correlation=_NO_CORRELATION
            )

        t = _as_text(request[ENVELOPE_KEY_TYPE], "t")
        correlation = _as_bytes(request[ENVELOPE_KEY_ID], "id")

        if not is_inbound(t, catalogue=self._catalogue):
            direction = self._catalogue.messages[t].direction
            return self._decode_error(
                _TYPE_IDENTITY,
                f"the catalogue declares {t!r} as {direction}, "
                f"so the Sandbox_Runtime does not accept it",
                correlation=correlation,
            )

        unary = self._operations.operation_for(t)
        if unary is not None:
            return _UnaryRoute(
                request=request, correlation=correlation, operation=unary
            )
        streaming = self._operations.stream_for(t)
        if streaming is not None:
            return _StreamRoute(
                request=request,
                correlation=correlation,
                operation=streaming,
                admission=self._operations.admission_class_for(t),
            )
        return ProtocolReply(
            status=HTTPStatus.NOT_IMPLEMENTED,
            wire=None,
            reason=f"this Sandbox_Runtime does not yet serve {t!r}",
        )

    def _encoded(self, reply: OperationReply, correlation: bytes) -> ProtocolReply:
        """Wrap one operation reply in the envelope and encode it."""
        return ProtocolReply(
            status=HTTPStatus.OK,
            wire=encode(
                self._envelope(reply.t, correlation, reply.body),
                catalogue=self._catalogue,
            ),
            reason=reply.t,
        )

    def _refuse(self, refusal: NotServing) -> ProtocolReply:
        """Report a closed gate at the transport, with the status the caller can act on."""
        status = (
            HTTPStatus.GONE if refusal.is_terminal else HTTPStatus.SERVICE_UNAVAILABLE  # nosemgrep: is-function-without-parentheses — @property
        )
        return ProtocolReply(status=status, wire=None, reason=str(refusal))

    def _decode_error(
        self, field: str, detail: str, *, correlation: bytes
    ) -> ProtocolReply:
        """Render a decode error as `error.decode`, naming the offending field (R8.6)."""
        body = self._body(ERROR_DECODE, {"field": field, "detail": detail})
        return ProtocolReply(
            status=HTTPStatus.BAD_REQUEST,
            wire=encode(
                self._envelope(ERROR_DECODE, correlation, body),
                catalogue=self._catalogue,
            ),
            reason=f"{field}: {detail}",
        )

    def _version_error(self, exc: VersionError) -> ProtocolReply:
        """Render a version error, reporting the received version and both bounds (R8.7).

        The three numbers come off the exception, which read them off the catalogue, so the
        bounds a peer is told are the bounds this codec admits and not a second copy of them.
        """
        body = self._body(
            ERROR_VERSION,
            {
                "received": exc.received,
                "supportedMin": exc.supported_min,
                "supportedMax": exc.supported_max,
            },
        )
        return ProtocolReply(
            status=HTTPStatus.BAD_REQUEST,
            wire=encode(
                self._envelope(ERROR_VERSION, _NO_CORRELATION, body),
                catalogue=self._catalogue,
            ),
            reason=str(exc),
        )

    def _body(self, t: str, fields: dict[str, Value]) -> dict[Value, Value]:
        """Key a body by the catalogue's field numbers rather than by hardcoded integers.

        The handler is the one place in the runtime that builds a message body from named
        fields, and it does it by asking the catalogue for each name's key. Writing `1` and `2`
        for `error.decode` would work today and quietly point at the wrong fields the first time
        the catalogue's field order changed.
        """
        message = self._catalogue.messages[t]
        return {
            message.field_by_name(name).key: value for name, value in fields.items()
        }

    def _envelope(
        self, t: str, correlation: bytes, body: dict[Value, Value]
    ) -> Message:
        """Build the four-key envelope around a reply body.

        The version is the catalogue's emitted version and the correlation identifier is the
        request's, echoed verbatim. Neither is an operation's to choose.
        """
        return {
            ENVELOPE_KEY_VERSION: self._catalogue.protocol_version,
            ENVELOPE_KEY_TYPE: t,
            ENVELOPE_KEY_ID: correlation,
            ENVELOPE_KEY_BODY: body,
        }


def _as_text(value: Value, field: str) -> str:
    """Narrow an envelope value the catalogue types as text.

    Unreachable through `decode`, which validated the envelope against the catalogue before
    returning it. Present so that the narrowing is a check rather than a type ignore over a
    value the schema already guarantees, and raising rather than reporting because a codec that
    returned a differently typed envelope is a defect here, not a peer's malformed input.
    """
    if isinstance(value, str):
        return value
    raise TypeError(
        f"decoded envelope key {field!r} is {type(value).__name__}, not text"
    )


def _as_bytes(value: Value, field: str) -> bytes:
    """Narrow an envelope value the catalogue types as a byte string. See `_as_text`."""
    if isinstance(value, bytes):
        return value
    raise TypeError(
        f"decoded envelope key {field!r} is {type(value).__name__}, not bytes"
    )
