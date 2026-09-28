# kiro-classification: public
"""The seam between the Sandbox_Protocol handler and the operations it dispatches into.

The design's Sandbox_Runtime drawing has the protocol handler pointing at four things: the
shared codec, the process manager, the filesystem operations and the exposed-port passthrough.
The codec is a package the handler imports. The other three are separate tasks, so what the
handler needs from them now is the shape of the call, not the call.

That shape is one entry per message type: a coroutine taking the decoded request and returning
the type and body of its reply. It deliberately does *not* return an envelope. The envelope
carries the protocol version and the correlation identifier, and both are the handler's to
set — the version because the codec emits exactly the one the catalogue names, the correlation
identifier because a reply that failed to echo its request's would be a bug no operation should
be able to introduce. An operation that could set them is an operation that could get them
wrong, so it cannot.

Registration is checked against the catalogue rather than trusted, on two counts:

- The type must exist. A registry keyed by free-form strings would accept `fs.raed` and answer
  501 for `fs.read` forever, which is a failure that shows up in an integration test at the
  earliest and in production at the latest.
- The type must be one the runtime can *receive*. `direction` is part of the catalogue, and
  `exec.result` is declared `runtime-to-client`; registering a handler for it would be
  declaring that the runtime answers its own replies.

**Streaming.** R7.2 needs one request to produce many frames — output chunks before the exit
code — and R7.5 needs one request to produce frames indefinitely, and one input frame to
produce none. So there is a second registration form alongside the unary one: an operation that
returns an async iterator of replies rather than one reply. It is deliberately additive, and the
unary form is unchanged, because most operations answer exactly once and forcing them to be
generators would make every filesystem call carry streaming machinery it never uses.

A type is registered in one form or the other, never both. `exec.request` is registered
streaming even though it answers once when its `stream` field is false, because the *shape* of
its reply is a property of the request rather than of the type, and the alternative — two
registrations for one type — is the ambiguity `register` already refuses.

How many replies a stream produces is then the transport's business, not the operation's. The
count is meaningful: zero replies is a terminal input frame that is written and acknowledged by
nothing, one reply is an ordinary answer, and many replies need a transport that can carry many
frames. `runtime.protocol_handler` maps those three cases onto the request/response transport,
and `runtime.app` sends all of them over the WebSocket, where many frames is the normal case.

**How long a stream lasts is the operation's business, and it is declared here.** A streaming
registration carries the `runtime.readiness.AdmissionClass` the readiness drain should judge it
by, because whether the Runtime or the caller bounds an operation's duration is a fact about the
operation. `exec.request` is `IN_FLIGHT`: it ends when its process ends. `pty.open` is
`LONG_LIVED`: it ends when the operator's shell does. The gate never asks a request what it is —
it cannot, since it admits before the frame is decoded — so this table is where the handler looks
once the route is known.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import Final

from protocol.codec.values import Message, Value
from protocol.schema import Catalogue, Direction, load_catalogue
from runtime.readiness import AdmissionClass

__all__ = [
    "INBOUND_DIRECTIONS",
    "OperationRegistry",
    "OperationReply",
    "ProtocolOperation",
    "StreamingOperation",
    "UnroutableMessageType",
    "is_inbound",
]

#: The directions a message may travel and still arrive at the Sandbox_Runtime. `BOTH` is
#: included because the catalogue uses it for types that flow each way — `proc.status`,
#: `pty.data` — and the runtime receives those as well as sending them.
INBOUND_DIRECTIONS: Final = frozenset(
    {
        Direction.CLIENT_TO_RUNTIME,
        Direction.ORCHESTRATOR_TO_RUNTIME,
        Direction.BOTH,
    }
)


@dataclass(frozen=True, slots=True)
class OperationReply:
    """What an operation returns: a message type and its body, and no envelope.

    `body` is keyed by the small unsigned integers the catalogue assigns to that type's fields,
    which is the same keying the codec validates against, so an operation builds the body the
    schema declares rather than a dictionary of names someone then translates.
    """

    t: str
    body: dict[Value, Value]


#: One operation: the decoded request in, the type and body of the reply out.
type ProtocolOperation = Callable[[Message], Awaitable[OperationReply]]

#: One streaming operation: the decoded request in, zero or more replies out, produced as they
#: become available rather than collected first. R7.2 is the reason this is lazy — an operation
#: that returned a list of chunks would satisfy a looser type and not the requirement.
#:
#: An async *generator* rather than a bare async iterator, because the caller has to be able to
#: finalise it: a consumer that stops reading half way through a command's output must be able to
#: release the subprocess, and `aclose` is what makes that deterministic rather than dependent on
#: when the interpreter next collects an abandoned generator.
type StreamingOperation = Callable[[Message], AsyncGenerator[OperationReply]]


class UnroutableMessageType(Exception):
    """A message type was registered that the runtime cannot receive, or does not exist.

    Raised at registration and never at request time, which is the point: it is a defect in the
    runtime's own wiring, so it should stop the process starting rather than become a 501 that
    someone eventually notices in a log.
    """


def is_inbound(t: str, *, catalogue: Catalogue | None = None) -> bool:
    """Whether the catalogue declares `t` as a type the Sandbox_Runtime may receive."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    message = resolved.messages.get(t)
    return message is not None and message.direction in INBOUND_DIRECTIONS


class OperationRegistry:
    """The handler's routing table, one entry per Sandbox_Protocol message type.

    Empty is a legitimate state and not an error. A runtime whose process manager and
    filesystem operations have not been wired in answers every request 501, which is a true
    statement about it, and is what the handler reports until those operations exist.
    """

    def __init__(self, *, catalogue: Catalogue | None = None) -> None:
        self._catalogue = catalogue if catalogue is not None else load_catalogue()
        self._operations: dict[str, ProtocolOperation] = {}
        self._streams: dict[str, StreamingOperation] = {}
        self._admission: dict[str, AdmissionClass] = {}

    @property
    def catalogue(self) -> Catalogue:
        """The catalogue this registry validates registrations against."""
        return self._catalogue

    def register(self, t: str, operation: ProtocolOperation) -> None:
        """Route `t` to a unary `operation`: one request, one reply.

        Raises `UnroutableMessageType` if the catalogue does not declare `t`, declares it as a
        type the runtime only sends, or if `t` is already routed. The last of those is included
        because two registrations for one type means two modules believe they own it, and
        silently keeping the later one hides which.
        """
        self._check_routable(t)
        self._operations[t] = operation

    def register_stream(
        self,
        t: str,
        operation: StreamingOperation,
        *,
        admission: AdmissionClass = AdmissionClass.IN_FLIGHT,
    ) -> None:
        """Route `t` to a streaming `operation`: one request, zero or more replies.

        The same checks as `register`, against the same shared name space, so a type cannot be
        routed unary here and streaming there.

        `admission` is the class the readiness drain judges this operation by, and the module that
        owns the operation is the one that declares it: whether the caller or the Runtime bounds an
        operation's duration is a fact about the operation, not about the gate, so a central list
        of long-lived type names would be a second place to keep that fact true. It defaults to
        `IN_FLIGHT` because that is what almost every operation is, and because a new operation
        that forgot to say would then be *over*-counted by the drain — a hook that waits for
        something it need not have waited for — rather than under-counted, which is the failure
        R7.9's wait exists to prevent.
        """
        self._check_routable(t)
        self._streams[t] = operation
        self._admission[t] = admission

    def _check_routable(self, t: str) -> None:
        """Whether `t` may be routed at all, and is not routed already. See `register`."""
        if t not in self._catalogue.messages:
            raise UnroutableMessageType(f"the catalogue declares no message type {t!r}")
        if not is_inbound(t, catalogue=self._catalogue):
            direction = self._catalogue.messages[t].direction
            raise UnroutableMessageType(
                f"{t!r} is declared {direction}, so the Sandbox_Runtime never receives it"
            )
        if t in self._operations or t in self._streams:
            raise UnroutableMessageType(f"{t!r} is already routed")

    def operation_for(self, t: str) -> ProtocolOperation | None:
        """The unary operation routing `t`, or None. A streaming route answers None here."""
        return self._operations.get(t)

    def stream_for(self, t: str) -> StreamingOperation | None:
        """The streaming operation routing `t`, or None. A unary route answers None here."""
        return self._streams.get(t)

    def admission_class_for(self, t: str) -> AdmissionClass:
        """The class the readiness drain judges `t` by.

        `IN_FLIGHT` for a unary route and for a type nothing routes, in both cases because there is
        nothing whose duration a caller could control: a unary operation answers once and an
        unrouted type answers `501` before any operation runs.
        """
        return self._admission.get(t, AdmissionClass.IN_FLIGHT)

    def routed(self) -> frozenset[str]:
        """Every message type this registry routes, in either form."""
        return frozenset(self._operations) | frozenset(self._streams)

    def unrouted_inbound(self) -> Iterator[str]:
        """Every inbound type the catalogue declares that nothing routes yet.

        The gap between the protocol as specified and the runtime as built, in catalogue order.
        Reportable rather than asserted: the tasks that close it are the process manager, the
        filesystem operations and the exposed-port passthrough.
        """
        routed = self.routed()
        for t in self._catalogue.message_types:
            if is_inbound(t, catalogue=self._catalogue) and t not in routed:
                yield t
