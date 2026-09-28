# kiro-classification: public
"""The runtime side of the duration-ceiling handoff: `session.quiesce` (R10.11).

R10.11 is the orchestrator's requirement — persist the declared path set, provision a replacement
that restores it — and the design's *Duration ceiling continuation* sequence gives this runtime one
step of it: `protocol: quiesce (stop accepting new work)`, delivered as the catalogue's one
`orchestrator-to-runtime` message with an empty body. `control_plane.orchestrator.continuation`'s
`SandboxQuiesce` is the other end of the seam, and it asks for exactly that and reports whether the
Sandbox acknowledged.

So this is not `runtime.quiesce`, which is the `/suspend` hook's flush (R7.9). Nothing is flushed
here and nothing is stopped: the archive is read by `/terminate`, which the orchestrator invokes
next and which ends the Session's work before it reads the tree. Quiesce is what turns a request
arriving at the ceiling into a clean refusal instead of a half-served one.

**Why it awaits nothing.** `session.quiesce` is admitted as `IN_FLIGHT` like every other protocol
request, so it is itself one of the admissions a drain waits for; a handler that closed the gate
*and drained* would be waiting for its own release. `runtime.hooks.QUIESCE_SEQUENCE` declares that
emptiness and `drain_ordering_violations` refuses the alternative at import, which is the same
machinery `/suspend` and `/terminate` are held to rather than a second rule for this one message.

**Why it closes the gate rather than terminating it.** The gate has one non-terminal closure and
this uses it, so a request arriving during the handoff is `503` — time is the recovery, and the
Session returns at the next generation. `410` is the other option and it is wrong here: it sends
the Client_SDK to re-resolve (R9.12) a Sandbox that is still there, and `/terminate` has not run.

**Why the acknowledgement is a reply count of zero.** The catalogue declares no reply type for
`session.quiesce`, and inventing one would be a change to `protocol/messages.yaml` made to carry an
acknowledgement the transport already carries: a streaming operation that yields nothing is
answered `204 No Content` over `POST /protocol`, which is the acknowledgement
`SandboxQuiesce.quiesce` reports.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Final

from protocol.codec.values import Message
from runtime.hooks import QUIESCE_SEQUENCE
from runtime.operations import OperationRegistry, OperationReply
from runtime.readiness import ReadinessGate

__all__ = [
    "SESSION_QUIESCE",
    "SessionQuiesce",
    "register_continuation_operations",
]

#: The one `orchestrator-to-runtime` type the catalogue declares (R10.11).
SESSION_QUIESCE: Final = "session.quiesce"


class SessionQuiesce:
    """The `session.quiesce` operation over one readiness gate (R10.11)."""

    def __init__(self, *, gate: ReadinessGate) -> None:
        self._gate = gate

    def register(self, registry: OperationRegistry) -> None:
        """Route `session.quiesce` onto this operation.

        A streaming registration in the default `IN_FLIGHT` class, which is both what
        `runtime.readiness`'s admission table already declares for this type and the form that
        admits a reply count of zero.
        """
        registry.register_stream(SESSION_QUIESCE, self.quiesce)

    async def quiesce(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Stop accepting new protocol requests, and answer with no message.

        The gate is handed `QUIESCE_SEQUENCE`'s first step verbatim, so what this awaits is the
        declared and import-checked value rather than one spelled here.

        An illegal transition is unreachable, and redelivery never reaches here: only a serving
        gate admits a request at all, so `SERVING -> SUSPENDED` is the only transition this can
        attempt and a second `session.quiesce` is refused `503` by the gate it already closed.
        That refusal is a truthful answer to the ask, and the orchestrator seam records an
        unacknowledged quiesce rather than abandoning the handoff over one.
        """
        close, _acknowledge = QUIESCE_SEQUENCE
        await self._gate.suspend(drains=close.awaits)
        # A generator that yields nothing, written as an empty iteration rather than an
        # unreachable `yield`: the acknowledgement is the reply count, and this count is zero.
        nothing: tuple[OperationReply, ...] = ()
        for reply in nothing:
            yield reply


def register_continuation_operations(
    registry: OperationRegistry, *, gate: ReadinessGate
) -> SessionQuiesce:
    """Route `session.quiesce` onto a `SessionQuiesce` over `gate`, and return it."""
    operation = SessionQuiesce(gate=gate)
    operation.register(registry)
    return operation
