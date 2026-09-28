# kiro-classification: public
"""The readiness gate: the mechanism that holds the Sandbox_Protocol handler closed.

R7.8 has two halves. The first is a promise about `/run` — return 200 only once the Sandbox
will accept Sandbox_Protocol requests. The second is a prohibition — before `/run` is
invoked, apply no per-Session configuration. The design makes both hold by "holding the
protocol handler closed until it completes", and this module is that hold.

It is a state machine and not a flag, for a reason worth stating. A boolean set at the end of
`/run` answers "is it ready" but not "why is it not", and the two questions have different
answers with different recoveries: a Sandbox that has not been started yet will serve traffic
shortly, and one that failed its restoration or has been terminated never will. The transport
picks a different response for those two cases, so the gate has to distinguish them. A flag
also has nothing to say about the request already in flight when `/suspend` arrives, and R7.9
requires the flush to happen after new requests stop, not alongside them.

So the gate carries a phase, a table of the transitions that phase admits, and one count per
admission class with a drain wait over the classes a caller names:

- Admission reads the phase and increments the in-flight count **under one lock**, so a
  request cannot be admitted by a phase that changed between the check and the increment.
  That window is the race R7.8 exists to close, and closing it is the whole point of the lock.
- `suspend()` and `terminate()` change the phase first and only then wait for the counts to
  reach zero. Changing it first is what makes the wait finite: no admission can follow it.

## Two admission classes, and why the drain covers one of them

The design's *Admission classes and the readiness drain* settles this and the reasoning is
recorded there rather than restated here. What the module holds is the mechanism:

| Class | What it covers | Drained |
| --- | --- | --- |
| `IN_FLIGHT` | An operation whose duration the Runtime controls: `exec.request` including its streaming form, the `fs.*` operations, `proc.*`, `port.expose`, `session.quiesce` | Yes |
| `LONG_LIVED` | An operation whose duration the caller controls and does not bound: a protocol-driven pseudo-terminal, one admission held from `pty.open` until the peer closes it | No |

`DRAINED_CLASSES` is the set the drain covers, and it is a value rather than a literal inside
`suspend` and `terminate` because `runtime.hooks` declares what each hook waits for and checks
that declaration against what the hook's later steps are required to release. A `DRAINED_CLASSES`
that included `LONG_LIVED` would fail that check at import, which is the structural form of the
design's rule that no step of `/terminate` may await a drain a later step must satisfy.

**`admit` stays content-blind, and reclassification is why it can.** The handler admits before it
decodes, deliberately: refusing a frame in a phase where nothing has been configured is what makes
R7.8's prohibition true, so an admission decision must not depend on the request's content. So
every admission enters `IN_FLIGHT` — `admit` reads the phase and nothing else — and the handler
moves it to `LONG_LIVED` through `Admission.becomes_long_lived` once the decoded route says it is
one. The window in which a pseudo-terminal still counts as in-flight is a decode and a routing
lookup, bounded by the Runtime and not by the caller, so a drain beginning inside that window
waits for it and no longer.

The phases are the Sandbox_Runtime's own, not the provider's `SandboxState`. They overlap in
places and it would be tempting to reuse that enum, but they answer different questions —
`SandboxState` is what the provider observes from outside, this is what the process inside
knows about its own configuration — and a Sandbox can be `RUNNING` to its provider while this
gate is still `STARTING`. That gap is exactly the interval the gate exists to police.
"""

from __future__ import annotations

import asyncio
import enum
from collections.abc import AsyncIterator, Collection, Mapping
from contextlib import asynccontextmanager
from typing import Final

__all__ = [
    "DRAINED_CLASSES",
    "Admission",
    "AdmissionClass",
    "IllegalPhaseTransition",
    "NotServing",
    "ReadinessGate",
    "RuntimePhase",
]


class AdmissionClass(enum.StrEnum):
    """Which of the two classes an admitted Sandbox_Protocol request belongs to.

    The distinction is who bounds the operation's duration, and it is not a matter of degree: a
    streaming `exec.request` ends when the process ends, and `timeoutMs` bounds even that, while a
    pseudo-terminal ends when the operator's shell exits, which is hours away or never.
    """

    #: An operation whose duration the Runtime controls. Drained by `/suspend` and `/terminate`.
    IN_FLIGHT = "in-flight"
    #: An operation whose duration the caller controls and does not bound. Not drained.
    LONG_LIVED = "long-lived"


#: The classes a drain covers. One entry, written as a set for the same reason `_ADMITTING` is:
#: what the drain waits for is a stated set rather than a comparison spelled at each wait, and
#: `runtime.hooks` reads this value when it declares what each hook's drain step awaits.
DRAINED_CLASSES: Final[frozenset[AdmissionClass]] = frozenset(
    {AdmissionClass.IN_FLIGHT}
)


class RuntimePhase(enum.StrEnum):
    """What the Sandbox_Runtime knows about its own readiness to serve the protocol."""

    #: Started, no `/run` yet. No per-Session configuration has been applied (R7.8).
    CLOSED = "closed"
    #: `/run` is executing. Configuration is being applied; the handler is still closed.
    STARTING = "starting"
    #: `/run` returned 200. The only phase that admits a Sandbox_Protocol request.
    SERVING = "serving"
    #: `/suspend` returned. Reopened by `/resume`, which is the auto-resume path (R10.5).
    SUSPENDED = "suspended"
    #: `/run` did not complete — a restoration failure, for instance (R13.7). Terminal here.
    FAILED = "failed"
    #: `/terminate` ran. Terminal.
    TERMINATED = "terminated"


#: The phase that admits protocol traffic. A set of one, written as a set because the
#: admission check reads it rather than comparing against a single member: a future phase that
#: also serves (a drain-but-still-answering state, say) is then one entry here and no edit to
#: the check.
_ADMITTING: Final = frozenset({RuntimePhase.SERVING})

#: Phases from which the runtime will never serve again. The transport reports these
#: differently from the not-yet-ready ones, because the caller's recovery differs.
_TERMINAL: Final = frozenset({RuntimePhase.FAILED, RuntimePhase.TERMINATED})

#: Every transition the gate admits, and no others.
#:
#: `CLOSED -> TERMINATED` is present because the orchestrator may terminate a Sandbox on which
#: `/run` was never invoked, which is the disposal path for an allocated-but-unused Sandbox.
#: `STARTING -> STARTING` and `SERVING -> STARTING` are both absent, and that absence is
#: load-bearing: a second `/run` would regenerate the per-Session unique values R7.12 requires
#: to be generated exactly once, so it is refused rather than absorbed.
_TRANSITIONS: Final[Mapping[RuntimePhase, frozenset[RuntimePhase]]] = {
    RuntimePhase.CLOSED: frozenset({RuntimePhase.STARTING, RuntimePhase.TERMINATED}),
    RuntimePhase.STARTING: frozenset(
        {RuntimePhase.SERVING, RuntimePhase.FAILED, RuntimePhase.TERMINATED}
    ),
    RuntimePhase.SERVING: frozenset({RuntimePhase.SUSPENDED, RuntimePhase.TERMINATED}),
    RuntimePhase.SUSPENDED: frozenset({RuntimePhase.SERVING, RuntimePhase.TERMINATED}),
    RuntimePhase.FAILED: frozenset({RuntimePhase.TERMINATED}),
    RuntimePhase.TERMINATED: frozenset(),
}


class NotServing(RuntimeError):
    """A Sandbox_Protocol request arrived in a phase that does not admit one.

    Carries the phase, and whether that phase is terminal, because the transport chooses its
    response from those two facts: a caller that arrived early should retry, and a caller that
    arrived after termination should not.
    """

    def __init__(self, phase: RuntimePhase, *, reason: str | None = None) -> None:
        self.phase = phase
        self.reason = reason
        detail = f"the Sandbox_Runtime is {phase}, not serving"
        super().__init__(detail if reason is None else f"{detail}: {reason}")

    @property
    def is_terminal(self) -> bool:
        """Whether the runtime will never serve again."""
        return self.phase in _TERMINAL


class IllegalPhaseTransition(RuntimeError):
    """A lifecycle hook was invoked in a phase from which its transition is not admitted.

    This is a defect in whoever invoked the hook, not a condition a caller can recover from by
    retrying, which is why it is distinct from `NotServing`. The commonest cause is a second
    `/run` against one Sandbox.
    """

    def __init__(self, current: RuntimePhase, requested: RuntimePhase) -> None:
        self.current = current
        self.requested = requested
        super().__init__(f"cannot move from {current} to {requested}")


class Admission:
    """One admitted Sandbox_Protocol request, and the class the drain judges it by.

    Yielded by `ReadinessGate.admit` and held for the duration of the request. Its whole public
    surface is one coroutine, `becomes_long_lived`, because there is exactly one thing a caller
    may do with an admission beyond holding it: say that the route it decoded is a stream whose
    end is the caller's decision and not the Runtime's.

    There is no move in the other direction. A stream that has become long-lived does not become
    in-flight again, because the class describes who bounds the operation and that does not change
    half way through one; and a drain that had already stopped counting an admission cannot be
    made to start again without the wait it bounds becoming unbounded retrospectively.
    """

    __slots__ = ("_admission_class", "_gate")

    def __init__(self, gate: ReadinessGate) -> None:
        self._gate = gate
        self._admission_class = AdmissionClass.IN_FLIGHT

    @property
    def admission_class(self) -> AdmissionClass:
        """The class this admission currently counts against."""
        return self._admission_class

    async def becomes_long_lived(self) -> None:
        """Move this admission out of the drained class. Idempotent.

        Called once the decoded route says the operation is one whose duration the caller
        controls. Idempotent because a transport may drive the same route through more than one
        code path and a second declaration of the same fact is not an error.
        """
        await self._gate.reclassify(self, AdmissionClass.LONG_LIVED)

    def _classified(self, into: AdmissionClass) -> None:
        """Record the class the gate has just moved this admission into.

        The gate's to call and no one else's: it is the second half of a transfer whose first
        half is the two counter adjustments, and both happen under the gate's lock so that no
        drain can observe an admission counted twice or not at all.
        """
        self._admission_class = into


class ReadinessGate:
    """The phase of one Sandbox_Runtime, and the admission of protocol requests against it.

    Every method is a coroutine, including the ones that only read, because reading the phase
    and acting on it has to be one atomic step and the lock is the thing that makes it one.
    `phase` is the exception: it is a plain property, for reporting rather than for deciding.
    """

    def __init__(self) -> None:
        self._phase = RuntimePhase.CLOSED
        self._reason: str | None = None
        self._counts: dict[AdmissionClass, int] = dict.fromkeys(AdmissionClass, 0)
        self._lock = asyncio.Lock()
        #: One event per class rather than one for the whole gate, because `drain` waits for the
        #: classes it was given and a single event could not distinguish them.
        self._drained: dict[AdmissionClass, asyncio.Event] = {
            admission_class: asyncio.Event() for admission_class in AdmissionClass
        }
        for drained in self._drained.values():
            drained.set()

    @property
    def phase(self) -> RuntimePhase:
        """The current phase. For reporting; an admission decision uses `admit`."""
        return self._phase

    @property
    def reason(self) -> str | None:
        """Why the runtime is in a failed phase, where it is in one."""
        return self._reason

    @property
    def in_flight(self) -> int:
        """How many admitted requests of the drained class have not finished."""
        return self._counts[AdmissionClass.IN_FLIGHT]

    @property
    def long_lived(self) -> int:
        """How many admitted long-lived streams are open. Reported, never drained."""
        return self._counts[AdmissionClass.LONG_LIVED]

    @asynccontextmanager
    async def admit(self) -> AsyncIterator[Admission]:
        """Admit one Sandbox_Protocol request, or raise `NotServing`.

        The check and the in-flight increment happen under one lock, so the phase cannot change
        between them: a request is either admitted by a serving gate and counted, or refused.
        Nothing between those two outcomes exists, which is what makes a pre-readiness request
        a defined response rather than a race.

        **Nothing here reads the request.** The phase is the whole of the decision, and it has to
        be: refusing before decoding is what makes R7.8's prohibition true, so an admission that
        consulted the body would have parsed attacker-supplied bytes in a phase where nothing has
        been configured. Every admission therefore enters `IN_FLIGHT`, and the yielded `Admission`
        is how a caller that has since decoded a long-lived route says so.
        """
        async with self._lock:
            if self._phase not in _ADMITTING:
                raise NotServing(self._phase, reason=self._reason)
            admission = Admission(self)
            self._counts[AdmissionClass.IN_FLIGHT] += 1
            self._drained[AdmissionClass.IN_FLIGHT].clear()
        try:
            yield admission
        finally:
            async with self._lock:
                released = admission.admission_class
                self._counts[released] -= 1
                self._settle(released)

    async def reclassify(self, admission: Admission, into: AdmissionClass) -> None:
        """Move one admission between classes. `Admission.becomes_long_lived` is the caller.

        Both counter adjustments and the admission's own record of its class happen under one
        lock and with nothing awaited between them, so a concurrent `drain` sees the admission in
        exactly one class. A cancellation can only land on the way into the lock, before anything
        has moved.
        """
        async with self._lock:
            current = admission.admission_class
            if current is into:
                return
            self._counts[current] -= 1
            self._counts[into] += 1
            # The gate owns the transfer; `_classified` is the half of it the admission holds.
            admission._classified(into)
            self._settle(current)
            self._settle(into)

    async def drain(
        self, classes: Collection[AdmissionClass] = DRAINED_CLASSES
    ) -> None:
        """Wait until every admission of each named class has finished.

        Bounded only by the caller having closed the gate first: with the phase changed no further
        admission is possible, so the counts only fall. Called with the gate still serving it is a
        wait on traffic that is still arriving, which is why both hooks change the phase first and
        why this method does not do it for them.

        Waiting on the events in sequence is sufficient for the same reason. A class that has
        reached zero cannot leave zero again while the gate is closed, so an earlier class cannot
        be un-drained by the time a later one finishes.
        """
        for admission_class in classes:
            await self._drained[admission_class].wait()

    def _settle(self, admission_class: AdmissionClass) -> None:
        """Set or clear one class's drain event to match its count. Callers hold the lock."""
        drained = self._drained[admission_class]
        if self._counts[admission_class] == 0:
            drained.set()
        else:
            drained.clear()

    async def begin_start(self) -> None:
        """`/run` has begun. Configuration application starts now and not before (R7.8)."""
        async with self._lock:
            self._move_to(RuntimePhase.STARTING)

    async def finish_start(self) -> None:
        """`/run` completed. The handler opens, and only now may `/run` return 200 (R7.8)."""
        async with self._lock:
            self._move_to(RuntimePhase.SERVING)

    async def fail_start(self, reason: str) -> None:
        """`/run` did not complete. The handler stays closed and the reason is retained.

        `reason` is the identifying reason R13.7 requires the non-200 to carry, held here as
        well as returned, so that a protocol request arriving afterwards is refused with the
        same explanation rather than a bare "not ready".
        """
        async with self._lock:
            self._reason = reason
            self._move_to(RuntimePhase.FAILED)

    async def suspend(
        self, *, drains: Collection[AdmissionClass] = DRAINED_CLASSES
    ) -> None:
        """Stop accepting new protocol requests and wait for the admitted ones to finish.

        The phase changes before the wait. That ordering is R7.9's first clause and it is also
        what bounds the wait: with the gate closed no further request can be admitted, so the
        counts only fall. Repeating `/suspend` on an already suspended runtime is absorbed,
        because a hook may be delivered more than once.

        `drains` is what the wait covers, defaulting to `DRAINED_CLASSES`. It is a parameter
        because the caller is the one that knows what its own later steps are required to release,
        and `runtime.hooks` passes the value it has checked against that. An open pseudo-terminal
        is not in the default set, which is R7.9's "the wait covers in-flight requests only":
        suspension proceeding while a terminal is open is the defined behaviour, because the
        terminal's descriptors and shell state are memory and memory survives suspension (R13.2).
        """
        async with self._lock:
            if self._phase is RuntimePhase.SUSPENDED:
                return
            self._move_to(RuntimePhase.SUSPENDED)
        await self.drain(drains)

    async def resume(self) -> None:
        """Reopen the handler after `/resume` has refreshed what it needs to refresh.

        Absorbed when already serving, for the same delivery reason as `suspend`.
        """
        async with self._lock:
            if self._phase is RuntimePhase.SERVING:
                return
            self._move_to(RuntimePhase.SERVING)

    async def terminate(
        self, *, drains: Collection[AdmissionClass] = DRAINED_CLASSES
    ) -> None:
        """Close the handler for good and wait for admitted requests of `drains` to finish.

        Idempotent: `terminate` is the one hook the orchestrator and the Reaper may both
        invoke, and R10.7 requires that to be safe.

        Here the default set is a correctness condition rather than an economy. The step that
        closes an open pseudo-terminal runs *after* this wait — it is the shutdown inside
        `/terminate`'s own artifact step — so a wait that included `LONG_LIVED` would sit in front
        of the only thing that could release it, which is not a slow hook but a deadlock holding a
        billable Sandbox. `runtime.hooks` enforces that at import over the value it passes here.
        """
        async with self._lock:
            if self._phase is RuntimePhase.TERMINATED:
                return
            self._move_to(RuntimePhase.TERMINATED)
        await self.drain(drains)

    def _move_to(self, requested: RuntimePhase) -> None:
        """Apply a transition, or raise. Callers hold the lock."""
        if requested not in _TRANSITIONS[self._phase]:
            raise IllegalPhaseTransition(self._phase, requested)
        self._phase = requested
