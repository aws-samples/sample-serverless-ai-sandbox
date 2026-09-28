# kiro-classification: public
"""The four lifecycle hook endpoints (R7.7), and the gate transitions around them.

R7.7 is one sentence — the runtime implements `/run`, `/resume`, `/suspend` and `/terminate` —
and this module is the four endpoints it names. What each hook *does* between its transitions
is separate work: the run hook's configuration fetch, per-Session value generation and state
restoration, and the suspend, resume and terminate hooks' flush, egress refresh and artifact
write. Those arrive as their own tasks. What is here is the part that cannot be theirs, because
it is the same in all four: the readiness transition, and its ordering against the work.

The ordering is the design's, and in three of the four hooks it is not interchangeable:

- **`/run` opens the gate last.** Configuration is applied while the handler is still closed,
  and 200 is returned only after it opens. That is both halves of R7.8 in one sequence, and
  reversing any two steps breaks one of them.
- **`/suspend` closes the gate first**, then flushes. R7.9 orders it that way — stop accepting
  requests, then flush pending writes — and the reason is that flushing while a request could
  still be writing does not flush anything in particular. The gate's own drain wait means the
  flush also happens after the admitted requests have finished, not merely after new ones stop.
- **`/resume` refreshes before it opens.** R7.10 has the refresh complete before 200, and the
  gate opening after it means no request can be served against a stale egress identity. The
  client's own credential is untouched here; it is a different family and a different lifetime.
- **`/terminate` closes the gate first**, then writes artifacts, for the same reason `/suspend`
  flushes second.

## The drain, and the one ordering rule that is checked rather than described

Both draining hooks wait on admissions, and the design fixes what that wait covers: in-flight
requests and not long-lived streams. `/terminate` is where getting it wrong is not a slow hook but
a deadlock — the step that closes an open pseudo-terminal is the artifact step, which runs *after*
the wait, so a wait that included streams would sit in front of the only thing that could release
it, and would hold a billable Sandbox while it did. The design states the rule as: no step of
`/terminate` may await a drain that a later step of `/terminate` is required to satisfy.

That rule is a declaration and a check here rather than a comment. `SUSPEND_SEQUENCE` and
`TERMINATE_SEQUENCE` name each step and what it awaits and releases; `drain_ordering_violations`
computes the rule over them; and `_enforce_drain_ordering` runs at import, so a sequence in
violation stops the runtime starting. The declaration is load-bearing because the drain step's
`awaits` is the value the gate is handed — widening it to cover long-lived streams does not
produce a hook that hangs, it produces a module that will not import. `QUIESCE_SEQUENCE` is
declared and checked here too, for the same reason and not because `session.quiesce` is a hook: it
is `runtime.continuation`'s sequence, and it closes the gate from inside an admission of the very
class a drain would wait for.

The work each hook delegates to is `LifecycleActions`. It is a Protocol rather than a base
class because the runtime holds one implementation and the tests hold another, and neither
needs to inherit anything from the other. Its four method names are the design's own phrasing
for the four steps, so that the task that implements them is filling in a named seam rather
than choosing one.

Each hook also records what it did, under the log group and stream that identify the Session
(R14.1). `runtime.observability` owns both names and decides what a record may carry; what is
here is only the placement, and the placement is the same in all four: after the transitions,
before the return. A record emitted before the transition it describes would report an intention
rather than an outcome, and would be the only account of a hook that then failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Final, Protocol

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from runtime.observability import LogLevel, SessionLogEmitter
from runtime.readiness import (
    DRAINED_CLASSES,
    AdmissionClass,
    IllegalPhaseTransition,
    ReadinessGate,
)

__all__ = [
    "HOOK_PATHS",
    "QUIESCE_SEQUENCE",
    "SUSPEND_SEQUENCE",
    "TERMINATE_SEQUENCE",
    "DrainOrdering",
    "HookStep",
    "LifecycleActions",
    "LifecycleHooks",
    "RestorationFailure",
    "drain_ordering_violations",
]

#: The four hook paths, as the provider invokes them.
HOOK_PATHS: Final = (
    "/aws/lambda-microvms/runtime/v1/run",
    "/aws/lambda-microvms/runtime/v1/suspend",
    "/aws/lambda-microvms/runtime/v1/resume",
    "/aws/lambda-microvms/runtime/v1/terminate",
)


@dataclass(frozen=True, slots=True)
class HookStep:
    """One step of a lifecycle hook, and its relationship to the readiness drain.

    `awaits` is the set of admission classes this step waits to reach zero. `releases` is the set
    it is *required to* release — not the set it happens to touch, but the classes whose only
    releaser inside the hook is this step.
    """

    name: str
    awaits: frozenset[AdmissionClass] = field(default_factory=frozenset)
    releases: frozenset[AdmissionClass] = field(default_factory=frozenset)


class DrainOrdering(RuntimeError):
    """A hook was declared with a drain in front of the step that has to release it.

    Raised at import and never at request time, for the same reason
    `runtime.operations.UnroutableMessageType` is: it is a defect in this module's own ordering,
    and a runtime whose `/terminate` deadlocks should refuse to start rather than hold a billable
    Sandbox open the first time someone opens a pseudo-terminal.
    """

    def __init__(self, hook: str, violations: tuple[str, ...]) -> None:
        self.hook = hook
        self.violations = violations
        super().__init__(
            f"{hook} awaits a drain a later step must satisfy: {violations}"
        )


def drain_ordering_violations(steps: tuple[HookStep, ...]) -> tuple[str, ...]:
    """Every step of `steps` that awaits an admission class a later step is required to release.

    The design's rule for `/terminate` is that no step may await a drain that a later step of
    `/terminate` is required to satisfy, and this is that rule as a computation over the declared
    sequence rather than as a comment beside it. A single-class drain — one that waited for the
    long-lived streams as well as the in-flight requests — is exactly what this returns a violation
    for, because the step that closes an open pseudo-terminal comes after the wait.
    """
    violations: list[str] = []
    for index, step in enumerate(steps):
        later = frozenset[AdmissionClass]().union(
            *(subsequent.releases for subsequent in steps[index + 1 :])
        )
        overlap = step.awaits & later
        if overlap:
            releasers = ", ".join(
                subsequent.name
                for subsequent in steps[index + 1 :]
                if subsequent.releases & overlap
            )
            violations.append(
                f"{step.name!r} awaits {sorted(overlap)}, released only by {releasers!r}"
            )
    return tuple(violations)


#: `/suspend`, as R7.9 orders it. The flush releases nothing — a suspended Session keeps its
#: processes and its pseudo-terminals, because R13.2 and R10.5 say a resume restores them — so the
#: only thing that could put this sequence in violation is widening what the drain covers.
SUSPEND_SEQUENCE: Final = (
    HookStep(
        "close the handler and wait for the admitted requests", awaits=DRAINED_CLASSES
    ),
    HookStep("flush pending writes and close outbound connections"),
)

#: `/terminate`, as R13.3 orders it. The second step is where `LifecycleActions.persist_artifacts`
#: ends the Session's running work, and closing every open pseudo-terminal is part of that: it is
#: the only releaser of a long-lived admission anywhere in the hook. That is what makes the
#: declaration load-bearing rather than descriptive — the drain step is handed `awaits` verbatim,
#: so a `DRAINED_CLASSES` widened to include `LONG_LIVED` would put the wait in front of its own
#: releaser and this module would refuse to import.
TERMINATE_SEQUENCE: Final = (
    HookStep(
        "close the handler for good and wait for the admitted requests",
        awaits=DRAINED_CLASSES,
    ),
    HookStep(
        "end the Session's running work and write the artifacts",
        releases=frozenset({AdmissionClass.LONG_LIVED}),
    ),
)


#: `session.quiesce`, the orchestrator's ask at the duration ceiling (R10.11). Not a hook, but the
#: same rule applies to it and for a sharper reason: the message is itself an in-flight admission,
#: so a close step declared to await `DRAINED_CLASSES` would be waiting for its own release. That
#: is why the first step awaits nothing, and why the emptiness is declared here where
#: `drain_ordering_violations` can refuse the alternative at import rather than left as a comment
#: beside the call. `runtime.continuation` is handed this step's `awaits` verbatim.
QUIESCE_SEQUENCE: Final = (
    HookStep("close the handler to new requests"),
    HookStep(
        "acknowledge, releasing this message's own admission",
        releases=DRAINED_CLASSES,
    ),
)


def _enforce_drain_ordering() -> None:
    """Check every declared sequence at import. See `DrainOrdering`."""
    for hook, steps in (
        ("/suspend", SUSPEND_SEQUENCE),
        ("/terminate", TERMINATE_SEQUENCE),
        ("session.quiesce", QUIESCE_SEQUENCE),
    ):
        violations = drain_ordering_violations(steps)
        if violations:
            raise DrainOrdering(hook, violations)


_enforce_drain_ordering()

#: The body of a hook that succeeded. Hook responses are read by the provider and the
#: orchestrator for their status, not their content, so this is a token rather than a document.
_OK_BODY: Final = "ok"


class RestorationFailure(Exception):
    """Restoring previously persisted state into the filesystem failed (R13.7).

    Distinct from every other failure the run hook can meet, because R13.7 fixes what happens
    next: a non-200 carrying a reason that identifies the restoration failure, which the
    Control_Plane records against the Session. The reason is therefore part of the exception
    rather than a log line, since it has to travel back over the wire.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class LifecycleActions(Protocol):
    """The substantive work of the four hooks, which the hooks sequence but do not perform."""

    async def apply_configuration(self, payload: bytes) -> None:
        """Apply the per-Session configuration delivered in the run hook payload.

        Covers the whole of what the run hook does between its gate transitions: reading the
        payload inline or fetching it by reference when it exceeds the provider-declared limit
        (R7.11), generating every per-Session unique value (R7.12), and restoring previously
        persisted state (R13.4).

        Raises:
            RestorationFailure: state restoration failed, and this is the identifying reason
                the hook must report (R13.7).
        """
        ...

    async def quiesce_and_flush(self) -> None:
        """Flush pending filesystem writes and close outbound connections (R7.9)."""
        ...

    async def refresh_egress_identity(self) -> None:
        """Refresh the Sandbox's own egress identity (R7.10)."""
        ...

    async def persist_artifacts(self) -> None:
        """Write the configured Session output artifacts to the State_Store (R13.3)."""
        ...


class LifecycleHooks:
    """The four endpoints, bound to one gate and one set of actions."""

    def __init__(
        self,
        *,
        gate: ReadinessGate,
        actions: LifecycleActions,
        emitter: SessionLogEmitter | None = None,
    ) -> None:
        """Bind the gate, the actions and — where the deployment named one — the log emitter.

        `emitter` is optional and absent means this runtime emits no lifecycle records. That is a
        truthful configuration rather than a convenient one: the emitter's whole content is a
        Tenant, a Session and a generation the provider carried in (R14.1), and a runtime that was
        told none of them has no Session to identify. It is *not* a way to run without logs in a
        deployment — `runtime.observability.SessionIdentity.from_environment` fails loudly when the
        environment is incomplete, so a deployed Sandbox reaches this constructor with an emitter
        or does not reach it at all.

        Nothing about a hook's behaviour depends on it. Each hook emits after its transitions and
        before it returns, so the record describes what happened rather than what was about to, and
        `SessionLogEmitter.emit` cannot raise into the transition it is describing.
        """
        self._gate = gate
        self._actions = actions
        self._emitter = emitter

    def _emit(
        self,
        hook: str,
        *,
        outcome: str,
        status: HTTPStatus,
        level: LogLevel = LogLevel.INFO,
        reason: str | None = None,
    ) -> None:
        """Record one hook transition under the Session-identifying stream (R14.1).

        Every field here is drawn from `runtime.observability.EMITTABLE_FIELDS`, which is what
        keeps a hook from logging something the boundary does not admit: a name outside that set
        raises, and these five are literals rather than caller-supplied strings.

        `phase` is read from the gate rather than assumed from the hook, because the two can
        differ — a refused transition leaves the phase where it was, and that is the fact worth
        recording.
        """
        if self._emitter is None:
            return
        self._emitter.emit(
            f"hook.{hook}",
            level=level,
            detail={
                "hook": hook,
                "outcome": outcome,
                "status": int(status),
                "phase": str(self._gate.phase),
                "reason": reason,
            },
        )

    async def run(self, request: Request) -> Response:
        """`/run`: apply configuration behind a closed handler, then open it and return 200.

        A `/run` arriving in a phase that does not admit it — most importantly a second `/run`
        against one Sandbox, which would regenerate the values R7.12 requires to be generated
        once — is refused with `409` and changes nothing, rather than being absorbed.
        """
        try:
            await self._gate.begin_start()
        except IllegalPhaseTransition as exc:
            self._emit(
                "run",
                outcome="refused",
                status=HTTPStatus.CONFLICT,
                level=LogLevel.WARNING,
                reason=str(exc),
            )
            return PlainTextResponse(str(exc), status_code=HTTPStatus.CONFLICT)

        payload = await request.body()
        try:
            await self._actions.apply_configuration(payload)
        except RestorationFailure as exc:
            await self._gate.fail_start(exc.reason)
            self._emit(
                "run",
                outcome="failed",
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                level=LogLevel.ERROR,
                reason=exc.reason,
            )
            return PlainTextResponse(
                exc.reason, status_code=HTTPStatus.INTERNAL_SERVER_ERROR
            )
        except Exception as exc:  # noqa: BLE001 - see the comment: fail closed, never leak
            # Every other failure also has to leave the gate closed and the reason recorded.
            # Letting it propagate would return 500 with the gate stuck in `STARTING`, which is
            # a phase that admits no protocol request and no further hook: the Sandbox would be
            # unreachable and unterminatable rather than failed.
            await self._gate.fail_start(f"{type(exc).__name__}: {exc}")
            self._emit(
                "run",
                outcome="failed",
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                level=LogLevel.ERROR,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return PlainTextResponse(
                f"{type(exc).__name__}: {exc}",
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        await self._gate.finish_start()
        self._emit("run", outcome="serving", status=HTTPStatus.OK)
        return PlainTextResponse(_OK_BODY, status_code=HTTPStatus.OK)

    async def suspend(self, request: Request) -> Response:
        """`/suspend`: close the handler and drain, then flush and close connections (R7.9).

        The drain covers what `SUSPEND_SEQUENCE`'s first step declares it covers, which is the
        in-flight requests and not the long-lived streams: an open pseudo-terminal does not hold
        suspension off, because its descriptors and shell state are memory and memory survives a
        suspension (R13.2). The caller's next keystroke is a request arriving at a suspended
        Session, which is the auto-resume path R10.5 already specifies.
        """
        close, _flush = SUSPEND_SEQUENCE
        await self._gate.suspend(drains=close.awaits)
        await self._actions.quiesce_and_flush()
        self._emit("suspend", outcome="suspended", status=HTTPStatus.OK)
        return PlainTextResponse(_OK_BODY, status_code=HTTPStatus.OK)

    async def resume(self, request: Request) -> Response:
        """`/resume`: refresh the egress identity, then reopen the handler (R7.10)."""
        await self._actions.refresh_egress_identity()
        try:
            await self._gate.resume()
        except IllegalPhaseTransition as exc:
            self._emit(
                "resume",
                outcome="refused",
                status=HTTPStatus.CONFLICT,
                level=LogLevel.WARNING,
                reason=str(exc),
            )
            return PlainTextResponse(str(exc), status_code=HTTPStatus.CONFLICT)
        self._emit("resume", outcome="serving", status=HTTPStatus.OK)
        return PlainTextResponse(_OK_BODY, status_code=HTTPStatus.OK)

    async def terminate(self, request: Request) -> Response:
        """`/terminate`: close the handler for good and drain, then write artifacts (R13.3).

        The drain is `TERMINATE_SEQUENCE`'s first step and it is handed that step's declared
        `awaits`, which is the mechanism rather than the documentation: the second step is the only
        releaser of a long-lived admission in the hook, so a drain declared to cover that class
        would be a wait in front of its own releaser and `drain_ordering_violations` refuses the
        sequence at import.
        """
        close, _work = TERMINATE_SEQUENCE
        await self._gate.terminate(drains=close.awaits)
        await self._actions.persist_artifacts()
        self._emit("terminate", outcome="terminated", status=HTTPStatus.OK)
        return PlainTextResponse(_OK_BODY, status_code=HTTPStatus.OK)
