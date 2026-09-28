# kiro-classification: public
"""How a suspended Session is reported, and what it costs while it is (R10.4).

R10.4 has two clauses and they are discharged by different things.

1. **The Control_Plane reports the Session lifecycle state as suspended.** That is a write:
   the provider reports a suspended Sandbox, the report is mirrored onto the Session row through
   :mod:`control_plane.lifecycle`, and every response that carries `lifecycleState` reads it from
   there. :func:`record_suspension` is the one entry point for that write.
2. **The Session incurs snapshot storage charges and no compute charges.** That is not a write at
   all. It is a consequence of the anchored suspend semantics — a suspended MicroVM's memory and disk
   live in a snapshot and no vCPU is scheduled — so there is nothing here that *causes* it. What this
   module does is *state* it, as :data:`LIFECYCLE_COST_POSTURE`, total over every lifecycle state and
   asserted at import, so the claim is a value the Cost_Model and the Comparison_Report can read
   rather than a sentence in a document that nothing checks.

## A suspension is a live transition, and that is structural

The write goes through :class:`~control_plane.lifecycle.LifecycleReconciler` like every other
lifecycle write, which means :func:`~control_plane.lifecycle.write_for` chooses the write type from
the mirrored state's terminality and no caller chooses for it. `SUSPENDING` and `SUSPENDED` both
mirror onto live lifecycle states, so a suspension can only ever produce a
:class:`~control_plane.lifecycle.LiveTransition` — the write type that carries no binding key and
therefore cannot delete an Affinity_Key binding.

That is asserted at import rather than left to a test: :data:`SUSPENSION_REPORT_STATES` is checked
against :data:`~control_plane.lifecycle.PROVIDER_STATE_MIRROR`, so a future change that made either
state mirror onto a terminal one would fail the build. It matters because the binding is precisely
what a caller reconnects through, and a suspended Session is the case in which reconnecting is the
whole point: deleting the binding would strand a Sandbox that is still holding the caller's memory
state and is still being paid for as a snapshot.

## Nothing here ends anything

Applying an idle policy and recording its result kill no process and close no terminal. A suspended
Session retains filesystem *and* memory state and may be resumed by nothing more than a request
arriving (R13.2, R10.5), so a suspension that reaped the Sandbox's children would empty the Sandbox
that auto-resume promises is intact. This module holds no provider, so it cannot call `suspend`,
`resume` or `terminate` even by accident; it records what a Sandbox has already done.

## And nothing here resumes anything

R10.5 is the provider's, entirely: the first request the caller delivers to the endpoint is what
resumes the Sandbox, and the orchestrator observes the transition on its next poll rather than
mediating it. The consequence for the reconnect path is R6.20 and it is already implemented —
:data:`~control_plane.api.resolution.LOSER_BRANCHES` sends a suspended Session to
:attr:`~control_plane.api.resolution.LoserBranch.RETURN_CREDENTIAL`, which mints a credential and
leaves the row untouched. This module adds no resume path, so a resolution of a suspended Session
still writes nothing at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from control_plane.lifecycle import (
    PROVIDER_STATE_MIRROR,
    LifecycleReconciler,
    Reconciliation,
)
from control_plane.providers.base import SandboxState, SandboxStatus
from control_plane.state.records import LifecycleState, SessionRecord

__all__ = [
    "LIFECYCLE_COST_POSTURE",
    "SUSPENDED_COST_POSTURE",
    "SUSPENSION_REPORT_STATES",
    "CostPosture",
    "NotASuspensionReport",
    "cost_posture_for",
    "record_suspension",
]


@dataclass(frozen=True, slots=True)
class CostPosture:
    """What a Session is charged for while it holds one lifecycle state.

    Two independent facts rather than one enumerated tier, because R10.4 asserts both halves
    separately — snapshot storage charges *and* no compute charges — and a single tier name would
    make "no compute" something a reader had to infer from a label.
    """

    compute_billed: bool
    snapshot_storage_billed: bool


#: R10.4's second clause, as a value. The one row of the table below that a requirement states
#: directly, named so a test and the Cost_Model can both assert it without restating the pair.
SUSPENDED_COST_POSTURE: Final = CostPosture(
    compute_billed=False, snapshot_storage_billed=True
)

#: A live Sandbox: vCPU is scheduled for it, and there is no suspend snapshot to store.
_RUNNING_COST_POSTURE: Final = CostPosture(
    compute_billed=True, snapshot_storage_billed=False
)

#: No Sandbox exists, so nothing about this Session is billable. Session output artifacts are
#: charged under the artifact retention period rather than against a lifecycle state, which is why
#: `TERMINATED` sits here.
_NO_COST_POSTURE: Final = CostPosture(
    compute_billed=False, snapshot_storage_billed=False
)

#: Every lifecycle state, and what the Session is charged for while it holds that state (R10.4).
#:
#: Total over :class:`~control_plane.state.records.LifecycleState` and asserted at import, so a state
#: added later fails the build rather than falling into a default — the posture
#: :data:`~control_plane.api.resolution.LOSER_BRANCHES` and
#: :data:`~control_plane.lifecycle.PROVIDER_STATE_MIRROR` both take. A default here would be worse
#: than a missing branch: it would silently attribute a cost to a state nobody priced.
#:
#: The rule generating it is one question — does this state hold a MicroVM that is scheduled? —
#: and the three answers are the three constants above. Two rows are worth reading:
#:
#: - `SUSPENDING` is billed for compute, not as a snapshot. Its Sandbox is mid-flush: `/suspend` has
#:   been called and has not returned, so the MicroVM is still running and there is not yet a
#:   snapshot to charge for. This is the same distinction that keeps `SUSPENDING` out of the
#:   resolution branch that treats a Session as reachable.
#: - `PROVISIONING` is billed for compute, because a Sandbox the provider has accepted is billable
#:   before it is useful. That is the same reading that makes a provider-reported `PENDING` mirror
#:   onto `PROVISIONING` rather than back onto `PENDING`.
LIFECYCLE_COST_POSTURE: Final[Mapping[LifecycleState, CostPosture]] = {
    # No Sandbox yet: the row exists and the execution may not even have started.
    LifecycleState.PENDING: _NO_COST_POSTURE,
    LifecycleState.ORCHESTRATING: _NO_COST_POSTURE,
    # A Sandbox exists and is scheduled.
    LifecycleState.PROVISIONING: _RUNNING_COST_POSTURE,
    LifecycleState.STARTING: _RUNNING_COST_POSTURE,
    LifecycleState.RUNNING: _RUNNING_COST_POSTURE,
    LifecycleState.SUSPENDING: _RUNNING_COST_POSTURE,
    # R10.4, and the only row a requirement states outright.
    LifecycleState.SUSPENDED: SUSPENDED_COST_POSTURE,
    LifecycleState.RESUMING: _RUNNING_COST_POSTURE,
    # The outgoing Sandbox of a duration-ceiling handoff is still running while its state is
    # persisted, and the incoming one is provisioning.
    LifecycleState.CONTINUING: _RUNNING_COST_POSTURE,
    LifecycleState.TERMINATING: _RUNNING_COST_POSTURE,
    # Nothing is allocated, which R10.9's release check is what confirms.
    LifecycleState.TERMINATED: _NO_COST_POSTURE,
    LifecycleState.FAILED: _NO_COST_POSTURE,
}

#: The Sandbox states that report a suspension: the transition and the state it settles into.
#:
#: Both are reports of the same event and both are recorded the same way, which is why they are one
#: set rather than two branches. Derived from neither the mirror nor the lifecycle enum, because the
#: pair is a statement about which provider reports belong to a suspension and that is the thing
#: being declared here.
SUSPENSION_REPORT_STATES: Final[frozenset[SandboxState]] = frozenset(
    {SandboxState.SUSPENDING, SandboxState.SUSPENDED}
)

if set(LIFECYCLE_COST_POSTURE) != set(
    LifecycleState
):  # pragma: no cover - import-time invariant
    _unpriced = sorted(
        state.value for state in LifecycleState if state not in LIFECYCLE_COST_POSTURE
    )
    raise AssertionError(f"lifecycle states with no recorded cost posture: {_unpriced}")

if any(
    PROVIDER_STATE_MIRROR[state].is_terminal for state in SUSPENSION_REPORT_STATES  # nosemgrep: is-function-without-parentheses — @property
):  # pragma: no cover - import-time invariant
    # A suspension that mirrored onto a terminal state would be recorded by a TerminalSettlement,
    # which deletes the Affinity_Key binding (R10.16) — and a suspended Session is exactly the one
    # a caller is about to reconnect through (R6.20). Fail the build rather than the reconnect.
    raise AssertionError(
        "a suspension report mirrors onto a terminal lifecycle state, so recording one would "
        "delete the Affinity_Key binding of a Session that is still resumable"
    )


class NotASuspensionReport(ValueError):
    """A provider report that is not a suspension reached the suspension path.

    A defect rather than an operational condition: the orchestrator's suspend observation reaches
    :func:`record_suspension` and every other report reaches
    :meth:`~control_plane.lifecycle.LifecycleReconciler.reconcile`. Refusing keeps this function's
    documented guarantee — that what it writes is always a live transition and never touches a
    binding — true of the function rather than only of the two states it was written for.
    """

    def __init__(self, state: SandboxState) -> None:
        admitted = ", ".join(
            sorted(reported.value for reported in SUSPENSION_REPORT_STATES)
        )
        super().__init__(
            f"{state.value} is not a suspension report; the suspension path admits {admitted}"
        )
        self.state = state


def cost_posture_for(state: LifecycleState) -> CostPosture:
    """What a Session in this lifecycle state is charged for (R10.4).

    A total lookup with no default, so an unpriced state is a `KeyError` at the call site rather than
    a zero cost quietly attributed to it. The import-time check above means that cannot happen for a
    state the model declares.
    """
    return LIFECYCLE_COST_POSTURE[state]


def record_suspension(
    reconciler: LifecycleReconciler, record: SessionRecord, status: SandboxStatus
) -> Reconciliation:
    """Record a provider-reported suspension on the Session row (R10.4).

    Everything about the write — the condition that makes a terminal row absorb it, the reason drawn
    from the provider's own report, the `stateCreatedAt` the state's index key is derived from, and
    the clock — belongs to :class:`~control_plane.lifecycle.LifecycleReconciler` and is not restated
    here. What this function adds is the refusal: only a suspension report may travel this path, and
    both members of :data:`SUSPENSION_REPORT_STATES` mirror onto live states, so the write is a
    :class:`~control_plane.lifecycle.LiveTransition` and the Affinity_Key binding survives it.

    A report arriving after the Session has already reached a terminal state is absorbed and reported
    as :attr:`~control_plane.lifecycle.ReconciliationOutcome.ABSORBED`, not raised. A Reaper that
    terminated a Session for exceeding its suspended duration (R10.7) while a poll was in flight is
    the ordinary way that happens.

    Raises:
        NotASuspensionReport: `status` reports a state that is not a suspension.
        SessionRecordAbsent: the row named by `record` no longer exists.
    """
    if status.state not in SUSPENSION_REPORT_STATES:
        raise NotASuspensionReport(status.state)
    return reconciler.reconcile(record, status)
