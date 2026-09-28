# kiro-classification: public
"""The Reaper: one bounded index query per shard, four reap classifications, and cleanup layer 2.

R10.8 requires the Reaper to run on a schedule and to terminate every Sandbox whose recorded Session
has exceeded a configured limit, **including Sandboxes whose Session_Orchestrator execution has
failed**. That last clause is the design problem, and the answer is the one thing this module is
careful about: it shares no state source with the orchestration it backstops.

- **State source.** :data:`~control_plane.state.table.DEADLINE_INDEX`, read directly. Not Step
  Functions execution history, not `ListExecutions`, not an in-memory registry. A Session row exists
  before provisioning is attempted (R6.6), so every Sandbox that could exist has a row this sweep can
  find — including one created by a Control_Plane invocation that crashed before starting an
  execution at all.
- **Step Functions APIs used: none.** There is no such client on :class:`Reaper`, so a sweep cannot
  call `StartExecution`, `DescribeExecution` or `ListExecutions` even by accident.
- **Progression through time.** Independent scheduled invocations. There is no in-flight state to
  lose, which is what makes the Reaper survive the failure mode that stops an execution.

## A sweep is one bounded query per shard, and that is a property of the projection

:meth:`Reaper.sweep` issues exactly one :meth:`DeadlineIndexQuery.due_rows` per shard and **no read
per due row**. That is only possible because `deadline-index` projects, by deliberate choice, exactly
what classifying and settling a due row needs: the Session's keys, `tenantId`, `lifecycleState`,
`createdAt`, `sandboxHandle`, `affinityKeyDigest` and `orchestrationExecutionArn`.
:data:`REQUIRED_PROJECTION` names what this module reads and is checked against
:data:`~control_plane.state.table.DEADLINE_INDEX` at import, so a future attribute this sweep starts
depending on fails the build here rather than becoming a `GetItem` per row in a deployment.

`createdAt` is the one entry that looks gratuitous and is not. A terminal write must supply
`stateCreatedAt`, which is `<lifecycleState>#<createdAt>`, and DynamoDB cannot compose a string in an
update expression — so without `createdAt` projected the terminal write would need the full row.

The index holds only Sessions with outstanding work, because a global secondary index is sparse and
:meth:`~control_plane.lifecycle.SessionLifecycleStore.settle_terminal_state` removes `reapDeadline`.
So what one query is bounded *against* is the overdue set, not the deployment's history.

## Why classification is a table over lifecycle states rather than a chain of `if`s

`reapDeadline` is the **earliest** of the maximum-duration deadline, the suspended-duration deadline,
the budget deadline and the connector drain deadline. Collapsing them is what makes the query one
bounded range scan; the cost is that a due row does not say *which* deadline fired, and the design's
answer is that "the reason for the deadline is recoverable from the other attributes on the row".

:data:`DEADLINE_SOURCE` is that recovery, and it is **total over
:class:`~control_plane.state.records.LifecycleState` with no default**, asserted at import — the shape
:data:`~control_plane.api.resolution.LOSER_BRANCHES`,
:data:`~control_plane.lifecycle.PROVIDER_STATE_MIRROR` and
:data:`~control_plane.suspension.LIFECYCLE_COST_POSTURE` all take. A default here would be worse than
a missing branch twice over: a lifecycle state added later would either be swept under a reason
nobody chose, or silently skipped and left running and billable. So it fails the build instead.

The classification is deliberately consistent with
:data:`~control_plane.orchestrator.definition.GOVERNING_BRANCHES`, which is the orchestrator's table
over the same territory keyed on the *provider's* enum. `SUSPENDED` keeps polling there and is a
reap reason here, and the two do not contradict: that comment says in as many words that the
suspended-duration limit belongs to the Reaper (R10.7).

## The orphan window, and why the signal is the execution ARN

`orchestrationExecutionArn` is written by
:meth:`~control_plane.api.creation.SessionRowStore.mark_orchestration_started`, whose docstring fixes
the window exactly: the attribute "is absent only in the orphan window between the row write and
`StartExecution`". So its **absence** is the orphan signal, and not the lifecycle state — a
`PROVISIONING` row always carries an ARN, because only a started execution writes that state.

Absence alone is not enough, because a creating handler at this instant between its two writes has a
row whose ARN is absent and which is about to be governed perfectly well. A due row with no ARN is
therefore classified :attr:`DueRowClass.WITHIN_ORPHAN_WINDOW` until it is older than
`orphan_threshold_seconds`, and the sweep **defers** it: writes nothing, terminates nothing, and
looks again next time. Reaping inside that window would settle a Session `FAILED` while its execution
was starting, and the execution would then provision a Sandbox for a Session already terminal.

Past the threshold the row is :attr:`DueRowClass.ORPHANED` and settles **`FAILED`**, not
`TERMINATED`, which is the edge the design's lifecycle diagram draws as `PENDING → FAILED`, owner
"Reaper orphan pass, execution never started". `FAILED` rather than `TERMINATED` because nothing about
this Session ran: recording it as terminated would claim a lifecycle it never had.

## Idempotence and convergence are the store's, not this module's (R10.7)

`terminate` is the one provider hook the orchestrator and the Reaper may both invoke, and both
components may settle one Session. Nothing here arbitrates that. `provider.terminate` is idempotent
on an already terminal Sandbox, and every terminal write goes through
:meth:`~control_plane.lifecycle.LifecycleReconciler.settle`, whose condition makes the first terminal
state stand and reports the second as
:attr:`~control_plane.lifecycle.ReconciliationOutcome.ABSORBED`. So a sweep that overlaps an
orchestrator teardown converges, and it converges because of a condition expression in the store
rather than because of a check in this file — which is the only kind of arbitration that survives two
components racing.

## Every lifecycle write goes through :mod:`control_plane.lifecycle`

There is exactly one write path out of this module and it is
:meth:`~control_plane.lifecycle.LifecycleReconciler.settle`. It cannot record a live state — a
:class:`~control_plane.lifecycle.TerminalSettlement` refuses one at construction — and it cannot
record a terminal state without deleting the Affinity_Key binding in the same transaction, which is
**cleanup layer 2** (R10.17). The digest is read from the projected `affinityKeyDigest` rather than
recomputed, because the Reaper never sees a raw Affinity_Key and should not be able to.

## What this module cannot do, by the types it holds

- **It does not provision.** :class:`SandboxReclaimer` declares three methods — `terminate`,
  `release_check`, `discover` — so there is no `provision` on the collaborator this module holds.
  `ci/lint_rules/orchestrated_provisioning.py` keeps every initiation of provisioning inside
  `control_plane/orchestrator/tasks.py`, and this module is deliberately not on that allow-list.
- **It mints nothing.** There is no :class:`~control_plane.credentials.ConnectionIssuer` here and no
  reason for one: a settlement records that a Sandbox is gone, and nobody connects to it afterwards.
- **It assembles no Tenant partition key.** :func:`~control_plane.tenancy.pk_for` is the sole
  producer, and :meth:`DueRow.from_projection` derives the key it will write to from the projected
  `tenantId` through that producer, then refuses the row if the derivation disagrees with the
  projected `pk`. The sweep is partitioned by `reapShard` rather than by Tenant, so that check is
  where a row's key and its recorded Tenant are made to agree before anything is written back.
- **It does not quarantine inside the terminal write.** R11.13's quarantine accompanies a `FAILED`
  write and is a **separate step** afterwards, for the reason :mod:`control_plane.lifecycle` gives:
  the claim item sits outside every Tenant partition and is written with a different role, so the two
  cannot share a transaction — and a claim-ledger failure must not block the write that stops a
  billable Sandbox.

## What a sweep leaves to the third layer, and to later tasks

Two dependencies remain shared with the orchestrator: DynamoDB and the provider control API. The
design does not pretend otherwise; it adds a third layer that depends on neither, the idle and
duration policy written onto the MicroVM at provisioning time
(:mod:`control_plane.idle_policy`). Reaper failure is itself detected, by a CloudWatch alarm on
missing data points for :data:`HEARTBEAT_METRIC_NAME` — see :func:`heartbeat_alarm_for`.

The connector drain deadline is the fourth collapsed deadline and it is **not** classified here. Task
10.10 adds it, as one more expired deadline over `egressGeneration` (R12.7), which is why that
attribute is projected and why this module reads it not at all.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final, Protocol

from control_plane.allocation.ledger import SandboxClaimLedger, SandboxNotClaimed
from control_plane.allocation.tags import sandbox_tags
from control_plane.lifecycle import (
    LifecycleReconciler,
    ReconciliationOutcome,
)
from control_plane.providers.base import SandboxHandle, SandboxStatus
from control_plane.state.keys import (
    SEPARATOR,
    SESSION_PREFIX,
    ItemShapeError,
    session_sort_key,
)
from control_plane.state.records import LifecycleState
from control_plane.state.table import (
    DEADLINE_INDEX,
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = [
    "BINDING_CLEANUP_LAYER",
    "DEADLINE_SOURCE",
    "HEARTBEAT_METRIC_NAME",
    "NON_REAPING_CLASSES",
    "REAP_REASONS",
    "REAP_SETTLEMENTS",
    "REQUIRED_PROJECTION",
    "DeadlineIndexQuery",
    "DeadlineSource",
    "DueRow",
    "DueRowClass",
    "HeartbeatAlarm",
    "Reaper",
    "ReaperSettings",
    "RowOutcome",
    "SandboxReclaimer",
    "SweepAction",
    "SweepMetrics",
    "SweepReport",
    "classify",
    "handle_of",
    "heartbeat_alarm_for",
]

_MILLISECONDS_PER_SECOND: Final = 1000

#: The metric whose *absence* is the signal. A Reaper that stops running emits nothing, so the alarm
#: is on missing data points rather than on a value; see :func:`heartbeat_alarm_for`.
HEARTBEAT_METRIC_NAME: Final = "ReaperSweepHeartbeat"

#: Sandboxes reaped, dimensioned by :attr:`RowOutcome.classification`, so a reason that stops firing
#: is visible as a shift in the mix rather than as a fall in one total.
REAPED_METRIC_NAME: Final = "SandboxesReaped"

#: Affinity_Key bindings deleted. Compared against :data:`REAPED_METRIC_NAME` by the dashboard: the
#: two counts move together, so a binding-cleanup regression shows as a divergence.
BINDINGS_DELETED_METRIC_NAME: Final = "AffinityBindingsDeleted"

#: Which of the three cleanup layers this component is (R10.17), as the dimension value the
#: bindings-deleted counter carries. Layer 1 is the orchestrator and layer 3 is DynamoDB TTL.
BINDING_CLEANUP_LAYER: Final = "reaper"


class DeadlineSource(Enum):
    """Which of the collapsed deadlines a row past `reapDeadline` in this lifecycle state hit.

    Three values rather than two, because "the row is due and there is nothing to reap" is still a
    reachable answer. A terminal write removes `reapDeadline` and `deadline-index` is sparse, so a
    settled Session leaves the index — but a row settled after the index query took its snapshot is
    classified from that snapshot, and this is the value that says so. Recognising it is what keeps a
    sweep from calling `terminate` on a Sandbox that is already gone.
    """

    #: The maximum-duration deadline (R10.6).
    MAX_DURATION = "max-duration"
    #: The suspended-duration deadline (R10.7).
    SUSPENDED_DURATION = "suspended-duration"
    #: No deadline is outstanding, because the Session is already settled.
    NONE = "none"


class DueRowClass(Enum):
    """What one due row is, and therefore what the sweep does about it.

    Four reap classifications and two non-reaping ones. The four are the design's list; the two exist
    because "due" and "reapable" are not the same predicate, and a sweep that conflated them would
    either re-terminate settled Sessions or reap a Session whose execution was still starting.
    """

    #: The Session reached its configured maximum duration (R10.6).
    MAX_DURATION_REACHED = "max-duration-reached"
    #: The Session stayed suspended for longer than its configured suspended duration (R10.7).
    SUSPENDED_TOO_LONG = "suspended-too-long"
    #: The Session outlived the deployment-wide configured budget (R10.8).
    BUDGET_EXCEEDED = "budget-exceeded"
    #: The governing execution never started, and the orphan window has closed.
    ORPHANED = "orphaned"
    #: The row is already terminal. Nothing to terminate and no binding left to delete. Rare rather
    #: than routine: a settled row has no `reapDeadline` and so is not in the index, and this is the
    #: narrow case of a row settled between the query's snapshot and this classification.
    ALREADY_SETTLED = "already-settled"
    #: No execution ARN yet, and the row is younger than the orphan threshold. Deferred, not reaped.
    WITHIN_ORPHAN_WINDOW = "within-orphan-window"


#: Every lifecycle state, mapped onto which collapsed deadline a due row in it hit.
#:
#: Total over :class:`~control_plane.state.records.LifecycleState`, asserted at import, with no
#: default. Two rows are worth reading:
#:
#: - `SUSPENDING` sits with `SUSPENDED` rather than with the live states. A row mid-flush is a row
#:   whose caller asked it to stop being scheduled, and the suspended-duration deadline is the one
#:   that governs it from that moment. Classifying it as a maximum-duration reap would report the
#:   wrong reason for the same termination.
#: - `PENDING` and `ORCHESTRATING` are `MAX_DURATION`, not a third source. Their orphanhood is decided
#:   by the *execution ARN*, not by the state, so there is nothing for the state table to say about
#:   them: a `PENDING` row that does carry an ARN is an ordinary Session whose execution has simply
#:   not reached `Provision` yet, and its deadline is its duration.
DEADLINE_SOURCE: Final[Mapping[LifecycleState, DeadlineSource]] = {
    LifecycleState.PENDING: DeadlineSource.MAX_DURATION,
    LifecycleState.ORCHESTRATING: DeadlineSource.MAX_DURATION,
    LifecycleState.PROVISIONING: DeadlineSource.MAX_DURATION,
    LifecycleState.STARTING: DeadlineSource.MAX_DURATION,
    LifecycleState.RUNNING: DeadlineSource.MAX_DURATION,
    LifecycleState.SUSPENDING: DeadlineSource.SUSPENDED_DURATION,
    LifecycleState.SUSPENDED: DeadlineSource.SUSPENDED_DURATION,
    LifecycleState.RESUMING: DeadlineSource.MAX_DURATION,
    LifecycleState.CONTINUING: DeadlineSource.MAX_DURATION,
    LifecycleState.TERMINATING: DeadlineSource.MAX_DURATION,
    LifecycleState.TERMINATED: DeadlineSource.NONE,
    LifecycleState.FAILED: DeadlineSource.NONE,
}

#: The classification each outstanding deadline source produces, once the orphan and budget tests
#: have been answered. Total over the two sources that are not :attr:`DeadlineSource.NONE`.
_DEADLINE_CLASSES: Final[Mapping[DeadlineSource, DueRowClass]] = {
    DeadlineSource.MAX_DURATION: DueRowClass.MAX_DURATION_REACHED,
    DeadlineSource.SUSPENDED_DURATION: DueRowClass.SUSPENDED_TOO_LONG,
}

#: The terminal state each reap classification settles, and the reason the four are not one value.
#:
#: An orphan settles `FAILED`: the design's lifecycle diagram draws `PENDING → FAILED` owned by the
#: Reaper's orphan pass, and a Session whose execution never started never ran, so `TERMINATED` would
#: claim a lifecycle it did not have. The three deadline reaps settle `TERMINATED`, which is the
#: routine end of a Session that did run.
REAP_SETTLEMENTS: Final[Mapping[DueRowClass, LifecycleState]] = {
    DueRowClass.MAX_DURATION_REACHED: LifecycleState.TERMINATED,
    DueRowClass.SUSPENDED_TOO_LONG: LifecycleState.TERMINATED,
    DueRowClass.BUDGET_EXCEEDED: LifecycleState.TERMINATED,
    DueRowClass.ORPHANED: LifecycleState.FAILED,
}

#: The `stateReason` each reap records, naming the requirement it discharges (R14.2). Never blank,
#: because :func:`~control_plane.lifecycle.settlement_for` refuses a transition that records none.
REAP_REASONS: Final[Mapping[DueRowClass, str]] = {
    DueRowClass.MAX_DURATION_REACHED: (
        "terminated by the Reaper: the Session reached its configured maximum duration (R10.6)"
    ),
    DueRowClass.SUSPENDED_TOO_LONG: (
        "terminated by the Reaper: the Session remained suspended for longer than its configured "
        "suspended duration (R10.7)"
    ),
    DueRowClass.BUDGET_EXCEEDED: (
        "terminated by the Reaper: the Session exceeded the configured budget limit (R10.8)"
    ),
    DueRowClass.ORPHANED: (
        "recorded FAILED by the Reaper's orphan pass: no Session_Orchestrator execution was ever "
        "started for this Session, so nothing governs it (R6.10, R10.8)"
    ),
}

#: The two classifications that write nothing and call no provider. Derived from
#: :data:`REAP_SETTLEMENTS` rather than listed, so the two cannot disagree about which
#: classifications reap.
NON_REAPING_CLASSES: Final[frozenset[DueRowClass]] = frozenset(DueRowClass) - frozenset(
    REAP_SETTLEMENTS
)

#: Every State_Store attribute this module reads off a due row. Checked against
#: :data:`~control_plane.state.table.DEADLINE_INDEX` at import, which is what makes "one bounded query
#: and no follow-up read" a property of the code rather than a claim about it.
REQUIRED_PROJECTION: Final[frozenset[str]] = frozenset(
    {
        PARTITION_KEY_ATTRIBUTE,
        SORT_KEY_ATTRIBUTE,
        "tenantId",
        "lifecycleState",
        "createdAt",
        "sandboxHandle",
        "affinityKeyDigest",
        "orchestrationExecutionArn",
        DEADLINE_INDEX.partition_key,
        DEADLINE_INDEX.sort_key,
    }
)

#: What a `deadline-index` query actually returns: the named non-key attributes, plus the table's own
#: key attributes and the index's own, which DynamoDB projects into every index without their being
#: named.
_PROJECTED_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    DEADLINE_INDEX.non_key_attributes
) | {
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    DEADLINE_INDEX.partition_key,
    DEADLINE_INDEX.sort_key,
}

if set(DEADLINE_SOURCE) != set(
    LifecycleState
):  # pragma: no cover - import-time invariant
    _unclassified = sorted(
        state.value for state in LifecycleState if state not in DEADLINE_SOURCE
    )
    raise AssertionError(
        f"lifecycle states with no reap deadline source: {_unclassified}"
    )

if set(_DEADLINE_CLASSES) != set(DeadlineSource) - {
    DeadlineSource.NONE
}:  # pragma: no cover - import-time invariant
    raise AssertionError(
        "an outstanding deadline source has no reap classification, so a due row in it would be "
        "neither reaped nor recognised as needing nothing"
    )

if set(REAP_SETTLEMENTS) | NON_REAPING_CLASSES != set(
    DueRowClass
):  # pragma: no cover - import-time invariant
    raise AssertionError("a due-row classification is neither reaped nor exempted")

if set(REAP_REASONS) != set(
    REAP_SETTLEMENTS
):  # pragma: no cover - import-time invariant
    _reasonless = sorted(
        entry.value for entry in set(REAP_SETTLEMENTS) - set(REAP_REASONS)
    )
    raise AssertionError(f"reap classifications with no recorded reason: {_reasonless}")

if not REQUIRED_PROJECTION <= _PROJECTED_ATTRIBUTES:  # pragma: no cover - import-time
    _unprojected = sorted(REQUIRED_PROJECTION - _PROJECTED_ATTRIBUTES)
    # The Reaper's whole design premise is a single bounded index query. An attribute it needs and
    # the index does not project would be a `GetItem` per due row, which is a sweep whose cost grows
    # with the number of expiring Sessions. Fail the build and decide the projection deliberately.
    raise AssertionError(
        f"the Reaper reads attributes deadline-index does not project: {_unprojected}"
    )


@dataclass(frozen=True, slots=True)
class HeartbeatAlarm:
    """The missing-data alarm that makes a stopped Reaper visible rather than silent.

    Declared as data so `ControlPlaneStack` reads it in phase 12 and the alarm's window cannot drift
    away from the schedule that feeds it — :func:`heartbeat_alarm_for` derives the period from the
    sweep interval, so changing the schedule changes the alarm.
    """

    metric_name: str
    period_seconds: int
    evaluation_periods: int
    treat_missing_data: str


@dataclass(frozen=True, slots=True)
class ReaperSettings:
    """The deployment-configured values a sweep reads, none of them with a literal default.

    Every one is a CDK context value, in the same posture as
    :class:`~control_plane.api.creation.CreationSettings` and
    :class:`~control_plane.orchestrator.OrchestratorSettings`.

    `shard_count` is the modulus :attr:`~control_plane.api.creation.CreationSettings.reap_shard_count`
    assigns rows with, and the two are **one deployment context value read twice**. They have to be:
    the writer picks the shard and the sweep enumerates them, so a sweep with a smaller count would
    never visit the shards above its own range and the Sessions in them would never be reaped. Nothing
    in this module can check that, because the two sides run in different Lambda functions and neither
    reads the other's configuration; what this module does instead is cover *every* shard below the
    count on every sweep, so the only way to lose a row is to misconfigure the pair.

    `session_budget_seconds` is the budget limit of R10.8 — a deployment-wide ceiling on Session age,
    independent of any one Session's `maxDurationSeconds`. It is the third reap classification, and it
    is the one whose deadline the sweep can verify from the projection, since `createdAt` is there.

    `orphan_threshold_seconds` is how long a row may carry no `orchestrationExecutionArn` before the
    orphan pass claims it. It must exceed the time a creating handler can take between writing the row
    and `StartExecution` returning, because inside that interval the absence is not orphanhood.

    `max_rows_per_shard` bounds one query, and therefore bounds one invocation. A bounded invocation
    is what keeps a backlog from turning every sweep into a timeout that reaps nothing at all.

    **A shard's due set is bounded by outstanding work, not by history.** Every terminal write
    removes `reapDeadline` (:attr:`~control_plane.lifecycle.TerminalSettlement.removed_attributes`)
    and `deadline-index` is sparse, so a settled Session leaves the index and no later query returns
    it. So the limit has to accommodate the Sessions a shard can have overdue at once, and not the
    number the deployment has ever ended. What it does not bound is arrival: a shard with more
    genuinely overdue rows than the limit reaps the earliest deadlines first and takes the rest on
    subsequent sweeps, which is the intended behaviour rather than a loss.

    `sweep_interval_seconds` is the scheduler's fixed rate. The sweep does not wait on it; it is read
    to derive the heartbeat alarm's evaluation period.

    `invocation_identity` is this invocation's own identity — the function ARN or request identifier —
    and it is the calling principal R14.2 wants on a lifecycle audit record. It is also what
    :meth:`DueRow.from_projection` builds an :class:`~control_plane.tenancy.AuthenticatedPrincipal`
    from, so the partition key a sweep writes to still comes from
    :func:`~control_plane.tenancy.pk_for`.
    """

    shard_count: int
    session_budget_seconds: int
    orphan_threshold_seconds: int
    max_rows_per_shard: int
    sweep_interval_seconds: int
    invocation_identity: str

    def __post_init__(self) -> None:
        for name in (
            "shard_count",
            "session_budget_seconds",
            "orphan_threshold_seconds",
            "max_rows_per_shard",
            "sweep_interval_seconds",
        ):
            value = getattr(self, name)
            if value <= 0:
                raise ValueError(f"{name} must be positive: {value}")
        if not self.invocation_identity:
            raise ValueError("invocation_identity must not be empty")

    @property
    def shards(self) -> tuple[int, ...]:
        """Every shard one sweep covers, which is all of them.

        R10.8 says *every* Sandbox past a configured limit, and a shard is an implementation detail
        of the query rather than a subset anybody chose. Returning the whole range from the settings
        is what stops a sweep from being partial by accident.
        """
        return tuple(range(self.shard_count))


def heartbeat_alarm_for(settings: ReaperSettings) -> HeartbeatAlarm:
    """The CloudWatch alarm that detects a Reaper which has stopped running.

    `treatMissingData` is `breaching`, which is the whole point: a Reaper that is not running emits no
    data points, so an alarm treating missing data as anything else would go quiet exactly when the
    component it watches goes quiet. Two evaluation periods rather than one, so a single skipped
    invocation — a cold start colliding with a scheduler jitter — does not page anybody, while two
    consecutive silences do.

    The period is the sweep interval, derived rather than configured separately: an alarm evaluating a
    window shorter than the schedule alarms on every gap between sweeps, and one evaluating a much
    longer window hides an outage for as long as it lasts.
    """
    return HeartbeatAlarm(
        metric_name=HEARTBEAT_METRIC_NAME,
        period_seconds=settings.sweep_interval_seconds,
        evaluation_periods=2,
        treat_missing_data="breaching",
    )


def handle_of(row: DueRow) -> SandboxHandle | None:
    """Rebuild the provider handle from the projected `sandboxHandle`, or `None` for a row with none.

    `None` rather than an exception, because a due row with no recorded handle is an ordinary case
    here and not a defect: it is the row a `provision` left behind before it could record what it
    created, and reaching its Sandbox is what :meth:`SandboxReclaimer.discover` is for. A *malformed*
    handle is a different thing and does raise.

    **Consolidation candidate**, noted in the same terms
    :func:`control_plane.orchestrator.tasks.handle_of` notes it: this is the third reading of the
    same attribute, and one reader on the record would serve all three. It is spelled again here
    rather than imported because the orchestrator's takes an orchestrator state, and because
    importing that module would pull provisioning code into the Reaper.

    Raises:
        ItemShapeError: the stored handle is present and malformed.
    """
    stored = row.sandbox_handle
    if stored is None:
        return None
    provider_name = stored.get("providerName")
    sandbox_id = stored.get("sandboxId")
    if not isinstance(provider_name, str) or not provider_name:
        raise ItemShapeError("sandboxHandle carries no providerName")
    if not isinstance(sandbox_id, str) or not sandbox_id:
        raise ItemShapeError("sandboxHandle carries no sandboxId")
    opaque = stored.get("opaque", {})
    if not isinstance(opaque, Mapping):
        raise ItemShapeError("sandboxHandle opaque data is not a map")
    return SandboxHandle(
        provider_name=provider_name,
        sandbox_id=sandbox_id,
        opaque={str(key): str(value) for key, value in opaque.items()},
    )


@dataclass(frozen=True, slots=True)
class DueRow:
    """One row the `deadline-index` returned, parsed from the projection and nothing else.

    Not a :class:`~control_plane.state.records.SessionRecord`, and deliberately not convertible into
    one. A complete record requires the four configured limits, `updatedAt`, the port set and the
    execution role, none of which `deadline-index` projects; building one here would mean either a
    `GetItem` per due row or fabricated values sitting in a record that other code trusts. So this is
    its own type, holding exactly what the projection carries and what a settlement needs — which is
    why it satisfies :class:`~control_plane.lifecycle.SettlementSubject` and nothing wider.

    :attr:`pk` is derived through :func:`~control_plane.tenancy.pk_for` from the projected `tenantId`
    and then checked against the projected partition key, rather than taken from the projection. The
    sweep is partitioned by `reapShard` rather than by Tenant, so this is the one point at which a
    row's key and its recorded Tenant are made to agree before the sweep writes back through that key.
    """

    pk: str
    session_id: str
    tenant_id: str
    lifecycle_state: LifecycleState
    created_at: int
    reap_shard: int
    reap_deadline: int
    sandbox_handle: Mapping[str, Any] | None
    affinity_key_digest: str | None
    orchestration_execution_arn: str | None

    @property
    def sort_key(self) -> str:
        """`S#<sessionId>`, derived so the key written to cannot disagree with the identifier read."""
        return session_sort_key(self.session_id)

    @classmethod
    def from_projection(
        cls, item: Mapping[str, Any], *, invocation_identity: str
    ) -> DueRow:
        """Parse one projected row.

        Raises:
            ItemShapeError: an attribute the projection must carry is absent or malformed, the sort
                key is not a Session sort key, or the partition key and the recorded `tenantId` name
                two different Tenants.
        """
        sort_key = _text(item, SORT_KEY_ATTRIBUTE)
        session_id = _session_id_of(sort_key)
        tenant_id = _text(item, "tenantId")
        projected_pk = _text(item, PARTITION_KEY_ATTRIBUTE)
        partition_key = pk_for(
            AuthenticatedPrincipal(
                caller_identity=invocation_identity, tenant_id=tenant_id
            )
        )
        if partition_key != projected_pk:
            raise ItemShapeError(
                f"the row at {projected_pk!r} records tenantId {tenant_id!r}, whose partition key "
                f"is {partition_key!r}; the Reaper writes to keys it derives, so a row whose two "
                f"halves disagree is refused rather than written to"
            )
        handle = item.get("sandboxHandle")
        if handle is not None and not isinstance(handle, Mapping):
            raise ItemShapeError("sandboxHandle is not a map")
        return cls(
            pk=partition_key,
            session_id=session_id,
            tenant_id=tenant_id,
            lifecycle_state=LifecycleState(_text(item, "lifecycleState")),
            created_at=_whole(item, "createdAt"),
            reap_shard=_whole(item, DEADLINE_INDEX.partition_key),
            reap_deadline=_whole(item, DEADLINE_INDEX.sort_key),
            sandbox_handle=None if handle is None else dict(handle),
            affinity_key_digest=_optional_text(item, "affinityKeyDigest"),
            orchestration_execution_arn=_optional_text(
                item, "orchestrationExecutionArn"
            ),
        )

    def tags(self) -> dict[str, str]:
        """The Tenant and Session tags `discover` matches on (R11.7).

        Built by :func:`~control_plane.allocation.tags.sandbox_tags`, the sole producer, so the tags
        this sweep searches for are the same tags the provisioning task attached. A Session tag as
        well as a Tenant tag, because a Tenant tag alone would return every Sandbox of a Tenant and a
        sweep that cannot narrow to one Session cannot terminate one orphan without risking a live
        sibling.
        """
        return sandbox_tags(tenant_id=self.tenant_id, session_id=self.session_id)


def classify(row: DueRow, *, now: int, settings: ReaperSettings) -> DueRowClass:
    """Classify one due row, from the projection alone.

    The order of the four questions is the classification, and each step is a decision:

    1. **Is the row already settled?** From :data:`DEADLINE_SOURCE`. A terminal write removes
       `reapDeadline`, so such a row is normally out of the index entirely; asking first still
       matters because the query's snapshot can predate a settlement, and terminating a gone Sandbox
       on that basis is what this stops.
    2. **Did an execution ever start?** From the presence of `orchestrationExecutionArn`. Absent and
       inside the window, the row is deferred; absent and past it, the row is an orphan. This precedes
       the deadline questions because a Session with no execution has no Sandbox and no duration to
       have exceeded — classifying it as a duration reap would send the sweep looking for a handle
       whose absence means something else entirely.
    3. **Is the row past the deployment budget?** The one deadline whose source this function can
       actually verify, since `createdAt` is projected and the budget is configuration. Where it has
       demonstrably passed, it is the reason reported.
    4. **Otherwise, which deadline does the state imply?** `SUSPENDED`/`SUSPENDING` means the
       suspended-duration deadline (R10.7); every other live state means the maximum-duration one
       (R10.6). This is the recovery the design means by "the reason for the deadline is recoverable
       from the other attributes on the row", and it is total because :data:`DEADLINE_SOURCE` is.

    Nothing here reads a clock: `now` is passed in, because a sweep is entirely about elapsed time and
    a function that read the wall clock could not be tested at any deadline but the present one.
    """
    source = DEADLINE_SOURCE[row.lifecycle_state]
    if source is DeadlineSource.NONE:
        return DueRowClass.ALREADY_SETTLED
    age_seconds = (now - row.created_at) // _MILLISECONDS_PER_SECOND
    if row.orchestration_execution_arn is None:
        if age_seconds < settings.orphan_threshold_seconds:
            return DueRowClass.WITHIN_ORPHAN_WINDOW
        return DueRowClass.ORPHANED
    if age_seconds >= settings.session_budget_seconds:
        return DueRowClass.BUDGET_EXCEEDED
    return _DEADLINE_CLASSES[source]


class SweepAction(Enum):
    """What the sweep did about one due row.

    Distinct from :class:`DueRowClass`, which says what the row *is*. The two are reported side by
    side because an operator needs both: a rising `RESOURCES_RETAINED` under
    `MAX_DURATION_REACHED` is a provider that is not releasing, and a rising `ABSORBED` under the
    same classification is an orchestrator racing the sweep and winning, which is healthy.
    """

    #: The terminal state was written and the binding, if there was one, went with it.
    SETTLED = "settled"
    #: Another component had already settled this Session. The sweep's write was refused (R10.7).
    ABSORBED = "absorbed"
    #: The row was terminal when the sweep read it, so there was nothing to do.
    NOTHING_TO_DO = "nothing-to-do"
    #: Inside the orphan window. Nothing written, nothing terminated, looked at again next sweep.
    DEFERRED = "deferred"
    #: `release_check` still reported allocated resources, so no terminal state was written (R10.9).
    RESOURCES_RETAINED = "resources-retained"
    #: A provider call failed. Recorded against this row and the sweep continued to the next.
    PROVIDER_FAILED = "provider-failed"


@dataclass(frozen=True, slots=True)
class RowOutcome:
    """What became of one due row, in enough detail to act on without reading the row again.

    :attr:`classification` is optional, and `None` means exactly one thing: the row would not parse,
    so there was nothing to classify. An unparseable row is deliberately not filed under a real
    classification — attributing it to one would put a defect into the reaped-by-reason mix and make a
    malformed item look like a reason that fired.
    """

    session_id: str
    shard: int
    action: SweepAction
    classification: DueRowClass | None = None
    binding_deleted: bool = False
    terminated: tuple[str, ...] = ()
    retained: tuple[str, ...] = ()
    discovered: int = 0
    quarantined: int = 0
    failure: str | None = None

    @property
    def reaped(self) -> bool:
        """Whether this row's Session ended in this sweep, which is what R10.17 pairs a delete to."""
        return self.action is SweepAction.SETTLED


@dataclass(frozen=True, slots=True)
class SweepReport:
    """One sweep, as the value the metric emitter reads and the caller returns.

    The heartbeat is a property rather than a field: a report exists because a sweep completed, so
    there is no value of this type that represents a sweep that did not happen and therefore no way
    to emit a heartbeat for one.
    """

    swept_at: int
    shards: tuple[int, ...]
    outcomes: tuple[RowOutcome, ...]

    @property
    def heartbeat(self) -> int:
        """The value :data:`HEARTBEAT_METRIC_NAME` carries. Always one; the alarm is on absence."""
        return 1

    @property
    def rows_examined(self) -> int:
        return len(self.outcomes)

    @property
    def sandboxes_reaped(self) -> int:
        """Sessions this sweep settled. Compared against :attr:`bindings_deleted` on the dashboard."""
        return sum(1 for outcome in self.outcomes if outcome.reaped)

    @property
    def bindings_deleted(self) -> int:
        """Bindings deleted as cleanup layer 2 (R10.17)."""
        return sum(1 for outcome in self.outcomes if outcome.binding_deleted)

    @property
    def reaped_by_reason(self) -> Mapping[DueRowClass, int]:
        """Settled rows by classification, with a zero for every reason that did not fire.

        Zeros are present on purpose. A reason that stops appearing is indistinguishable from a
        reason that never fires if the absent keys are simply missing from the emitted dimension set.
        """
        counts = dict.fromkeys(REAP_SETTLEMENTS, 0)
        for outcome in self.outcomes:
            if outcome.reaped and outcome.classification is not None:
                counts[outcome.classification] += 1
        return counts


class DeadlineIndexQuery(Protocol):
    """The Reaper's one read, stated as the query it is (R10.8).

    A structural type, so the offline suite drives the whole sweep against an in-memory index keyed as
    DynamoDB is, with no deployed resource and no network.

    Reached with the Reaper's own role rather than a per-request tenant-confined credential: the sweep
    is a system component operating across Tenants, which is exactly why
    :data:`~control_plane.state.table.DEADLINE_INDEX` is partitioned on the shard number rather than
    on a Tenant key. A Tenant-scoped read path would force the Reaper either to enumerate Tenants or
    to scan the table.
    """

    def due_rows(
        self, *, shard: int, due_at: int, limit: int
    ) -> Sequence[Mapping[str, Any]]:
        """`Query` `deadline-index` for the rows of one shard that are due.

        `KeyConditionExpression: reapShard = :shard AND reapDeadline <= :dueAt`, with `Limit = limit`.
        A bounded range query rather than a scan, so cost and duration do not grow with the number of
        healthy Sessions.

        The index projects `INCLUDE`, so each returned item carries
        :data:`~control_plane.state.table.DEADLINE_INDEX.non_key_attributes` and the key attributes
        and nothing else. An implementation must **not** follow a returned row with a `GetItem` to
        complete it: that would restore the per-row read the projection exists to remove, and
        :data:`REQUIRED_PROJECTION` is asserted against the index so that nothing here needs one.
        """
        ...


class SandboxReclaimer(Protocol):
    """The three provider operations a sweep performs, and deliberately no fourth.

    Narrowed the way :class:`~control_plane.allocation.ledger.SandboxTerminator` is narrowed, and for
    a sharper reason: the Reaper must not provision (R6.11, and
    `ci/lint_rules/orchestrated_provisioning.py`) and has no reason to mint a credential
    (`ci/lint_rules/sole_credential_issuer.py`). Both prohibitions are visible in this type rather
    than only in a lint rule — there is no `provision` and no `issue_connection` on the collaborator
    :class:`Reaper` holds, so neither is reachable however the sweep is called.
    :class:`~control_plane.providers.base.ComputeProvider` satisfies it structurally, which is why no
    adapter exists.
    """

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Terminate a Sandbox. Idempotent on an already terminal one, which is what makes a sweep
        overlapping an orchestrator teardown converge rather than conflict (R10.7)."""
        ...

    def release_check(self, handle: SandboxHandle) -> list[str]:
        """Return the identifiers of resources still allocated to a terminated Sandbox (R10.9)."""
        ...

    def discover(self, tags: dict[str, str]) -> list[SandboxStatus]:
        """Find Sandboxes by tag, for a Session whose handle was never recorded (R11.7)."""
        ...


class SweepMetrics(Protocol):
    """Where a sweep's heartbeat and counts go.

    One method taking the whole report, rather than a counter API the sweep drives: the counts that
    matter are relationships between numbers — reaped against bindings deleted — and an emitter handed
    the report can assert that relationship, while one handed increments cannot see it.

    No default implementation and no optional field on :class:`Reaper`. A no-op default would drop the
    heartbeat, and the heartbeat's absence is what the alarm alarms on, so a deployment that forgot to
    wire an emitter would look exactly like a Reaper that had stopped running.
    """

    def record_sweep(self, report: SweepReport) -> None:
        """Emit the heartbeat and the counts for one completed sweep.

        Embedded metric format, which is why this cannot fail a lifecycle transition: the design
        chooses EMF over `PutMetricData` precisely so that a throttle during a terminate can never
        leave a Sandbox allocated.
        """
        ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _text(item: Mapping[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value:
        raise ItemShapeError(f"{name} is missing or not a non-empty string")
    return value


def _optional_text(item: Mapping[str, Any], name: str) -> str | None:
    value = item.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ItemShapeError(f"{name} is present and not a non-empty string")
    return value


def _whole(item: Mapping[str, Any], name: str) -> int:
    value = item.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ItemShapeError(f"{name} is missing or not a number")
    as_int = int(value)
    if as_int != value:
        raise ItemShapeError(f"{name} is not an integer: {value!r}")
    return as_int


def _session_id_of(sort_key: str) -> str:
    """Read the Session identifier back out of the sort key the index returned.

    The same reading :meth:`~control_plane.state.records.SessionRecord.from_item` performs, spelled
    the same way: the prefix must be the Session prefix and the remainder must carry no separator. A
    sort key of any other item shape — a binding, an artifact entry, a continuation record — is
    refused here rather than becoming a Session identifier the sweep would then write against. The
    index returns only Session rows in practice, because only a Session row carries `reapShard`; the
    refusal is what keeps that "in practice" from being the whole of the guarantee.
    """
    prefix = f"{SESSION_PREFIX}{SEPARATOR}"
    remainder = sort_key.removeprefix(prefix)
    if (
        not sort_key.startswith(prefix)
        or not remainder
        or SEPARATOR in remainder
        or session_sort_key(remainder) != sort_key
    ):
        raise ItemShapeError(f"not a Session sort key: {sort_key!r}")
    return remainder


@dataclass(frozen=True, slots=True)
class Reaper:
    """The scheduled sweep: query each shard, classify, terminate, settle, delete the binding.

    Every collaborator is injected and every one is a structural type, so the whole component runs
    offline with no deployed resource and no network. There is no Step Functions client, no
    `provision`, and no credential issuer — the three things the Reaper must not reach are absent from
    its fields rather than merely unused by its methods.

    Lifecycle state is written through :attr:`reconciler` and nowhere else, which is what makes
    cleanup layer 2 (R10.17) inseparable from the terminal write: a
    :class:`~control_plane.lifecycle.TerminalSettlement` derives the binding key from the same row it
    settles, so the sweep has no argument through which it could omit the deletion.
    """

    index: DeadlineIndexQuery
    provider: SandboxReclaimer
    reconciler: LifecycleReconciler
    ledger: SandboxClaimLedger
    metrics: SweepMetrics
    settings: ReaperSettings
    clock: Callable[[], datetime] = _utc_now

    def sweep(self) -> SweepReport:
        """Run one scheduled sweep across every shard, and emit the heartbeat.

        One :meth:`DeadlineIndexQuery.due_rows` per shard and no read per due row. Every shard below
        `shard_count` is covered, because R10.8 is a claim about every Sandbox past a limit and a
        sweep that visited a subset would leave the rest running.

        The clock is read **once**, at the top, and the same instant classifies every row in the
        sweep. Reading it per row would let two rows with the same deadline be classified differently
        because the sweep took a second, which is a difference no operator could explain.

        A malformed row and a failing provider call are both recorded against the row and the sweep
        continues. R10.8 asks the Reaper to terminate *every* Sandbox past its limit, and one row that
        cannot be parsed must not stop the sweep from reaching the rest — which is the same failure
        mode as the Reaper not running at all, on a subset.
        """
        now = self._now()
        outcomes: list[RowOutcome] = []
        for shard in self.settings.shards:
            for item in self.index.due_rows(
                shard=shard,
                due_at=now,
                limit=self.settings.max_rows_per_shard,
            ):
                outcomes.append(self._handle_row(item, shard=shard, now=now))
        report = SweepReport(
            swept_at=now, shards=self.settings.shards, outcomes=tuple(outcomes)
        )
        self.metrics.record_sweep(report)
        return report

    def _handle_row(
        self, item: Mapping[str, Any], *, shard: int, now: int
    ) -> RowOutcome:
        """Classify and act on one due row, absorbing whatever it does wrong.

        Parsing is inside the guard because a projected row is data this component did not write in
        this invocation, and an unparseable one is a defect to report rather than a reason to abandon
        the remaining Sessions.
        """
        try:
            row = DueRow.from_projection(
                item, invocation_identity=self.settings.invocation_identity
            )
        except ValueError as error:
            # `ItemShapeError` is a `ValueError`, and so is the `LifecycleState` a forged
            # `lifecycleState` would fail to construct. Both are malformed data rather than a state
            # this sweep can act on, and neither is a reason to abandon the remaining Sessions.
            return RowOutcome(
                session_id=_unparsed_identifier(item),
                shard=shard,
                action=SweepAction.PROVIDER_FAILED,
                failure=f"{type(error).__name__}: {error}",
            )
        classification = classify(row, now=now, settings=self.settings)
        if classification in NON_REAPING_CLASSES:
            return RowOutcome(
                session_id=row.session_id,
                shard=shard,
                action=_NON_REAPING_ACTIONS[classification],
                classification=classification,
            )
        return self._reap(row, shard=shard, classification=classification)

    def _reap(
        self, row: DueRow, *, shard: int, classification: DueRowClass
    ) -> RowOutcome:
        """Terminate this Session's Sandboxes, confirm release, then settle it.

        The order is the design's and it is not interchangeable. `terminate`, then `release_check`,
        then the terminal write — so a Session is never recorded as ended while resources it owns are
        still allocated, which is the one thing R10.9 asks not to be done. When the check still
        reports identifiers the sweep writes **nothing**: the row keeps its state and its binding, and
        the next sweep tries again, because the deadline has not moved.

        A row with no recorded handle reaches `discover` (R11.7). That covers a `provision` whose
        execution died before recording what it created, and it returns nothing at all for a Session
        whose execution never started — which is the cheap price of not special-casing the orphan
        state here, and is why the orphan pass and the discover pass are one path rather than two.
        """
        try:
            handles, discovered = self._handles_for(row)
            terminated, retained = self._reclaim(handles)
        except Exception as error:  # noqa: BLE001 - one bad Sandbox must not stop the sweep
            # Every provider failure lands here rather than propagating. A sweep that aborted on the
            # first unreachable backend would leave every later shard unreaped, which is the failure
            # the heartbeat alarm is meant to make visible and this one would not be.
            return RowOutcome(
                session_id=row.session_id,
                shard=shard,
                action=SweepAction.PROVIDER_FAILED,
                classification=classification,
                failure=f"{type(error).__name__}: {error}",
            )
        if retained:
            return RowOutcome(
                session_id=row.session_id,
                shard=shard,
                action=SweepAction.RESOURCES_RETAINED,
                classification=classification,
                terminated=terminated,
                retained=retained,
                discovered=discovered,
            )
        state = REAP_SETTLEMENTS[classification]
        settled = self.reconciler.settle(
            row, state=state, reason=REAP_REASONS[classification]
        )
        if settled.outcome is ReconciliationOutcome.ABSORBED:
            # Another component settled this Session first, so its terminal state stands and nothing
            # about this row is this sweep's to record — including the quarantine, which belongs to
            # whichever component wrote the `FAILED` that absorbed this write.
            return RowOutcome(
                session_id=row.session_id,
                shard=shard,
                action=SweepAction.ABSORBED,
                classification=classification,
                terminated=terminated,
                discovered=discovered,
            )
        return RowOutcome(
            session_id=row.session_id,
            shard=shard,
            action=SweepAction.SETTLED,
            classification=classification,
            binding_deleted=settled.binding_deleted,
            terminated=terminated,
            discovered=discovered,
            quarantined=(
                self._quarantine(handles) if state is LifecycleState.FAILED else 0
            ),
        )

    def _handles_for(self, row: DueRow) -> tuple[tuple[SandboxHandle, ...], int]:
        """The Sandboxes to stop for this Session, and how many `discover` had to find.

        The recorded handle where the row carries one, which is the ordinary case and costs no
        provider call. Otherwise `discover` by the Tenant and Session tags R11.7 puts on every
        Sandbox — the only route to a Sandbox whose handle was never recorded, and the reason those
        tags are a precondition of a claim rather than metadata.
        """
        recorded = handle_of(row)
        if recorded is not None:
            return (recorded,), 0
        found = tuple(status.handle for status in self.provider.discover(row.tags()))
        return found, len(found)

    def _reclaim(
        self, handles: Sequence[SandboxHandle]
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Terminate each Sandbox and confirm its release, returning both answers (R10.9).

        `terminate` is idempotent, so calling it on a Sandbox an orchestrator teardown already stopped
        is convergence rather than a conflict. The release check is per Sandbox, and one Sandbox
        holding resources is enough to withhold the terminal write for the whole Session: a Session is
        ended when nothing of it remains allocated, not when most of it does.
        """
        terminated: list[str] = []
        retained: list[str] = []
        for handle in handles:
            self.provider.terminate(handle)
            outstanding = tuple(self.provider.release_check(handle))
            if outstanding:
                retained.extend(outstanding)
            else:
                terminated.append(handle.sandbox_id)
        return tuple(terminated), tuple(retained)

    def _quarantine(self, handles: Sequence[SandboxHandle]) -> int:
        """Quarantine the claims of a Session the sweep recorded `FAILED` (R11.13).

        A **separate step**, after the settlement and never inside its transaction, for the reason
        :mod:`control_plane.lifecycle` states: the claim item sits outside every Tenant partition and
        is written with a different role, so the two cannot share a transaction — and a claim-ledger
        failure must not block the write that stops a billable Sandbox. That ordering is why this is
        called with the settlement already committed and why its answer is a count rather than a
        precondition of anything.

        A Session orphaned before it ever claimed a Sandbox holds no claim, which is an absence rather
        than a failure and is reported as one. That is the common case here: an orphan is by definition
        a Session whose execution never reached `ClaimSandbox`.
        """
        quarantined = 0
        for handle in handles:
            try:
                self.ledger.quarantine_for_session_failure(handle)
            except SandboxNotClaimed:
                continue
            quarantined += 1
        return quarantined

    def _now(self) -> int:
        """Epoch milliseconds, the unit every recorded timestamp in the State_Store uses."""
        moment = self.clock()
        if moment.tzinfo is None:
            raise ValueError("the Reaper's clock must return an aware datetime")
        return int(moment.timestamp() * _MILLISECONDS_PER_SECOND)


#: What the sweep does about each classification that reaps nothing. Total over
#: :data:`NON_REAPING_CLASSES`, asserted at import, so a non-reaping classification added later cannot
#: fall through to a reap.
_NON_REAPING_ACTIONS: Final[Mapping[DueRowClass, SweepAction]] = {
    DueRowClass.ALREADY_SETTLED: SweepAction.NOTHING_TO_DO,
    DueRowClass.WITHIN_ORPHAN_WINDOW: SweepAction.DEFERRED,
}

if set(_NON_REAPING_ACTIONS) != NON_REAPING_CLASSES:  # pragma: no cover - import-time
    raise AssertionError(
        "a non-reaping due-row classification has no sweep action, so a row in it would fall "
        "through to a reap"
    )


def _unparsed_identifier(item: Mapping[str, Any]) -> str:
    """Name a row that would not parse, without trusting the value that made it unparseable."""
    sort_key = item.get(SORT_KEY_ATTRIBUTE)
    return sort_key if isinstance(sort_key, str) and sort_key else "<unparseable>"
