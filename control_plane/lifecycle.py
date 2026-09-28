# kiro-classification: public
"""Lifecycle reconciliation, and the terminal write that cannot forget the Affinity_Key binding.

Three things live here, and the third is the reason the other two share a module.

1. **The provider-state mirror (R6.7).** :data:`PROVIDER_STATE_MIRROR` maps every
   :class:`~control_plane.providers.base.SandboxState` a Compute_Provider can report onto the
   :class:`~control_plane.state.records.LifecycleState` recorded on the Session row. It is total over
   the provider's enum, asserted at import, so a provider state added later fails the build rather
   than falling into a default that would silently stop mirroring.
2. **Terminal states absorb, and they absorb in the store.** Once a row is `TERMINATED` or `FAILED`,
   no later report moves it back to a live state. That is a `ConditionExpression` on every lifecycle
   write rather than a check a caller performs first, because out-of-order provider reports are the
   ordinary case and a read-then-write has a window between the two halves that no care at the call
   site closes.
3. **Cleanup layer 1 (R10.16).** Every terminal write deletes the Affinity_Key binding in the same
   step, as one `TransactWriteItems`, so no instant exists in which a binding names a terminated
   Session.

## Why absorption is a condition and not a guard

A Compute_Provider's reports are not ordered. `describe` polled twice, a suspend and a terminate
racing, a Reaper sweep overlapping an orchestrator teardown — each can deliver a live state *after* a
terminal one. The naive shape reads the row, sees a live state, and writes; between the read and the
write the orchestrator writes `TERMINATED`, and the mirror resurrects a Session whose Sandbox is
gone, whose binding has been deleted, and which the Reaper will therefore never look at again.

So every write here carries `NOT lifecycleState IN (:terminated, :failed)` and the store arbitrates.
A write whose condition fails is not an error: it is absorption working, reported as
:attr:`ReconciliationOutcome.ABSORBED`. The same condition is carried by the *terminal* write, which
makes the first terminal state the one that stands — a Reaper writing `TERMINATED` over an
orchestrator's `FAILED` would replace the diagnostic state with the routine one, the same reasoning
that makes the first quarantine reason win in
:meth:`~control_plane.allocation.ledger.SandboxClaimLedger._record`. Both writes therefore converge
when applied twice, which is what the design requires of every operation the Reaper and the
orchestrator may both perform.

## Why a terminal state cannot be written without the deletion

This is the structural point of the module, and it is expressed in the types rather than in a rule
each call site must remember.

- :class:`SessionLifecycleStore` has exactly two write methods. Neither takes a lifecycle state as a
  loose argument; each takes one of the two write types below and nothing else.
- :class:`LiveTransition` **refuses a terminal state at construction**. There is no value of
  `advance_live_state`'s parameter type that carries one.
- :class:`TerminalSettlement` **refuses a non-terminal state at construction**, and it is built only
  from a :class:`~control_plane.state.records.SessionRecord`, from which it derives the binding key
  itself. A caller does not pass the binding key and so cannot omit it.
- :func:`write_for` picks between the two purely from the state's terminality, so the *type* of a
  lifecycle write is a function of the state being written.

Composing those: the only type that can carry `TERMINATED` or `FAILED` is one that already carries
the binding key derived from the same record, and the only method that accepts that type commits both
items in one transaction. "The binding is deleted in the same step as every terminal write" is
therefore a property of the shape of this module, not a discipline observed by its callers. A Session
that was never created through get-or-create carries no `affinityKeyDigest`, so its settlement's
:attr:`TerminalSettlement.binding` is `None` and the transaction holds one item — the absence of a
binding, rather than a forgotten delete.

## Why the audit record is emitted from here

R14.2 wants one structured record per Session lifecycle transition, carrying the Session, the Tenant,
both states, the timestamp and the calling principal. Every lifecycle write the Control_Plane makes
after the row is created passes through :class:`LifecycleReconciler` — a mirrored provider report, a
terminal settlement, and the live transitions the orchestrator decides on through
:meth:`LifecycleReconciler.advance` — so this is the one place a record per transition can be emitted
without a rule each caller has to remember. :class:`~control_plane.observability.LifecycleAuditor`
holds the principal and the sink; this module supplies the states.

Three consequences of putting it after the write:

- **An absorbed write emits nothing.** A report the store refused moved no row, so there was no
  transition, and a record for one would break the contiguity of the chain R14.3 asks an operator to
  follow.
- **A write that records the state the row already holds emits nothing** either, for the same reason.
  The governing loop mirrors `RUNNING` on every poll turn; those are observations, not transitions.
- **The record's timestamp is the write's own `updatedAt`**, not a second clock reading, so a record
  and the row it moved carry the identical number.

The record is emitted, never raised into the transition: see
:mod:`control_plane.observability` on why a sink failure is counted and swallowed.

The two lifecycle writes on the *creation* path — the `PENDING` row itself and the
`PENDING → ORCHESTRATING` write of
:meth:`~control_plane.api.creation.SessionRowStore.mark_orchestration_started` — do not pass through
here and are not yet audited. They are the remaining half of R14.2 and they need the API handler's own
:class:`~control_plane.tenancy.AuthenticatedPrincipal` rather than a component identity.

## What this module does not compute

**It does not compute a binding expiry.** `expiresAt` is
`min(sessionDeadline, boundAt + configuredMaxAge)` in **epoch seconds**, and it is produced by
:func:`~control_plane.api.resolution.binding_for` alone, at the one moment a binding is written. A
binding cannot exist without it, so there is nothing here to recompute and deliberately no second
spelling of the formula: milliseconds in that field would place every expiry tens of thousands of
years out and make cleanup layer 3 silently inert. This module reads the *key* a binding was written
at, through :func:`~control_plane.state.keys.binding_sort_key`, and reads no other part of it.

**It does not quarantine the Sandbox claim.** R11.13's quarantine accompanies a `FAILED` write and is
:meth:`~control_plane.allocation.ledger.SandboxClaimLedger.quarantine_for_session_failure`. It cannot
join the transaction below: the claim item sits outside every Tenant partition and is written with
the orchestrator's own role rather than the per-request tenant-confined credentials this write uses,
so the two are necessarily two steps. Keeping them separate is also what keeps a claim-ledger failure
from blocking the terminal write that stops a billable Sandbox.

**It does not sweep, terminate or provision.** Cleanup layer 2 is the Reaper's own sweep and reaches
the same :meth:`SessionLifecycleStore.settle_terminal_state` from there; layer 3 is DynamoDB TTL and
is nobody's code. No provider lifecycle call is made from here — a settlement records what already
happened to a Sandbox and does not make it happen.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Final, Protocol

from control_plane.api.lookup import SessionLookup
from control_plane.observability import LifecycleAuditor
from control_plane.providers.base import SandboxState, SandboxStatus
from control_plane.state.keys import binding_sort_key, tenant_state_sort_key
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.state.table import DEADLINE_INDEX

__all__ = [
    "ABSORBING_LIFECYCLE_STATES",
    "PROVIDER_STATE_MIRROR",
    "REAP_DEADLINE_ATTRIBUTE",
    "RECORD_ONLY_LIFECYCLE_STATES",
    "BindingKey",
    "LifecycleConditionFailed",
    "LifecycleReconciler",
    "LiveStateNeedsNoSettlement",
    "LiveTransition",
    "Reconciliation",
    "ReconciliationOutcome",
    "SessionLifecycleStore",
    "SessionRecordAbsent",
    "SettlementSubject",
    "TerminalSettlement",
    "TerminalStateNeedsSettlement",
    "live_transition_for",
    "reason_for_report",
    "settlement_for",
    "write_for",
]

_MILLISECONDS_PER_SECOND: Final = 1000

#: The attribute a terminal settlement removes, which is `deadline-index`'s sort key. A DynamoDB
#: global secondary index is sparse, so an item without it is not in the index at all: removing it
#: is what takes a settled Session out of the Reaper's read path permanently.
REAP_DEADLINE_ATTRIBUTE: Final = DEADLINE_INDEX.sort_key

#: The states a lifecycle write's condition excludes, so that reaching one is one-way. The same
#: frozenset the record's own `is_terminal` reads, named again here in the vocabulary of the
#: condition expression rather than restated as a second set, because a condition that excluded a
#: different set from the one the record calls terminal is exactly the drift this alias prevents.
ABSORBING_LIFECYCLE_STATES: Final[frozenset[LifecycleState]] = frozenset(
    state for state in LifecycleState if state.is_terminal  # nosemgrep: is-function-without-parentheses — @property
)

#: Every provider-reported Sandbox state, mapped onto the state recorded on the Session row (R6.7).
#:
#: Eight of the nine entries are the identically named lifecycle state. The ninth is the one worth
#: reading: **a provider reporting `PENDING` mirrors onto `PROVISIONING`, not onto `PENDING`.** The
#: two words mean different things on the two sides of the seam. `LifecycleState.PENDING` is the
#: Session row written before any execution and before any Sandbox exists (R6.6), so no provider can
#: ever report it — a provider that reports anything at all is reporting a Sandbox that exists. What
#: `SandboxState.PENDING` describes is a Sandbox accepted and not yet started, which the lifecycle
#: model calls `PROVISIONING`. Mirroring it onto `PENDING` would move a record backwards into the
#: orphan window the Reaper's orphan pass keys on, and it would do so for a Session whose Sandbox is
#: already provisioned and billable.
PROVIDER_STATE_MIRROR: Final[Mapping[SandboxState, LifecycleState]] = {
    SandboxState.PENDING: LifecycleState.PROVISIONING,
    SandboxState.STARTING: LifecycleState.STARTING,
    SandboxState.RUNNING: LifecycleState.RUNNING,
    SandboxState.SUSPENDING: LifecycleState.SUSPENDING,
    SandboxState.SUSPENDED: LifecycleState.SUSPENDED,
    SandboxState.RESUMING: LifecycleState.RESUMING,
    SandboxState.TERMINATING: LifecycleState.TERMINATING,
    SandboxState.TERMINATED: LifecycleState.TERMINATED,
    SandboxState.FAILED: LifecycleState.FAILED,
}

#: The lifecycle states no provider report can produce, because each describes the Session *record*
#: rather than a Sandbox. `PENDING` is the row before any execution, `ORCHESTRATING` is an execution
#: with no Sandbox yet, and `CONTINUING` is a duration-ceiling handoff in which the outgoing Sandbox
#: is being torn down deliberately. Derived from the mirror rather than listed, so the two cannot
#: disagree about which states are record-only.
RECORD_ONLY_LIFECYCLE_STATES: Final[frozenset[LifecycleState]] = frozenset(
    LifecycleState
) - frozenset(PROVIDER_STATE_MIRROR.values())

if set(PROVIDER_STATE_MIRROR) != set(
    SandboxState
):  # pragma: no cover - import-time invariant
    _unmirrored = sorted(
        state.value for state in SandboxState if state not in PROVIDER_STATE_MIRROR
    )
    raise AssertionError(f"provider states with no lifecycle mirror: {_unmirrored}")

if RECORD_ONLY_LIFECYCLE_STATES != {
    LifecycleState.PENDING,
    LifecycleState.ORCHESTRATING,
    LifecycleState.CONTINUING,
}:  # pragma: no cover - import-time invariant
    # A lifecycle state that stopped being record-only, or started being one, is a change to which
    # component effects which transition. That is a design decision and it fails the build here
    # rather than quietly changing what a provider report can do to a row.
    raise AssertionError(
        f"the record-only lifecycle states have changed: "
        f"{sorted(state.value for state in RECORD_ONLY_LIFECYCLE_STATES)}"
    )


class LifecycleConditionFailed(Exception):
    """A conditional lifecycle write found the row in a state its condition excluded.

    DynamoDB's `ConditionalCheckFailedException`, or a `TransactionCanceledException` with a
    `ConditionalCheckFailed` on the Session item, at this seam. It is raised by a
    :class:`SessionLifecycleStore` implementation and says only that the condition did not hold;
    which of the two excluded cases it was, and what that means, is decided by
    :class:`LifecycleReconciler` and by nothing in the store.

    A transaction cancelled for any other reason — a capacity rejection, a transaction conflict, the
    binding `Delete` — is not this. Absorbing one into it would report an infrastructure failure as a
    Session that was already terminal, and the caller would stop trying to stop a running Sandbox.
    """


class SessionRecordAbsent(Exception):
    """A lifecycle write named a Session row that does not exist.

    A defect rather than an operational condition. Every path that reconciles a Session is holding a
    record it read, and the row is the one thing in this design that is written before a Sandbox
    exists and deleted by nothing. Refusing is what stops a mirror write from re-creating, as a
    two-attribute stub, a row that R6.6 requires to be complete.
    """

    def __init__(self, partition_key: str, sort_key: str) -> None:
        super().__init__(f"no Session row exists at {partition_key!r} / {sort_key!r}")
        self.partition_key = partition_key
        self.sort_key = sort_key


class TerminalStateNeedsSettlement(ValueError):
    """A terminal state was offered as a live transition, which would leave the binding behind.

    Raised by :class:`LiveTransition`, and it is one half of what makes cleanup layer 1 structural:
    the write type that carries no binding key refuses to carry a terminal state, so the only way to
    record one is :class:`TerminalSettlement`, which always carries the key.
    """

    def __init__(self, state: LifecycleState) -> None:
        super().__init__(
            f"{state.value} is terminal, so it is recorded by a TerminalSettlement that also "
            f"deletes the Affinity_Key binding (R10.16), never as a live transition"
        )
        self.state = state


class LiveStateNeedsNoSettlement(ValueError):
    """A live state was offered as a terminal settlement, which would delete a live binding.

    The other half. A settlement deletes the binding, so admitting a live state would strand a
    Session that is still serving requests with no way for its caller to reconnect to it.
    """

    def __init__(self, state: LifecycleState) -> None:
        super().__init__(
            f"{state.value} is not terminal, so recording it must not delete the "
            f"Affinity_Key binding; use a LiveTransition"
        )
        self.state = state


def _require_reason(state: LifecycleState, reason: str) -> None:
    """Refuse a transition that records no reason for itself.

    R14.2 requires an operator to determine both which state a Session occupies and *why* it
    transitioned, and `stateReason` is where the second half is recorded. A blank reason would
    satisfy the attribute and answer nothing, so it is refused where the transition is built rather
    than discovered as an empty field during an incident.
    """
    if not reason.strip():
        raise ValueError(f"a transition to {state.value} must record a reason")


@dataclass(frozen=True, slots=True)
class BindingKey:
    """The primary key of one Affinity_Key binding item.

    A key and nothing else. A settlement deletes a binding by key rather than reading it first,
    because there is nothing on the item a decision could depend on: it holds a Session identifier,
    a `boundAt` and an expiry, and the Session identifier is the one this settlement is terminating.
    """

    partition_key: str
    sort_key: str


class SettlementSubject(Protocol):
    """What a terminal settlement reads off the row it settles, and what its audit record needs.

    :class:`~control_plane.state.records.SessionRecord` satisfies it, and it is what every caller
    inside a Session_Orchestrator execution passes. It exists as a protocol for the Reaper, whose
    whole design premise is that a sweep is **one bounded query with no follow-up read**: the rows it
    settles come from the `deadline-index` projection, which carries the Session's keys, its
    `tenantId`, its `lifecycleState`, its `createdAt` and its `affinityKeyDigest` and deliberately not
    the four configured limits a complete :class:`~control_plane.state.records.SessionRecord`
    requires. Every attribute below is one that projection carries — it was chosen for this — so
    widening this parameter is what lets the Reaper reach :meth:`LifecycleReconciler.settle` rather
    than either fabricating the unprojected half of a record or spending a `GetItem` per due row.

    The first four are what the *write* needs. :attr:`session_id`, :attr:`tenant_id` and
    :attr:`lifecycle_state` are what the *audit record* needs, and they are read for nothing else:
    R14.2 requires a record naming the Session, the Tenant and the state transitioned from, and none
    of the three is derivable from a key without reversing one. Nothing here decides *whether* to
    settle — the state being recorded is still the settlement's own argument, and
    :class:`TerminalSettlement` carries none of these three, so the store cannot condition on one.
    """

    @property
    def pk(self) -> str:
        """The Tenant partition key the row was written at."""
        ...

    @property
    def sort_key(self) -> str:
        """`S#<sessionId>`."""
        ...

    @property
    def created_at(self) -> int:
        """Epoch milliseconds, read only to derive the `tenant-state-index` sort key."""
        ...

    @property
    def affinity_key_digest(self) -> str | None:
        """The digest cleanup layers 1 and 2 both delete the binding by, or `None` for no binding."""
        ...

    @property
    def session_id(self) -> str:
        """The Session an audit record names, and the identifier R14.3 correlates on."""
        ...

    @property
    def tenant_id(self) -> str:
        """The Tenant an audit record attributes the transition to (R14.2)."""
        ...

    @property
    def lifecycle_state(self) -> LifecycleState:
        """The state this component observed, which is the record's `previousState` (R14.2)."""
        ...


@dataclass(frozen=True, slots=True)
class LiveTransition:
    """A lifecycle write that moves a Session between two live states.

    Constructed through :func:`live_transition_for` or :func:`write_for`, both of which derive every
    field from the Session record, so a transition cannot name a row in one partition and a state
    derived from another.

    Raises:
        TerminalStateNeedsSettlement: `state` is terminal. There is deliberately no value of this
            type that carries one.
        ValueError: `state_reason` is blank.
    """

    partition_key: str
    sort_key: str
    state: LifecycleState
    state_reason: str
    updated_at: int
    state_created_at: str

    def __post_init__(self) -> None:
        if self.state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise TerminalStateNeedsSettlement(self.state)
        _require_reason(self.state, self.state_reason)


@dataclass(frozen=True, slots=True)
class TerminalSettlement:
    """A terminal lifecycle write together with the binding deletion that accompanies it (R10.16).

    Constructed through :func:`settlement_for` or :func:`write_for`, which derive :attr:`binding`
    from the record's own `affinityKeyDigest`. A caller supplies no binding key and therefore cannot
    supply the wrong one or none at all; `None` means the record carries no digest, so this Session
    was never created through get-or-create and there is no binding to delete.

    Raises:
        LiveStateNeedsNoSettlement: `state` is not terminal.
        ValueError: `state_reason` is blank.
    """

    partition_key: str
    sort_key: str
    state: LifecycleState
    state_reason: str
    updated_at: int
    state_created_at: str
    binding: BindingKey | None

    @property
    def removed_attributes(self) -> tuple[str, ...]:
        """What the update's `REMOVE` clause names: `reapDeadline`, always.

        A property rather than a field, so no caller can settle a Session and leave it in
        `deadline-index`. :class:`LiveTransition` has no counterpart — a live transition keeps the
        row in the index, because a Session that is still running still has a deadline to reach.
        """
        return (REAP_DEADLINE_ATTRIBUTE,)

    def __post_init__(self) -> None:
        if not self.state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise LiveStateNeedsNoSettlement(self.state)
        _require_reason(self.state, self.state_reason)
        if (
            self.binding is not None
            and self.binding.partition_key != self.partition_key
        ):
            # Both items are in the Tenant partition the record came from, and a transaction whose
            # two items sat in different partitions would be refused by `dynamodb:LeadingKeys`
            # anyway. Refusing here says which of the two keys was wrong.
            raise ValueError(
                f"the binding at {self.binding.partition_key!r} is not in the Session's "
                f"partition {self.partition_key!r}"
            )


class ReconciliationOutcome(Enum):
    """What became of one reconciliation.

    Three outcomes rather than a boolean, because "the write did not happen" has two meanings that
    an operator must be able to tell apart: a report discarded because the Session was already
    terminal is the mechanism working, and anything else is not.
    """

    #: A live state was written and the record now mirrors the report.
    MIRRORED = "mirrored"
    #: A terminal state was written and the binding, if there was one, was deleted with it.
    SETTLED = "settled"
    #: The record was already terminal, so the write was refused and the report discarded (R6.7).
    ABSORBED = "absorbed"


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """The outcome of one reconciliation, and the state the row holds afterwards.

    :attr:`state` is the recorded state as it now stands rather than the state that was offered, so
    an absorbed report reports the terminal state that absorbed it. That is the value a caller
    should log and act on: a caller told only "absorbed" would still have to read the row to find out
    what it was absorbed into.
    """

    state: LifecycleState
    outcome: ReconciliationOutcome
    binding_deleted: bool


class SessionLifecycleStore(Protocol):
    """The two lifecycle writes, stated as the condition expressions they carry.

    The conditions *are* the guarantees. An implementation that dropped one would still satisfy both
    signatures and would break absorption or cleanup layer 1, so they are written down here rather
    than left to each implementation to remember — the posture
    :class:`~control_plane.allocation.ledger.ClaimItemStore` and
    :class:`~control_plane.api.resolution.BindingStore` both take.

    A structural type, so the offline suite drives every path against an in-memory store keyed as
    DynamoDB is, with no deployed resource and no network.

    Reached with the per-request tenant-confined credentials of :mod:`control_plane.state.access`,
    whose action set already carries `UpdateItem`, `DeleteItem` and `TransactWriteItems`. Both items
    of the transaction below sit in one Tenant partition, so a settlement that reached another
    Tenant's partition would be refused by IAM rather than by a check here.
    """

    def advance_live_state(self, transition: LiveTransition) -> None:
        """`UpdateItem` the row to a live state, refusing to move a terminal row.

        `SET lifecycleState = :state, stateReason = :reason, updatedAt = :at,
        stateCreatedAt = :stateCreatedAt` under
        `ConditionExpression: attribute_exists(pk) AND NOT lifecycleState IN (:terminated, :failed)`.

        `stateCreatedAt` is written with the state because it is the `tenant-state-index` sort key
        derived from it; a write that moved one without the other would leave `ListSessions` with a
        state filter returning the row under the state it used to hold.

        No `REMOVE`. A live transition leaves `reapDeadline` in place, because a Session that is
        still live still has a deadline for the Reaper to find it by.

        Raises:
            LifecycleConditionFailed: the row is absent, or it is already terminal.
        """
        ...

    def settle_terminal_state(self, settlement: TerminalSettlement) -> None:
        """`TransactWriteItems` the terminal state and the binding deletion, as one step (R10.16).

        An `Update` on the Session row carrying the same condition as
        :meth:`advance_live_state` — so the first terminal state stands and a second converges — and
        a `Delete` on `settlement.binding` when there is one. One transaction, so no instant exists
        in which the row is terminal and the binding still names it.

        The `Update` is `SET lifecycleState = :state, stateReason = :reason, updatedAt = :at,
        stateCreatedAt = :stateCreatedAt REMOVE reapDeadline`. The `REMOVE` is
        :attr:`TerminalSettlement.removed_attributes` and is not optional: `deadline-index` is
        sparse, so dropping its sort key is what takes the settled row out of the Reaper's read path
        for good. An implementation that wrote only the `SET` would leave every Session the
        deployment has ever ended in the index, and a sweep's bounded query would fill with rows
        needing nothing.

        The `Delete` carries **no** condition. A binding already deleted by an earlier settlement, by
        a Reaper sweep or by TTL expiry is the outcome this operation wants, and conditioning on its
        presence would fail the whole transaction — and with it the terminal write that stops a
        billable Sandbox — for a binding that is already gone.

        Raises:
            LifecycleConditionFailed: the Session item's condition failed. Never raised for the
                binding `Delete`, which carries no condition to fail.
        """
        ...


def reason_for_report(status: SandboxStatus) -> str:
    """The `stateReason` to record for a provider report.

    The provider's own reason where it gave one, because a quota name or a start-up failure written
    by the backend is more use than anything this module could compose; otherwise a statement of what
    was reported, which is true and is never blank. Nothing is hardcoded about *why* a provider
    reported a state, for the same reason the duration-ceiling rejection quotes the provider's own
    ceiling rather than a constant.
    """
    reported = status.state_reason
    if reported is not None and reported.strip():
        return reported
    return f"provider reported {status.state.value}"


def live_transition_for(
    record: SessionRecord, *, state: LifecycleState, reason: str, at: int
) -> LiveTransition:
    """Build the live transition recording `state` against this Session row.

    Raises:
        TerminalStateNeedsSettlement: `state` is terminal; use :func:`settlement_for`.
    """
    return LiveTransition(
        partition_key=record.pk,
        sort_key=record.sort_key,
        state=state,
        state_reason=reason,
        updated_at=at,
        state_created_at=tenant_state_sort_key(state.value, record.created_at),
    )


def settlement_for(
    record: SettlementSubject, *, state: LifecycleState, reason: str, at: int
) -> TerminalSettlement:
    """Build the terminal settlement recording `state` and deleting this Session's binding (R10.16).

    The binding key is derived here, from the `affinityKeyDigest` the row has carried since its first
    write, through the same :func:`~control_plane.state.keys.binding_sort_key` that produced the key
    the binding was written at. That shared producer is the whole of the guarantee: the item this
    deletes and the item :func:`~control_plane.api.resolution.binding_for` wrote are the same item by
    construction rather than by two spellings that happen to agree.

    `record` is a :class:`SettlementSubject` rather than a
    :class:`~control_plane.state.records.SessionRecord`, which every Session_Orchestrator caller
    still passes. The widening is the Reaper's: it settles rows read from the `deadline-index`
    projection, and the four attributes this function reads are the four that projection carries for
    exactly this purpose.

    Raises:
        LiveStateNeedsNoSettlement: `state` is not terminal.
    """
    return TerminalSettlement(
        partition_key=record.pk,
        sort_key=record.sort_key,
        state=state,
        state_reason=reason,
        updated_at=at,
        state_created_at=tenant_state_sort_key(state.value, record.created_at),
        binding=None
        if record.affinity_key_digest is None
        else BindingKey(
            partition_key=record.pk,
            sort_key=binding_sort_key(record.affinity_key_digest),
        ),
    )


def write_for(
    record: SessionRecord, *, state: LifecycleState, reason: str, at: int
) -> LiveTransition | TerminalSettlement:
    """Build the lifecycle write for this state, choosing the type from the state's terminality.

    This dispatch is where cleanup layer 1 stops being a rule and becomes a shape: a terminal state
    can only ever produce a :class:`TerminalSettlement`, which carries the binding key, and a live
    state can only ever produce a :class:`LiveTransition`, which cannot carry a terminal state to
    begin with. No caller chooses, so no caller can choose wrongly.
    """
    if state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
        return settlement_for(record, state=state, reason=reason, at=at)
    return live_transition_for(record, state=state, reason=reason, at=at)


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class LifecycleReconciler:
    """Mirrors provider-reported state onto the Session record, and settles it terminally.

    Both collaborators are injected and both are structural types. There is no provider on this
    class: a reconciliation records what a Sandbox has already done and cannot suspend, terminate or
    provision one, so the blast radius of every path below is two DynamoDB writes and one read.

    The read is used on one path only — an absorbed write, to say which terminal state absorbed it —
    so the ordinary reconciliation is a single write.

    `audit` has no default, the posture :class:`~control_plane.reaper.SweepMetrics` takes and for the
    same reason: a no-op default would leave a deployment that forgot to wire an auditor looking
    exactly like one in which no Session ever changed state.
    """

    store: SessionLifecycleStore
    lookup: SessionLookup
    audit: LifecycleAuditor
    clock: Callable[[], datetime] = _utc_now

    def reconcile(self, record: SessionRecord, status: SandboxStatus) -> Reconciliation:
        """Mirror one provider report onto the Session record (R6.7).

        A terminal report settles the Session and deletes its binding in the same step; a live
        report advances the record. Which of the two happens is decided by :func:`write_for` from
        the mirrored state alone, so this method contains no branch that could pair a terminal state
        with a live write.

        A report arriving after the record is already terminal is *absorbed*: reported as
        :attr:`ReconciliationOutcome.ABSORBED` with the terminal state that absorbed it, not raised.
        Out-of-order reports are the ordinary case here rather than the exceptional one.

        Raises:
            SessionRecordAbsent: the row named by `record` no longer exists.
        """
        return self._commit(
            write_for(
                record,
                state=PROVIDER_STATE_MIRROR[status.state],
                reason=reason_for_report(status),
                at=self._now(),
            ),
            subject=record,
        )

    def settle(
        self, record: SettlementSubject, *, state: LifecycleState, reason: str
    ) -> Reconciliation:
        """Record a terminal state this component decided on, deleting the binding with it (R10.16).

        The path for every terminal state no provider reported: provisioning refused for an
        exhausted quota (R6.8), a `/run` hook that returned non-200 including a failed state restore
        (R13.7), a claim collision, an explicit terminate that has completed, and a Reaper sweep. All
        of them reach one method, and it is the method that cannot omit the deletion.

        `record` is a :class:`SettlementSubject` so that a Reaper sweep — which holds a
        `deadline-index` projection rather than a complete row — settles through this method like
        everything else. It is also what makes the convergence R10.7 asks for the store's business
        rather than the Reaper's: two components settling one Session both arrive here, the first
        terminal state stands, and the second is reported
        :attr:`ReconciliationOutcome.ABSORBED`.

        Raises:
            LiveStateNeedsNoSettlement: `state` is not terminal.
            SessionRecordAbsent: the row named by `record` no longer exists.
        """
        return self._commit(
            settlement_for(record, state=state, reason=reason, at=self._now()),
            subject=record,
        )

    def advance(
        self, record: SessionRecord, *, state: LifecycleState, reason: str
    ) -> None:
        """Commit one live transition this component decided on, and audit it (R14.2).

        The transitions no provider reports: `ORCHESTRATING → PROVISIONING`, `STARTING → RUNNING` and
        the `CONTINUING` a duration-ceiling handoff begins with. They reach this method rather than
        the store directly so that every audited transition is audited in one place.

        A condition failure is **not** absorbed. Each caller is about to do something to a Sandbox,
        and a row that has gone terminal underneath it is a reason to stop rather than a note to add
        to a result.

        Raises:
            TerminalStateNeedsSettlement: `state` is terminal; use :meth:`settle`.
            LifecycleConditionFailed: the row is absent, or it is already terminal.
        """
        write = live_transition_for(record, state=state, reason=reason, at=self._now())
        self.store.advance_live_state(write)
        self._audit(write, subject=record)

    def _commit(
        self, write: LiveTransition | TerminalSettlement, *, subject: SettlementSubject
    ) -> Reconciliation:
        """Apply one lifecycle write, reporting an excluded condition rather than raising it."""
        try:
            if isinstance(write, TerminalSettlement):
                self.store.settle_terminal_state(write)
                self._audit(write, subject=subject)
                return Reconciliation(
                    state=write.state,
                    outcome=ReconciliationOutcome.SETTLED,
                    binding_deleted=write.binding is not None,
                )
            self.store.advance_live_state(write)
        except LifecycleConditionFailed as failure:
            return self._absorbed(write, failure)
        self._audit(write, subject=subject)
        return Reconciliation(
            state=write.state,
            outcome=ReconciliationOutcome.MIRRORED,
            binding_deleted=False,
        )

    def _audit(
        self,
        write: LiveTransition | TerminalSettlement,
        *,
        subject: SettlementSubject,
    ) -> None:
        """Emit the audit record for a transition that happened (R14.2).

        After the write, so a refused one is audited as nothing. Skipped when the write recorded the
        state the row already held: the governing loop mirrors `RUNNING` on every poll turn, and those
        are observations rather than transitions.

        The timestamp is the write's own `updatedAt`, so the record and the row it moved join by
        equality rather than by proximity.
        """
        if subject.lifecycle_state is write.state:
            return
        self.audit.emit(
            session_id=subject.session_id,
            tenant_id=subject.tenant_id,
            previous_state=subject.lifecycle_state,
            new_state=write.state,
            reason=write.state_reason,
            occurred_at=write.updated_at,
        )

    def _absorbed(
        self,
        write: LiveTransition | TerminalSettlement,
        failure: LifecycleConditionFailed,
    ) -> Reconciliation:
        """Establish which of the condition's two excluded cases occurred, and report it.

        The read happens only on this already-exceptional path, so the ordinary reconciliation stays
        one write. A row that is present and *not* terminal did not fail this condition for a reason
        this module understands, so the failure is re-raised rather than reported as an absorption
        that did not happen.

        Raises:
            SessionRecordAbsent: there is no row at the write's key.
            LifecycleConditionFailed: the row is present and live.
        """
        item = self.lookup.read_session(
            partition_key=write.partition_key, sort_key=write.sort_key
        )
        if item is None:
            raise SessionRecordAbsent(write.partition_key, write.sort_key) from failure
        recorded = SessionRecord.from_item(item).lifecycle_state
        if not recorded.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise failure
        return Reconciliation(
            state=recorded,
            outcome=ReconciliationOutcome.ABSORBED,
            binding_deleted=False,
        )

    def _now(self) -> int:
        """Epoch milliseconds, the unit every recorded timestamp in the State_Store uses."""
        moment = self.clock()
        if moment.tzinfo is None:
            raise ValueError("the lifecycle clock must return an aware datetime")
        return int(moment.timestamp() * _MILLISECONDS_PER_SECOND)
