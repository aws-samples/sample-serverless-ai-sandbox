# kiro-classification: public
"""Lifecycle reconciliation, terminal-state absorption, and cleanup layer 1.

Every assertion here is deterministic. Property 20 — Reaper convergence and lifecycle reconciliation
over drawn record sets and drawn sequences of provider-reported states — and Property 38 — a binding
outliving its Session by no path — both belong to phase 9's tasks and to their own files, so nothing
here draws inputs. What this file establishes is the behaviour those drawn sequences will be
quantified over, and it does so in three structural senses rather than by example alone:

- `test_the_write_type_is_a_function_of_the_states_terminality` walks every
  `LifecycleState` and asserts which of the two write types it produces. A state added later fails
  here rather than reaching a write that could pair it with the wrong treatment.
- `test_a_terminal_state_cannot_be_recorded_without_the_binding_deletion` asserts the refusal at the
  *constructor*, not at a call site: there is no value of `advance_live_state`'s parameter type that
  carries a terminal state, and no way to build a settlement that does not carry the binding key.
- `test_a_settlement_is_one_step_and_the_row_and_the_binding_move_together` reads the store double's
  recorded step log. The terminal write and the delete are one entry, which is R10.16 stated as an
  atomicity rather than as a comment.

The store double enforces the condition expressions
:class:`~control_plane.lifecycle.SessionLifecycleStore` documents, because those conditions are what
absorption *is*. A double that wrote unconditionally would let every test here pass while the
deployed behaviour resurrected terminated Sessions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

import pytest

from control_plane.api.resolution import BindingSettings, binding_for
from control_plane.lifecycle import (
    ABSORBING_LIFECYCLE_STATES,
    PROVIDER_STATE_MIRROR,
    REAP_DEADLINE_ATTRIBUTE,
    RECORD_ONLY_LIFECYCLE_STATES,
    BindingKey,
    LifecycleConditionFailed,
    LifecycleReconciler,
    LiveStateNeedsNoSettlement,
    LiveTransition,
    ReconciliationOutcome,
    SessionRecordAbsent,
    TerminalSettlement,
    TerminalStateNeedsSettlement,
    live_transition_for,
    reason_for_report,
    settlement_for,
    write_for,
)
from control_plane.observability import LifecycleAuditor
from control_plane.providers.base import SandboxHandle, SandboxState, SandboxStatus
from control_plane.state.keys import affinity_key_digest, binding_sort_key
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.state.table import (
    DEADLINE_INDEX,
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for
from tests.test_control_plane_observability import BrokenSink, RecordingSink

TENANT: Final = "tenant-a"
OTHER_TENANT: Final = "tenant-b"
CALLER: Final = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
OTHER_CALLER: Final = f"arn:aws:sts::123456789012:assumed-role/Caller/{OTHER_TENANT}"
SESSION_ID: Final = "01HB0000000000000000000000"
PROVIDER: Final = "local-firecracker"
SANDBOX_ID: Final = "sandbox-1"

AFFINITY_KEY: Final = "thread#9f3"
DIGEST: Final = affinity_key_digest(AFFINITY_KEY)

#: Epoch milliseconds, fixed so every timestamp expectation is arithmetic rather than a comparison
#: against the wall clock.
CREATED_MS: Final = 1_700_000_000_000
NOW_MS: Final = CREATED_MS + 90_000
NOW: Final = datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)

MAX_DURATION_SECONDS: Final = 3600

#: The names the store double records for the two halves of a settlement, spelled once so a test and
#: the double cannot disagree about what "one step" contained.
UPDATE_SESSION: Final = "update-session"
DELETE_BINDING: Final = "delete-binding"
ADVANCE_SESSION: Final = "advance-session"


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=TENANT)


def other_principal() -> AuthenticatedPrincipal:
    """A second Tenant, so a partition key that is not this Session's still comes from `pk_for`."""
    return AuthenticatedPrincipal(caller_identity=OTHER_CALLER, tenant_id=OTHER_TENANT)


def handle() -> SandboxHandle:
    return SandboxHandle(provider_name=PROVIDER, sandbox_id=SANDBOX_ID, opaque={})


def report(state: SandboxState, reason: str | None = None) -> SandboxStatus:
    """A provider report of one Sandbox state, with no reason unless a test needs one."""
    return SandboxStatus(
        handle=handle(),
        state=state,
        memory_bytes=512 * 1024 * 1024,
        started_at=None,
        state_reason=reason,
    )


def session_record(
    *, state: LifecycleState, digest: str | None = DIGEST
) -> SessionRecord:
    """A complete Session row in the given state, bound to `digest` unless a test says otherwise."""
    return SessionRecord(
        pk=pk_for(principal()),
        session_id=SESSION_ID,
        tenant_id=TENANT,
        provider_name=PROVIDER,
        lifecycle_state=state,
        created_at=CREATED_MS,
        updated_at=CREATED_MS,
        max_duration_seconds=MAX_DURATION_SECONDS,
        idle_seconds=300,
        suspended_seconds=600,
        auto_resume=True,
        memory_bytes=512 * 1024 * 1024,
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        reap_shard=3,
        reap_deadline=CREATED_MS + MAX_DURATION_SECONDS * 1000,
        artifact_retention_days=7,
        sandbox_id=SANDBOX_ID,
        affinity_key_digest=digest,
    )


# --- the store double ------------------------------------------------------------------------------


@dataclass
class FakeLifecycleStore:
    """An in-memory State_Store that enforces the conditions the store protocol documents.

    `steps` records one entry per atomic step, listing the operations that step committed. A
    settlement therefore appears as a single entry naming both halves, and a settlement whose
    condition failed appears as no entry at all — which is what lets a test assert that neither item
    moved rather than only that the row did not.
    """

    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    steps: list[tuple[str, ...]] = field(default_factory=list)

    # -- seating ----------------------------------------------------------------------------------

    def seat(self, record: SessionRecord) -> SessionRecord:
        self.items[(record.pk, record.sort_key)] = dict(record.to_item())
        if record.affinity_key_digest is not None:
            binding = binding_for(record, record.affinity_key_digest, BindingSettings())
            self.items[(binding.pk, binding.sort_key)] = dict(binding.to_item())
        return record

    def row(self, record: SessionRecord) -> SessionRecord:
        return SessionRecord.from_item(self.items[(record.pk, record.sort_key)])

    def holds_binding(self, record: SessionRecord, digest: str = DIGEST) -> bool:
        return (record.pk, binding_sort_key(digest)) in self.items

    # -- the reader -------------------------------------------------------------------------------

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        item = self.items.get((partition_key, sort_key))
        return None if item is None else dict(item)

    # -- the two writes ---------------------------------------------------------------------------

    def advance_live_state(self, transition: LiveTransition) -> None:
        item = self._admit(transition.partition_key, transition.sort_key)
        self._set_state(item, transition)
        self.steps.append((ADVANCE_SESSION,))

    def settle_terminal_state(self, settlement: TerminalSettlement) -> None:
        # Read the condition before either write, so a refused settlement commits neither item.
        item = self._admit(settlement.partition_key, settlement.sort_key)
        self._set_state(item, settlement)
        # The `REMOVE` half. Honoured here because a double that ignored it would leave every
        # assertion about a settled row passing while the deployed write kept the row in
        # `deadline-index`.
        for attribute in settlement.removed_attributes:
            item.pop(attribute, None)
        committed = [UPDATE_SESSION]
        if settlement.binding is not None:
            # Unconditional: a binding already gone is the outcome this operation wants.
            self.items.pop(
                (settlement.binding.partition_key, settlement.binding.sort_key), None
            )
            committed.append(DELETE_BINDING)
        self.steps.append(tuple(committed))

    # -- the condition ----------------------------------------------------------------------------

    def _admit(self, partition_key: str, sort_key: str) -> dict[str, Any]:
        """`attribute_exists(pk) AND NOT lifecycleState IN (:terminated, :failed)`."""
        item = self.items.get((partition_key, sort_key))
        if item is None:
            raise LifecycleConditionFailed("no item at this key")
        if LifecycleState(item["lifecycleState"]) in ABSORBING_LIFECYCLE_STATES:
            raise LifecycleConditionFailed("the row is already terminal")
        return item

    @staticmethod
    def _set_state(
        item: dict[str, Any], write: LiveTransition | TerminalSettlement
    ) -> None:
        item["lifecycleState"] = write.state.value
        item["stateReason"] = write.state_reason
        item["updatedAt"] = write.updated_at
        item[TENANT_STATE_INDEX.sort_key] = write.state_created_at


class AlwaysRefusingStore(FakeLifecycleStore):
    """A store whose condition fails while the row it names is live and present.

    Not a state the deployed store can reach — the condition excludes exactly two cases and this is
    neither — which is why the reconciler must re-raise rather than report it as an absorption that
    did not happen.
    """

    def advance_live_state(self, transition: LiveTransition) -> None:
        raise LifecycleConditionFailed(
            "refused for no reason the reconciler understands"
        )


def auditor(sink: RecordingSink | BrokenSink | None = None) -> LifecycleAuditor:
    """The auditor every reconciliation below writes through, attributed to this caller."""
    return LifecycleAuditor(principal=CALLER, sink=RecordingSink() if sink is None else sink)


def reconciler(
    store: FakeLifecycleStore, *, audit: LifecycleAuditor | None = None
) -> LifecycleReconciler:
    return LifecycleReconciler(
        store=store,
        lookup=store,
        audit=auditor() if audit is None else audit,
        clock=lambda: NOW,
    )


def audited(
    store: FakeLifecycleStore,
) -> tuple[LifecycleReconciler, RecordingSink]:
    """A reconciler and the sink its audit records land in (R14.2)."""
    sink = RecordingSink()
    return reconciler(store, audit=auditor(sink)), sink


# --- the mirror ------------------------------------------------------------------------------------


def test_the_mirror_is_total_over_every_state_a_provider_can_report() -> None:
    """R6.7 is a claim about every provider report, so the mapping admits no default."""
    assert set(PROVIDER_STATE_MIRROR) == set(SandboxState)


def test_the_record_only_states_are_the_three_no_sandbox_can_be_in() -> None:
    """Each describes the Session record rather than a Sandbox, so no report can produce it."""
    assert RECORD_ONLY_LIFECYCLE_STATES == {
        LifecycleState.PENDING,
        LifecycleState.ORCHESTRATING,
        LifecycleState.CONTINUING,
    }


def test_a_reported_pending_sandbox_mirrors_onto_provisioning() -> None:
    """The one entry whose two sides are spelled differently, and the reason the mirror is explicit.

    `LifecycleState.PENDING` is the row written before any execution and before any Sandbox exists,
    so mirroring a provider's `PENDING` onto it would move a Session whose Sandbox is already
    billable backwards into the orphan window the Reaper's orphan pass keys on.
    """
    assert PROVIDER_STATE_MIRROR[SandboxState.PENDING] is LifecycleState.PROVISIONING


def test_the_recorded_reason_prefers_the_providers_own_and_is_never_blank() -> None:
    assert reason_for_report(report(SandboxState.FAILED, "quota exhausted")) == (
        "quota exhausted"
    )
    assert reason_for_report(report(SandboxState.FAILED, "   ")) == (
        "provider reported FAILED"
    )
    assert (
        reason_for_report(report(SandboxState.RUNNING)) == "provider reported RUNNING"
    )


# --- the write types -------------------------------------------------------------------------------


def test_the_write_type_is_a_function_of_the_states_terminality() -> None:
    """Every lifecycle state, and which of the two write types it can produce.

    This is the whole of cleanup layer 1 as a shape: a terminal state has no way to become anything
    but a settlement, and a settlement always carries the binding key. A state added to the model
    later fails here rather than reaching a write that treats it as live.
    """
    record = session_record(state=LifecycleState.RUNNING)
    for state in LifecycleState:
        write = write_for(record, state=state, reason="because", at=NOW_MS)
        if state.is_terminal:
            assert isinstance(write, TerminalSettlement), state
            assert write.binding is not None, state
        else:
            assert isinstance(write, LiveTransition), state


def test_a_terminal_state_cannot_be_recorded_without_the_binding_deletion() -> None:
    """Both halves of the refusal, asserted at the constructors rather than at a call site."""
    record = session_record(state=LifecycleState.RUNNING)
    for terminal in sorted(ABSORBING_LIFECYCLE_STATES, key=lambda state: state.value):
        with pytest.raises(TerminalStateNeedsSettlement):
            live_transition_for(record, state=terminal, reason="because", at=NOW_MS)
    with pytest.raises(LiveStateNeedsNoSettlement):
        settlement_for(
            record, state=LifecycleState.RUNNING, reason="because", at=NOW_MS
        )


def test_a_settlement_deletes_the_item_the_binding_writer_wrote() -> None:
    """The delete and the write share one key producer, so they cannot name different items.

    The unit is asserted alongside it: `expiresAt` is epoch seconds while `boundAt` is epoch
    milliseconds, and milliseconds in the TTL attribute would put every expiry tens of thousands of
    years out and make cleanup layer 3 silently inert (R13.8).
    """
    record = session_record(state=LifecycleState.TERMINATING)
    binding = binding_for(record, DIGEST, BindingSettings())
    settlement = settlement_for(
        record, state=LifecycleState.TERMINATED, reason="terminated", at=NOW_MS
    )

    assert settlement.binding is not None
    assert settlement.binding.partition_key == binding.pk == record.pk
    assert settlement.binding.sort_key == binding.sort_key

    deadline_seconds = (record.created_at + record.max_duration_seconds * 1000) // 1000
    assert binding.expires_at == deadline_seconds
    assert (
        binding.expires_at * 1000
        <= binding.bound_at + record.max_duration_seconds * 1000
    )


def test_a_session_never_bound_settles_with_no_binding_to_delete() -> None:
    """`None` is the absence of a binding, not a forgotten delete."""
    record = session_record(state=LifecycleState.STARTING, digest=None)
    settlement = settlement_for(
        record, state=LifecycleState.FAILED, reason="/run returned 500", at=NOW_MS
    )
    assert settlement.binding is None


def test_a_transition_that_records_no_reason_is_refused() -> None:
    """R14.2 needs the why as well as the what, and a blank reason answers neither."""
    record = session_record(state=LifecycleState.RUNNING)
    with pytest.raises(ValueError, match="must record a reason"):
        live_transition_for(
            record, state=LifecycleState.SUSPENDED, reason=" ", at=NOW_MS
        )
    with pytest.raises(ValueError, match="must record a reason"):
        settlement_for(record, state=LifecycleState.TERMINATED, reason="", at=NOW_MS)


# --- mirroring a live report -----------------------------------------------------------------------


def test_a_live_report_is_mirrored_onto_the_record_and_the_binding_survives() -> None:
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.STARTING))

    outcome = reconciler(store).reconcile(record, report(SandboxState.RUNNING))

    assert outcome.outcome is ReconciliationOutcome.MIRRORED
    assert outcome.state is LifecycleState.RUNNING
    assert outcome.binding_deleted is False
    assert store.row(record).lifecycle_state is LifecycleState.RUNNING
    assert store.row(record).updated_at == NOW_MS
    assert store.holds_binding(record)
    assert store.steps == [(ADVANCE_SESSION,)]


def test_a_mirror_write_moves_the_index_sort_key_with_the_state() -> None:
    """`stateCreatedAt` is derived from the state, so a write that moved one alone would leave
    `ListSessions` with a state filter returning the row under the state it used to hold."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))

    reconciler(store).reconcile(record, report(SandboxState.SUSPENDED))

    item = store.items[(record.pk, record.sort_key)]
    assert item[TENANT_STATE_INDEX.sort_key] == f"SUSPENDED#{CREATED_MS}"
    assert item["lifecycleState"] == "SUSPENDED"


# --- the terminal write ----------------------------------------------------------------------------


def test_a_settlement_is_one_step_and_the_row_and_the_binding_move_together() -> None:
    """R10.16: no instant exists in which the row is terminal and the binding still names it."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.TERMINATING))

    outcome = reconciler(store).reconcile(record, report(SandboxState.TERMINATED))

    assert outcome.outcome is ReconciliationOutcome.SETTLED
    assert outcome.state is LifecycleState.TERMINATED
    assert outcome.binding_deleted is True
    assert store.row(record).lifecycle_state is LifecycleState.TERMINATED
    assert not store.holds_binding(record)
    assert store.steps == [(UPDATE_SESSION, DELETE_BINDING)]


def test_a_settled_row_leaves_the_deadline_index() -> None:
    """The `REMOVE` half of the terminal write, which is what makes `deadline-index` sparse.

    A settled Session no longer carries the index's sort key, so no later Reaper sweep returns it.
    Asserted on the stored item rather than only on the record, because it is the *absence* of the
    attribute — not a null value — that keeps the row out of a global secondary index.
    """
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.TERMINATING))
    assert DEADLINE_INDEX.sort_key in store.items[(record.pk, record.sort_key)]

    reconciler(store).reconcile(record, report(SandboxState.TERMINATED))

    assert DEADLINE_INDEX.sort_key not in store.items[(record.pk, record.sort_key)]
    assert store.row(record).reap_deadline is None


def test_a_live_transition_keeps_the_row_in_the_deadline_index() -> None:
    """Only the terminal write removes the deadline: a live Session still has one to reach."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))

    reconciler(store).reconcile(record, report(SandboxState.SUSPENDED, "idle policy"))

    assert store.row(record).reap_deadline == record.reap_deadline


def test_the_settlement_names_the_attribute_it_removes_and_a_transition_names_none() -> (
    None
):
    """The removal is on the write type, so no caller can settle a row and leave it in the index."""
    record = session_record(state=LifecycleState.RUNNING)
    settlement = write_for(
        record, state=LifecycleState.FAILED, reason="provisioning failed", at=NOW_MS
    )
    assert isinstance(settlement, TerminalSettlement)
    assert settlement.removed_attributes == (REAP_DEADLINE_ATTRIBUTE,)
    assert REAP_DEADLINE_ATTRIBUTE == DEADLINE_INDEX.sort_key
    assert not hasattr(
        write_for(record, state=LifecycleState.SUSPENDED, reason="idle", at=NOW_MS),
        "removed_attributes",
    )


def test_a_terminal_state_this_component_decided_on_settles_the_same_way() -> None:
    """Provisioning failure, quota exhaustion and a non-200 `/run` reach `settle`, not the mirror."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.PROVISIONING))

    outcome = reconciler(store).settle(
        record,
        state=LifecycleState.FAILED,
        reason="quota 'ConcurrentSandboxes' exhausted",
    )

    assert outcome.outcome is ReconciliationOutcome.SETTLED
    assert store.row(record).lifecycle_state is LifecycleState.FAILED
    assert store.row(record).state_reason == "quota 'ConcurrentSandboxes' exhausted"
    assert not store.holds_binding(record)
    assert store.steps == [(UPDATE_SESSION, DELETE_BINDING)]


def test_settle_refuses_a_live_state_rather_than_deleting_a_live_binding() -> None:
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))

    with pytest.raises(LiveStateNeedsNoSettlement):
        reconciler(store).settle(
            record, state=LifecycleState.SUSPENDED, reason="idle policy"
        )

    assert store.steps == []
    assert store.holds_binding(record)


# --- absorption ------------------------------------------------------------------------------------


def test_a_live_report_arriving_after_a_terminal_state_is_absorbed() -> None:
    """The out-of-order report, which is the ordinary case rather than the edge one.

    The record stays terminal, the binding stays deleted, and the store committed nothing — the
    absorption is the condition on the write rather than a check this caller performed first.
    """
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.TERMINATING))
    reconciler(store).reconcile(record, report(SandboxState.TERMINATED))
    store.steps.clear()

    outcome = reconciler(store).reconcile(record, report(SandboxState.RUNNING))

    assert outcome.outcome is ReconciliationOutcome.ABSORBED
    assert outcome.state is LifecycleState.TERMINATED
    assert outcome.binding_deleted is False
    assert store.row(record).lifecycle_state is LifecycleState.TERMINATED
    assert not store.holds_binding(record)
    assert store.steps == []


def test_a_second_terminal_write_converges_and_the_first_state_stands() -> None:
    """Two components may settle one Session, so the terminal write carries the condition too.

    A Reaper writing `TERMINATED` over an orchestrator's `FAILED` would replace the diagnostic state
    with the routine one, so the first terminal state is the one that survives and the second is
    absorbed rather than raised.
    """
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.PROVISIONING))
    reconciler(store).settle(
        record, state=LifecycleState.FAILED, reason="/run returned 500"
    )
    store.steps.clear()

    outcome = reconciler(store).settle(
        record, state=LifecycleState.TERMINATED, reason="reaper sweep"
    )

    assert outcome.outcome is ReconciliationOutcome.ABSORBED
    assert outcome.state is LifecycleState.FAILED
    assert store.row(record).state_reason == "/run returned 500"
    assert store.steps == []


def test_a_report_for_a_row_that_is_gone_is_a_defect_and_not_an_absorption() -> None:
    store = FakeLifecycleStore()
    record = session_record(state=LifecycleState.RUNNING)

    with pytest.raises(SessionRecordAbsent):
        reconciler(store).reconcile(record, report(SandboxState.SUSPENDED))


def test_a_condition_failure_on_a_live_row_is_re_raised() -> None:
    """Neither of the two cases the condition excludes, so it is not absorption and is not hidden."""
    store = AlwaysRefusingStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))

    with pytest.raises(LifecycleConditionFailed):
        reconciler(store).reconcile(record, report(SandboxState.SUSPENDED))

    assert store.row(record).lifecycle_state is LifecycleState.RUNNING


# --- the keys a reconciliation touches -------------------------------------------------------------


def test_every_key_a_settlement_touches_is_the_sessions_own_partition() -> None:
    """The Session row and the binding are one Tenant's items, which is why one transaction can
    carry both under a `dynamodb:LeadingKeys` condition pinned to a single partition."""
    record = session_record(state=LifecycleState.TERMINATING)
    settlement = settlement_for(
        record, state=LifecycleState.TERMINATED, reason="terminated", at=NOW_MS
    )
    assert settlement.binding is not None
    assert {settlement.partition_key, settlement.binding.partition_key} == {
        pk_for(principal())
    }


def test_a_settlement_naming_a_binding_in_another_partition_is_refused() -> None:
    """Unreachable through the factories, which derive both keys from one record. Refused anyway,
    because the message names which of the two keys was wrong."""
    record = session_record(state=LifecycleState.TERMINATING)
    settlement = settlement_for(
        record, state=LifecycleState.TERMINATED, reason="terminated", at=NOW_MS
    )
    assert settlement.binding is not None
    with pytest.raises(ValueError, match="is not in the Session's partition"):
        TerminalSettlement(
            partition_key=settlement.partition_key,
            sort_key=settlement.sort_key,
            state=settlement.state,
            state_reason=settlement.state_reason,
            updated_at=settlement.updated_at,
            state_created_at=settlement.state_created_at,
            binding=BindingKey(
                partition_key=pk_for(other_principal()),
                sort_key=settlement.binding.sort_key,
            ),
        )


def test_the_reaper_index_projects_what_a_terminal_write_needs() -> None:
    """A lifecycle write must supply `stateCreatedAt`, which is derived from `createdAt`, and
    DynamoDB cannot compose a string in an update expression. Without `createdAt` projected, cleanup
    layer 2 would need a `GetItem` per due row and a sweep would stop being one bounded query."""
    assert {"createdAt", "lifecycleState", "affinityKeyDigest"} <= set(
        DEADLINE_INDEX.non_key_attributes
    )


def test_the_store_double_writes_the_attributes_the_protocol_names() -> None:
    """Guards the double itself: a double that silently dropped an attribute would make every
    assertion above pass while the deployed write left the row incomplete."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))
    reconciler(store).reconcile(record, report(SandboxState.SUSPENDING, "idle policy"))

    item = store.items[(record.pk, record.sort_key)]
    assert item[PARTITION_KEY_ATTRIBUTE] == record.pk
    assert item[SORT_KEY_ATTRIBUTE] == record.sort_key
    assert item["stateReason"] == "idle policy"
    assert item["updatedAt"] == NOW_MS

    settled = store.seat(session_record(state=LifecycleState.TERMINATING))
    reconciler(store).reconcile(settled, report(SandboxState.TERMINATED))
    assert DEADLINE_INDEX.sort_key not in store.items[(settled.pk, settled.sort_key)]
