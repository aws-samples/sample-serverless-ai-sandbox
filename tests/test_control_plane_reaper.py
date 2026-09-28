# kiro-classification: public
"""The Reaper's sweep: the bounded query, the four classifications, and cleanup layer 2.

Deterministic throughout, and nothing here draws inputs. **Property 20** — Reaper convergence and
lifecycle reconciliation, quantified over drawn record sets and drawn interleavings of an
orchestrator teardown against a sweep — is task 9.4, and **Property 38** — a binding outlives its
Session by no path — is task 9.7. Both own their numbers, so every test below is an example, and the
implementation is shaped so those two properties are reachable offline: the clock is injected, the
index is a structural seam over an in-memory table, and the provider seam is three methods wide.

Four things here are structural rather than exemplary, and they are the reason this file exists
alongside the examples:

- `test_the_deadline_source_is_total_over_every_lifecycle_state` and its three neighbours walk the
  enums. A lifecycle state or a classification added later fails at import, and these say why.
- `test_a_sweep_reads_only_what_the_index_projects` drives a whole sweep against an index double that
  returns **only** the projected attributes and a store that counts `GetItem`s. The count is zero,
  which is "one bounded query per shard with no follow-up read" asserted rather than described.
- `test_a_sweep_covers_every_shard_exactly_once` reads the double's query log. R10.8 is a claim about
  every Sandbox past a limit, and a sweep visiting a subset of shards would silently exempt the rest.
- `test_the_reclaimer_seam_cannot_provision_or_mint` reads the protocol's own members. The Reaper's
  inability to provision (R6.11) and to mint (R11.4) is a property of the type it holds, not only of
  the lint rules.

The store double enforces the condition expressions
:class:`~control_plane.lifecycle.SessionLifecycleStore` documents, because those conditions are what
convergence *is* (R10.7). A double that wrote unconditionally would let every test here pass while a
deployed sweep replaced an orchestrator's diagnostic `FAILED` with its own routine `TERMINATED`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

import pytest

from control_plane.allocation.ledger import (
    ClaimConditionFailed,
    SandboxClaimLedger,
)
from control_plane.allocation.tags import (
    SESSION_TAG_KEY,
    TENANT_TAG_KEY,
    sandbox_tags,
)
from control_plane.api.resolution import BindingSettings, binding_for
from control_plane.lifecycle import (
    ABSORBING_LIFECYCLE_STATES,
    LifecycleConditionFailed,
    LifecycleReconciler,
    LiveTransition,
    TerminalSettlement,
)
from control_plane.observability import LifecycleAuditor
from control_plane.providers.base import SandboxHandle, SandboxState, SandboxStatus
from control_plane.reaper import (
    BINDING_CLEANUP_LAYER,
    DEADLINE_SOURCE,
    HEARTBEAT_METRIC_NAME,
    NON_REAPING_CLASSES,
    REAP_REASONS,
    REAP_SETTLEMENTS,
    REQUIRED_PROJECTION,
    DeadlineSource,
    DueRow,
    DueRowClass,
    Reaper,
    ReaperSettings,
    SandboxReclaimer,
    SweepAction,
    SweepReport,
    classify,
    handle_of,
    heartbeat_alarm_for,
)
from control_plane.state.keys import (
    ItemShapeError,
    affinity_key_digest,
    binding_sort_key,
)
from control_plane.state.records import (
    Eligibility,
    LifecycleState,
    SandboxClaimRecord,
    SessionRecord,
)
from control_plane.state.table import (
    DEADLINE_INDEX,
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for
from tests.test_control_plane_observability import RecordingSink

TENANT: Final = "tenant-a"
OTHER_TENANT: Final = "tenant-b"
CALLER: Final = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
REAPER_IDENTITY: Final = "arn:aws:lambda:us-east-1:123456789012:function:Reaper"
PROVIDER: Final = "local-firecracker"
EXECUTION_ARN: Final = (
    "arn:aws:states:us-east-1:123456789012:execution:SessionOrchestrator:01HB"
)

AFFINITY_KEY: Final = "thread#9f3"
DIGEST: Final = affinity_key_digest(AFFINITY_KEY)

#: Epoch milliseconds, fixed so every deadline expectation is arithmetic rather than a comparison
#: against the wall clock. A sweep is entirely about elapsed time, so a real clock here would make
#: every case below either slow or unwritable.
CREATED_MS: Final = 1_700_000_000_000
MAX_DURATION_SECONDS: Final = 3600
NOW_MS: Final = CREATED_MS + 3_700_000
NOW: Final = datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)

SHARD_COUNT: Final = 4
BUDGET_SECONDS: Final = 86_400
ORPHAN_THRESHOLD_SECONDS: Final = 300
MAX_ROWS_PER_SHARD: Final = 50
SWEEP_INTERVAL_SECONDS: Final = 60

#: Exactly what a `deadline-index` query returns: the named non-key attributes plus the table's key
#: attributes and the index's own, which DynamoDB projects without their being named. Rebuilt here
#: from the index definition rather than imported from the Reaper, so the two cannot agree by sharing
#: one wrong constant.
PROJECTED: Final[frozenset[str]] = frozenset(DEADLINE_INDEX.non_key_attributes) | {
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    DEADLINE_INDEX.partition_key,
    DEADLINE_INDEX.sort_key,
}


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=TENANT)


def handle(sandbox_id: str = "sandbox-1") -> SandboxHandle:
    return SandboxHandle(provider_name=PROVIDER, sandbox_id=sandbox_id, opaque={})


def handle_map(sandbox_id: str = "sandbox-1") -> dict[str, Any]:
    return {"providerName": PROVIDER, "sandboxId": sandbox_id, "opaque": {}}


def status(state: SandboxState, sandbox_id: str = "sandbox-1") -> SandboxStatus:
    return SandboxStatus(
        handle=handle(sandbox_id),
        state=state,
        memory_bytes=512 * 1024 * 1024,
        started_at=None,
        state_reason=None,
    )


def session_record(
    *,
    session_id: str,
    state: LifecycleState = LifecycleState.RUNNING,
    created_at: int = CREATED_MS,
    reap_deadline: int | None = None,
    reap_shard: int = 1,
    digest: str | None = DIGEST,
    sandbox_id: str | None = "sandbox-1",
    execution_arn: str | None = EXECUTION_ARN,
    tenant_id: str = TENANT,
) -> SessionRecord:
    """A complete Session row, with only the attributes a case varies exposed as parameters."""
    return SessionRecord(
        pk=pk_for(AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=tenant_id)),
        session_id=session_id,
        tenant_id=tenant_id,
        provider_name=PROVIDER,
        lifecycle_state=state,
        created_at=created_at,
        updated_at=created_at,
        max_duration_seconds=MAX_DURATION_SECONDS,
        idle_seconds=300,
        suspended_seconds=600,
        auto_resume=True,
        memory_bytes=512 * 1024 * 1024,
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        reap_shard=reap_shard,
        reap_deadline=(
            created_at + MAX_DURATION_SECONDS * 1000
            if reap_deadline is None
            else reap_deadline
        ),
        artifact_retention_days=7,
        sandbox_id=sandbox_id,
        sandbox_handle=None if sandbox_id is None else handle_map(sandbox_id),
        orchestration_execution_arn=execution_arn,
        affinity_key_digest=digest,
    )


def settings(**overrides: Any) -> ReaperSettings:
    values: dict[str, Any] = {
        "shard_count": SHARD_COUNT,
        "session_budget_seconds": BUDGET_SECONDS,
        "orphan_threshold_seconds": ORPHAN_THRESHOLD_SECONDS,
        "max_rows_per_shard": MAX_ROWS_PER_SHARD,
        "sweep_interval_seconds": SWEEP_INTERVAL_SECONDS,
        "invocation_identity": REAPER_IDENTITY,
    }
    values.update(overrides)
    return ReaperSettings(**values)


def projection_of(record: SessionRecord) -> dict[str, Any]:
    """The item a `deadline-index` query returns for this row, and not one attribute more."""
    return {
        name: value for name, value in record.to_item().items() if name in PROJECTED
    }


def due_row(record: SessionRecord) -> DueRow:
    return DueRow.from_projection(
        projection_of(record), invocation_identity=REAPER_IDENTITY
    )


# --- the doubles -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecordedQuery:
    """One `deadline-index` query, so a test can assert how many a sweep issued and against what."""

    shard: int
    due_at: int
    limit: int


@dataclass
class FakeState:
    """An in-memory State_Store that is at once the index, the lookup and the lifecycle store.

    One object rather than three, because the point of several assertions here is a *relationship*
    between the three seams: that a sweep queries the index and never follows up with the lookup.
    `reads` counts `GetItem`s and `queries` logs every index query, so "one bounded query per shard,
    no follow-up read" is a pair of numbers rather than a claim.

    The index returns :func:`projection_of` and nothing wider, so a sweep that came to depend on an
    unprojected attribute fails here rather than in a deployment.
    """

    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    raw_rows: list[dict[str, Any]] = field(default_factory=list)
    queries: list[RecordedQuery] = field(default_factory=list)
    reads: int = 0
    steps: list[tuple[str, ...]] = field(default_factory=list)

    # -- seating ----------------------------------------------------------------------------------

    def seat(self, record: SessionRecord) -> SessionRecord:
        self.items[(record.pk, record.sort_key)] = dict(record.to_item())
        if record.affinity_key_digest is not None:
            binding = binding_for(record, record.affinity_key_digest, BindingSettings())
            self.items[(binding.pk, binding.sort_key)] = dict(binding.to_item())
        return record

    def seat_raw(self, item: Mapping[str, Any]) -> None:
        """Seat a projected row the index will return verbatim, malformed or otherwise."""
        self.raw_rows.append(dict(item))

    def row(self, record: SessionRecord) -> SessionRecord:
        return SessionRecord.from_item(self.items[(record.pk, record.sort_key)])

    def holds_binding(self, record: SessionRecord, digest: str = DIGEST) -> bool:
        return (record.pk, binding_sort_key(digest)) in self.items

    # -- the index ---------------------------------------------------------------------------------

    def due_rows(
        self, *, shard: int, due_at: int, limit: int
    ) -> Sequence[Mapping[str, Any]]:
        self.queries.append(RecordedQuery(shard=shard, due_at=due_at, limit=limit))
        rows = [
            {name: value for name, value in item.items() if name in PROJECTED}
            for _, item in sorted(self.items.items())
            if item.get(DEADLINE_INDEX.partition_key) == shard
            # Sparse, as a global secondary index is: an item carrying no `reapDeadline` is not in
            # the index at all, which is how a settled Session leaves the Reaper's read path.
            and item.get(DEADLINE_INDEX.sort_key) is not None
            and int(item[DEADLINE_INDEX.sort_key]) <= due_at
        ]
        rows.extend(
            dict(item)
            for item in self.raw_rows
            if item.get(DEADLINE_INDEX.partition_key) == shard
        )
        return rows[:limit]

    # -- the lookup --------------------------------------------------------------------------------

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.reads += 1
        item = self.items.get((partition_key, sort_key))
        return None if item is None else dict(item)

    # -- the two lifecycle writes ------------------------------------------------------------------

    def advance_live_state(self, transition: LiveTransition) -> None:
        item = self._admit(transition.partition_key, transition.sort_key)
        self._set_state(item, transition)
        self.steps.append(("advance-session",))

    def settle_terminal_state(self, settlement: TerminalSettlement) -> None:
        item = self._admit(settlement.partition_key, settlement.sort_key)
        self._set_state(item, settlement)
        # `REMOVE reapDeadline`, which is what drops the row out of the sparse index this fake's
        # `due_rows` reads. Without it a sweep would keep returning every Session ever settled.
        for attribute in settlement.removed_attributes:
            item.pop(attribute, None)
        committed = ["update-session"]
        if settlement.binding is not None:
            self.items.pop(
                (settlement.binding.partition_key, settlement.binding.sort_key), None
            )
            committed.append("delete-binding")
        self.steps.append(tuple(committed))

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


class OrchestratorWinsStore(FakeState):
    """A store in which an orchestrator settles the row between the sweep's read and its write.

    Not a contrivance: it is the interleaving R10.7 requires to converge, and it is the only way to
    reach the absorbed path — a sweep classifying a live row and writing to a terminal one. The
    orchestrator's `FAILED` is applied first, then the condition fails, which is exactly what
    DynamoDB does.
    """

    def settle_terminal_state(self, settlement: TerminalSettlement) -> None:
        item = self.items.get((settlement.partition_key, settlement.sort_key))
        if (
            item is not None
            and LifecycleState(item["lifecycleState"]) not in ABSORBING_LIFECYCLE_STATES
        ):
            item["lifecycleState"] = LifecycleState.FAILED.value
            item["stateReason"] = "recorded FAILED by the Session_Orchestrator"
        raise LifecycleConditionFailed("the row is already terminal")


@dataclass
class RecordingReclaimer:
    """The provider seam, recording every call and answering from configured tables."""

    release: dict[str, tuple[str, ...]] = field(default_factory=dict)
    discovered: dict[tuple[str, str], tuple[SandboxStatus, ...]] = field(
        default_factory=dict
    )
    terminate_failures: set[str] = field(default_factory=set)
    terminated: list[str] = field(default_factory=list)
    release_checked: list[str] = field(default_factory=list)
    discoveries: list[dict[str, str]] = field(default_factory=list)

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        self.terminated.append(handle.sandbox_id)
        if handle.sandbox_id in self.terminate_failures:
            raise RuntimeError(f"the backend refused to stop {handle.sandbox_id}")
        return status(SandboxState.TERMINATED, handle.sandbox_id)

    def release_check(self, handle: SandboxHandle) -> list[str]:
        self.release_checked.append(handle.sandbox_id)
        return list(self.release.get(handle.sandbox_id, ()))

    def discover(self, tags: dict[str, str]) -> list[SandboxStatus]:
        self.discoveries.append(dict(tags))
        key = (tags[TENANT_TAG_KEY], tags[SESSION_TAG_KEY])
        return list(self.discovered.get(key, ()))


@dataclass
class RecordingMetrics:
    """Every sweep report the Reaper emitted, in order."""

    reports: list[SweepReport] = field(default_factory=list)

    def record_sweep(self, report: SweepReport) -> None:
        self.reports.append(report)


@dataclass
class FakeClaimStore:
    """The claim ledger's four operations, with the conditions the protocol documents."""

    items: dict[str, dict[str, Any]] = field(default_factory=dict)

    def seat(self, record: SandboxClaimRecord) -> None:
        self.items[record.pk] = dict(record.to_item())

    def put_claim_if_absent(self, item: Mapping[str, Any]) -> None:
        key = str(item[PARTITION_KEY_ATTRIBUTE])
        if key in self.items:
            raise ClaimConditionFailed("a claim already exists")
        self.items[key] = dict(item)

    def read_claim(self, *, partition_key: str) -> Mapping[str, Any] | None:
        item = self.items.get(partition_key)
        return None if item is None else dict(item)

    def mark_claim_used(self, *, partition_key: str) -> None:
        item = self.items.get(partition_key)
        if item is None or item["eligibility"] != Eligibility.NEVER_RUN.value:
            raise ClaimConditionFailed("not a never-run claim")
        item["eligibility"] = Eligibility.USED.value

    def quarantine_claim(self, *, partition_key: str, reason: str) -> None:
        item = self.items.get(partition_key)
        if item is None or "quarantineReason" in item:
            raise ClaimConditionFailed("absent, or already quarantined")
        item["eligibility"] = Eligibility.QUARANTINED.value
        item["quarantineReason"] = reason


@dataclass(frozen=True, slots=True)
class Harness:
    """One wired Reaper and the doubles behind it, so a test names only what it varies."""

    state: FakeState
    provider: RecordingReclaimer
    metrics: RecordingMetrics
    claims: FakeClaimStore
    reaper: Reaper


def harness(
    *,
    state: FakeState | None = None,
    reaper_settings: ReaperSettings | None = None,
    now: datetime = NOW,
) -> Harness:
    store = state if state is not None else FakeState()
    provider = RecordingReclaimer()
    metrics = RecordingMetrics()
    claims = FakeClaimStore()
    return Harness(
        state=store,
        provider=provider,
        metrics=metrics,
        claims=claims,
        reaper=Reaper(
            index=store,
            provider=provider,
            reconciler=LifecycleReconciler(
                store=store,
                lookup=store,
                audit=LifecycleAuditor(
                    principal=REAPER_IDENTITY, sink=RecordingSink()
                ),
                clock=lambda: now,
            ),
            ledger=SandboxClaimLedger(store=claims, terminator=provider),
            metrics=metrics,
            settings=(reaper_settings if reaper_settings is not None else settings()),
            clock=lambda: now,
        ),
    )


def only(report: SweepReport) -> Any:
    """The single row outcome of a sweep that examined one row."""
    assert len(report.outcomes) == 1, report.outcomes
    return report.outcomes[0]


# --- the classification is total, with no default --------------------------------------------------


def test_the_deadline_source_is_total_over_every_lifecycle_state() -> None:
    """A lifecycle state added later must fail the build rather than be silently swept or skipped."""
    assert set(DEADLINE_SOURCE) == set(LifecycleState)


def test_only_the_terminal_states_have_no_outstanding_deadline() -> None:
    """A settled row normally leaves the index, but one caught mid-settlement must do nothing."""
    assert {
        state
        for state, source in DEADLINE_SOURCE.items()
        if source is DeadlineSource.NONE
    } == ABSORBING_LIFECYCLE_STATES


def test_suspending_is_governed_by_the_suspended_duration_not_the_maximum() -> None:
    """A row mid-flush is one whose caller asked it to stop being scheduled (R10.7)."""
    assert (
        DEADLINE_SOURCE[LifecycleState.SUSPENDING] is DeadlineSource.SUSPENDED_DURATION
    )
    assert (
        DEADLINE_SOURCE[LifecycleState.SUSPENDED] is DeadlineSource.SUSPENDED_DURATION
    )
    assert DEADLINE_SOURCE[LifecycleState.RUNNING] is DeadlineSource.MAX_DURATION


def test_every_classification_either_reaps_or_is_exempted_and_never_both() -> None:
    assert set(REAP_SETTLEMENTS) | NON_REAPING_CLASSES == set(DueRowClass)
    assert not set(REAP_SETTLEMENTS) & NON_REAPING_CLASSES
    assert set(REAP_REASONS) == set(REAP_SETTLEMENTS)


def test_every_reap_records_a_terminal_state_and_a_non_blank_reason() -> None:
    """A settlement refuses a live state and refuses a blank reason, so both must hold here."""
    for classification, state in REAP_SETTLEMENTS.items():
        assert state.is_terminal
        assert REAP_REASONS[classification].strip()


def test_the_orphan_pass_records_failed_and_the_deadline_reaps_record_terminated() -> (
    None
):
    """`PENDING → FAILED` is the design's edge for an execution that never started."""
    assert REAP_SETTLEMENTS[DueRowClass.ORPHANED] is LifecycleState.FAILED
    assert {
        state
        for classification, state in REAP_SETTLEMENTS.items()
        if classification is not DueRowClass.ORPHANED
    } == {LifecycleState.TERMINATED}


def test_the_sweep_needs_no_attribute_the_deadline_index_withholds() -> None:
    """The premise of the whole component: no attribute it reads costs a `GetItem` per due row."""
    assert REQUIRED_PROJECTION <= PROJECTED


# --- classifying one due row -----------------------------------------------------------------------


def test_a_due_running_row_is_a_maximum_duration_reap() -> None:
    row = due_row(session_record(session_id="s-duration"))
    assert (
        classify(row, now=NOW_MS, settings=settings())
        is DueRowClass.MAX_DURATION_REACHED
    )


def test_a_due_suspended_row_is_a_suspended_duration_reap() -> None:
    row = due_row(
        session_record(session_id="s-suspended", state=LifecycleState.SUSPENDED)
    )
    assert (
        classify(row, now=NOW_MS, settings=settings()) is DueRowClass.SUSPENDED_TOO_LONG
    )


def test_a_row_older_than_the_configured_budget_is_a_budget_reap() -> None:
    """The one collapsed deadline the sweep can verify, because `createdAt` is projected."""
    created = NOW_MS - (BUDGET_SECONDS + 1) * 1000
    row = due_row(
        session_record(
            session_id="s-budget", created_at=created, reap_deadline=NOW_MS - 1
        )
    )
    assert classify(row, now=NOW_MS, settings=settings()) is DueRowClass.BUDGET_EXCEEDED


def test_a_terminal_row_is_already_settled_rather_than_reaped_again() -> None:
    for state in ABSORBING_LIFECYCLE_STATES:
        row = due_row(session_record(session_id="s-settled", state=state))
        assert (
            classify(row, now=NOW_MS, settings=settings())
            is DueRowClass.ALREADY_SETTLED
        )


def test_a_row_with_no_execution_arn_past_the_threshold_is_an_orphan() -> None:
    """`orchestrationExecutionArn` is absent only between the row write and `StartExecution`."""
    row = due_row(
        session_record(
            session_id="s-orphan",
            state=LifecycleState.PENDING,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    assert classify(row, now=NOW_MS, settings=settings()) is DueRowClass.ORPHANED


def test_a_row_with_no_execution_arn_inside_the_window_is_deferred() -> None:
    """Inside the window the absence is not orphanhood: the handler is between its two writes.

    Reaping here would settle a Session `FAILED` while its execution was starting, and that
    execution would then provision a Sandbox for a Session already terminal.
    """
    created = NOW_MS - (ORPHAN_THRESHOLD_SECONDS - 1) * 1000
    row = due_row(
        session_record(
            session_id="s-young",
            state=LifecycleState.PENDING,
            created_at=created,
            reap_deadline=created + 1,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    assert (
        classify(row, now=NOW_MS, settings=settings())
        is DueRowClass.WITHIN_ORPHAN_WINDOW
    )


def test_the_orphan_window_closes_exactly_at_the_configured_threshold() -> None:
    created = NOW_MS - ORPHAN_THRESHOLD_SECONDS * 1000
    row = due_row(
        session_record(
            session_id="s-edge",
            state=LifecycleState.PENDING,
            created_at=created,
            reap_deadline=created + 1,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    assert classify(row, now=NOW_MS, settings=settings()) is DueRowClass.ORPHANED


def test_orphanhood_is_decided_by_the_execution_arn_and_not_by_the_state() -> None:
    """A `PENDING` row that carries an ARN is an ordinary Session, and a `PROVISIONING` row
    always carries one, so a state-based orphan test would classify both wrongly."""
    pending_with_execution = due_row(
        session_record(session_id="s-pending", state=LifecycleState.PENDING)
    )
    assert (
        classify(pending_with_execution, now=NOW_MS, settings=settings())
        is DueRowClass.MAX_DURATION_REACHED
    )
    provisioning_without_handle = due_row(
        session_record(
            session_id="s-provisioning",
            state=LifecycleState.PROVISIONING,
            sandbox_id=None,
        )
    )
    assert (
        classify(provisioning_without_handle, now=NOW_MS, settings=settings())
        is DueRowClass.MAX_DURATION_REACHED
    )


# --- parsing a projected row -----------------------------------------------------------------------


def test_a_due_row_carries_the_key_derived_from_its_recorded_tenant() -> None:
    """`pk_for` is the sole producer, so the key a sweep writes to is derived and not read back."""
    record = session_record(session_id="s-key")
    row = due_row(record)
    assert row.pk == pk_for(principal())
    assert row.sort_key == record.sort_key
    assert row.session_id == "s-key"


def test_a_row_whose_partition_key_and_tenant_disagree_is_refused() -> None:
    """The sweep is partitioned by shard rather than by Tenant, so this is where the two must agree."""
    item = projection_of(session_record(session_id="s-forged"))
    item["tenantId"] = OTHER_TENANT
    with pytest.raises(ItemShapeError, match="whose partition key is"):
        DueRow.from_projection(item, invocation_identity=REAPER_IDENTITY)


def test_a_sort_key_of_another_item_shape_is_refused() -> None:
    item = projection_of(session_record(session_id="s-shape"))
    item[SORT_KEY_ATTRIBUTE] = binding_sort_key(DIGEST)
    with pytest.raises(ItemShapeError, match="not a Session sort key"):
        DueRow.from_projection(item, invocation_identity=REAPER_IDENTITY)


def test_a_row_with_no_recorded_handle_reports_none_rather_than_raising() -> None:
    """An absent handle is the ordinary orphan case; a malformed one is a defect."""
    assert (
        handle_of(due_row(session_record(session_id="s-none", sandbox_id=None))) is None
    )
    malformed = projection_of(session_record(session_id="s-bad"))
    malformed["sandboxHandle"] = {"providerName": PROVIDER}
    row = DueRow.from_projection(malformed, invocation_identity=REAPER_IDENTITY)
    with pytest.raises(ItemShapeError, match="no sandboxId"):
        handle_of(row)


def test_the_discover_tags_come_from_the_sole_producer() -> None:
    row = due_row(session_record(session_id="s-tags"))
    assert row.tags() == sandbox_tags(tenant_id=TENANT, session_id="s-tags")


# --- the sweep is one bounded query per shard ------------------------------------------------------


def test_a_sweep_covers_every_shard_exactly_once() -> None:
    """R10.8 is a claim about every Sandbox past a limit, so a partial sweep exempts the rest."""
    wired = harness()
    wired.reaper.sweep()
    assert [query.shard for query in wired.state.queries] == list(range(SHARD_COUNT))
    assert {query.due_at for query in wired.state.queries} == {NOW_MS}
    assert {query.limit for query in wired.state.queries} == {MAX_ROWS_PER_SHARD}


def test_a_sweep_reads_only_what_the_index_projects() -> None:
    """One query per shard and no `GetItem` at all, which is the component's whole premise."""
    wired = harness()
    record = wired.state.seat(session_record(session_id="s-bounded"))
    report = wired.reaper.sweep()
    assert only(report).action is SweepAction.SETTLED
    assert len(wired.state.queries) == SHARD_COUNT
    assert wired.state.reads == 0
    assert wired.state.row(record).lifecycle_state is LifecycleState.TERMINATED


def test_one_sweep_reads_the_clock_once_for_every_row() -> None:
    """Two rows with the same deadline must be classified identically however long the sweep took."""
    wired = harness()
    wired.state.seat(session_record(session_id="s-one", reap_shard=0))
    wired.state.seat(session_record(session_id="s-two", reap_shard=2))
    report = wired.reaper.sweep()
    assert report.swept_at == NOW_MS
    assert {query.due_at for query in wired.state.queries} == {report.swept_at}


def test_one_query_per_shard_is_bounded_by_the_configured_row_limit() -> None:
    """A bounded invocation, because a backlog must not turn every sweep into a timeout."""
    wired = harness(reaper_settings=settings(max_rows_per_shard=1))
    wired.state.seat(session_record(session_id="s-a", reap_shard=1))
    wired.state.seat(session_record(session_id="s-b", reap_shard=1))
    assert len(wired.reaper.sweep().outcomes) == 1
    assert len(wired.state.queries) == SHARD_COUNT


def test_a_limit_above_the_due_set_settles_the_whole_shard_in_one_sweep() -> None:
    wired = harness(reaper_settings=settings(max_rows_per_shard=2))
    first = wired.state.seat(session_record(session_id="s-a", reap_shard=1))
    second = wired.state.seat(session_record(session_id="s-b", reap_shard=1))
    report = wired.reaper.sweep()
    assert [outcome.action for outcome in report.outcomes] == [
        SweepAction.SETTLED,
        SweepAction.SETTLED,
    ]
    for record in (first, second):
        assert wired.state.row(record).lifecycle_state is LifecycleState.TERMINATED


def test_a_settled_row_vacates_its_slot_in_the_due_set() -> None:
    """The bound on a shard's due set is outstanding work, not the deployment's history.

    The terminal write removes `reapDeadline` and `deadline-index` is sparse, so a settled Session
    leaves the index. With a row limit of one, the live row behind the settled one is therefore
    reached by the very next sweep rather than queueing behind a backlog that never shrinks.
    """
    wired = harness(reaper_settings=settings(max_rows_per_shard=1))
    settled = wired.state.seat(session_record(session_id="s-a", reap_shard=1))
    behind = wired.state.seat(session_record(session_id="s-b", reap_shard=1))
    assert only(wired.reaper.sweep()).session_id == "s-a"
    assert wired.state.row(settled).lifecycle_state is LifecycleState.TERMINATED
    assert wired.state.row(settled).reap_deadline is None
    assert DEADLINE_INDEX.sort_key not in wired.state.items[settled.pk, settled.sort_key]

    second = only(wired.reaper.sweep())
    assert second.session_id == "s-b"
    assert second.action is SweepAction.SETTLED
    assert wired.state.row(behind).lifecycle_state is LifecycleState.TERMINATED


# --- reaping, and cleanup layer 2 ------------------------------------------------------------------


def test_a_maximum_duration_reap_terminates_confirms_release_and_settles() -> None:
    """R10.6, then R10.9's confirmation, then the terminal write. The order is not interchangeable."""
    wired = harness()
    record = wired.state.seat(session_record(session_id="s-max"))
    outcome = only(wired.reaper.sweep())
    assert outcome.classification is DueRowClass.MAX_DURATION_REACHED
    assert outcome.action is SweepAction.SETTLED
    assert wired.provider.terminated == ["sandbox-1"]
    assert wired.provider.release_checked == ["sandbox-1"]
    stored = wired.state.row(record)
    assert stored.lifecycle_state is LifecycleState.TERMINATED
    assert stored.state_reason == REAP_REASONS[DueRowClass.MAX_DURATION_REACHED]


def test_the_binding_is_deleted_in_the_same_step_as_the_terminal_write() -> None:
    """Cleanup layer 2 (R10.17), and it is one atomic step rather than two writes in order."""
    wired = harness()
    record = wired.state.seat(session_record(session_id="s-binding"))
    assert wired.state.holds_binding(record)
    outcome = only(wired.reaper.sweep())
    assert outcome.binding_deleted
    assert not wired.state.holds_binding(record)
    assert wired.state.steps == [("update-session", "delete-binding")]


def test_a_session_with_no_binding_settles_with_one_item_rather_than_a_forgotten_delete() -> (
    None
):
    wired = harness()
    wired.state.seat(session_record(session_id="s-nobinding", digest=None))
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.SETTLED
    assert not outcome.binding_deleted
    assert wired.state.steps == [("update-session",)]


def test_a_suspended_reap_records_the_suspended_duration_reason() -> None:
    wired = harness()
    record = wired.state.seat(
        session_record(session_id="s-susp", state=LifecycleState.SUSPENDED)
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.classification is DueRowClass.SUSPENDED_TOO_LONG
    assert (
        wired.state.row(record).state_reason
        == (REAP_REASONS[DueRowClass.SUSPENDED_TOO_LONG])
    )


def test_an_orphan_settles_failed_and_reaches_discover_by_its_tags() -> None:
    """The row a handler left behind: no execution, no handle, and only tags to find it by (R11.7)."""
    wired = harness()
    record = wired.state.seat(
        session_record(
            session_id="s-orphan",
            state=LifecycleState.PENDING,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    wired.provider.discovered[(TENANT, "s-orphan")] = (
        status(SandboxState.RUNNING, "leaked-1"),
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.classification is DueRowClass.ORPHANED
    assert outcome.action is SweepAction.SETTLED
    assert outcome.discovered == 1
    assert wired.provider.discoveries == [
        sandbox_tags(tenant_id=TENANT, session_id="s-orphan")
    ]
    assert wired.provider.terminated == ["leaked-1"]
    assert wired.state.row(record).lifecycle_state is LifecycleState.FAILED
    assert not wired.state.holds_binding(record)


def test_an_orphan_that_never_provisioned_settles_without_terminating_anything() -> (
    None
):
    """`discover` answers nothing for a Session whose execution never started, which is the point."""
    wired = harness()
    record = wired.state.seat(
        session_record(
            session_id="s-empty",
            state=LifecycleState.PENDING,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.SETTLED
    assert outcome.discovered == 0
    assert wired.provider.terminated == []
    assert wired.state.row(record).lifecycle_state is LifecycleState.FAILED


def test_a_row_inside_the_orphan_window_is_deferred_and_nothing_is_written() -> None:
    wired = harness()
    created = NOW_MS - (ORPHAN_THRESHOLD_SECONDS - 1) * 1000
    record = wired.state.seat(
        session_record(
            session_id="s-defer",
            state=LifecycleState.PENDING,
            created_at=created,
            reap_deadline=created + 1,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.DEFERRED
    assert wired.state.steps == []
    assert wired.provider.terminated == []
    assert wired.provider.discoveries == []
    assert wired.state.row(record).lifecycle_state is LifecycleState.PENDING
    assert wired.state.holds_binding(record)


def test_an_already_settled_row_is_recognised_rather_than_terminated_again() -> None:
    """A row settled after the index query's snapshot is still classified from that snapshot."""
    wired = harness()
    wired.state.seat(
        session_record(session_id="s-done", state=LifecycleState.TERMINATED)
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.classification is DueRowClass.ALREADY_SETTLED
    assert outcome.action is SweepAction.NOTHING_TO_DO
    assert wired.provider.terminated == []
    assert wired.state.steps == []


# --- convergence with the orchestrator (R10.7) -----------------------------------------------------


def test_sweeping_twice_converges_rather_than_reaping_twice() -> None:
    """The settled row has left the index, so the second sweep has no row to reap at all."""
    wired = harness()
    record = wired.state.seat(session_record(session_id="s-twice"))
    assert only(wired.reaper.sweep()).action is SweepAction.SETTLED
    assert wired.reaper.sweep().outcomes == ()
    assert wired.provider.terminated == ["sandbox-1"]
    assert wired.state.row(record).lifecycle_state is LifecycleState.TERMINATED
    assert len(wired.state.steps) == 1


def test_an_orchestrator_settling_first_absorbs_the_sweeps_write() -> None:
    """The first terminal state stands, so a routine `TERMINATED` never replaces a diagnostic
    `FAILED` — and the sweep reports the absorption rather than raising."""
    wired = harness(state=OrchestratorWinsStore())
    record = wired.state.seat(session_record(session_id="s-race"))
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.ABSORBED
    assert not outcome.binding_deleted
    assert outcome.quarantined == 0
    assert wired.state.row(record).lifecycle_state is LifecycleState.FAILED
    assert wired.state.row(record).state_reason == (
        "recorded FAILED by the Session_Orchestrator"
    )


# --- R10.9, and failures that must not stop a sweep ------------------------------------------------


def test_retained_resources_withhold_the_terminal_write_and_the_binding() -> None:
    """R10.9: a Session is never recorded as ended while resources it owns are still allocated."""
    wired = harness()
    wired.provider.release["sandbox-1"] = ("eni-7",)
    record = wired.state.seat(session_record(session_id="s-retained"))
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.RESOURCES_RETAINED
    assert outcome.retained == ("eni-7",)
    assert wired.state.steps == []
    assert wired.state.row(record).lifecycle_state is LifecycleState.RUNNING
    assert wired.state.holds_binding(record)


def test_a_release_that_completes_is_settled_by_the_next_sweep() -> None:
    """The deadline does not move, so the remainder is still due and the retry needs no state."""
    wired = harness()
    wired.provider.release["sandbox-1"] = ("eni-7",)
    record = wired.state.seat(session_record(session_id="s-later"))
    assert only(wired.reaper.sweep()).action is SweepAction.RESOURCES_RETAINED
    wired.provider.release.clear()
    assert only(wired.reaper.sweep()).action is SweepAction.SETTLED
    assert wired.state.row(record).lifecycle_state is LifecycleState.TERMINATED
    assert not wired.state.holds_binding(record)


def test_one_failing_provider_call_does_not_stop_the_rest_of_the_sweep() -> None:
    """A sweep that aborted on the first unreachable backend would leave later shards unreaped."""
    wired = harness()
    wired.provider.terminate_failures.add("sandbox-bad")
    bad = wired.state.seat(
        session_record(session_id="s-bad", reap_shard=0, sandbox_id="sandbox-bad")
    )
    good = wired.state.seat(
        session_record(session_id="s-good", reap_shard=3, sandbox_id="sandbox-good")
    )
    report = wired.reaper.sweep()
    by_session = {outcome.session_id: outcome for outcome in report.outcomes}
    assert by_session["s-bad"].action is SweepAction.PROVIDER_FAILED
    assert by_session["s-bad"].failure is not None
    assert by_session["s-good"].action is SweepAction.SETTLED
    assert wired.state.row(bad).lifecycle_state is LifecycleState.RUNNING
    assert wired.state.row(good).lifecycle_state is LifecycleState.TERMINATED


def test_a_malformed_row_is_reported_and_the_sweep_continues() -> None:
    wired = harness()
    wired.state.seat_raw({PARTITION_KEY_ATTRIBUTE: pk_for(principal()), "reapShard": 0})
    good = wired.state.seat(session_record(session_id="s-fine", reap_shard=2))
    report = wired.reaper.sweep()
    actions = {outcome.action for outcome in report.outcomes}
    assert actions == {SweepAction.PROVIDER_FAILED, SweepAction.SETTLED}
    assert wired.state.row(good).lifecycle_state is LifecycleState.TERMINATED
    unparsed = next(
        outcome
        for outcome in report.outcomes
        if outcome.action is SweepAction.PROVIDER_FAILED
    )
    assert unparsed.classification is None


# --- R11.13's quarantine is a separate step --------------------------------------------------------


def test_a_failed_settlement_quarantines_the_claim_afterwards_and_not_inside_it() -> (
    None
):
    """The claim item sits outside every Tenant partition, so the two cannot share a transaction."""
    wired = harness()
    wired.state.seat(
        session_record(
            session_id="s-quarantine",
            state=LifecycleState.PENDING,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    leaked = handle("leaked-2")
    wired.claims.seat(
        SandboxClaimRecord(
            pk=f"H#{PROVIDER}#leaked-2",
            session_id="s-quarantine",
            tenant_id=TENANT,
            claimed_at=CREATED_MS,
        )
    )
    wired.provider.discovered[(TENANT, "s-quarantine")] = (
        status(SandboxState.RUNNING, "leaked-2"),
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.SETTLED
    assert outcome.quarantined == 1
    assert wired.claims.items[f"H#{PROVIDER}#leaked-2"]["eligibility"] == (
        Eligibility.QUARANTINED.value
    )
    # The settlement is one step and the quarantine is not in it.
    assert wired.state.steps == [("update-session", "delete-binding")]
    assert wired.reaper.ledger.quarantine_of(leaked) is not None


def test_an_orphan_holding_no_claim_quarantines_nothing_and_still_settles() -> None:
    """The common case: an orphan is a Session whose execution never reached `ClaimSandbox`."""
    wired = harness()
    record = wired.state.seat(
        session_record(
            session_id="s-noclaim",
            state=LifecycleState.PENDING,
            execution_arn=None,
            sandbox_id=None,
        )
    )
    wired.provider.discovered[(TENANT, "s-noclaim")] = (
        status(SandboxState.RUNNING, "leaked-3"),
    )
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.SETTLED
    assert outcome.quarantined == 0
    assert wired.state.row(record).lifecycle_state is LifecycleState.FAILED


def test_a_terminated_reap_quarantines_nothing() -> None:
    """R11.13's trigger is a recorded Session *failure*, and a deadline reap is not one."""
    wired = harness()
    wired.claims.seat(
        SandboxClaimRecord(
            pk=f"H#{PROVIDER}#sandbox-1",
            session_id="s-plain",
            tenant_id=TENANT,
            claimed_at=CREATED_MS,
        )
    )
    wired.state.seat(session_record(session_id="s-plain"))
    outcome = only(wired.reaper.sweep())
    assert outcome.action is SweepAction.SETTLED
    assert outcome.quarantined == 0
    assert wired.claims.items[f"H#{PROVIDER}#sandbox-1"]["eligibility"] == (
        Eligibility.NEVER_RUN.value
    )


# --- the heartbeat and the counts ------------------------------------------------------------------


def test_a_sweep_that_found_nothing_still_emits_its_heartbeat() -> None:
    """The alarm is on missing data points, so a quiet sweep must still be a data point."""
    wired = harness()
    report = wired.reaper.sweep()
    assert wired.metrics.reports == [report]
    assert report.heartbeat == 1
    assert report.rows_examined == 0
    assert report.shards == tuple(range(SHARD_COUNT))


def test_the_reaped_and_binding_counts_move_together_and_a_gap_is_visible() -> None:
    """ "A binding-cleanup regression shows as a divergence between the two counts", as data."""
    wired = harness()
    wired.state.seat(session_record(session_id="s-bound", reap_shard=0))
    wired.state.seat(session_record(session_id="s-unbound", reap_shard=1, digest=None))
    report = wired.reaper.sweep()
    assert report.sandboxes_reaped == 2
    assert report.bindings_deleted == 1
    assert report.reaped_by_reason[DueRowClass.MAX_DURATION_REACHED] == 2


def test_the_reason_counts_carry_a_zero_for_every_reason_that_did_not_fire() -> None:
    """A reason that stops firing is invisible if its key is simply absent from the dimension set."""
    wired = harness()
    wired.state.seat(session_record(session_id="s-only"))
    counts = wired.reaper.sweep().reaped_by_reason
    assert set(counts) == set(REAP_SETTLEMENTS)
    assert counts[DueRowClass.SUSPENDED_TOO_LONG] == 0


def test_an_absorbed_row_is_not_counted_as_reaped_by_this_sweep() -> None:
    wired = harness(state=OrchestratorWinsStore())
    wired.state.seat(session_record(session_id="s-absorbed"))
    report = wired.reaper.sweep()
    assert report.sandboxes_reaped == 0
    assert report.bindings_deleted == 0


def test_the_heartbeat_alarm_treats_missing_data_as_breaching() -> None:
    """A Reaper that stops running emits nothing, so any other treatment goes quiet with it."""
    alarm = heartbeat_alarm_for(settings())
    assert alarm.metric_name == HEARTBEAT_METRIC_NAME
    assert alarm.treat_missing_data == "breaching"
    assert alarm.period_seconds == SWEEP_INTERVAL_SECONDS
    assert alarm.evaluation_periods == 2


def test_the_binding_cleanup_layer_is_named_so_the_mix_is_readable() -> None:
    assert BINDING_CLEANUP_LAYER == "reaper"


# --- what the component cannot do ------------------------------------------------------------------


def test_the_reclaimer_seam_cannot_provision_or_mint() -> None:
    """R6.11 and R11.4 as a property of the type the Reaper holds, not only of the lint rules."""
    declared = {name for name in vars(SandboxReclaimer) if not name.startswith("_")}
    assert declared == {"terminate", "release_check", "discover"}


def test_the_reaper_holds_no_step_functions_client_and_no_issuer() -> None:
    """Its independence from the orchestration is a matter of which fields exist."""
    assert set(Reaper.__dataclass_fields__) == {
        "index",
        "provider",
        "reconciler",
        "ledger",
        "metrics",
        "settings",
        "clock",
    }


# --- configuration and the clock -------------------------------------------------------------------


def test_every_configured_value_is_refused_at_zero_or_below() -> None:
    """No literal default and no non-positive value: a shard count of zero sweeps nothing at all."""
    for name in (
        "shard_count",
        "session_budget_seconds",
        "orphan_threshold_seconds",
        "max_rows_per_shard",
        "sweep_interval_seconds",
    ):
        with pytest.raises(ValueError, match=name):
            settings(**{name: 0})
    with pytest.raises(ValueError, match="invocation_identity"):
        settings(invocation_identity="")


def test_the_shard_range_is_every_shard_below_the_configured_count() -> None:
    assert settings(shard_count=3).shards == (0, 1, 2)


def test_a_naive_clock_is_refused_rather_than_read_as_utc() -> None:
    """Every recorded timestamp is epoch milliseconds, and a naive datetime has no epoch."""
    wired = harness(
        now=datetime.fromtimestamp(NOW_MS / 1000, tz=UTC).replace(tzinfo=None)
    )
    with pytest.raises(ValueError, match="aware datetime"):
        wired.reaper.sweep()
