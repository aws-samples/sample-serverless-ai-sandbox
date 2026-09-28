# kiro-classification: public
"""Property 12: the Session record precedes provisioning and is complete (R6.6).

Two conjuncts, and this file is arranged so that each can fail on its own.

## Precedence, stated about Sandboxes rather than about method names

R6.6 orders a write against a provisioning attempt. Task 6.4 discharged that ordering in its
strong form: there is no provisioning call on the request path *at all* — provisioning happens
inside the Session_Orchestrator execution the handler starts, and
`ci/lint_rules/orchestrated_provisioning.py` fails the build if such a call appears outside the
Compute_Provider seam. So the design's "instrumented stub whose `provision` records the call
order" is realised here by *observation* rather than by invocation, and in two forms:

- the ordering of the recorded collaborator calls, which is the weaker form: it would still pass
  against an implementation that called a provider by some other name;
- the population of a real `LocalFirecrackerProvider`, sampled **at the moment of the first
  write** and again after the call returns. No Sandbox and no consumed capacity, at either
  point. That is the claim about Sandboxes, and it is the one that carries the property: a
  handler that provisioned before writing the row would be caught by it whatever the call was
  spelled.

Nothing in this file calls the provisioning method, and adding this module to that rule's
allow-list would defeat the rule this property helps enforce.

## Completeness, asserted at the first write

The item handed to `put_new_session` is captured and round-tripped through
`SessionRecord.from_item`. The record's own constructor refuses an incomplete or invalid item, so
parseability at the **first** write is the completeness claim, and asserting it there rather than
on the row as it finally stands is the point: a row that only became complete after
`mark_orchestration_started` would leave a window in which a Sandbox could exist beside a partial
record. `sandboxHandle`, `connection` and `orchestrationExecutionArn` are legitimately absent at
that point — each is written by whoever creates the thing it names — so their absence is asserted
rather than tolerated.

## The domain, and why the failure paths are the interesting half

`create_request()` crosses the four admitted limits over absent, explicitly null, and boundary
values read from the provider's own `limits()`, together with declared port sets including the
empty set, duplicates and out-of-range members. Crossed with that:

| Drawn outcome | How it is reached | What R6.6 must still hold |
| --- | --- | --- |
| the execution starts | `start_execution` returns an ARN | complete row, written first, no Sandbox |
| a transport failure | `start_execution` raises a drawn error | a **complete** row, still `PENDING` |
| quota exhausted | a provider whose published ceiling is below the Session's memory, so any provisioning attempt would be refused | complete row, and no Sandbox |
| admission rejects | a boundary value outside the provider's declared range | nothing written, nothing started |

Whether a drawn request is admitted is *observed* rather than predicted: the property catches the
rejection and switches branch. Re-deriving admission here would restate Property 11 and would
make this test agree with a defect in the code it is checking.

`test_every_drawn_arm_is_reached_by_name` enumerates that table rather than trusting the sampler
to visit every cell, and the three `test_the_checker_rejects_*` tests feed the checker the
evidence a plausible wrong implementation would have left — an ordering inversion, a partial
first write completed by the second, and a Sandbox existing beside the row — so the property is
known to be able to fail. All four draw nothing.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final

from hypothesis import given, settings
from hypothesis import strategies as st

from control_plane.api.admission import (
    AUTO_RESUME_FIELD,
    IDLE_SECONDS_FIELD,
    MAX_DURATION_FIELD,
    SUSPENDED_SECONDS_FIELD,
    AdmissionPolicy,
    SessionAdmissionRejected,
)
from control_plane.api.creation import (
    EXPOSED_PORTS_FIELD,
    CreationOperations,
    CreationSettings,
    NoCreationWait,
    OrchestrationStart,
)
from control_plane.api.handlers import OperationRequest
from control_plane.api.routes import Operation
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import ItemShapeError
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for
from tests.harness import MINIMUM_EXAMPLES

# --- The deployment around the handler, standing in for CDK context values ----------------

POLICY: Final = AdmissionPolicy(
    default_duration_seconds=3600,
    default_idle_seconds=300,
    default_suspended_seconds=600,
    default_auto_resume=True,
)

EXECUTION_ROLE_ARN: Final = "arn:aws:iam::123456789012:role/SandboxExecution"
STATE_MACHINE: Final = (
    "arn:aws:states:us-east-1:123456789012:stateMachine:SessionOrchestrator"
)

#: The recorded call names, spelled once so the checker and the collaborators cannot disagree.
PUT_NEW_SESSION: Final = "put_new_session"
MARK_ORCHESTRATION_STARTED: Final = "mark_orchestration_started"
START_EXECUTION: Final = "start_execution"

#: Read from the provider rather than restated, so a boundary is this provider's boundary. The
#: same posture `control_plane.api.admission` takes about the ceiling it names in a rejection.
_LIMITS: Final = LocalFirecrackerProvider().limits()

_MILLISECONDS_PER_SECOND: Final = 1000

#: The `maxDurationSeconds` domain: negative, zero, both sides of the declared floor, mid-range,
#: both sides of the declared ceiling, and far beyond it. Half of these are rejections.
DURATION_VALUES: Final = (
    -_LIMITS.max_duration_seconds,
    -1,
    0,
    _LIMITS.min_duration_seconds - 1,
    _LIMITS.min_duration_seconds,
    _LIMITS.min_duration_seconds + 1,
    _LIMITS.max_duration_seconds // 2,
    _LIMITS.max_duration_seconds - 1,
    _LIMITS.max_duration_seconds,
    _LIMITS.max_duration_seconds + 1,
    _LIMITS.max_duration_seconds * 10,
)

#: The idle and suspended domain. R10.3's boundary is zero, so it is drawn from both sides.
SHORT_DURATION_VALUES: Final = (-3600, -1, 0, 1, 2, 300, 86_400)

#: Port declarations: the empty set, ordinary sets, sets carrying duplicates, the boundary ports,
#: and shapes a caller can send that are not a port set at all.
PORT_DECLARATIONS: Final[tuple[Any, ...]] = (
    [],
    [8080],
    [9000, 8080],
    [8080, 8080],
    [9000, 8080, 9000],
    [1, 65_535],
    [0],
    [65_536],
    [-1],
    ["8080"],
    [True],
    [None],
    "8080",
    8080,
)

#: Tenant identifiers, all of them values `require_tenant_id` accepts. The Tenant on the row is a
#: field R6.6 names, so it is drawn rather than fixed.
TENANTS: Final = ("tenant-a", "tenant-b", "T-0000000001", "tenant.with-punctuation")

#: ULID-shaped Session identifiers, in the Crockford alphabet `new_session_id` draws from. Fixed
#: values rather than generated ones, so a shrunk counterexample names the same Session twice; the
#: reap shard is a digest of this value, so drawing several is what varies the shard.
SESSION_IDS: Final = (
    "01JCREATIONAAAAAAAAAAAAAAA",
    "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
    "0000000000000000000000000K",
    "01JQPVXK9TG2MB4H7YWZ3NRSDF",
)

#: Creation instants, on whole seconds so the expected epoch-millisecond value is arithmetic.
MOMENTS: Final = (
    datetime.fromtimestamp(1_700_000_000, tz=UTC),
    datetime.fromtimestamp(0, tz=UTC),
    datetime.fromtimestamp(2_000_000_000, tz=UTC),
)

#: Transport failures `start_execution` can fail with. Ordinary error types rather than a marker
#: class of this file's own, because a failure the handler could distinguish by type is not the
#: failure being modelled.
TRANSPORT_FAILURE_KINDS: Final = (ConnectionError, TimeoutError, OSError, RuntimeError)
TRANSPORT_FAILURE_MESSAGES: Final = (
    "connection reset by peer",
    "the request timed out",
    "",
)


class Capacity(Enum):
    """Whether a provisioning attempt against the drawn provider would be refused for quota.

    `AT_CEILING` publishes a ceiling below any Session's memory, so the provider would answer a
    provisioning attempt with `QuotaExhausted` — the design's second drawn outcome, reached by
    configuring the provider rather than by asking it, since nothing on this path may ask.
    """

    AMPLE = "ample"
    AT_CEILING = "at-ceiling"

    @property
    def limit_bytes(self) -> int | None:
        """The published capacity ceiling, or `None` for a provider publishing none."""
        return None if self is Capacity.AMPLE else 1


@dataclass(frozen=True, slots=True)
class TransportFailure:
    """A drawn failure of the `StartExecution` call itself."""

    kind: type[Exception]
    message: str

    def build(self) -> Exception:
        return self.kind(self.message)


@dataclass(frozen=True, slots=True)
class CreationCase:
    """One drawn create request, with the deployment and the outcomes it meets."""

    body: Mapping[str, Any]
    tenant_id: str
    session_id: str
    moment: datetime
    settings: CreationSettings
    capacity: Capacity
    failure: TransportFailure | None

    @property
    def principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            caller_identity=f"arn:aws:sts::123456789012:assumed-role/C/{self.tenant_id}",
            tenant_id=self.tenant_id,
        )

    @property
    def created_at(self) -> int:
        return int(self.moment.timestamp() * _MILLISECONDS_PER_SECOND)


# --- The generators -------------------------------------------------------------------------


def create_request() -> st.SearchStrategy[dict[str, Any]]:
    """Draw a `CreateSession` body across the optional-field space.

    Every field is drawn in three modes: omitted, present as null, and present with a value.
    Admission treats the first two alike, and a client that serialises an unset option as null is
    the reason both have to be reachable.
    """
    return st.fixed_dictionaries(
        {},
        optional={
            MAX_DURATION_FIELD: st.one_of(
                st.none(), st.sampled_from(DURATION_VALUES), st.just("3600")
            ),
            IDLE_SECONDS_FIELD: st.one_of(
                st.none(), st.sampled_from(SHORT_DURATION_VALUES)
            ),
            SUSPENDED_SECONDS_FIELD: st.one_of(
                st.none(), st.sampled_from(SHORT_DURATION_VALUES)
            ),
            AUTO_RESUME_FIELD: st.one_of(
                st.none(), st.booleans(), st.just("yes"), st.just(1)
            ),
            EXPOSED_PORTS_FIELD: st.one_of(
                st.none(),
                st.sampled_from(PORT_DECLARATIONS),
                st.lists(st.integers(min_value=1, max_value=65_535), max_size=4),
            ),
        },
    )


def creation_settings() -> st.SearchStrategy[CreationSettings]:
    """Draw the deployment-configured row fields, which are five of the values R6.6 names."""
    return st.builds(
        CreationSettings,
        memory_bytes=st.sampled_from(_LIMITS.memory_bytes_choices),
        execution_role_arn=st.just(EXECUTION_ROLE_ARN),
        artifact_retention_days=st.sampled_from((0, 1, 7, 30)),
        # The modulus the reap shard is taken over: 1 collapses every Session into one shard, so
        # a shard drawn outside the range is reachable in both a wide and a degenerate deployment.
        reap_shard_count=st.sampled_from((1, 8, 64)),
    )


def creation_case() -> st.SearchStrategy[CreationCase]:
    """Draw a create request crossed with the provider and orchestration outcomes it meets."""
    return st.builds(
        CreationCase,
        body=create_request(),
        tenant_id=st.sampled_from(TENANTS),
        session_id=st.sampled_from(SESSION_IDS),
        moment=st.sampled_from(MOMENTS),
        settings=creation_settings(),
        capacity=st.sampled_from(Capacity),
        failure=st.one_of(
            st.none(),
            st.builds(
                TransportFailure,
                kind=st.sampled_from(TRANSPORT_FAILURE_KINDS),
                message=st.sampled_from(TRANSPORT_FAILURE_MESSAGES),
            ),
        ),
    )


# --- The collaborators: one records, one observes, neither provisions -----------------------


@dataclass
class ObservingStore:
    """An in-memory State_Store keyed exactly as DynamoDB is: partition key, then sort key.

    It also samples the provider's Sandbox population at each write, which is what turns "the row
    precedes provisioning" into a statement about the instant of the write rather than about the
    end of the call. The provider is asked what it *holds* — never asked to create anything.
    """

    provider: LocalFirecrackerProvider
    log: list[str] = field(default_factory=list)
    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    captured: list[dict[str, Any]] = field(default_factory=list)
    population_at_writes: list[tuple[int, int]] = field(default_factory=list)

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        key = (item[PARTITION_KEY_ATTRIBUTE], item[SORT_KEY_ATTRIBUTE])
        if key in self.items:
            raise AssertionError(f"a Session row already exists at {key}")
        self.captured.append(dict(item))
        self.items[key] = dict(item)
        self.log.append(PUT_NEW_SESSION)
        self.population_at_writes.append(self._population())

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        item = self.items[(start.partition_key, start.sort_key)]
        item["lifecycleState"] = start.state.value
        item["stateReason"] = start.state_reason
        item[TENANT_STATE_INDEX.sort_key] = start.state_created_at
        item["orchestrationExecutionArn"] = start.execution_arn
        item["updatedAt"] = start.updated_at
        self.log.append(MARK_ORCHESTRATION_STARTED)
        self.population_at_writes.append(self._population())

    def _population(self) -> tuple[int, int]:
        """How many Sandboxes the provider holds, and how much capacity they consume."""
        return len(self.provider.discover({})), self.provider.consumed_capacity()


@dataclass
class OutcomeStarter:
    """`StartExecution`, which either returns an ARN or fails with the drawn transport error.

    The instance it raised is kept so the caller can recognise its own drawn failure and re-raise
    anything else. Catching the type would swallow a genuine defect that happened to be an
    `OSError`.
    """

    log: list[str]
    failure: TransportFailure | None = None
    executions: dict[str, dict[str, Any]] = field(default_factory=dict)
    raised: BaseException | None = None

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        self.log.append(START_EXECUTION)
        if self.failure is not None:
            error = self.failure.build()
            self.raised = error
            raise error
        self.executions[name] = dict(payload)
        return f"{STATE_MACHINE}:{name}"


# --- What one creation left behind ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Observation:
    """The evidence one `create_session` call leaves, and the whole input of the checker."""

    log: tuple[str, ...]
    captured: tuple[Mapping[str, Any], ...]
    rows: tuple[Mapping[str, Any], ...]
    population_at_writes: tuple[tuple[int, int], ...]
    sandboxes_after: int
    capacity_after: int
    rejected: bool
    start_failed: bool


def observe(case: CreationCase) -> Observation:
    """Run one creation against a real provider and record what it left behind."""
    provider = LocalFirecrackerProvider(capacity_limit_bytes=case.capacity.limit_bytes)
    store = ObservingStore(provider=provider)
    starter = OutcomeStarter(log=store.log, failure=case.failure)

    def clock() -> datetime:
        return case.moment

    def session_ids() -> str:
        return case.session_id

    operation = CreationOperations(
        provider=provider,
        policy=POLICY,
        settings=case.settings,
        store=store,
        orchestration=starter,
        wait=NoCreationWait(),
        clock=clock,
        session_ids=session_ids,
    )
    request = OperationRequest(
        operation=Operation.CREATE_SESSION,
        principal=case.principal,
        body=case.body,
    )

    rejected = False
    start_failed = False
    try:
        operation.create_session(request)
    except SessionAdmissionRejected:
        rejected = True
    except Exception as error:
        if error is not starter.raised:
            raise
        start_failed = True

    return Observation(
        log=tuple(store.log),
        captured=tuple(store.captured),
        rows=tuple(store.items.values()),
        population_at_writes=tuple(store.population_at_writes),
        sandboxes_after=len(provider.discover({})),
        capacity_after=provider.consumed_capacity(),
        rejected=rejected,
        start_failed=start_failed,
    )


# --- The checker -----------------------------------------------------------------------------


def violations(observed: Observation, case: CreationCase) -> tuple[str, ...]:
    """Every way this observation falls short of Property 12, in one pass.

    Returned rather than asserted one at a time, so a counterexample reports the whole shortfall
    instead of only whichever conjunct happened to be checked first.
    """
    if observed.rejected:
        return tuple(_rejection_faults(observed))
    return tuple(_admitted_faults(observed, case))


def _rejection_faults(observed: Observation) -> Iterator[str]:
    """A rejected request writes nothing, starts nothing, and provisions nothing."""
    if observed.log:
        yield f"a rejected request reached {list(observed.log)}"
    if observed.rows:
        yield f"a rejected request left {len(observed.rows)} row(s) in the store"
    yield from _no_sandbox_faults(observed)


def _no_sandbox_faults(observed: Observation) -> Iterator[str]:
    """No Sandbox exists at any write, or after the call: R6.6's precedence, strongly."""
    for index, (sandboxes, held) in enumerate(observed.population_at_writes, start=1):
        if sandboxes or held:
            yield (
                f"{sandboxes} Sandbox(es) holding {held} bytes already existed at "
                f"write {index}, so provisioning did not follow the row"
            )
    if observed.sandboxes_after or observed.capacity_after:
        yield (
            f"{observed.sandboxes_after} Sandbox(es) holding "
            f"{observed.capacity_after} bytes exist after the creation path"
        )


def _admitted_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    yield from _no_sandbox_faults(observed)

    if not observed.log:
        yield "an admitted request wrote no row and started no execution"
        return
    if observed.log[0] != PUT_NEW_SESSION:
        yield (
            f"the first call on the creation path was {observed.log[0]!r}, "
            f"not the Session row write"
        )
    if START_EXECUTION in observed.log and observed.log.index(
        START_EXECUTION
    ) < observed.log.index(PUT_NEW_SESSION):
        yield f"the execution was started before the row was written: {list(observed.log)}"

    if len(observed.captured) != 1:
        yield f"the Session row was created {len(observed.captured)} times, not once"
        if not observed.captured:
            return

    try:
        first = SessionRecord.from_item(observed.captured[0])
    except (ItemShapeError, ValueError) as error:
        yield (
            f"the item handed to the first write is not a whole Session record: {error}"
        )
        return

    yield from _completeness_faults(first, case)
    yield from _absence_faults(first)
    yield from _requested_value_faults(first, case)
    yield from _surviving_row_faults(observed, case)


def _completeness_faults(record: SessionRecord, case: CreationCase) -> Iterator[str]:
    """Every field R6.6 names, on the record as it was first written."""
    expected = (
        ("pk", record.pk, pk_for(case.principal)),
        ("tenantId", record.tenant_id, case.principal.tenant_id),
        ("providerName", record.provider_name, LocalFirecrackerProvider.name),
        ("sessionId", record.session_id, case.session_id),
        ("lifecycleState", record.lifecycle_state, LifecycleState.PENDING),
        ("createdAt", record.created_at, case.created_at),
        ("updatedAt", record.updated_at, case.created_at),
        ("memoryBytes", record.memory_bytes, case.settings.memory_bytes),
        (
            "executionRoleArn",
            record.execution_role_arn,
            case.settings.execution_role_arn,
        ),
        (
            "artifactRetentionDays",
            record.artifact_retention_days,
            case.settings.artifact_retention_days,
        ),
        (
            "continuationEnabled",
            record.continuation_enabled,
            case.settings.continuation_enabled,
        ),
        (
            "reapDeadline",
            record.reap_deadline,
            case.created_at + record.max_duration_seconds * _MILLISECONDS_PER_SECOND,
        ),
    )
    for name, actual, wanted in expected:
        if actual != wanted:
            yield f"the first write carried {name}={actual!r}, expected {wanted!r}"

    # The four configured limits are present and usable. `from_item` already refused an absent
    # one, so what is left to state is that the values are ones a Session can be governed by.
    for name, seconds in (
        (MAX_DURATION_FIELD, record.max_duration_seconds),
        (IDLE_SECONDS_FIELD, record.idle_seconds),
        (SUSPENDED_SECONDS_FIELD, record.suspended_seconds),
    ):
        if seconds <= 0:
            yield f"the first write carried {name}={seconds}, which governs nothing"
    if not isinstance(record.auto_resume, bool):
        yield f"the first write carried a non-boolean {AUTO_RESUME_FIELD}"
    if not 0 <= record.reap_shard < case.settings.reap_shard_count:
        yield (
            f"the first write carried reapShard={record.reap_shard}, outside the "
            f"{case.settings.reap_shard_count} shards the Reaper sweeps"
        )


def _absence_faults(record: SessionRecord) -> Iterator[str]:
    """The three fields that must be absent at the first write, each for its own reason."""
    if record.sandbox_handle is not None or record.sandbox_id is not None:
        yield "the first write already named a Sandbox, which cannot exist yet"
    if record.connection is not None:
        yield "the first write already carried a connection credential (R6.12 publishes it)"
    if record.orchestration_execution_arn is not None:
        yield "the first write already named an execution, which has not been started"


def _requested_value_faults(record: SessionRecord, case: CreationCase) -> Iterator[str]:
    """An admitted request's own values reach the row unchanged.

    Only values the request actually supplied are checked. What an omitted field defaults to is
    Property 11's claim, and restating it here would make this test agree with a defect in the
    module it is checking.
    """
    for name, actual in (
        (MAX_DURATION_FIELD, record.max_duration_seconds),
        (IDLE_SECONDS_FIELD, record.idle_seconds),
        (SUSPENDED_SECONDS_FIELD, record.suspended_seconds),
    ):
        requested = case.body.get(name)
        if _is_integer(requested) and requested != actual:
            yield f"{name} was admitted as {requested!r} but recorded as {actual}"

    resume = case.body.get(AUTO_RESUME_FIELD)
    if isinstance(resume, bool) and resume is not record.auto_resume:
        yield f"{AUTO_RESUME_FIELD} was admitted as {resume} but recorded as {record.auto_resume}"

    declared = case.body.get(EXPOSED_PORTS_FIELD)
    if isinstance(declared, list) and all(_is_integer(port) for port in declared):
        wanted = tuple(sorted(set(declared)))
        if record.exposed_ports != wanted:
            yield (
                f"{EXPOSED_PORTS_FIELD} {declared} was recorded as "
                f"{list(record.exposed_ports)}, not {list(wanted)}"
            )


def _surviving_row_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """The row left in the store is whole, whether or not the execution started.

    This is the failure path R6.6 has to survive: a `StartExecution` that raised must leave a
    complete `PENDING` row that the Reaper's orphan pass can act on, not a partial one.
    """
    if len(observed.rows) != 1:
        yield f"the store holds {len(observed.rows)} Session rows, not one"
        return
    try:
        surviving = SessionRecord.from_item(observed.rows[0])
    except (ItemShapeError, ValueError) as error:
        yield f"the row left in the store is not a whole Session record: {error}"
        return

    wanted = (
        LifecycleState.PENDING
        if observed.start_failed
        else LifecycleState.ORCHESTRATING
    )
    if surviving.lifecycle_state is not wanted:
        yield (
            f"the surviving row is {surviving.lifecycle_state.value}, expected "
            f"{wanted.value}"
        )
    if observed.start_failed and surviving.orchestration_execution_arn is not None:
        yield "a failed StartExecution left an execution ARN on the row"
    if not observed.start_failed and surviving.orchestration_execution_arn is None:
        yield "a started execution was not recorded on the row"
    if surviving.tenant_id != case.principal.tenant_id:
        yield f"the surviving row names Tenant {surviving.tenant_id!r}"


def _is_integer(value: object) -> bool:
    """Whether a body value is an integer, with `bool` excluded as admission excludes it."""
    return isinstance(value, int) and not isinstance(value, bool)


# --- The property ---------------------------------------------------------------------------

#: The drawn space crosses five request fields in three presence modes with two capacity modes
#: and thirteen `StartExecution` outcomes, so the design's floor of 100 would leave cells of that
#: cross product unvisited. Every example is a few dictionary operations against an in-process
#: store and provider — no subprocess, no socket — so four times the floor costs well under a
#: second of the suite's 300.
EXAMPLES: Final = 4 * MINIMUM_EXAMPLES


# Feature: aws-serverless-agent-sandbox, Property 12: For all create requests, including those
# whose provisioning attempt fails, a Session record exists in the State_Store carrying the
# Tenant identifier, the Compute_Provider name, a lifecycle state, a creation timestamp and the
# configured limits, and that record is written before the provider is asked to provision.
@given(case=creation_case())
@settings(max_examples=EXAMPLES)
def test_the_session_record_precedes_provisioning_and_is_complete(
    case: CreationCase,
) -> None:
    observed = observe(case)
    faults = violations(observed, case)
    assert not faults, (
        f"body={dict(case.body)!r} capacity={case.capacity.value} "
        f"failure={case.failure!r}: " + "; ".join(faults)
    )


# --- The oracles, which draw nothing --------------------------------------------------------

#: One body every rule admits, and one no rule admits: the two branches of the property, named
#: rather than sampled.
ADMITTED_BODY: Final[Mapping[str, Any]] = {
    MAX_DURATION_FIELD: 7200,
    IDLE_SECONDS_FIELD: 300,
    EXPOSED_PORTS_FIELD: [9000, 8080, 9000],
}
REJECTED_BODY: Final[Mapping[str, Any]] = {
    MAX_DURATION_FIELD: _LIMITS.max_duration_seconds + 1
}

#: The two `StartExecution` outcomes and the two bodies, named so the arm table below reads as a
#: table rather than as a nest of literals.
STARTED: Final[TransportFailure | None] = None
TRANSPORT_FAILED: Final[TransportFailure | None] = TransportFailure(
    ConnectionError, "connection reset by peer"
)
START_OUTCOMES: Final[tuple[TransportFailure | None, ...]] = (STARTED, TRANSPORT_FAILED)
BODIES: Final[tuple[Mapping[str, Any], ...]] = (ADMITTED_BODY, REJECTED_BODY)


def case_for(
    *,
    body: Mapping[str, Any],
    capacity: Capacity = Capacity.AMPLE,
    failure: TransportFailure | None = None,
) -> CreationCase:
    """One case with everything but the named dimensions held fixed."""
    return CreationCase(
        body=body,
        tenant_id=TENANTS[0],
        session_id=SESSION_IDS[0],
        moment=MOMENTS[0],
        settings=CreationSettings(
            memory_bytes=_LIMITS.memory_bytes_choices[0],
            execution_role_arn=EXECUTION_ROLE_ARN,
            artifact_retention_days=7,
            reap_shard_count=8,
        ),
        capacity=capacity,
        failure=failure,
    )


def test_every_drawn_arm_is_reached_by_name() -> None:
    """Each cell of the outcome table, exercised once and identified, not left to the sampler.

    A property whose failure arms were unreachable would pass while asserting only the success
    path, and nothing in a passing Hypothesis run says which arms it visited. So each arm is
    entered here by construction and its distinguishing evidence is asserted: a rejection wrote
    nothing, a transport failure left a `PENDING` row with no execution ARN, and a start that
    returned left an `ORCHESTRATING` one.
    """
    for capacity, failure, body in itertools.product(
        tuple(Capacity), START_OUTCOMES, BODIES
    ):
        case = case_for(body=body, capacity=capacity, failure=failure)
        observed = observe(case)
        arm = f"capacity={capacity.value} failure={failure!r} body={body!r}"

        assert violations(observed, case) == (), arm
        if body is REJECTED_BODY:
            assert observed.rejected, arm
            assert observed.log == (), arm
            continue

        assert not observed.rejected, arm
        assert observed.start_failed is (failure is not None), arm
        surviving = SessionRecord.from_item(observed.rows[0])
        if failure is None:
            assert observed.log == (
                PUT_NEW_SESSION,
                START_EXECUTION,
                MARK_ORCHESTRATION_STARTED,
            ), arm
            assert surviving.lifecycle_state is LifecycleState.ORCHESTRATING, arm
        else:
            assert observed.log == (PUT_NEW_SESSION, START_EXECUTION), arm
            assert surviving.lifecycle_state is LifecycleState.PENDING, arm
            assert surviving.orchestration_execution_arn is None, arm


def test_the_at_ceiling_arm_is_a_provider_that_would_refuse_to_provision() -> None:
    """The quota arm is only worth drawing if that provider would really refuse.

    Stated in the provider's own published terms — the ceiling `limits()` declares against the
    capacity `consumed_capacity()` reports — because asking it directly is the one thing no module
    outside the Session_Orchestrator may do.
    """
    memory = _LIMITS.memory_bytes_choices[0]
    for capacity, would_refuse in (
        (Capacity.AT_CEILING, True),
        (Capacity.AMPLE, False),
    ):
        provider = LocalFirecrackerProvider(capacity_limit_bytes=capacity.limit_bytes)
        ceiling = provider.limits().capacity_limit
        refused = (
            ceiling is not None and provider.consumed_capacity() + memory > ceiling
        )
        assert refused is would_refuse, capacity


def test_the_checker_rejects_an_execution_started_before_the_row() -> None:
    """The ordering inversion task 6.4's docstring describes as the window it closed."""
    case = case_for(body=ADMITTED_BODY)
    observed = observe(case)
    assert violations(observed, case) == ()

    inverted = replace(
        observed,
        log=(START_EXECUTION, PUT_NEW_SESSION, MARK_ORCHESTRATION_STARTED),
    )
    faults = violations(inverted, case)
    assert any("started before the row" in fault for fault in faults), faults


def test_the_checker_rejects_a_first_write_completed_by_the_second() -> None:
    """A partial first write is the failure the completeness conjunct exists to catch.

    Every field R6.6 names is dropped from the captured item in turn. The row would still be
    whole once `mark_orchestration_started` had run, which is precisely why completeness is
    asserted at the first write and not at the end.
    """
    case = case_for(body=ADMITTED_BODY)
    observed = observe(case)
    complete = dict(observed.captured[0])

    for attribute in (
        "tenantId",
        "providerName",
        "lifecycleState",
        "createdAt",
        "maxDurationSeconds",
        "idleSeconds",
        "suspendedSeconds",
        "autoResume",
    ):
        partial = {key: value for key, value in complete.items() if key != attribute}
        faults = violations(replace(observed, captured=(partial,)), case)
        assert any("not a whole Session record" in fault for fault in faults), attribute


def test_the_checker_rejects_a_sandbox_that_exists_beside_the_row() -> None:
    """The precedence conjunct, in the form that does not depend on a method name."""
    case = case_for(body=ADMITTED_BODY)
    observed = observe(case)
    memory = case.settings.memory_bytes

    provisioned_first = replace(
        observed, population_at_writes=((1, memory), (1, memory))
    )
    assert any(
        "already existed at write 1" in fault
        for fault in violations(provisioned_first, case)
    )

    provisioned_at_all = replace(observed, sandboxes_after=1, capacity_after=memory)
    assert any(
        "exist after the creation path" in fault
        for fault in violations(provisioned_at_all, case)
    )


def test_the_checker_rejects_a_rejection_that_wrote_a_row() -> None:
    """R6.6 on the admission path: a `400` costs neither a row nor an execution."""
    case = case_for(body=REJECTED_BODY)
    observed = observe(case)
    assert observed.rejected
    assert violations(observed, case) == ()

    wrote_anyway = replace(
        observed,
        log=(PUT_NEW_SESSION,),
        rows=(dict(observe(case_for(body=ADMITTED_BODY)).captured[0]),),
    )
    faults = violations(wrote_anyway, case)
    assert any("a rejected request reached" in fault for fault in faults), faults
    assert any("left 1 row" in fault for fault in faults), faults
