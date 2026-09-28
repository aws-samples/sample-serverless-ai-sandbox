# kiro-classification: public
"""The creation wait: the clamp, the jitter, the fallback, and where the credential comes from.

Every assertion here is deterministic. Property 37 — both contracts deliver a credential and neither
loses the Session, over drawn contracts and drawn provision latencies — is task 6.8 and belongs to
its own file, so nothing here draws inputs.

Nothing here sleeps. `FakeTime` is one object that is both the clock and the sleep: sleeping advances
the clock it reports, so a 12 second budget costs no wall-clock time and the sequence of intervals
is a value a test can read. That is what makes the above-budget half of the domain affordable, and
it is also what makes the assertions sharper than a timing test could be — "the wait never overshoots
its budget" is arithmetic on a list rather than an inequality against a stopwatch.

The store fakes are keyed exactly as DynamoDB is, following `tests/test_control_plane_creation.py`.
`LaggingStore` is the interesting one: it serves a snapshot taken before the credential was
published, which is what an eventually consistent read can do, and the test that uses it shows the
spurious degradation the strongly consistent read exists to prevent.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import pytest

from control_plane.api.creation import (
    CreationOperations,
    NoCreationWait,
    OrchestrationStart,
)
from control_plane.api.creation_wait import (
    POLL_INTERVAL_SECONDS,
    POLL_JITTER_SECONDS,
    RESPONSE_MARGIN_SECONDS,
    CreationContract,
    CreationWaitSettings,
    PollingCreationWait,
    SessionProvisioningFailed,
    wait_for_contract,
)
from control_plane.api.errors import ControlPlaneError
from control_plane.api.handlers import OperationRequest, OperationResult
from control_plane.api.routes import Operation
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import ItemShapeError
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)
from tests.test_control_plane_creation import (
    POLICY,
    SETTINGS,
    RecordingStarter,
)

TENANT = "tenant-a"
CALLER = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
SESSION_ID = "01JCWAITAAAAAAAAAAAAAAAAAA"
NOW_MS = 1_700_000_000_000

#: The design's configured API integration timeout (R10.13), stated here as a test input rather than
#: as a default anywhere in the module under test: the deployment owns it.
INTEGRATION_TIMEOUT = 29.0

#: An obviously-fake credential. Nothing in this suite carries a real one.
PUBLISHED = ConnectionDescriptor(
    base_url="https://sandbox.invalid",
    auth_header_name="X-aws-proxy-auth",
    auth_header_value="fake-endpoint-token-for-tests",
    ports=(8000,),
    expires_at="2026-06-22T10:15:00Z",
)


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=TENANT)


def orchestrating_record() -> SessionRecord:
    """The row the handler hands the wait: written, execution started, nothing published yet."""
    return SessionRecord(
        pk=pk_for(principal()),
        session_id=SESSION_ID,
        tenant_id=TENANT,
        provider_name=LocalFirecrackerProvider.name,
        lifecycle_state=LifecycleState.ORCHESTRATING,
        created_at=NOW_MS,
        updated_at=NOW_MS,
        max_duration_seconds=3600,
        idle_seconds=300,
        suspended_seconds=600,
        auto_resume=True,
        memory_bytes=SETTINGS.memory_bytes,
        execution_role_arn=SETTINGS.execution_role_arn,
        reap_shard=3,
        reap_deadline=NOW_MS + 3_600_000,
        artifact_retention_days=SETTINGS.artifact_retention_days,
        state_reason="orchestration started",
    )


@dataclass
class FakeTime:
    """A monotonic clock and a sleep that advances it. No test here waits for anything.

    `slept` is the sequence of intervals, so jitter and the final clamp are read off a list.
    """

    now: float = 0.0
    slept: list[float] = field(default_factory=list)

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    @property
    def elapsed(self) -> float:
        """What the wait's own clock reports, rather than the sum of the intervals.

        The two differ by floating-point noise once there are sixty of them, and the clock is the
        one the budget is measured against.
        """
        return self.now


@dataclass
class PublishingStore:
    """A Session row the orchestration publishes onto after a given number of reads.

    `after` is a read count rather than a timestamp because that is what the loop's shape makes
    observable: a wait that read once and then waited out its budget is a different failure from one
    that polled and never saw the write.
    """

    item: dict[str, Any]
    after: int = 0
    published: ConnectionDescriptor | None = PUBLISHED
    reads: list[tuple[str, str]] = field(default_factory=list)

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.reads.append((partition_key, sort_key))
        if len(self.reads) > self.after and self.published is not None:
            self.item["connection"] = self.published.to_map()
        key = (self.item[PARTITION_KEY_ATTRIBUTE], self.item[SORT_KEY_ATTRIBUTE])
        return dict(self.item) if key == (partition_key, sort_key) else None


@dataclass
class LaggingStore:
    """A read that serves a snapshot taken before the credential was published.

    This is what an eventually consistent `GetItem` is allowed to do, and it is why the wait's read
    is strongly consistent: the row *has* a credential and this reader cannot see it.
    """

    committed: dict[str, Any]
    stale: dict[str, Any]
    reads: int = 0

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        del partition_key, sort_key
        self.reads += 1
        return dict(self.stale)


@dataclass
class AbsentStore:
    """A row that is not there. Counts the reads so the bound on them is checkable."""

    reads: int = 0

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        del partition_key, sort_key
        self.reads += 1
        return None


@dataclass
class OneItemStore:
    """A fixed item, returned for every read. Also the creation path's two writes."""

    item: dict[str, Any]
    reads: int = 0

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        del partition_key, sort_key
        self.reads += 1
        return dict(self.item)

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        self.item = dict(item)

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        self.item["lifecycleState"] = start.state.value
        self.item["stateReason"] = start.state_reason
        self.item[TENANT_STATE_INDEX.sort_key] = start.state_created_at
        self.item["orchestrationExecutionArn"] = start.execution_arn
        self.item["updatedAt"] = start.updated_at


def settings(
    *,
    contract: CreationContract = CreationContract.SYNCHRONOUS,
    integration_timeout_seconds: float = INTEGRATION_TIMEOUT,
    wait_budget_seconds: float = 12.0,
) -> CreationWaitSettings:
    return CreationWaitSettings(
        contract=contract,
        integration_timeout_seconds=integration_timeout_seconds,
        wait_budget_seconds=wait_budget_seconds,
    )


def midpoint(low: float, high: float) -> float:
    """A jitter draw fixed at the middle of the range, so an interval count is arithmetic."""
    return (low + high) / 2


def fixed_draw(value: float) -> Any:
    """A jitter draw fixed at `value`, recording the bounds it was offered."""

    def draw(low: float, high: float) -> float:
        draw.offered.append((low, high))  # type: ignore[attr-defined]
        return value

    draw.offered = []  # type: ignore[attr-defined]
    return draw


def wait(
    lookup: Any,
    *,
    clock: FakeTime,
    budget: float = 12.0,
    jitter: Any = midpoint,
) -> PollingCreationWait:
    return PollingCreationWait(
        lookup=lookup,
        settings=settings(wait_budget_seconds=budget),
        clock=clock.monotonic,
        sleep=clock.sleep,
        jitter=jitter,
    )


# --- The budget clamp, derived from the configured integration timeout (R10.13) -------------------


def test_the_budget_is_clamped_inside_the_configured_integration_timeout() -> None:
    """A budget longer than the request it runs inside is clamped, not honoured."""
    clamped = settings(integration_timeout_seconds=29.0, wait_budget_seconds=60.0)
    assert clamped.budget_seconds == 29.0 - RESPONSE_MARGIN_SECONDS
    assert clamped.is_clamped


def test_a_budget_inside_the_timeout_is_left_alone() -> None:
    inside = settings(integration_timeout_seconds=29.0, wait_budget_seconds=12.0)
    assert inside.budget_seconds == 12.0
    assert not inside.is_clamped


def test_the_clamp_moves_with_the_configured_timeout_and_is_not_a_second_number() -> (
    None
):
    """The bound is derived, so a deployment that lowers the timeout lowers the budget with it.

    This is the whole reason the timeout is a field of the settings rather than a constant beside
    them: there is no number a deployment could set that leaves the wait outliving its request.
    """
    for timeout in (29.0, 20.0, 10.0, 3.0):
        derived = settings(
            integration_timeout_seconds=timeout, wait_budget_seconds=1_000.0
        )
        assert derived.budget_seconds == timeout - RESPONSE_MARGIN_SECONDS
        assert derived.budget_seconds < timeout


@pytest.mark.parametrize(
    "overrides",
    [
        # No budget remains to wait in once the response margin is held back.
        {"integration_timeout_seconds": RESPONSE_MARGIN_SECONDS},
        {"integration_timeout_seconds": 1.0},
        {"integration_timeout_seconds": 0.0},
        {"integration_timeout_seconds": -1.0},
        {"wait_budget_seconds": 0.0},
        {"wait_budget_seconds": -0.5},
        {"wait_budget_seconds": True},
        {"integration_timeout_seconds": "29"},
    ],
)
def test_a_misconfigured_deployment_fails_where_it_is_built(
    overrides: Mapping[str, Any],
) -> None:
    base: dict[str, Any] = {
        "contract": CreationContract.SYNCHRONOUS,
        "integration_timeout_seconds": INTEGRATION_TIMEOUT,
        "wait_budget_seconds": 12.0,
    }
    with pytest.raises(ValueError):
        CreationWaitSettings(**{**base, **overrides})


def test_the_wait_never_sleeps_past_its_budget() -> None:
    """The bound is the clamp, and the last interval is clipped to what remains of it.

    0.6 seconds of budget at 0.25 second intervals is two whole intervals and a 0.1 second
    remainder, so the wait ends exactly on its budget rather than one interval beyond it.
    """
    clock = FakeTime()
    store = AbsentStore()
    result = wait(store, clock=clock, budget=0.6, jitter=fixed_draw(0.25))

    assert result.await_connection(orchestrating_record()) is None
    assert clock.slept == pytest.approx([0.25, 0.25, 0.1])
    assert clock.elapsed == pytest.approx(0.6)


def test_the_wait_is_bounded_by_the_clamp_rather_than_by_an_iteration_count() -> None:
    """A configured budget of an hour still ends inside the integration timeout."""
    clock = FakeTime()
    result = PollingCreationWait(
        lookup=AbsentStore(),
        settings=settings(wait_budget_seconds=3_600.0),
        clock=clock.monotonic,
        sleep=clock.sleep,
        jitter=midpoint,
    )
    assert result.await_connection(orchestrating_record()) is None
    assert clock.elapsed <= INTEGRATION_TIMEOUT - RESPONSE_MARGIN_SECONDS
    assert clock.elapsed > 0


def test_the_read_count_matches_the_cost_the_design_states() -> None:
    """About 60 strongly consistent reads for a 12 second wait at 200 ms, and that is the cost.

    Asserted as a range rather than an exact count because the interval is jittered; the point is
    the order of magnitude the design's cost argument rests on, not a fixed number.
    """
    clock = FakeTime()
    store = AbsentStore()
    wait(store, clock=clock, budget=12.0).await_connection(orchestrating_record())
    assert 55 <= store.reads <= 65


# --- The jitter -----------------------------------------------------------------------------------


def test_every_interval_is_drawn_from_the_interval_plus_or_minus_the_jitter() -> None:
    """150 ms to 250 ms around a 200 ms interval, and the bounds are the module's own constants."""
    clock = FakeTime()
    draw = fixed_draw(POLL_INTERVAL_SECONDS)
    wait(AbsentStore(), clock=clock, budget=1.0, jitter=draw).await_connection(
        orchestrating_record()
    )

    expected = (
        POLL_INTERVAL_SECONDS - POLL_JITTER_SECONDS,
        POLL_INTERVAL_SECONDS + POLL_JITTER_SECONDS,
    )
    assert draw.offered  # type: ignore[attr-defined]
    assert set(draw.offered) == {expected}  # type: ignore[attr-defined]
    assert expected == pytest.approx((0.15, 0.25))


def test_two_waiters_on_one_row_do_not_poll_in_lockstep() -> None:
    """The get-or-create case: the loser waits on the winner's row (R6.19).

    With a real draw the two waiters' read times diverge. Asserted against the module's default
    jitter source rather than an injected one, because the claim is about the source the deployment
    uses; the clock and the sleep stay injected, so this still costs no real time.
    """
    record = orchestrating_record()
    schedules = []
    for _ in range(2):
        clock = FakeTime()
        PollingCreationWait(
            lookup=AbsentStore(),
            settings=settings(wait_budget_seconds=2.0),
            clock=clock.monotonic,
            sleep=clock.sleep,
        ).await_connection(record)
        schedules.append(tuple(clock.slept))

    first, second = schedules
    assert first != second
    for interval in first + second:
        assert 0 < interval <= POLL_INTERVAL_SECONDS + POLL_JITTER_SECONDS


# --- The credential comes from the store, never from a mint (R6.12, R6.13) -----------------------


def test_a_credential_already_on_the_row_is_returned_without_waiting() -> None:
    """One read, no sleep. The get-or-create loser's common case."""
    clock = FakeTime()
    store = PublishingStore(item=dict(published_item()), after=0)

    result = wait(store, clock=clock).await_connection(orchestrating_record())

    assert result == PUBLISHED
    assert clock.slept == []
    assert len(store.reads) == 1


def test_the_returned_descriptor_is_the_one_the_orchestration_published() -> None:
    """Read from the State_Store and returned unchanged, rather than reconstructed or minted."""
    clock = FakeTime()
    store = PublishingStore(item=dict(orchestrating_item()), after=3)

    result = wait(store, clock=clock).await_connection(orchestrating_record())

    assert result is not None
    assert result.to_map() == store.item["connection"]
    assert result.to_map() == PUBLISHED.to_map()


def test_a_credential_published_mid_wait_is_returned_on_the_next_read() -> None:
    clock = FakeTime()
    store = PublishingStore(item=dict(orchestrating_item()), after=4)

    result = wait(store, clock=clock).await_connection(orchestrating_record())

    assert result == PUBLISHED
    assert len(store.reads) == 5
    assert len(clock.slept) == 4
    assert clock.elapsed < 12.0


def test_the_read_is_issued_at_the_row_the_handler_wrote() -> None:
    """The key comes from the record, so no partition key is built on this path."""
    clock = FakeTime()
    record = orchestrating_record()
    store = PublishingStore(item=dict(published_item()), after=0)

    wait(store, clock=clock).await_connection(record)

    assert store.reads == [(record.pk, record.sort_key)]
    assert record.pk == pk_for(principal())


def test_the_wait_holds_nothing_that_could_mint_a_credential() -> None:
    """Structural: a wait with no provider and no issuer cannot be the source of a credential.

    R6.13 requires the returned credential to be read from the State_Store rather than from a
    Compute_Provider call the Control_Plane issued. The way that is guaranteed here is that the wait
    has no way to issue one.
    """
    held = {held_field.name for held_field in fields(PollingCreationWait)}
    assert held == {"lookup", "settings", "clock", "sleep", "jitter"}


def test_an_eventually_consistent_read_would_lose_a_published_credential() -> None:
    """Why the read is strongly consistent, shown rather than asserted about.

    The row carries a credential; this reader serves a snapshot from before it was published. The
    wait cannot see what it cannot read, so it degrades to the asynchronous shape — a successful
    creation reported as "not yet published". Bounded and safe, and still wrong, which is the whole
    argument for the consistent read.
    """
    clock = FakeTime()
    store = LaggingStore(
        committed=dict(published_item()), stale=dict(orchestrating_item())
    )

    assert wait(store, clock=clock).await_connection(orchestrating_record()) is None
    assert store.committed["connection"] == PUBLISHED.to_map()
    assert store.reads > 1


# --- The fallback: a 202, never a 504, and never a lost Session (R10.14) -------------------------


def test_an_expired_budget_is_not_an_error() -> None:
    clock = FakeTime()
    assert (
        wait(AbsentStore(), clock=clock).await_connection(orchestrating_record())
        is None
    )


def test_a_synchronous_creation_that_blows_the_budget_still_names_the_session() -> None:
    """The response degrades to the asynchronous shape rather than to a gateway timeout.

    `202`, the Session identifier present, `connection` absent rather than null, and no error raised
    at all. A `504` would carry no body, and therefore no identifier the caller could poll,
    terminate or bill against.
    """
    clock = FakeTime()
    store = OneItemStore(item={})
    result = create(store=store, wait=wait(store, clock=clock))

    assert result.status == HTTPStatus.ACCEPTED
    assert result.payload["sessionId"] == SESSION_ID
    assert "connection" not in result.payload
    assert clock.elapsed <= INTEGRATION_TIMEOUT - RESPONSE_MARGIN_SECONDS


def test_a_synchronous_creation_inside_the_budget_returns_the_published_credential() -> (
    None
):
    clock = FakeTime()
    store = OneItemStore(item={})
    publishing = PublishingOnRead(store=store, after=3)
    result = create(store=store, wait=wait(publishing, clock=clock))

    assert result.status == HTTPStatus.CREATED
    assert result.payload["connection"] == PUBLISHED.to_map()
    assert result.payload["sessionId"] == SESSION_ID


def test_the_asynchronous_contract_returns_without_reading_anything() -> None:
    store = OneItemStore(item={})
    selected = wait_for_contract(
        settings(contract=CreationContract.ASYNCHRONOUS), lookup=store
    )
    result = create(store=store, wait=selected)

    assert result.status == HTTPStatus.ACCEPTED
    assert "connection" not in result.payload
    assert store.reads == 0


# --- The contract switch --------------------------------------------------------------------------


def test_the_switch_selects_the_polling_wait_for_the_synchronous_contract() -> None:
    selected = wait_for_contract(
        settings(contract=CreationContract.SYNCHRONOUS), lookup=AbsentStore()
    )
    assert isinstance(selected, PollingCreationWait)


def test_the_switch_selects_the_waitless_wait_for_the_asynchronous_contract() -> None:
    """The asynchronous contract removes a wait, not a data path: the credential still comes from
    the State_Store, read by a subsequent `GetSession`."""
    selected = wait_for_contract(
        settings(contract=CreationContract.ASYNCHRONOUS), lookup=AbsentStore()
    )
    assert isinstance(selected, NoCreationWait)
    assert selected.await_connection(orchestrating_record()) is None


def test_both_contracts_are_reachable_from_the_context_value_spelling() -> None:
    """A CDK context string maps onto the enum directly, and a third value fails where it is read."""
    assert CreationContract("synchronous") is CreationContract.SYNCHRONOUS
    assert CreationContract("asynchronous") is CreationContract.ASYNCHRONOUS
    with pytest.raises(ValueError):
        CreationContract("eventual")


def test_the_switch_defaults_to_no_contract_of_its_own() -> None:
    """There is no default contract: the deployment supplies one, as it supplies the budget."""
    with pytest.raises(TypeError):
        CreationWaitSettings(  # type: ignore[call-arg]
            integration_timeout_seconds=INTEGRATION_TIMEOUT, wait_budget_seconds=12.0
        )


# --- A terminal row stops the wait and reports the recorded reason (R6.14) ----------------------


@pytest.mark.parametrize("state", [LifecycleState.FAILED, LifecycleState.TERMINATED])
def test_a_terminal_row_ends_the_wait_with_the_recorded_reason(
    state: LifecycleState,
) -> None:
    clock = FakeTime()
    item = dict(orchestrating_item())
    item["lifecycleState"] = state.value
    item["stateReason"] = "quota ConcurrentExecutions exhausted for lambda-microvm"

    with pytest.raises(SessionProvisioningFailed) as raised:
        wait(OneItemStore(item=item), clock=clock).await_connection(
            orchestrating_record()
        )

    assert raised.value.reason == item["stateReason"]
    assert raised.value.state is state
    # Reported at once rather than after the budget: a terminal row will never publish.
    assert clock.slept == []


def test_the_recorded_reason_reaches_the_caller_in_the_response() -> None:
    item = dict(orchestrating_item())
    item["lifecycleState"] = LifecycleState.FAILED.value
    item["stateReason"] = "quota ConcurrentExecutions exhausted"

    with pytest.raises(ControlPlaneError) as raised:
        wait(OneItemStore(item=item), clock=FakeTime()).await_connection(
            orchestrating_record()
        )

    response = raised.value.response
    assert response.status == HTTPStatus.BAD_GATEWAY
    assert b"quota ConcurrentExecutions exhausted" in response.body
    assert b"SessionProvisioningFailed" in response.body


def test_a_terminal_row_with_no_recorded_reason_still_says_something_true() -> None:
    item = dict(orchestrating_item())
    item["lifecycleState"] = LifecycleState.FAILED.value
    item.pop("stateReason", None)

    with pytest.raises(SessionProvisioningFailed) as raised:
        wait(OneItemStore(item=item), clock=FakeTime()).await_connection(
            orchestrating_record()
        )

    assert LifecycleState.FAILED.value in raised.value.reason


def test_a_credential_on_a_terminal_row_is_not_handed_out() -> None:
    """The race where both hold: the credential names a Sandbox being torn down."""
    item = dict(published_item())
    item["lifecycleState"] = LifecycleState.TERMINATED.value
    item["stateReason"] = "maximum duration reached"

    with pytest.raises(SessionProvisioningFailed):
        wait(OneItemStore(item=item), clock=FakeTime()).await_connection(
            orchestrating_record()
        )


@pytest.mark.parametrize(
    "state",
    [
        LifecycleState.PENDING,
        LifecycleState.ORCHESTRATING,
        LifecycleState.PROVISIONING,
        LifecycleState.STARTING,
        LifecycleState.RUNNING,
    ],
)
def test_a_non_terminal_row_is_waited_on_rather_than_reported(
    state: LifecycleState,
) -> None:
    clock = FakeTime()
    item = dict(orchestrating_item())
    item["lifecycleState"] = state.value

    assert (
        wait(OneItemStore(item=item), clock=clock, budget=1.0).await_connection(
            orchestrating_record()
        )
        is None
    )
    assert clock.slept


# --- A malformed row is a defect, not a fallback ------------------------------------------------


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("lifecycleState", "ASCENDING"),
        ("lifecycleState", 7),
        ("connection", "a token"),
        ("stateReason", 7),
    ],
)
def test_a_malformed_row_is_not_absorbed_into_the_fallback(
    attribute: str, value: Any
) -> None:
    """The posture `resolve_session` takes: a shape defect in the caller's own partition is a bug.

    Reporting it as "not yet published" would hide it behind a legitimate response.
    """
    item = dict(orchestrating_item())
    if attribute == "stateReason":
        item["lifecycleState"] = LifecycleState.FAILED.value
    item[attribute] = value

    with pytest.raises(ItemShapeError):
        wait(OneItemStore(item=item), clock=FakeTime()).await_connection(
            orchestrating_record()
        )


def test_a_row_that_projects_only_the_credential_is_enough() -> None:
    """A deployed `GetItem` projects three attributes; a narrower projection still works."""
    clock = FakeTime()
    store = OneItemStore(item={"connection": PUBLISHED.to_map()})
    assert (
        wait(store, clock=clock).await_connection(orchestrating_record()) == PUBLISHED
    )


def test_a_vanished_row_degrades_rather_than_reporting_not_found() -> None:
    """A row removed underneath the creation is bounded, then reported as the asynchronous shape.

    A `404` here would deny the existence of a Session whose orchestration may be provisioning, which
    loses it exactly as a `504` would.
    """
    clock = FakeTime()
    store = AbsentStore()
    assert (
        wait(store, clock=clock, budget=1.0).await_connection(orchestrating_record())
        is None
    )
    assert store.reads > 1


# --- Helpers -------------------------------------------------------------------------------------


@dataclass
class PublishingOnRead:
    """Publishes onto the store's own item after a number of reads, as the orchestration would."""

    store: OneItemStore
    after: int
    reads: int = 0

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.reads += 1
        if self.reads > self.after:
            self.store.item["connection"] = PUBLISHED.to_map()
        return self.store.read_session(partition_key=partition_key, sort_key=sort_key)


def orchestrating_item() -> Mapping[str, Any]:
    return orchestrating_record().to_item()


def published_item() -> Mapping[str, Any]:
    return replace(
        orchestrating_record(),
        lifecycle_state=LifecycleState.RUNNING,
        connection=PUBLISHED,
        connection_published_at=NOW_MS + 5_000,
    ).to_item()


def create(*, store: Any, wait: Any) -> OperationResult:
    """Drive the whole creation path with the wait under test in step 4."""
    operations = CreationOperations(
        provider=LocalFirecrackerProvider(),
        policy=POLICY,
        settings=SETTINGS,
        store=store,
        orchestration=RecordingStarter(),
        wait=wait,
        clock=lambda: datetime.fromtimestamp(NOW_MS / 1000, tz=UTC),
        session_ids=lambda: SESSION_ID,
    )
    return operations.create_session(
        OperationRequest(
            operation=Operation.CREATE_SESSION, principal=principal(), body={}
        )
    )
