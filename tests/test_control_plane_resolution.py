# kiro-classification: public
"""Get-or-create by Affinity_Key: one conditional transaction, and the loser's branch table.

Every assertion here is deterministic. Property 35 — resolve-or-create over drawn binding states and
drawn Affinity_Keys — is task 6.10, and Property 36 — concurrent same-key requests over drawn
concurrency degrees and arrival schedules — is task 6.11. Both belong to their own files, so nothing
here draws inputs. What this file establishes is the behaviour those drawn inputs will be quantified
over, and it does so in four structural senses:

- `test_the_claim_is_one_transaction_and_nothing_is_read_before_it` reads one recorded call log. The
  first store operation of a resolution is the two-item transaction, not a `read_binding`, which is
  R6.18 stated as an order rather than as a comment.
- `test_a_losing_claim_leaves_neither_a_session_row_nor_a_binding` asks the store what it holds after
  a lost race. One Session row and one binding, both the winner's — which is the property a
  transaction buys over two conditional writes.
- `test_every_key_touched_is_the_callers_own_partition` records every key of every read and write and
  compares the set against `pk_for(principal)`. That is the confinement half of R11.11, asserted over
  keys rather than over an absent comparison.
- `test_the_loser_branch_table_covers_every_lifecycle_state` walks
  `LifecycleState` and asserts a decision exists for each, so a state added later fails here rather
  than falling into a default.

The mint double is `RecordingMint` imported from `tests.test_connection_credentials` rather than
defined here, because `ci/lint_rules/sole_credential_issuer.py` allows a definition of
`issue_connection` in that module and in the provider seam and nowhere else.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import pytest

from control_plane.api import ControlPlaneApi
from control_plane.api.admission import AdmissionPolicy, SessionAdmissionRejected
from control_plane.api.connection import ConnectionUnavailable
from control_plane.api.creation import (
    EXECUTION_NAME_PREFIX,
    CreationOperations,
    CreationSettings,
    NoCreationWait,
    OrchestrationStart,
)
from control_plane.api.errors import OperationNotImplemented
from control_plane.api.handlers import OperationRequest, OperationResult
from control_plane.api.resolution import (
    AFFINITY_KEY_FIELD,
    DEFAULT_BINDING_MAX_AGE_SECONDS,
    LOSER_BRANCHES,
    MAX_CLAIM_ATTEMPTS,
    RESOLUTION_FIELD,
    BindingConditionFailed,
    BindingSettings,
    InvalidAffinityKey,
    ResolutionDidNotSettle,
    ResolutionOperations,
    ResolutionOutcome,
    binding_for,
    digest_of_requested_affinity_key,
    resolution_payload,
)
from control_plane.api.routes import Operation
from control_plane.credentials import ConnectionIssuer, CredentialPolicy
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import (
    BINDING_PREFIX,
    SEPARATOR,
    affinity_key_digest,
    binding_sort_key,
    session_sort_key,
)
from control_plane.state.records import (
    AffinityKeyBindingRecord,
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
    TTL_ATTRIBUTE,
)
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)
from tests.test_connection_credentials import RecordingMint

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
CALLER = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
OTHER_CALLER = f"arn:aws:sts::123456789012:assumed-role/Caller/{OTHER_TENANT}"

#: A conversation identifier of the shape a caller's agent framework supplies. It carries the
#: sort-key delimiter deliberately: the digest is what makes that safe, so the ordinary fixture
#: exercises it rather than a special case doing so once.
AFFINITY_KEY = "thread#9f3"
DIGEST = affinity_key_digest(AFFINITY_KEY)

#: Epoch milliseconds, fixed so every timestamp expectation is arithmetic rather than a comparison
#: against the wall clock.
NOW_MS = 1_700_000_000_000
NOW = datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)
STATE_MACHINE = "arn:aws:states:us-east-1:123456789012:stateMachine:SessionOrchestrator"

#: An obviously-fake credential. Nothing in this suite carries a real one.
FAKE_TOKEN = "fake-endpoint-token-for-tests"  # nosec B105 — test fixture
AUTH_HEADER = "X-aws-proxy-auth"

#: The credential an orchestration published onto a row. R6.23 requires a resolution to return a
#: credential that is *not* this one, which is what makes it a distinguishable fixture value.
PUBLISHED = ConnectionDescriptor(
    base_url="https://published.invalid",
    auth_header_name=AUTH_HEADER,
    auth_header_value="fake-published-token-nobody-should-see-again",
    ports=(8000,),
    expires_at="2026-06-22T10:15:00Z",
)

POLICY = AdmissionPolicy(
    default_duration_seconds=3600,
    default_idle_seconds=300,
    default_suspended_seconds=600,
    default_auto_resume=True,
)

SETTINGS = CreationSettings(
    memory_bytes=512 * 1024 * 1024,
    execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
    artifact_retention_days=7,
    reap_shard_count=8,
)

SANDBOX_HANDLE: Mapping[str, Any] = {
    "providerName": LocalFirecrackerProvider.name,
    "sandboxId": "sandbox-1",
    "opaque": {"vm": "1"},
}


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


def principal(tenant_id: str = TENANT) -> AuthenticatedPrincipal:
    caller = CALLER if tenant_id == TENANT else OTHER_CALLER
    return AuthenticatedPrincipal(caller_identity=caller, tenant_id=tenant_id)


# --- the store double -----------------------------------------------------------------------------


@dataclass
class FakeStore:
    """One in-memory table keyed as DynamoDB is, serialising conditional writes as DynamoDB does.

    It implements all three seams a resolution reaches — the Session row writes, the two binding
    transactions and the strongly consistent reads — because in a deployment they are one table
    reached with one set of per-request credentials. Faithful in the four respects the requirements
    rest on:

    - a transaction commits **both** items or **neither** (R6.17), so a lost claim leaves no orphan;
    - the claim's condition is `attribute_not_exists(pk)` on the binding item alone (R6.18);
    - the replacement's condition is the binding still naming the expected Session (R6.21);
    - `keys_touched` records every key of every read and write, so confinement is assertable over
      what was addressed rather than over the absence of a comparison.
    """

    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    keys_touched: list[tuple[str, str]] = field(default_factory=list)
    #: Monotonic, and held on the store rather than on the operation, so several resolutions against
    #: one table draw distinct Session identifiers the way independent handler invocations would.
    minted_ids: int = 0

    def next_session_id(self) -> str:
        self.minted_ids += 1
        return f"01JRESOLVE{self.minted_ids:016d}"

    # -- the Session row writes (SessionRowStore) --------------------------------------------

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        self.log.append("put_new_session")
        self._put_if_absent(item)

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        self.log.append("mark_orchestration_started")
        self.keys_touched.append((start.partition_key, start.sort_key))
        row = self.items[(start.partition_key, start.sort_key)]
        row["lifecycleState"] = start.state.value
        row["stateReason"] = start.state_reason
        row[TENANT_STATE_INDEX.sort_key] = start.state_created_at
        row["orchestrationExecutionArn"] = start.execution_arn
        row["updatedAt"] = start.updated_at

    # -- the reads (SessionLookup, BindingStore) ---------------------------------------------

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.log.append("read_session")
        self.keys_touched.append((partition_key, sort_key))
        return self.items.get((partition_key, sort_key))

    def read_binding(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.log.append("read_binding")
        self.keys_touched.append((partition_key, sort_key))
        return self.items.get((partition_key, sort_key))

    # -- the two transactions (BindingStore) --------------------------------------------------

    def claim_binding(
        self, *, session_item: Mapping[str, Any], binding_item: Mapping[str, Any]
    ) -> None:
        self.log.append("claim_binding")
        self._transact(
            session_item,
            binding_item,
            holds=lambda existing: existing is None,
        )

    def replace_binding(
        self,
        *,
        session_item: Mapping[str, Any],
        binding_item: Mapping[str, Any],
        expected_session_id: str,
    ) -> None:
        self.log.append("replace_binding")
        self._transact(
            session_item,
            binding_item,
            holds=lambda existing: (
                existing is not None
                and existing.get("sessionId") == expected_session_id
            ),
        )

    def _transact(
        self,
        session_item: Mapping[str, Any],
        binding_item: Mapping[str, Any],
        *,
        holds: Any,
    ) -> None:
        binding_key = _key_of(binding_item)
        self.keys_touched.extend((_key_of(session_item), binding_key))
        if not holds(self.items.get(binding_key)):
            # Neither item is written. That is the whole reason the claim is a transaction.
            raise BindingConditionFailed(f"condition failed on {binding_key}")
        self._put_if_absent(session_item)
        self.items[binding_key] = dict(binding_item)

    def _put_if_absent(self, item: Mapping[str, Any]) -> None:
        key = _key_of(item)
        self.keys_touched.append(key)
        if key in self.items:
            raise AssertionError(f"an item already exists at {key}")
        self.items[key] = dict(item)

    # -- assertions read these -----------------------------------------------------------------

    def sessions(self) -> list[SessionRecord]:
        return [
            SessionRecord.from_item(item)
            for key, item in self.items.items()
            if key[1].startswith(f"S{SEPARATOR}")
        ]

    def bindings(self) -> list[AffinityKeyBindingRecord]:
        return [
            AffinityKeyBindingRecord.from_item(item)
            for key, item in self.items.items()
            if key[1].startswith(f"{BINDING_PREFIX}{SEPARATOR}")
        ]

    def only_binding(self) -> AffinityKeyBindingRecord:
        bindings = self.bindings()
        assert len(bindings) == 1, bindings
        return bindings[0]

    def place_session(self, record: SessionRecord) -> SessionRecord:
        """Seat a Session row directly, standing in for a Session created on an earlier turn."""
        self.items[(record.pk, record.sort_key)] = dict(record.to_item())
        return record

    def place_binding(self, record: AffinityKeyBindingRecord) -> None:
        self.items[(record.pk, record.sort_key)] = dict(record.to_item())


def _key_of(item: Mapping[str, Any]) -> tuple[str, str]:
    return (item[PARTITION_KEY_ATTRIBUTE], item[SORT_KEY_ATTRIBUTE])


@dataclass
class RecordingStarter:
    """`StartExecution` behaving as Step Functions does for a repeated name."""

    executions: dict[str, dict[str, Any]] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        self.log.append("start_execution")
        self.executions.setdefault(name, dict(payload))
        return f"{STATE_MACHINE}:{name}"


@dataclass
class PublishingWait:
    """A wait standing in for the winner's orchestration publishing a credential.

    Calling it is what the loser does on the transient branch, so it publishes onto the row the way
    an orchestration would — the credential *and* `RUNNING` *and* the Sandbox handle, since a
    credential is published only after `/run` has returned 200. `publishes=False` is the
    budget-expired case.
    """

    store: FakeStore
    session_id: str
    publishes: bool = True
    calls: list[str] = field(default_factory=list)
    reaches: LifecycleState = LifecycleState.RUNNING

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        self.calls.append(record.session_id)
        if not self.publishes:
            return None
        key = (record.pk, session_sort_key(self.session_id))
        row = self.store.items[key]
        row["lifecycleState"] = self.reaches.value
        row["connection"] = PUBLISHED.to_map()
        row["connectionPublishedAt"] = NOW_MS
        if self.reaches is not LifecycleState.FAILED:
            row["sandboxHandle"] = dict(SANDBOX_HANDLE)
        return PUBLISHED


def issuer(now: datetime = NOW) -> ConnectionIssuer:
    """The sole issuer, over a mint that honours the scope and TTL it is handed."""
    return ConnectionIssuer(
        mint=RecordingMint(now=now), policy=CredentialPolicy(), clock=lambda: now
    )


def operations(
    store: FakeStore,
    *,
    starter: RecordingStarter | None = None,
    wait: Any = None,
    settings: BindingSettings | None = None,
    session_ids: Any = None,
) -> ResolutionOperations:
    """The operation under test, with every collaborator injected and a fixed clock."""
    creation = CreationOperations(
        provider=LocalFirecrackerProvider(),
        policy=POLICY,
        settings=SETTINGS,
        store=store,
        orchestration=starter if starter is not None else RecordingStarter(),
        wait=wait if wait is not None else NoCreationWait(),
        clock=lambda: NOW,
        session_ids=session_ids if session_ids is not None else store.next_session_id,
    )
    return ResolutionOperations(
        creation=creation,
        bindings=store,
        lookup=store,
        issuer=issuer(),
        settings=settings if settings is not None else BindingSettings(),
    )


def resolve(
    operation: ResolutionOperations,
    *,
    tenant_id: str = TENANT,
    affinity_key: str = AFFINITY_KEY,
    extra: Mapping[str, Any] | None = None,
) -> OperationResult:
    body: dict[str, Any] = {AFFINITY_KEY_FIELD: affinity_key}
    if extra:
        body.update(extra)
    return operation.resolve_session(
        OperationRequest(
            operation=Operation.RESOLVE_SESSION,
            principal=principal(tenant_id),
            body=body,
        )
    )


def seated_session(
    store: FakeStore,
    *,
    state: LifecycleState,
    tenant_id: str = TENANT,
    session_id: str = "01JEARLIERTURNAAAAAAAAAAAA",
    with_handle: bool = True,
    max_duration_seconds: int = 3600,
    generation: int = 1,
    published: ConnectionDescriptor | None = PUBLISHED,
) -> SessionRecord:
    """A Session from an earlier turn, plus the binding naming it."""
    record = store.place_session(
        SessionRecord(
            pk=pk_for(principal(tenant_id)),
            session_id=session_id,
            tenant_id=tenant_id,
            provider_name=LocalFirecrackerProvider.name,
            lifecycle_state=state,
            created_at=NOW_MS,
            updated_at=NOW_MS,
            max_duration_seconds=max_duration_seconds,
            idle_seconds=300,
            suspended_seconds=600,
            auto_resume=True,
            memory_bytes=SETTINGS.memory_bytes,
            execution_role_arn=SETTINGS.execution_role_arn,
            reap_shard=3,
            reap_deadline=NOW_MS + max_duration_seconds * 1000,
            artifact_retention_days=SETTINGS.artifact_retention_days,
            generation=generation,
            sandbox_handle=dict(SANDBOX_HANDLE) if with_handle else None,
            connection=published,
            affinity_key_digest=DIGEST,
        )
    )
    store.place_binding(
        AffinityKeyBindingRecord(
            pk=record.pk,
            affinity_key_digest=DIGEST,
            session_id=session_id,
            bound_at=NOW_MS,
            expires_at=(NOW_MS + max_duration_seconds * 1000) // 1000,
        )
    )
    return record


# --- The claim: one transaction, and no read before it (R6.17, R6.18) ----------------------------


def test_the_claim_is_one_transaction_and_nothing_is_read_before_it() -> None:
    """R6.18: a conditional write, never a read followed by an unconditional one."""
    store = FakeStore()
    resolve(operations(store))

    assert store.log[0] == "claim_binding"
    assert "read_binding" not in store.log
    assert "put_new_session" not in store.log


def test_the_winner_creates_one_session_and_one_binding() -> None:
    store = FakeStore()
    starter = RecordingStarter()
    result = resolve(operations(store, starter=starter))

    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    sessions = store.sessions()
    assert len(sessions) == 1
    binding = store.only_binding()
    assert binding.session_id == sessions[0].session_id
    assert len(starter.executions) == 1
    assert f"{EXECUTION_NAME_PREFIX}{sessions[0].session_id}" in starter.executions


def test_the_created_row_carries_the_digest_the_reaper_reads() -> None:
    """R10.17's cleanup layer 2 needs `affinityKeyDigest` on the row from the first write."""
    store = FakeStore()
    resolve(operations(store))
    assert store.sessions()[0].affinity_key_digest == DIGEST


def test_a_second_request_for_the_same_key_creates_nothing() -> None:
    """R6.17: two requests, one Tenant, one Affinity_Key — one Session and one Sandbox."""
    store = FakeStore()
    starter = RecordingStarter()
    first = resolve(operations(store, starter=starter))
    session_id = first.payload["sessionId"]
    wait = PublishingWait(store, session_id)

    second = resolve(operations(store, starter=starter, wait=wait))

    assert len(store.sessions()) == 1
    assert len(starter.executions) == 1
    assert second.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    assert second.payload["sessionId"] == session_id


def test_a_losing_claim_leaves_neither_a_session_row_nor_a_binding() -> None:
    """The reason for a transaction rather than two conditional writes.

    Thirty-two requests arrive for one key. Exactly one Session row exists afterwards, and no losing
    request left a row behind for the Reaper to find.
    """
    store = FakeStore()
    starter = RecordingStarter()
    first = resolve(operations(store, starter=starter))
    winner = first.payload["sessionId"]
    wait = PublishingWait(store, winner)

    outcomes = [
        resolve(operations(store, starter=starter, wait=wait)) for _ in range(31)
    ]

    assert len(store.sessions()) == 1
    assert len(store.bindings()) == 1
    assert len(starter.executions) == 1
    # And every one of them returned a usable credential naming that one Session, not an error.
    assert {result.payload["sessionId"] for result in outcomes} == {winner}
    for result in outcomes:
        assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
        assert result.payload["connection"]["authHeaderValue"] == FAKE_TOKEN


# --- The loser's branch table (R6.19, R6.20, R6.21) ---------------------------------------------


def test_the_loser_branch_table_covers_every_lifecycle_state() -> None:
    """A state added to the lifecycle model without a resolution decision fails here."""
    assert set(LOSER_BRANCHES) == set(LifecycleState)


def test_a_running_bound_session_is_returned_and_nothing_is_created() -> None:
    store = FakeStore()
    starter = RecordingStarter()
    seated = seated_session(store, state=LifecycleState.RUNNING)

    result = resolve(operations(store, starter=starter))

    assert result.status == HTTPStatus.OK
    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    assert result.payload["sessionId"] == seated.session_id
    assert len(store.sessions()) == 1
    assert starter.executions == {}


def test_a_suspended_bound_session_is_returned_and_left_suspended() -> None:
    """R6.20: a credential, no resume, and the recorded state untouched.

    The provider is asked nothing at all — the first request the caller delivers to the endpoint is
    what resumes the Sandbox (R10.5), so resuming here would bill for compute the caller may never
    use.
    """
    store = FakeStore()
    provider = LocalFirecrackerProvider()
    seated = seated_session(store, state=LifecycleState.SUSPENDED)

    result = resolve(operations(store))

    assert result.payload["lifecycleState"] == LifecycleState.SUSPENDED.value
    assert "connection" in result.payload
    stored = store.read_session(partition_key=seated.pk, sort_key=seated.sort_key)
    assert stored is not None
    assert stored["lifecycleState"] == LifecycleState.SUSPENDED.value
    # No Sandbox was resumed, suspended or created anywhere on this path.
    assert provider.discover({}) == []


@pytest.mark.parametrize(
    "state",
    [
        LifecycleState.PENDING,
        LifecycleState.ORCHESTRATING,
        LifecycleState.PROVISIONING,
        LifecycleState.STARTING,
        LifecycleState.SUSPENDING,
        LifecycleState.RESUMING,
        LifecycleState.CONTINUING,
    ],
)
def test_a_transient_bound_session_is_waited_on_and_then_returned(
    state: LifecycleState,
) -> None:
    """R6.19: the loser reuses the creation wait verbatim and never fails.

    The wait is handed the winner's own row, which is why it was designed as a function of a Session
    record rather than of a request.
    """
    store = FakeStore()
    starter = RecordingStarter()
    seated = seated_session(store, state=state, with_handle=False, published=None)
    wait = PublishingWait(store, seated.session_id)

    result = resolve(operations(store, starter=starter, wait=wait))

    assert wait.calls == [seated.session_id]
    assert result.payload["sessionId"] == seated.session_id
    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    assert "connection" in result.payload
    # Nothing was created for the loser.
    assert len(store.sessions()) == 1
    assert starter.executions == {}


def test_a_wait_that_expires_returns_the_asynchronous_shape_and_not_a_gateway_timeout() -> (
    None
):
    """R9.16 and R10.14: an absent credential means "not yet published", never a `504`."""
    store = FakeStore()
    seated = seated_session(
        store, state=LifecycleState.PENDING, with_handle=False, published=None
    )
    wait = PublishingWait(store, seated.session_id, publishes=False)

    result = resolve(operations(store, wait=wait))

    assert result.status == HTTPStatus.ACCEPTED
    assert result.payload["sessionId"] == seated.session_id
    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    # Omitted rather than null: a third state would be a third thing every client had to learn.
    assert "connection" not in result.payload


def test_a_session_that_goes_terminal_during_the_wait_is_treated_as_absent() -> None:
    """The transient branch re-reads after the wait, so a row that died mid-wait is not returned."""
    store = FakeStore()
    starter = RecordingStarter()
    seated = seated_session(
        store, state=LifecycleState.PROVISIONING, with_handle=False, published=None
    )
    wait = PublishingWait(store, seated.session_id, reaches=LifecycleState.FAILED)

    result = resolve(operations(store, starter=starter, wait=wait))

    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert result.payload["sessionId"] != seated.session_id
    assert store.only_binding().session_id == result.payload["sessionId"]


@pytest.mark.parametrize(
    "state",
    [LifecycleState.TERMINATED, LifecycleState.FAILED, LifecycleState.TERMINATING],
)
def test_a_terminal_binding_is_treated_as_absent_and_replaced(
    state: LifecycleState,
) -> None:
    """R6.21: a new Session bound to the same digest, by replacement rather than delete-then-create."""
    store = FakeStore()
    starter = RecordingStarter()
    seated = seated_session(store, state=state)

    result = resolve(operations(store, starter=starter))

    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert result.payload["sessionId"] != seated.session_id
    binding = store.only_binding()
    assert binding.affinity_key_digest == DIGEST
    assert binding.session_id == result.payload["sessionId"]
    assert len(starter.executions) == 1
    # Replaced, never deleted: one conditional transaction did both halves.
    assert store.log.count("replace_binding") == 1


def test_a_binding_whose_session_record_is_absent_is_treated_as_absent() -> None:
    """R13.8's stale-binding self-heal: corrected on read, without waiting for any expiry."""
    store = FakeStore()
    store.place_binding(
        AffinityKeyBindingRecord(
            pk=pk_for(principal()),
            affinity_key_digest=DIGEST,
            session_id="01JVANISHEDAAAAAAAAAAAAAAA",
            bound_at=NOW_MS,
            # Not yet expired, so nothing here depends on a TTL having fired.
            expires_at=(NOW_MS + 3_600_000) // 1000,
        )
    )

    result = resolve(operations(store))

    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert store.only_binding().session_id == result.payload["sessionId"]


def test_concurrent_requests_on_one_terminal_binding_produce_one_session() -> None:
    """The case the conditional replacement exists for.

    Three requests each find the same terminal binding. Without the condition each would
    delete-then-create and produce three Sessions; with it one commits and the others re-enter the
    loser's path and find the live Session it created.
    """
    store = FakeStore()
    starter = RecordingStarter()
    seated = seated_session(store, state=LifecycleState.TERMINATED)

    first = resolve(operations(store, starter=starter))
    replacement = first.payload["sessionId"]
    wait = PublishingWait(store, replacement)
    others = [resolve(operations(store, starter=starter, wait=wait)) for _ in range(2)]

    # The terminal Session's row survives; what changed is which Session the binding names.
    assert {record.session_id for record in store.sessions()} == {
        seated.session_id,
        replacement,
    }
    assert store.only_binding().session_id == replacement
    assert len(starter.executions) == 1
    for result in others:
        assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
        assert result.payload["sessionId"] == replacement


def test_a_binding_deleted_between_the_failed_claim_and_the_read_is_claimed_afresh() -> (
    None
):
    """A vanished binding is not a resolution and not a replacement: the next attempt claims."""

    @dataclass
    class VanishingStore(FakeStore):
        """Fails the first claim as though a binding existed, then reports none."""

        first_claim_lost: bool = False

        def claim_binding(
            self, *, session_item: Mapping[str, Any], binding_item: Mapping[str, Any]
        ) -> None:
            if not self.first_claim_lost:
                self.first_claim_lost = True
                self.log.append("claim_binding")
                raise BindingConditionFailed("a binding existed a moment ago")
            super().claim_binding(session_item=session_item, binding_item=binding_item)

    store = VanishingStore()
    result = resolve(operations(store))

    assert store.log[:3] == ["claim_binding", "read_binding", "claim_binding"]
    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert store.only_binding().session_id == result.payload["sessionId"]


def test_contention_that_never_converges_is_bounded_and_reported() -> None:
    """`MAX_CLAIM_ATTEMPTS` bounds the loop, and exhausting it writes nothing."""

    @dataclass
    class NeverSettlesStore(FakeStore):
        def claim_binding(
            self, *, session_item: Mapping[str, Any], binding_item: Mapping[str, Any]
        ) -> None:
            self.log.append("claim_binding")
            raise BindingConditionFailed("somebody else always wins")

    store = NeverSettlesStore()
    with pytest.raises(ResolutionDidNotSettle) as raised:
        resolve(operations(store))

    assert raised.value.attempts == MAX_CLAIM_ATTEMPTS
    assert store.log.count("claim_binding") == MAX_CLAIM_ATTEMPTS
    assert raised.value.response.status == HTTPStatus.SERVICE_UNAVAILABLE
    # Every attempt was a transaction that committed nothing, so nothing is left behind.
    assert store.items == {}


# --- Freshly minted on every resolution (R6.23) --------------------------------------------------


@pytest.mark.parametrize("state", [LifecycleState.RUNNING, LifecycleState.SUSPENDED])
def test_the_resolved_credential_is_minted_and_not_the_one_on_the_row(
    state: LifecycleState,
) -> None:
    """R6.23: a credential minted now, never the one the orchestration published."""
    store = FakeStore()
    seated = seated_session(store, state=state, published=PUBLISHED)

    connection = resolve(operations(store)).payload["connection"]

    assert connection != PUBLISHED.to_map()
    assert connection["authHeaderValue"] == FAKE_TOKEN
    assert connection["authHeaderValue"] != PUBLISHED.auth_header_value
    # The published attribute is untouched: the resolve branch never reads it and never rewrites it.
    stored = store.read_session(partition_key=seated.pk, sort_key=seated.sort_key)
    assert stored is not None
    assert stored["connection"] == PUBLISHED.to_map()


def test_the_created_branch_returns_what_the_orchestration_published() -> None:
    """R6.13's other half: a creation reads its credential from the row and mints nothing."""
    store = FakeStore()

    @dataclass
    class PublishedOnCreation:
        def await_connection(
            self, record: SessionRecord
        ) -> ConnectionDescriptor | None:
            del record
            return PUBLISHED

    result = resolve(operations(store, wait=PublishedOnCreation()))

    assert result.status == HTTPStatus.CREATED
    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert result.payload["connection"] == PUBLISHED.to_map()


def test_a_live_session_that_admits_no_credential_is_a_409_naming_the_reason() -> None:
    """Reachable only for a Session live by its state whose maximum duration already elapsed."""
    store = FakeStore()
    seated_session(store, state=LifecycleState.RUNNING, max_duration_seconds=60)
    # A clock an hour past a sixty-second Session: the remainder is negative, so no credential could
    # be scoped to it. Creating a new Session instead would replace a binding naming a non-terminal
    # Session, which is not what R6.21 licenses.
    operation = ResolutionOperations(
        creation=operations(store).creation,
        bindings=store,
        lookup=store,
        issuer=issuer(now=datetime.fromtimestamp((NOW_MS + 3_600_000) / 1000, tz=UTC)),
    )
    with pytest.raises(ConnectionUnavailable):
        operation.resolve_session(
            OperationRequest(
                operation=Operation.RESOLVE_SESSION,
                principal=principal(),
                body={AFFINITY_KEY_FIELD: AFFINITY_KEY},
            )
        )


# --- Tenant confinement (R6.16, R11.11) ---------------------------------------------------------


def test_every_key_touched_is_the_callers_own_partition() -> None:
    """Confinement asserted over the keys addressed, not over an absent comparison."""
    store = FakeStore()
    seated_session(store, state=LifecycleState.TERMINATED)
    store.keys_touched.clear()

    resolve(operations(store))

    assert store.keys_touched
    assert {partition for partition, _ in store.keys_touched} == {pk_for(principal())}


def test_two_tenants_presenting_one_affinity_key_resolve_to_different_sessions() -> (
    None
):
    """R11.11: byte-identical keys, two partitions, and neither Tenant can name the other's."""
    store = FakeStore()
    starter = RecordingStarter()

    mine = resolve(operations(store, starter=starter), tenant_id=TENANT)
    theirs = resolve(operations(store, starter=starter), tenant_id=OTHER_TENANT)

    assert mine.payload["sessionId"] != theirs.payload["sessionId"]
    assert mine.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert theirs.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    # One digest, two bindings, one in each Tenant's partition.
    partitions = {binding.pk for binding in store.bindings()}
    assert partitions == {pk_for(principal(TENANT)), pk_for(principal(OTHER_TENANT))}
    assert {binding.affinity_key_digest for binding in store.bindings()} == {DIGEST}


def test_a_binding_in_another_tenants_partition_is_not_reached() -> None:
    """The other Tenant's live Session is not resolved; a new one is created in this partition."""
    store = FakeStore()
    theirs = seated_session(
        store,
        state=LifecycleState.RUNNING,
        tenant_id=OTHER_TENANT,
        session_id="01JTHEIRSESSIONAAAAAAAAAAA",
    )

    result = resolve(operations(store), tenant_id=TENANT)

    assert result.payload[RESOLUTION_FIELD] == ResolutionOutcome.CREATED.value
    assert result.payload["sessionId"] != theirs.session_id


# --- The digest sort key ------------------------------------------------------------------------


def test_the_binding_sort_key_is_the_digest_and_the_raw_key_is_never_stored() -> None:
    store = FakeStore()
    resolve(operations(store), affinity_key=AFFINITY_KEY)

    binding = store.only_binding()
    assert binding.sort_key == binding_sort_key(DIGEST)
    assert SEPARATOR not in binding.affinity_key_digest
    # The raw key carries the delimiter and would have broken the key structure. It appears nowhere.
    assert AFFINITY_KEY not in repr(store.items)


@pytest.mark.parametrize(
    "affinity_key",
    [
        "a",
        "thread-9f3",
        # The delimiter, doubled, and at both ends.
        "#",
        "##a##",
        f"S{SEPARATOR}01JLOOKSLIKEASESSIONROWKEY",
        # Long enough that a length cap would have refused it. The digest is fixed length, so no cap
        # is imposed and none is needed.
        "x" * 8192,
        # Non-ASCII, and an astral-plane character.
        "会話-9f3",
        "\U0001f600",
    ],
)
def test_any_key_with_a_utf8_encoding_names_a_binding(affinity_key: str) -> None:
    store = FakeStore()
    resolve(operations(store), affinity_key=affinity_key)

    binding = store.only_binding()
    assert binding.affinity_key_digest == affinity_key_digest(affinity_key)
    assert binding.sort_key.startswith(f"{BINDING_PREFIX}{SEPARATOR}")


def test_one_key_yields_one_digest_across_calls() -> None:
    assert digest_of_requested_affinity_key(
        {AFFINITY_KEY_FIELD: AFFINITY_KEY}
    ) == digest_of_requested_affinity_key({AFFINITY_KEY_FIELD: AFFINITY_KEY})


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({}, "is required"),
        ({AFFINITY_KEY_FIELD: None}, "is required"),
        ({AFFINITY_KEY_FIELD: ""}, "must not be empty"),
        ({AFFINITY_KEY_FIELD: 9}, "must be a string"),
        ({AFFINITY_KEY_FIELD: True}, "must be a string"),
        ({AFFINITY_KEY_FIELD: ["thread-9f3"]}, "must be a string"),
        # `json.loads('"\\ud800"')` produces exactly this, so it is reachable from the wire.
        ({AFFINITY_KEY_FIELD: "\ud800"}, "unpaired surrogate"),
    ],
)
def test_a_key_that_cannot_be_hashed_is_a_400_that_echoes_none_of_it(
    body: Mapping[str, Any], expected: str
) -> None:
    store = FakeStore()
    with pytest.raises(InvalidAffinityKey) as raised:
        operations(store).resolve_session(
            OperationRequest(
                operation=Operation.RESOLVE_SESSION,
                principal=principal(),
                body=body,
            )
        )
    assert expected in raised.value.reason
    assert raised.value.response.status == HTTPStatus.BAD_REQUEST
    # Nothing was written, and no value the caller sent is echoed back.
    assert store.items == {}
    assert b"thread" not in raised.value.response.body


# --- The binding record: what it holds, and what it deliberately does not ------------------------


def test_the_binding_names_a_session_and_nothing_that_could_fall_out_of_step() -> None:
    """R6.24: no handle, no generation, no credential, no lifecycle state — so nothing to update."""
    store = FakeStore()
    resolve(operations(store))

    item = store.items[(pk_for(principal()), binding_sort_key(DIGEST))]
    assert set(item) == {
        PARTITION_KEY_ATTRIBUTE,
        SORT_KEY_ATTRIBUTE,
        "sessionId",
        "boundAt",
        TTL_ATTRIBUTE,
    }


def test_the_binding_expiry_is_no_later_than_the_session_deadline() -> None:
    """R13.8, and in epoch seconds, which is the only unit DynamoDB expires an item on."""
    store = FakeStore()
    resolve(operations(store), extra={"maxDurationSeconds": 1800})

    binding = store.only_binding()
    record = store.sessions()[0]
    deadline_seconds = (record.created_at + record.max_duration_seconds * 1000) // 1000
    assert binding.expires_at == deadline_seconds
    assert binding.bound_at == record.created_at
    # Milliseconds here would put the expiry tens of thousands of years out and make cleanup layer 3
    # silently inert, so the two units are asserted against each other rather than each alone.
    assert binding.expires_at * 1000 <= binding.bound_at + 1800 * 1000


def test_a_configured_ceiling_shorter_than_the_session_clamps_the_expiry() -> None:
    """`min(sessionDeadline, boundAt + configuredMaxAge)`, so the ceiling only ever shortens."""
    store = FakeStore()
    resolve(
        operations(store, settings=BindingSettings(max_age_seconds=60)),
        extra={"maxDurationSeconds": 3600},
    )

    binding = store.only_binding()
    assert binding.expires_at == (binding.bound_at + 60_000) // 1000


def test_the_default_ceiling_is_the_session_duration_ceiling() -> None:
    """So the default clamps nothing and the Session's own deadline bounds every binding."""
    assert BindingSettings().max_age_seconds == DEFAULT_BINDING_MAX_AGE_SECONDS
    assert DEFAULT_BINDING_MAX_AGE_SECONDS == 28_800


@pytest.mark.parametrize("max_age", [0, -1, True, "3600", 1.5])
def test_a_misconfigured_binding_ceiling_fails_where_it_is_built(max_age: Any) -> None:
    with pytest.raises(ValueError):
        BindingSettings(max_age_seconds=max_age)


def test_binding_for_takes_its_partition_key_from_the_session_row() -> None:
    """Not rebuilt, so a binding and the Session it names cannot land in different partitions."""
    store = FakeStore()
    record = seated_session(store, state=LifecycleState.RUNNING)
    binding = binding_for(record, DIGEST, BindingSettings())
    assert binding.pk == record.pk == pk_for(principal())


# --- The response shape ------------------------------------------------------------------------


def test_the_payload_names_which_of_the_two_actions_happened() -> None:
    store = FakeStore()
    record = seated_session(store, state=LifecycleState.RUNNING, generation=3)

    created = resolution_payload(record, None, ResolutionOutcome.CREATED)
    assert created == {
        "sessionId": record.session_id,
        "generation": 3,
        "lifecycleState": LifecycleState.RUNNING.value,
        RESOLUTION_FIELD: "created",
    }
    resolved = resolution_payload(record, PUBLISHED, ResolutionOutcome.RESOLVED)
    assert resolved[RESOLUTION_FIELD] == "resolved"
    assert resolved["connection"] == PUBLISHED.to_map()


def test_a_continuation_leaves_the_binding_alone_while_the_generation_moves() -> None:
    """R6.24 needs no code: the binding names a Session identifier and nothing generational."""
    store = FakeStore()
    seated_session(store, state=LifecycleState.RUNNING, generation=1)
    before = store.only_binding()

    row_key = (pk_for(principal()), session_sort_key(before.session_id))
    store.items[row_key]["generation"] = 4
    result = resolve(operations(store))

    assert store.only_binding() == before
    assert result.payload["generation"] == 4
    assert result.payload["sessionId"] == before.session_id


# --- The route, and the seven seams this task does not fill --------------------------------------


def test_the_resolve_route_reaches_this_operation_through_the_dispatcher() -> None:
    store = FakeStore()
    dispatcher = ControlPlaneApi(operations=operations(store), lookup=store)
    response = dispatcher.handle(
        {
            "version": "2.0",
            "rawPath": "/sessions/resolve",
            "requestContext": {
                "http": {"method": "POST"},
                "authorizer": {"iam": {"userArn": CALLER}},
            },
            "body": f'{{"{AFFINITY_KEY_FIELD}":"{AFFINITY_KEY}"}}',
            "isBase64Encoded": False,
        }
    )

    assert response.status == HTTPStatus.ACCEPTED
    assert b'"resolution":"created"' in response.body
    assert len(store.bindings()) == 1


def test_a_resolve_body_naming_no_affinity_key_reaches_the_gateway_as_a_400() -> None:
    store = FakeStore()
    dispatcher = ControlPlaneApi(operations=operations(store), lookup=store)
    response = dispatcher.handle(
        {
            "version": "2.0",
            "rawPath": "/sessions/resolve",
            "requestContext": {
                "http": {"method": "POST"},
                "authorizer": {"iam": {"userArn": CALLER}},
            },
            "body": "{}",
            "isBase64Encoded": False,
        }
    )

    assert response.status == HTTPStatus.BAD_REQUEST
    assert b"InvalidAffinityKey" in response.body
    assert store.items == {}


def test_a_rejected_duration_on_the_resolve_path_writes_nothing() -> None:
    """Admission runs before the claim, so a `400` costs neither a binding nor an execution."""
    store = FakeStore()
    starter = RecordingStarter()
    ceiling = LocalFirecrackerProvider().limits().max_duration_seconds
    with pytest.raises(SessionAdmissionRejected):
        resolve(
            operations(store, starter=starter),
            extra={"maxDurationSeconds": ceiling + 1},
        )

    assert store.items == {}
    assert starter.executions == {}


def test_the_other_seven_operations_still_answer_501() -> None:
    operation = operations(FakeStore())
    for method_name in (
        "create_session",
        "get_session",
        "list_sessions",
        "suspend_session",
        "resume_session",
        "terminate_session",
        "refresh_connection",
    ):
        with pytest.raises(OperationNotImplemented):
            getattr(operation, method_name)(
                OperationRequest(
                    operation=Operation.GET_SESSION, principal=principal(), body={}
                )
            )
