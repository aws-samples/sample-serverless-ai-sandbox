# kiro-classification: public
"""Creation ordering: the complete row first, then the execution, and never a provision call.

Every assertion here is deterministic. Property 12 — the record precedes provisioning and is
complete, over drawn create-request shapes and drawn provider outcomes — is task 6.5 and belongs to
its own file, so nothing here draws inputs. What this file establishes is the ordering those drawn
inputs will be quantified over, and it does so in three structural senses:

- `test_the_complete_row_is_written_before_the_execution_starts` reads one recorded call log, and
  `test_the_row_is_complete_the_moment_it_is_written` parses the item captured at the *first* write
  back into a whole `SessionRecord`. A row that only became parseable after a second write would
  leave a window in which a Sandbox could exist beside a partial record.
- `test_no_sandbox_comes_into_existence_on_the_creation_path` asks a real Compute_Provider what it
  holds after a creation. Nothing — not a call log entry, an actual Sandbox — which is the form
  R6.11's claim takes from the provider's side.
- `test_no_module_outside_the_provider_seam_provisions` runs the lint rule over the tree, which is
  what carries the structural half of R6.11 into CI rather than leaving it to review.

The idempotency assertions are worth reading together: `execution_name_for` is a pure function of
the Session identifier, and `test_a_retried_creation_for_one_session_starts_one_execution` shows
what that buys against a starter behaving as Step Functions does.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import pytest

from ci.lint_rules import orchestrated_provisioning as rule
from control_plane.api import ControlPlaneApi
from control_plane.api.admission import AdmissionPolicy, SessionAdmissionRejected
from control_plane.api.creation import (
    EXECUTION_NAME_PREFIX,
    EXPOSED_PORTS_FIELD,
    MAX_EXECUTION_NAME_LENGTH,
    CreationOperations,
    CreationSettings,
    ExecutionNameError,
    NoCreationWait,
    OrchestrationStart,
    creation_payload,
    execution_name_for,
    new_session_id,
    orchestration_start_for,
)
from control_plane.api.errors import OperationNotImplemented
from control_plane.api.handlers import OperationRequest, OperationResult
from control_plane.api.routes import Operation
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import tenant_state_sort_key
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

TENANT = "tenant-a"
CALLER = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
SESSION_ID = "01JCREATIONAAAAAAAAAAAAAAA"
STATE_MACHINE = "arn:aws:states:us-east-1:123456789012:execution:SessionOrchestrator"
EXECUTION_ARN = f"{STATE_MACHINE}:{EXECUTION_NAME_PREFIX}{SESSION_ID}"

#: Epoch milliseconds, fixed so every timestamp expectation below is arithmetic rather than a
#: comparison against the wall clock.
NOW_MS = 1_700_000_000_000

#: The Crockford Base32 alphabet, spelled here so the identifier assertion checks the generator
#: against the alphabet rather than against itself.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: The characters Step Functions rejects in an execution name.
FORBIDDEN_IN_NAME = '<>{}[]?*"#%\\^|~`$&,;:/'


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """One Tenant, resolved from the deployment rather than from a request."""
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=TENANT)


def fixed_clock() -> datetime:
    return datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)


@dataclass
class FakeStore:
    """An in-memory State_Store keyed exactly as DynamoDB is: partition key, then sort key.

    Faithful in the two respects that matter here: a create refuses to overwrite an item already at
    the key, and an update touches a row that must already exist. No network, no deployed resource.

    `log` is shared with the starter in the ordering test, so one list records the order of the two
    collaborators' calls rather than two lists having to be interleaved after the fact.
    """

    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    captured: list[dict[str, Any]] = field(default_factory=list)

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        key = (item[PARTITION_KEY_ATTRIBUTE], item[SORT_KEY_ATTRIBUTE])
        if key in self.items:
            raise AssertionError(f"a Session row already exists at {key}")
        self.captured.append(dict(item))
        self.items[key] = dict(item)
        self.log.append("put_new_session")

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        item = self.items[(start.partition_key, start.sort_key)]
        item["lifecycleState"] = start.state.value
        item["stateReason"] = start.state_reason
        item[TENANT_STATE_INDEX.sort_key] = start.state_created_at
        item["orchestrationExecutionArn"] = start.execution_arn
        item["updatedAt"] = start.updated_at
        self.log.append("mark_orchestration_started")

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        return self.items.get((partition_key, sort_key))

    def only_row(self) -> dict[str, Any]:
        assert len(self.items) == 1, self.items
        return next(iter(self.items.values()))


@dataclass
class RecordingStarter:
    """A `StartExecution` behaving as Step Functions does for a repeated name.

    A second start under a name already used returns the existing execution rather than creating a
    second one, which is exactly the behaviour a name derived from the Session identifier reaches. A
    repeated name carrying a *different* input is the one case the service rejects, so it raises
    here rather than quietly accepting what a deployment would refuse.
    """

    log: list[str] = field(default_factory=list)
    executions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        self.log.append("start_execution")
        existing = self.executions.get(name)
        if existing is not None:
            if existing != dict(payload):
                raise AssertionError(
                    f"execution {name!r} already exists with a different input"
                )
            return f"{STATE_MACHINE}:{name}"
        self.executions[name] = dict(payload)
        return f"{STATE_MACHINE}:{name}"


@dataclass(frozen=True)
class PublishingWait:
    """A wait reporting a credential already published on the row.

    It reads nothing and mints nothing; task 6.6 supplies the polling that reads the row. Present so
    the response-shape difference between "a credential was published" and "none was" is exercised
    from this side of the seam.
    """

    connection: ConnectionDescriptor | None

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        del record
        return self.connection


@dataclass
class CapturingWait:
    """A wait that records the Session row it was handed and reports nothing published."""

    seen: list[SessionRecord] = field(default_factory=list)

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        self.seen.append(record)
        return None


PUBLISHED = ConnectionDescriptor(
    base_url="https://sandbox.invalid",
    auth_header_name="X-aws-proxy-auth",
    # An obviously-fake token. Nothing in this suite carries a real credential.
    auth_header_value="fake-endpoint-token-for-tests",
    ports=(8000,),
    expires_at="2026-06-22T10:15:00Z",
)

#: The deployment's configured defaults, standing in for CDK context values rather than asserting a
#: production default by choosing them.
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


def operations(
    *,
    store: FakeStore | None = None,
    starter: RecordingStarter | None = None,
    provider: LocalFirecrackerProvider | None = None,
    wait: Any = None,
    session_id: str = SESSION_ID,
) -> CreationOperations:
    """The operation under test, with every collaborator injected and a fixed clock.

    The provider is the real `local-firecracker` one rather than a double, so "nothing provisioned"
    is asked of a provider that would have recorded a Sandbox if anything had.
    """
    return CreationOperations(
        provider=provider if provider is not None else LocalFirecrackerProvider(),
        policy=POLICY,
        settings=SETTINGS,
        store=store if store is not None else FakeStore(),
        orchestration=starter if starter is not None else RecordingStarter(),
        wait=wait if wait is not None else NoCreationWait(),
        clock=fixed_clock,
        session_ids=lambda: session_id,
    )


def create(
    operation: CreationOperations, body: Mapping[str, Any] | None = None
) -> OperationResult:
    return operation.create_session(
        OperationRequest(
            operation=Operation.CREATE_SESSION,
            principal=principal(),
            body={} if body is None else body,
        )
    )


# --- The ordering (R6.6, R6.10) ------------------------------------------------------------------


def test_the_complete_row_is_written_before_the_execution_starts() -> None:
    """R6.6's ordering, read off one call log rather than inferred from two."""
    shared: list[str] = []
    store = FakeStore(log=shared)
    starter = RecordingStarter(log=shared)

    create(operations(store=store, starter=starter))

    assert shared == [
        "put_new_session",
        "start_execution",
        "mark_orchestration_started",
    ]


def test_the_written_row_carries_everything_r6_6_names() -> None:
    store = FakeStore()
    create(operations(store=store), {"maxDurationSeconds": 7200})

    record = SessionRecord.from_item(store.only_row())
    assert record.tenant_id == TENANT
    assert record.provider_name == LocalFirecrackerProvider.name
    assert record.lifecycle_state is LifecycleState.ORCHESTRATING
    assert record.created_at == NOW_MS
    assert record.max_duration_seconds == 7200
    assert record.idle_seconds == POLICY.default_idle_seconds
    assert record.suspended_seconds == POLICY.default_suspended_seconds
    assert record.auto_resume is True
    # And the partition key is the one the sole producer returns for this principal.
    assert record.pk == pk_for(principal())


def test_the_row_is_complete_the_moment_it_is_written() -> None:
    """Completeness is asserted at the first write, not after the update that follows it.

    This is what Property 12 will quantify over: the item handed to the store parses into a whole
    record, so there is no window in which a Sandbox could exist beside a partial one.
    """
    store = FakeStore()
    create(operations(store=store))

    assert len(store.captured) == 1
    first = SessionRecord.from_item(store.captured[0])
    assert first.lifecycle_state is LifecycleState.PENDING
    assert first.session_id == SESSION_ID
    assert first.tenant_id == TENANT
    assert first.created_at == NOW_MS == first.updated_at
    assert first.reap_deadline == NOW_MS + POLICY.default_duration_seconds * 1000
    assert first.memory_bytes == SETTINGS.memory_bytes
    assert first.execution_role_arn == SETTINGS.execution_role_arn
    assert first.artifact_retention_days == SETTINGS.artifact_retention_days
    assert 0 <= first.reap_shard < SETTINGS.reap_shard_count
    # No Sandbox, no credential and no execution yet: each is recorded by whoever creates it.
    assert first.sandbox_handle is None
    assert first.connection is None
    assert first.orchestration_execution_arn is None


def test_the_started_execution_is_recorded_on_the_row() -> None:
    store = FakeStore()
    create(operations(store=store))

    record = SessionRecord.from_item(store.only_row())
    assert record.orchestration_execution_arn == EXECUTION_ARN
    assert record.lifecycle_state is LifecycleState.ORCHESTRATING
    assert record.updated_at == NOW_MS


def test_the_execution_input_names_the_session_the_tenant_and_the_limits() -> None:
    starter = RecordingStarter()
    create(operations(starter=starter), {EXPOSED_PORTS_FIELD: [9000, 8080, 9000]})

    payload = starter.executions[f"{EXECUTION_NAME_PREFIX}{SESSION_ID}"]
    assert payload["sessionId"] == SESSION_ID
    assert payload["tenantId"] == TENANT
    assert payload["providerName"] == LocalFirecrackerProvider.name
    assert payload["exposedPorts"] == [8080, 9000]
    assert payload["limits"]["maxDurationSeconds"] == POLICY.default_duration_seconds
    # Neither a credential nor a partition key travels in the input: the orchestration mints the
    # one (R6.12) and derives the other through the sole producer.
    assert "connection" not in payload
    assert PARTITION_KEY_ATTRIBUTE not in payload


def test_a_rejected_request_writes_nothing_and_starts_nothing() -> None:
    """Validation precedes the write, so a `400` costs neither a row nor an execution."""
    store = FakeStore()
    starter = RecordingStarter()
    ceiling = LocalFirecrackerProvider().limits().max_duration_seconds
    with pytest.raises(SessionAdmissionRejected):
        create(
            operations(store=store, starter=starter),
            {"maxDurationSeconds": ceiling + 1},
        )

    assert store.items == {}
    assert starter.executions == {}


def test_the_rejection_reaches_the_gateway_as_the_400_admission_built() -> None:
    """The handler adds no error handling of its own: the dispatcher renders what was raised."""
    dispatcher = ControlPlaneApi(operations=operations(), lookup=FakeStore())
    response = dispatcher.handle(
        {
            "version": "2.0",
            "rawPath": "/sessions",
            "requestContext": {
                "http": {"method": "POST"},
                "authorizer": {"iam": {"userArn": CALLER}},
            },
            "body": '{"idleSeconds":0}',
            "isBase64Encoded": False,
        }
    )
    assert response.status == HTTPStatus.BAD_REQUEST
    assert b"InvalidSessionConfiguration" in response.body


def test_a_successful_creation_reaches_the_gateway_as_the_accepted_response() -> None:
    dispatcher = ControlPlaneApi(operations=operations(), lookup=FakeStore())
    response = dispatcher.handle(
        {
            "version": "2.0",
            "rawPath": "/sessions",
            "requestContext": {
                "http": {"method": "POST"},
                "authorizer": {"iam": {"userArn": CALLER}},
            },
            "body": None,
            "isBase64Encoded": False,
        }
    )
    assert response.status == HTTPStatus.ACCEPTED
    assert SESSION_ID.encode() in response.body


# --- The tenant-state-index sort key, against every lifecycle write this path performs -----------
#
# `stateCreatedAt` is `<lifecycleState>#<createdAt>` and it is the `tenant-state-index` sort key, so
# `ListSessions` filtered by lifecycle state reads it and nothing else. A write that moved
# `lifecycleState` and left it behind therefore returns the row under the state it used to hold and
# misses it under the one it holds now — which is what the creation path did, because its
# `mark_orchestration_started` contract had no parameter through which an implementation could have
# refreshed the key.
#
# These are deterministic tests rather than one of the design's 44 numbered properties. The
# invariant is asserted over *every* row after *every* write the path performs rather than over the
# one transition that was wrong, so a lifecycle write added to this path later is caught here
# without this test being extended.


def index_key_disagreements(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """Every stored row whose index sort key does not agree with its own state and creation time.

    Recomputed through the same producer the write uses, so this asserts that the two derivations
    agree about one row rather than restating the format and asserting the restatement.
    """
    return [
        f"{row[SORT_KEY_ATTRIBUTE]} is recorded {row['lifecycleState']} but is indexed at "
        f"{row.get(TENANT_STATE_INDEX.sort_key)!r}, not "
        f"{tenant_state_sort_key(row['lifecycleState'], row['createdAt'])!r}"
        for row in rows
        if row.get(TENANT_STATE_INDEX.sort_key)
        != tenant_state_sort_key(row["lifecycleState"], row["createdAt"])
    ]


def a_pending_record() -> SessionRecord:
    """The Session row as the path's first write leaves it, read back out of the store.

    Built by the handler rather than assembled here, so the record these assertions derive a write
    from is the one a write is actually derived from in production.
    """
    store = FakeStore()
    create(operations(store=store))
    return SessionRecord.from_item(store.captured[0])


@dataclass
class IndexAuditingStore(FakeStore):
    """`FakeStore`, auditing the index sort key of every row after each write it performs.

    Auditing after the write rather than asserting inside it, so a failure names which call left the
    store disagreeing with itself instead of surfacing as an exception from the handler.
    """

    audits: list[tuple[str, list[str]]] = field(default_factory=list)

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        super().put_new_session(item)
        self.audits.append(
            ("put_new_session", index_key_disagreements(self.items.values()))
        )

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        super().mark_orchestration_started(start)
        self.audits.append(
            ("mark_orchestration_started", index_key_disagreements(self.items.values()))
        )


def test_every_creation_write_leaves_index_key_and_state_agreeing() -> None:
    """The general invariant, over both writes rather than over the transition that was wrong."""
    store = IndexAuditingStore()

    create(operations(store=store))

    # Both writes audited, so an audit list that silently stopped being appended to is a failure
    # rather than a vacuous pass.
    assert [call for call, _ in store.audits] == [
        "put_new_session",
        "mark_orchestration_started",
    ]
    assert store.audits == [("put_new_session", []), ("mark_orchestration_started", [])]


def test_the_row_is_indexed_under_orchestrating_and_not_under_pending() -> None:
    """The `ListSessions` consequence, stated as the two queries a state filter would run."""
    store = FakeStore()

    create(operations(store=store))

    row = store.only_row()
    assert row["lifecycleState"] == LifecycleState.ORCHESTRATING.value
    assert row[TENANT_STATE_INDEX.sort_key] == tenant_state_sort_key(
        LifecycleState.ORCHESTRATING.value, NOW_MS
    )
    # A query for one state is a `begins_with` on this sort key, so the prefix is the whole of what
    # the index can be asked. The row must not still answer to the state it has left.
    assert not row[TENANT_STATE_INDEX.sort_key].startswith(
        f"{LifecycleState.PENDING.value}#"
    )


def test_the_returned_record_and_the_stored_row_report_one_index_key() -> None:
    """The handler returns the row it wrote, so the two cannot describe different transitions."""
    store = FakeStore()

    created = operations(store=store).create(principal(), {})

    stored = SessionRecord.from_item(store.only_row())
    assert created.record.lifecycle_state is stored.lifecycle_state
    assert created.record.state_created_at == stored.state_created_at
    assert created.record.state_reason == stored.state_reason


def test_an_orchestration_start_carries_no_index_key_a_caller_could_supply() -> None:
    """Why the divergence is unrepresentable rather than merely unlikely.

    `state_created_at` is not a field of :class:`OrchestrationStart`, so there is no value of the
    type in which it disagrees with `state`: it is computed from `state` and `created_at` on demand.
    A future field of that name would reintroduce exactly the defect this replaced, so its absence
    is asserted rather than assumed.
    """
    assert "state_created_at" not in {
        attribute.name for attribute in fields(OrchestrationStart)
    }

    start = orchestration_start_for(
        a_pending_record(), execution_arn=f"{STATE_MACHINE}:one", at=NOW_MS
    )
    assert start.state is LifecycleState.ORCHESTRATING
    assert start.state_created_at == tenant_state_sort_key(
        LifecycleState.ORCHESTRATING.value, NOW_MS
    )
    # The key follows the state wherever the state goes, which is the whole of the guarantee.
    assert replace(start, state=LifecycleState.RUNNING).state_created_at == (
        tenant_state_sort_key(LifecycleState.RUNNING.value, NOW_MS)
    )


@pytest.mark.parametrize("state", [LifecycleState.TERMINATED, LifecycleState.FAILED])
def test_an_orchestration_start_refuses_a_terminal_state(state: LifecycleState) -> None:
    """This write deletes no Affinity_Key binding, so it must not be able to record a terminal state.

    R10.16's deletion accompanies every terminal write and belongs to
    `control_plane.lifecycle.TerminalSettlement`. Refusing the state here is what keeps this update
    from becoming a second, binding-forgetting way to reach one.
    """
    start = orchestration_start_for(
        a_pending_record(), execution_arn=f"{STATE_MACHINE}:one", at=NOW_MS
    )

    with pytest.raises(ValueError, match="terminal"):
        replace(start, state=state)


# --- No provisioning on the request path (R6.11) -------------------------------------------------


def test_no_sandbox_comes_into_existence_on_the_creation_path() -> None:
    """R6.11 from the provider's side: after a creation, the provider holds nothing.

    The real `local-firecracker` provider records every Sandbox it creates and reports them through
    `discover` and `consumed_capacity`, so this is a statement about Sandboxes rather than about
    which methods happened to be called.
    """
    provider = LocalFirecrackerProvider()
    create(operations(provider=provider))

    assert provider.discover({}) == []
    assert provider.consumed_capacity() == 0


def test_no_sandbox_exists_after_a_rejected_request_either() -> None:
    provider = LocalFirecrackerProvider()
    with pytest.raises(SessionAdmissionRejected):
        create(operations(provider=provider), {"idleSeconds": -1})

    assert provider.discover({}) == []


def test_no_module_outside_the_provider_seam_provisions() -> None:
    violations = rule.check_repository()
    assert not violations, (
        "modules outside the Compute_Provider seam initiate provisioning: "
        + ", ".join(violation.describe() for violation in violations)
    )


def test_the_rule_reports_a_handler_that_provisions() -> None:
    source = textwrap.dedent(
        """\
        def create_session(self, request):
            self.store.put_new_session(record.to_item())
            status = self.provider.provision(spec)
            return status
        """
    )
    violations = rule.check_source(source, "control_plane/api/creation.py")
    assert [violation.line for violation in violations] == [3]


def test_the_rule_reports_a_second_provisioning_implementation() -> None:
    violations = rule.check_source(
        "def provision(spec):\n    return None\n", "control_plane/api/creation.py"
    )
    assert len(violations) == 1
    assert "Compute_Provider seam" in violations[0].detail


@pytest.mark.parametrize(
    "source",
    [
        # Prose naming the call is documentation, not an act of provisioning.
        '"""The orchestration provisions; this module starts the execution."""\n',
        "# provision moved into the state machine.\nX = None\n",
        # Naming it in order to assert the seam's shape is not calling it.
        'names = ("capabilities", "limits", "provision")\n',
        # The sanctioned path.
        "arn = self.orchestration.start_execution(name=n, payload=p)\n",
    ],
)
def test_the_rule_leaves_prose_and_the_sanctioned_path_alone(source: str) -> None:
    assert rule.check_source(source, "control_plane/api/creation.py") == ()


def test_the_exemption_is_the_providers_the_orchestrator_and_the_exercising_tests() -> (
    None
):
    """The allow-list is enumerated and every entry exists, so an extra entry cannot hide in it."""
    assert rule.ALLOWED_MODULES == (
        rule.PROVIDER_MODULES | rule.ORCHESTRATOR_MODULES | rule.ENFORCEMENT_MODULES
    )
    for relative in rule.ALLOWED_MODULES:
        assert (rule.REPOSITORY_ROOT / relative).is_file(), relative


# --- The execution name, and idempotency under retry (R6.10) -------------------------------------


def test_the_execution_name_is_a_pure_function_of_the_session_identifier() -> None:
    assert execution_name_for(SESSION_ID) == execution_name_for(SESSION_ID)
    assert execution_name_for(SESSION_ID) == f"{EXECUTION_NAME_PREFIX}{SESSION_ID}"
    assert execution_name_for("other") != execution_name_for(SESSION_ID)


def test_the_derived_name_fits_what_step_functions_accepts() -> None:
    name = execution_name_for(new_session_id())
    assert len(name) <= MAX_EXECUTION_NAME_LENGTH
    assert not any(character.isspace() for character in name)
    assert not set(name) & set(FORBIDDEN_IN_NAME)


@pytest.mark.parametrize(
    "session_id", ["", "with space", "with/slash", "a" * MAX_EXECUTION_NAME_LENGTH]
)
def test_an_identifier_that_cannot_name_an_execution_is_refused(
    session_id: str,
) -> None:
    with pytest.raises(ExecutionNameError):
        execution_name_for(session_id)


def test_a_retried_creation_for_one_session_starts_one_execution() -> None:
    """R6.10's idempotency, against a starter behaving as Step Functions does.

    Two creations resolving to the same Session derive the same execution name, so the second start
    joins the execution already running rather than beginning a second one — and therefore rather
    than provisioning a second Sandbox for one Session. Distinct Sessions still get distinct
    executions, which is the other half of the claim.
    """
    starter = RecordingStarter()
    first = create(operations(starter=starter))
    second = create(operations(store=FakeStore(), starter=starter))

    assert starter.log == ["start_execution", "start_execution"]
    assert len(starter.executions) == 1
    assert first.payload["sessionId"] == second.payload["sessionId"]

    create(operations(store=FakeStore(), starter=starter, session_id="OTHERSESSION"))
    assert len(starter.executions) == 2


def test_generated_identifiers_are_distinct_and_crockford_base32() -> None:
    generated = {new_session_id() for _ in range(64)}
    assert len(generated) == 64
    for identifier in generated:
        assert len(identifier) == 26
        assert set(identifier) <= set(CROCKFORD)


# --- The response, and the wait seam task 6.6 fills ---------------------------------------------


def test_with_no_configured_wait_the_response_names_the_session_and_no_credential() -> (
    None
):
    result = create(operations())
    assert result.status == HTTPStatus.ACCEPTED
    # Absent rather than null: a client treats absence as "not yet published" and polls GetSession.
    assert result.payload == {
        "sessionId": SESSION_ID,
        "lifecycleState": LifecycleState.ORCHESTRATING.value,
    }


def test_a_wait_that_reports_a_published_credential_returns_it() -> None:
    result = create(operations(wait=PublishingWait(PUBLISHED)))
    assert result.status == HTTPStatus.CREATED
    assert result.payload["connection"] == PUBLISHED.to_map()


def test_a_wait_that_publishes_nothing_leaves_the_response_shape_alone() -> None:
    result = create(operations(wait=PublishingWait(None)))
    assert result.status == HTTPStatus.ACCEPTED
    assert "connection" not in result.payload


def test_the_wait_is_handed_the_row_this_handler_wrote() -> None:
    wait = CapturingWait()
    create(operations(wait=wait))

    assert len(wait.seen) == 1
    # A function of a Session row rather than of a request, which is what lets the get-or-create
    # loser reuse the same wait (R6.19).
    assert wait.seen[0].session_id == SESSION_ID
    assert wait.seen[0].lifecycle_state is LifecycleState.ORCHESTRATING
    assert wait.seen[0].orchestration_execution_arn == EXECUTION_ARN


def test_the_payload_omits_a_credential_that_was_not_published() -> None:
    record = SessionRecord.from_item(pending_item())
    assert creation_payload(record, None) == {
        "sessionId": SESSION_ID,
        "lifecycleState": LifecycleState.PENDING.value,
    }
    assert creation_payload(record, PUBLISHED)["connection"] == PUBLISHED.to_map()


# --- The declared port set ---------------------------------------------------------------------


def test_the_declared_port_set_is_deduplicated_and_sorted_on_the_row() -> None:
    store = FakeStore()
    create(operations(store=store), {EXPOSED_PORTS_FIELD: [9000, 8080, 8080]})
    assert SessionRecord.from_item(store.only_row()).exposed_ports == (8080, 9000)


@pytest.mark.parametrize("value", [None, []])
def test_an_absent_or_empty_port_set_is_an_empty_one(value: Any) -> None:
    store = FakeStore()
    body = {} if value is None else {EXPOSED_PORTS_FIELD: value}
    create(operations(store=store), body)
    assert SessionRecord.from_item(store.only_row()).exposed_ports == ()


@pytest.mark.parametrize(
    "declared",
    [
        [0],
        [65_536],
        [-1],
        ["8080"],
        [True],
        [None],
        [{"port": 8080}],
        "8080",
        {"port": 8080},
        8080,
    ],
)
def test_a_malformed_port_set_is_a_400_rather_than_a_500(declared: Any) -> None:
    """Rejected before the record's own range check, which would surface it as a `500`."""
    store = FakeStore()
    with pytest.raises(SessionAdmissionRejected):
        create(operations(store=store), {EXPOSED_PORTS_FIELD: declared})
    assert store.items == {}


# --- The settings a deployment supplies ---------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"memory_bytes": 0},
        {"execution_role_arn": ""},
        {"artifact_retention_days": -1},
        {"reap_shard_count": 0},
        # Paths declared while continuation is disabled: nothing would restore them.
        {"continuation_paths": ("/work",)},
    ],
)
def test_a_misconfigured_deployment_fails_where_it_is_built(
    overrides: Mapping[str, Any],
) -> None:
    base: dict[str, Any] = {
        "memory_bytes": SETTINGS.memory_bytes,
        "execution_role_arn": SETTINGS.execution_role_arn,
        "artifact_retention_days": SETTINGS.artifact_retention_days,
        "reap_shard_count": SETTINGS.reap_shard_count,
    }
    with pytest.raises(ValueError):
        CreationSettings(**{**base, **overrides})


def test_the_other_seven_operations_still_answer_501() -> None:
    """Only `CreateSession` is filled here; the rest keep naming the task that fills them."""
    operation = operations()
    for method_name in (
        "resolve_session",
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


def pending_item() -> Mapping[str, Any]:
    """One `PENDING` Session item, for the payload assertion that needs no handler."""
    return SessionRecord(
        pk=pk_for(principal()),
        session_id=SESSION_ID,
        tenant_id=TENANT,
        provider_name=LocalFirecrackerProvider.name,
        lifecycle_state=LifecycleState.PENDING,
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
    ).to_item()
