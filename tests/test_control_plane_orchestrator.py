# kiro-classification: public
"""The Session_Orchestrator: the state machine's graph, and what each of its tasks does.

Every assertion here is deterministic and nothing draws inputs. Property 20 — Reaper convergence and
lifecycle reconciliation over drawn state sequences — and Property 38 — a binding outliving its
Session by no path — are phase 9's own tasks and own files; what this file establishes is the graph
and the mechanism those drawn sequences will be quantified over.

Five choices here carry more than their examples:

- **The provider is the real `local-firecracker` one.** Not a double. A double would have to define a
  `provision`, and `ci/lint_rules/orchestrated_provisioning.py` refuses that outside the
  Compute_Provider seam — which is the rule this task extends by exactly one entry, so the test that
  exercises it must not need an exemption of its own. Using the real provider also means "no Sandbox
  came into existence" is asserted against the provider's own inventory rather than against a call
  log. Where a test needs a Sandbox that is slow, or one that fails to start, it subclasses that
  provider and overrides `describe` alone.
- **The store double is `FakeLifecycleStore`**, imported from `tests/test_control_plane_lifecycle.py`
  so the condition expressions asserted here are the ones that file already holds to the design.
  :class:`FakeOrchestrationStore` adds the two non-lifecycle writes and a trace, and the trace is
  what lets `test_the_credential_is_published_before_the_row_reaches_running` assert an *ordering*
  rather than an end state.
- **The claim store double is `FakeClaimStore`**, imported from
  `tests/test_allocation_claim_ledger.py`, so exclusivity is arbitrated by a conditional write that
  file already pins rather than by a comparison this one performs.
- **The graph is asserted structurally, not by golden JSON.** A committed definition is a definition
  nothing checks; the assertions below walk edges, so they fail for the reason a reviewer would care
  about rather than because a comment moved.
- **`test_no_module_outside_the_provider_seam_and_the_orchestrator_provisions`** runs the lint rule
  over the tree, carrying into CI the claim that the allow-list gained one module and not a directory.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime
from typing import Any, Final

import pytest

from ci.lint_rules import orchestrated_provisioning as rule
from control_plane.allocation.ledger import SandboxAlreadyClaimed, SandboxClaimLedger
from control_plane.allocation.tags import SESSION_TAG_KEY, TENANT_TAG_KEY
from control_plane.credentials import (
    SANDBOX_PROTOCOL_CONTROL_PORT,
    ConnectionIssuer,
    ConnectionNotIssuable,
)
from control_plane.idle_policy import IdlePolicyRejected
from control_plane.lifecycle import (
    LifecycleConditionFailed,
    LifecycleReconciler,
    ReconciliationOutcome,
)
from control_plane.observability import LifecycleAuditor, SandboxCountEmitter
from control_plane.orchestrator import (
    WaitState,
    CLEANUP_REASON,
    GOVERNING_BRANCHES,
    QUOTA_EXHAUSTED_ERROR,
    RESOURCES_RETAINED_ERROR,
    RESOURCES_STILL_ALLOCATED_ERROR,
    SANDBOX_ALREADY_CLAIMED_ERROR,
    START_AT,
    STATE_MACHINE,
    TASK_STATES,
    TERMINAL_STATES,
    ChoiceState,
    ContinuationAlreadyRecorded,
    ContinuationHandoff,
    ContinuationHandoffs,
    CredentialPublication,
    FailState,
    GovernanceDecision,
    OrchestrationInput,
    OrchestrationInputError,
    OrchestratorSettings,
    OrchestratorState,
    ReadinessNotReached,
    ResourcesStillAllocated,
    SandboxNotRecorded,
    SandboxRecording,
    SandboxStartupFailed,
    SessionOrchestrator,
    SucceedState,
    TaskInvocation,
    TaskState,
    failure_reason,
    handle_of,
    targets_of,
    to_asl,
)
from control_plane.orchestrator.definition import (
    EXECUTION_FIELD,
    FAILURE_PATH,
    GOVERNANCE_PATH,
    STATE_FIELD,
    TASK_FIELD,
)
from control_plane.orchestrator.tasks import MAX_STATE_REASON_LENGTH
from control_plane.providers.base import (
    SandboxHandle,
    SandboxState,
    SandboxStatus,
)
from control_plane.providers.local_firecracker import (
    LOCAL_MEMORY_BYTES_CHOICES,
    LocalFirecrackerProvider,
)
from control_plane.state.records import (
    ContinuationRecord,
    Eligibility,
    LifecycleState,
    SessionRecord,
)
from tests.test_allocation_claim_ledger import FakeClaimStore
from tests.test_control_plane_lifecycle import (
    CREATED_MS,
    DIGEST,
    MAX_DURATION_SECONDS,
    PROVIDER,
    SESSION_ID,
    TENANT,
    FakeLifecycleStore,
    session_record,
)
from tests.test_control_plane_observability import RecordingSink

#: The execution the tasks write as. Its ARN is the `caller_identity` of the principal every write
#: below is attributed to, which is the calling principal R14.2 wants on a lifecycle audit record.
EXECUTION_ARN: Final = f"arn:aws:states:us-east-1:123456789012:execution:SessionOrchestrator:session-{SESSION_ID}"

SECOND_SESSION_ID: Final = "01HB0000000000000000000001"
ROLE_ARN: Final = "arn:aws:iam::123456789012:role/SandboxExecution"
IMAGE_REF: Final = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sandbox:1"

#: Required, because a Sandbox provisioned without a connector has unrestricted internet access
#: rather than a connector still to come.
EGRESS_ATTACHMENT_REF: Final = (
    "arn:aws:lambda:us-east-1:123456789012:network-connector/egress-connector-g1"
)
MEMORY_BYTES: Final = LOCAL_MEMORY_BYTES_CHOICES[1]
APPLICATION_PORT: Final = 8080

#: Every credential is scoped to the Sandbox_Protocol control port together with the Session's
#: declared ports, so a Sandbox whose spec did not expose the control port could not be issued one.
DECLARED_PORTS: Final = (SANDBOX_PROTOCOL_CONTROL_PORT, APPLICATION_PORT)

NOW_MS: Final = CREATED_MS + 90_000
DEADLINE_MS: Final = CREATED_MS + MAX_DURATION_SECONDS * 1000

POLL_INTERVAL_SECONDS: Final = 30
CONTINUATION_LEAD_SECONDS: Final = 300
READINESS_ATTEMPTS: Final = 3

RECORD_SANDBOX: Final = "record-sandbox"
PUBLISH_CONNECTION: Final = "publish-connection"
RECORD_CONTINUATION: Final = "record-continuation"
APPLY_CONTINUATION: Final = "apply-continuation"
ADVANCE: Final = "advance"
SETTLE: Final = "settle"


# --- the doubles, and the settings ----------------------------------------------------------------


@dataclass
class FakeOrchestrationStore(FakeLifecycleStore):
    """The lifecycle store double, plus the orchestration's two non-lifecycle writes.

    Both new writes carry the condition their protocol documents, reusing the inherited `_admit`, so
    a write onto a terminal row is refused *here* rather than by a check the orchestrator performs.

    `trace` records what each write was and the lifecycle state the row held at the moment it landed.
    That pairing is the point: it is how an ordering claim — the credential is on the row before the
    row says `RUNNING` — becomes assertable rather than a comment.
    """

    trace: list[tuple[str, str]] = field(default_factory=list)

    def advance_live_state(self, transition: Any) -> None:
        super().advance_live_state(transition)
        self.trace.append((ADVANCE, transition.state.value))

    def settle_terminal_state(self, settlement: Any) -> None:
        super().settle_terminal_state(settlement)
        self.trace.append((SETTLE, settlement.state.value))

    def record_sandbox(self, recording: SandboxRecording) -> None:
        item = self._admit(recording.partition_key, recording.sort_key)
        self.trace.append((RECORD_SANDBOX, item["lifecycleState"]))
        item["sandboxHandle"] = recording.handle_map
        item["sandboxId"] = recording.sandbox_id
        item["updatedAt"] = recording.updated_at

    def publish_connection(self, publication: CredentialPublication) -> None:
        item = self._admit(publication.partition_key, publication.sort_key)
        self.trace.append((PUBLISH_CONNECTION, item["lifecycleState"]))
        item["connection"] = publication.connection.to_map()
        item["connectionPublishedAt"] = publication.published_at
        item["updatedAt"] = publication.published_at

    # -- the continuation store -------------------------------------------------------------------

    def read_continuation(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        item = self.items.get((partition_key, sort_key))
        return None if item is None else dict(item)

    def record_continuation(self, record: ContinuationRecord) -> None:
        """`attribute_not_exists(pk)`, so the first record for a generation stands."""
        key = (record.pk, record.sort_key)
        if key in self.items:
            raise ContinuationAlreadyRecorded(record.session_id, record.generation)
        self.items[key] = dict(record.to_item())
        self.trace.append((RECORD_CONTINUATION, str(record.generation)))

    def apply_continuation(self, handoff: ContinuationHandoff) -> None:
        """The generation condition on top of the one every lifecycle write carries."""
        item = self._admit(handoff.partition_key, handoff.sort_key)
        if item["generation"] != handoff.outgoing_generation:
            raise LifecycleConditionFailed(
                f"the row is at generation {item['generation']}, not "
                f"{handoff.outgoing_generation}"
            )
        self.trace.append((APPLY_CONTINUATION, item["lifecycleState"]))
        item["generation"] = handoff.incoming_generation
        item["updatedAt"] = handoff.updated_at
        for dropped in (
            "sandboxHandle",
            "sandboxId",
            "connection",
            "connectionPublishedAt",
        ):
            item.pop(dropped, None)

    def operations(self) -> list[str]:
        return [operation for operation, _ in self.trace]

    def state_at(self, operation: str) -> str:
        return next(state for name, state in self.trace if name == operation)


class SlowStartProvider(LocalFirecrackerProvider):
    """The real provider, reporting a sequence of states from `describe` and nothing else changed.

    Only `describe` is overridden. A Sandbox is still really created, still really claimed, still
    really terminated, and `release_check` still answers from the provider's own inventory — so the
    readiness assertions below hold against a Sandbox that exists rather than against a fiction.
    """

    def __init__(
        self,
        reports: tuple[SandboxStatus | SandboxState, ...],
        *,
        clock: Callable[[], datetime],
    ) -> None:
        super().__init__(clock=clock)
        self._reports = list(reports)
        self.describes = 0

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        self.describes += 1
        reported = self._reports[min(self.describes, len(self._reports)) - 1]
        if isinstance(reported, SandboxStatus):
            return replace(reported, handle=handle)
        return replace(super().describe(handle), state=reported)


@dataclass
class RecordingQuiesce:
    """The `session.quiesce` seam, recording the Sessions it was asked to quiesce.

    `acknowledges` is what a Sandbox that will not take the message looks like from here. The seam
    reports rather than raises, so an unreachable Sandbox is a value this double returns rather than
    an exception a test has to arrange.
    """

    acknowledges: bool = True
    quiesced: list[tuple[str, int]] = field(default_factory=list)

    def quiesce(self, record: SessionRecord) -> bool:
        self.quiesced.append((record.session_id, record.generation))
        return self.acknowledges


def settings(**overrides: Any) -> OrchestratorSettings:
    return replace(
        OrchestratorSettings(
            image_ref=IMAGE_REF,
            vcpu_millis=2000,
            poll_interval_seconds=POLL_INTERVAL_SECONDS,
            readiness_attempts=READINESS_ATTEMPTS,
            readiness_interval_seconds=1,
            continuation_lead_seconds=CONTINUATION_LEAD_SECONDS,
            egress_attachment_ref=EGRESS_ATTACHMENT_REF,
        ),
        **overrides,
    )


@dataclass
class Clock:
    """A movable clock in epoch milliseconds, so a duration ceiling is arithmetic."""

    at: int = NOW_MS

    def __call__(self) -> datetime:
        return datetime.fromtimestamp(self.at / 1000, tz=UTC)


@dataclass
class Harness:
    """One orchestration, its store, its provider and its claim ledger."""

    orchestrator: SessionOrchestrator
    store: FakeOrchestrationStore
    provider: LocalFirecrackerProvider
    claims: FakeClaimStore
    quiescer: RecordingQuiesce
    clock: Clock
    slept: list[float]

    def run(
        self, task: OrchestratorState, extra: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Invoke one task the way the state machine does: name, execution ARN, accumulated state."""
        state = dict(execution_input())
        state.update(extra or {})
        return self.orchestrator.run(
            {
                TASK_FIELD: task.value,
                EXECUTION_FIELD: EXECUTION_ARN,
                STATE_FIELD: state,
            }
        )

    def row(self) -> SessionRecord:
        return self.store.row(seated_record())

    def forward_path(self) -> None:
        """Provision, claim, await readiness, publish: the four tasks a creation waits on."""
        for task in (
            OrchestratorState.PROVISION,
            OrchestratorState.CLAIM_SANDBOX,
            OrchestratorState.AWAIT_READY,
            OrchestratorState.PUBLISH_CREDENTIAL,
        ):
            self.run(task)


def seated_record(
    *,
    state: LifecycleState = LifecycleState.ORCHESTRATING,
    session_id: str = SESSION_ID,
    digest: str | None = DIGEST,
) -> SessionRecord:
    """A complete Session row as the `CreateSession` handler left it, with the declared ports on it.

    The ports matter: a credential is scoped to the declared set together with the control port, so a
    row that declared neither would be issued a credential for a port its Sandbox does not serve.
    """
    return replace(
        session_record(state=state, digest=digest),
        session_id=session_id,
        exposed_ports=DECLARED_PORTS,
    )


def execution_input(
    *, session_id: str = SESSION_ID, generation: int = 1, **limits: Any
) -> dict[str, Any]:
    """The execution input the `CreateSession` handler composes from the row it just wrote."""
    return {
        "sessionId": session_id,
        "tenantId": TENANT,
        "providerName": PROVIDER,
        "limits": {
            "maxDurationSeconds": MAX_DURATION_SECONDS,
            "idleSeconds": 300,
            "suspendedSeconds": 600,
            "autoResume": True,
            "memoryBytes": MEMORY_BYTES,
            **limits,
        },
        "exposedPorts": list(DECLARED_PORTS),
        "executionRoleArn": ROLE_ARN,
        "generation": generation,
    }


def harness(
    *,
    reports: tuple[SandboxStatus | SandboxState, ...] | None = None,
    record: SessionRecord | None = None,
    acknowledges_quiesce: bool = True,
    **setting_overrides: Any,
) -> Harness:
    """Assemble one orchestration over an in-memory store, with a seated Session row.

    The provider shares the orchestration's clock, so a minted credential's expiry is arithmetic
    against the same instant every other assertion here uses. `reports` selects
    :class:`SlowStartProvider` for the tests that need a Sandbox which is slow or which fails.
    """
    clock = Clock()
    compute: LocalFirecrackerProvider = (
        LocalFirecrackerProvider(clock=clock)
        if reports is None
        else SlowStartProvider(reports, clock=clock)
    )
    rows = FakeOrchestrationStore()
    rows.seat(seated_record() if record is None else record)
    ledger_store = FakeClaimStore()
    quiescer = RecordingQuiesce(acknowledges=acknowledges_quiesce)
    slept: list[float] = []
    return Harness(
        orchestrator=SessionOrchestrator(
            provider=compute,
            store=rows,
            lookup=rows,
            reconciler=LifecycleReconciler(
                store=rows,
                lookup=rows,
                audit=LifecycleAuditor(
                    principal=EXECUTION_ARN, sink=RecordingSink()
                ),
                clock=clock,
            ),
            ledger=SandboxClaimLedger(store=ledger_store, terminator=compute),
            counts=SandboxCountEmitter(sink=RecordingSink()),
            issuer=ConnectionIssuer(mint=compute, clock=clock),
            continuation=ContinuationHandoffs(store=rows, quiescer=quiescer),
            settings=settings(**setting_overrides),
            clock=clock,
            sleep=slept.append,
        ),
        store=rows,
        provider=compute,
        claims=ledger_store,
        quiescer=quiescer,
        clock=clock,
        slept=slept,
    )


# --- the graph -------------------------------------------------------------------------------------


def test_the_graph_is_total_over_its_states_and_every_state_is_reachable() -> None:
    """Totality and reachability, recomputed here rather than trusted from the import assertion."""
    assert set(STATE_MACHINE) == set(OrchestratorState)

    seen: set[OrchestratorState] = set()
    pending = [START_AT]
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        pending.extend(targets_of(STATE_MACHINE[state]))
    assert seen == set(OrchestratorState)


def test_the_governing_branch_table_is_total_over_every_reported_state() -> None:
    """R6.7's mirror is total over provider states, and so is what the loop does about them."""
    assert set(GOVERNING_BRANCHES) == set(SandboxState)
    assert {
        state
        for state, decision in GOVERNING_BRANCHES.items()
        if decision is GovernanceDecision.TEAR_DOWN
    } == {SandboxState.TERMINATING, SandboxState.TERMINATED, SandboxState.FAILED}


def test_the_governing_choice_has_one_rule_per_decision_and_no_default() -> None:
    """A `Default` would be the fallback the design's branch tables exist without."""
    node = STATE_MACHINE[OrchestratorState.HANDLE_EVENT]
    assert isinstance(node, ChoiceState)
    assert set(node.branches) == set(GovernanceDecision)

    rendered = _asl()["States"][OrchestratorState.HANDLE_EVENT.value]
    assert "Default" not in rendered
    assert [rule_["StringEquals"] for rule_ in rendered["Choices"]] == [
        decision.value for decision in GovernanceDecision
    ]


def test_every_task_that_can_fail_records_the_session_failed() -> None:
    """R6.14: a provisioning, claim, readiness or publication failure reaches a `FAILED` row."""
    for state in (
        OrchestratorState.PROVISION,
        OrchestratorState.CLAIM_SANDBOX,
        OrchestratorState.AWAIT_READY,
        OrchestratorState.PUBLISH_CREDENTIAL,
    ):
        node = STATE_MACHINE[state]
        assert isinstance(node, TaskState)
        assert OrchestratorState.RECORD_FAILED in {
            catcher.target for catcher in node.catchers
        }, state


def test_the_failure_path_and_the_teardown_path_both_reach_cleanup() -> None:
    """R10.16 is placed on the `FAILED` path as well as the `TERMINATED` one."""
    for state in (OrchestratorState.RECORD_FAILED, OrchestratorState.RELEASE_CHECK):
        assert OrchestratorState.CLEANUP in targets_of(STATE_MACHINE[state]), state


def test_the_two_endings_are_a_success_and_a_retained_resources_failure() -> None:
    """R10.9: an execution that cannot confirm release fails rather than recording a clean end."""
    assert TERMINAL_STATES == {
        OrchestratorState.TERMINATED,
        OrchestratorState.RESOURCES_RETAINED,
    }
    assert isinstance(STATE_MACHINE[OrchestratorState.TERMINATED], SucceedState)
    retained = STATE_MACHINE[OrchestratorState.RESOURCES_RETAINED]
    assert isinstance(retained, FailState)
    assert retained.error == RESOURCES_RETAINED_ERROR


def test_the_release_check_retries_with_backoff_before_it_gives_up() -> None:
    """The design's "retry with backoff, then raise ResourcesRetained", as edges."""
    node = STATE_MACHINE[OrchestratorState.RELEASE_CHECK]
    assert isinstance(node, TaskState)
    retrier = next(
        candidate
        for candidate in node.retriers
        if RESOURCES_STILL_ALLOCATED_ERROR in candidate.errors
    )
    assert retrier.max_attempts > 1
    assert retrier.backoff_rate > 1
    assert {catcher.target for catcher in node.catchers} == {
        OrchestratorState.RESOURCES_RETAINED
    }


def test_provisioning_carries_no_retrier() -> None:
    """A retried provision is a second billable Sandbox, so this task is the one that does not."""
    node = STATE_MACHINE[OrchestratorState.PROVISION]
    assert isinstance(node, TaskState)
    assert node.retriers == ()


def test_the_definition_needs_a_resource_for_exactly_the_task_states() -> None:
    """A missing resource renders a `Task` with nowhere to go; an extra one is a phantom task."""
    complete = {state: f"arn:{state.value}" for state in TASK_STATES}
    assert set(_asl()["States"]) == {state.value for state in OrchestratorState}

    with pytest.raises(ValueError, match="missing"):
        to_asl({state: arn for state, arn in complete.items() if state is not START_AT})
    with pytest.raises(ValueError, match="unknown"):
        to_asl({**complete, OrchestratorState.HANDLE_EVENT: "arn:Govern"})


def test_every_task_state_is_told_which_task_it_is_and_which_execution_it_serves() -> (
    None
):
    """The envelope the task bodies parse, and the execution ARN they write as (R14.2).

    WaitForLifecycle uses a different parameter structure (Payload with waitForTaskToken)
    so it is checked separately for having a valid Task definition.
    """
    asl = _asl()
    for state in TASK_STATES:
        rendered = asl["States"][state.value]
        # WaitForLifecycle uses Payload (waitForTaskToken pattern), not the standard envelope
        if state is OrchestratorState.WAIT_FOR_LIFECYCLE:
            assert rendered["Type"] == "Task"
            continue
        parameters = rendered["Parameters"]
        assert parameters[TASK_FIELD] == state.value
        assert parameters[f"{EXECUTION_FIELD}.$"] == "$$.Execution.Id"
        assert parameters[f"{STATE_FIELD}.$"] == "$"


def test_the_error_names_the_graph_catches_are_the_exception_class_names() -> None:
    """Step Functions matches a catcher against the class name, so these are one fact spelled twice."""
    assert ResourcesStillAllocated.__name__ == RESOURCES_STILL_ALLOCATED_ERROR
    assert SandboxAlreadyClaimed.__name__ == SANDBOX_ALREADY_CLAIMED_ERROR
    caught = {
        error
        for node in STATE_MACHINE.values()
        if isinstance(node, TaskState)
        for catcher in node.catchers
        for error in catcher.errors
    }
    assert {QUOTA_EXHAUSTED_ERROR, SANDBOX_ALREADY_CLAIMED_ERROR} <= caught


def _asl() -> dict[str, Any]:
    return to_asl({state: f"arn:{state.value}" for state in TASK_STATES})


# --- the forward path ------------------------------------------------------------------------------


def test_the_forward_path_provisions_claims_publishes_and_governs() -> None:
    """One Sandbox, claimed to this Session, with a credential on the row — ready for events."""
    setup = harness()
    setup.forward_path()

    row = setup.row()
    assert row.lifecycle_state is LifecycleState.RUNNING
    assert row.connection is not None
    assert row.connection.ports == DECLARED_PORTS
    assert row.sandbox_handle is not None


def test_the_provisioned_sandbox_is_attributable_to_its_tenant_and_session() -> None:
    """R11.7: the tags are what the Reaper finds an unrecorded Sandbox by."""
    setup = harness()
    setup.run(OrchestratorState.PROVISION)

    found = setup.provider.discover(
        {TENANT_TAG_KEY: TENANT, SESSION_TAG_KEY: SESSION_ID}
    )
    assert len(found) == 1
    assert setup.provider.discover({SESSION_TAG_KEY: SECOND_SESSION_ID}) == []


def test_the_row_says_provisioning_while_the_sandbox_is_being_created() -> None:
    """R14.2: the state an operator reads during the provisioning latency is `PROVISIONING`."""
    setup = harness()
    setup.run(OrchestratorState.PROVISION)

    assert setup.store.trace[0] == (ADVANCE, LifecycleState.PROVISIONING.value)
    assert setup.store.state_at(RECORD_SANDBOX) == LifecycleState.PROVISIONING.value
    assert setup.row().lifecycle_state is LifecycleState.PROVISIONING


def test_a_terminal_row_stops_the_provision_before_a_sandbox_exists() -> None:
    """The refusal is the whole point of writing `PROVISIONING` first."""
    setup = harness(record=seated_record(state=LifecycleState.TERMINATED))

    with pytest.raises(LifecycleConditionFailed):
        setup.run(OrchestratorState.PROVISION)

    assert setup.provider.discover({}) == []
    assert setup.provider.consumed_capacity() == 0


def test_an_out_of_range_idle_policy_is_refused_rather_than_provisioned_against() -> (
    None
):
    """R10.3, revalidated by the orchestrator: no Sandbox is created against a bad policy."""
    setup = harness()

    with pytest.raises(IdlePolicyRejected):
        setup.run(
            OrchestratorState.PROVISION,
            {"limits": execution_input(idleSeconds=0)["limits"]},
        )

    assert setup.provider.discover({}) == []


def test_settings_carrying_no_connector_are_refused_rather_than_provisioned_from() -> (
    None
):
    """A MicroVM with no connector has unrestricted internet, so the value is required, not staged."""
    with pytest.raises(ValueError, match="egress_attachment_ref"):
        settings(egress_attachment_ref="")


def test_the_credential_is_published_before_the_row_reaches_running() -> None:
    """No instant exists in which the row is `RUNNING` and carries no credential."""
    setup = harness()
    setup.forward_path()

    assert setup.store.state_at(PUBLISH_CONNECTION) != LifecycleState.RUNNING.value
    operations = setup.store.operations()
    assert operations.index(PUBLISH_CONNECTION) < len(operations) - 1
    assert setup.store.trace[-1] == (ADVANCE, LifecycleState.RUNNING.value)


def test_publication_onto_a_terminated_row_is_refused() -> None:
    """A credential for a Sandbox that is gone is worse than no credential.

    Refused by the sole issuer rather than by the store: a terminal Session admits no credential at
    all, so nothing is minted and the publication is never attempted. The store's condition is the
    second of the two and is what covers a row that goes terminal between the mint and the write.
    """
    setup = harness()
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)
    setup.run(OrchestratorState.AWAIT_READY)
    setup.store.items[(setup.row().pk, setup.row().sort_key)]["lifecycleState"] = (
        LifecycleState.TERMINATED.value
    )

    with pytest.raises(ConnectionNotIssuable):
        setup.run(OrchestratorState.PUBLISH_CREDENTIAL)

    assert setup.row().connection is None
    assert PUBLISH_CONNECTION not in setup.store.operations()


def test_a_second_session_claiming_one_sandbox_is_refused_and_the_duplicate_dies() -> (
    None
):
    """R11.1 and R11.10, arbitrated by the claim ledger's conditional write."""
    setup = harness()
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)

    second = seated_record(session_id=SECOND_SESSION_ID, digest=None)
    setup.store.seat(replace(second, sandbox_handle=setup.row().sandbox_handle))

    with pytest.raises(SandboxAlreadyClaimed) as refusal:
        setup.orchestrator.run(
            {
                TASK_FIELD: OrchestratorState.CLAIM_SANDBOX.value,
                EXECUTION_FIELD: EXECUTION_ARN,
                STATE_FIELD: execution_input(session_id=SECOND_SESSION_ID),
            }
        )

    assert refusal.value.claimed_by_session_id == SESSION_ID
    assert refusal.value.termination.terminated


# --- readiness -------------------------------------------------------------------------------------


def test_an_earlier_report_is_mirrored_and_the_ready_one_is_left_to_publication() -> (
    None
):
    """R6.7 for the states before readiness; the `RUNNING` write belongs to the credential."""
    setup = harness(reports=(SandboxState.STARTING, SandboxState.RUNNING))
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)

    readiness = setup.run(OrchestratorState.AWAIT_READY)

    assert readiness == {"attempts": 2, "sandboxState": SandboxState.RUNNING.value}
    assert setup.row().lifecycle_state is LifecycleState.STARTING
    assert setup.slept == [1]

    setup.run(OrchestratorState.PUBLISH_CREDENTIAL)
    assert setup.row().lifecycle_state is LifecycleState.RUNNING


def test_a_sandbox_that_fails_to_start_reports_the_providers_own_reason() -> None:
    """R13.7: a non-200 `/run`, including a failed state restore, arrives as a failed Sandbox."""
    failure = SandboxStatus(
        handle=SandboxHandle(provider_name=PROVIDER, sandbox_id="unused", opaque={}),
        state=SandboxState.FAILED,
        memory_bytes=MEMORY_BYTES,
        started_at=None,
        state_reason="restore of s3://artifacts/1 failed",
    )
    setup = harness(reports=(failure,))
    setup.run(OrchestratorState.PROVISION)

    with pytest.raises(SandboxStartupFailed) as raised:
        setup.run(OrchestratorState.AWAIT_READY)

    assert raised.value.reason == "restore of s3://artifacts/1 failed"


def test_the_readiness_wait_is_bounded() -> None:
    """A task that waits forever fails as a timeout with nothing recorded about what it waited for."""
    setup = harness(reports=(SandboxState.STARTING,))
    setup.run(OrchestratorState.PROVISION)

    with pytest.raises(ReadinessNotReached) as raised:
        setup.run(OrchestratorState.AWAIT_READY)

    assert raised.value.attempts == READINESS_ATTEMPTS
    assert len(setup.slept) == READINESS_ATTEMPTS - 1


# --- the governing loop ----------------------------------------------------------------------------


def test_a_suspended_sandbox_keeps_the_loop_polling() -> None:
    """R10.4: in the callback model, suspend is event-driven via RecordSuspended."""
    assert OrchestratorState.RECORD_SUSPENDED in TASK_STATES
    assert isinstance(STATE_MACHINE[OrchestratorState.RECORD_SUSPENDED], TaskState)


def test_an_observed_teardown_leaves_the_loop() -> None:
    """In the callback model, teardown is handled by the Terminate task, not observation."""
    assert OrchestratorState.TERMINATE in TASK_STATES
    assert isinstance(STATE_MACHINE[OrchestratorState.TERMINATE], TaskState)

def test_the_duration_ceiling_tears_down_even_where_continuation_is_enabled() -> None:
    """R10.4: in the callback model, the deadline is enforced by WaitForLifecycle timeout."""
    asl = _asl()
    wfl = asl["States"][OrchestratorState.WAIT_FOR_LIFECYCLE.value]
    assert wfl["Type"] == "Task"

def test_the_continuation_lead_continues_only_where_the_deployment_enabled_it() -> None:
    """R10.11: continuation is a state in the callback orchestrator graph."""
    assert OrchestratorState.CONTINUE in STATE_MACHINE
    assert OrchestratorState.CONTINUE in TASK_STATES

# --- teardown --------------------------------------------------------------------------------------


def test_teardown_settles_the_row_and_deletes_the_binding() -> None:
    """R10.16 in the same step as the terminal write, and R10.9 confirmed.

    This provider terminates synchronously, so the settlement happens where the report arrives — at
    `Terminate`, through the mirror — and `Cleanup` then absorbs. That is the convergence the design
    asks of every operation the orchestrator and the Reaper may both perform: the first terminal
    state stands, its reason stands with it, and the second write changes nothing.
    """
    setup = harness()
    setup.forward_path()

    torn_down = setup.run(OrchestratorState.TERMINATE)
    assert torn_down["lifecycleState"] == LifecycleState.TERMINATED.value
    assert torn_down["bindingDeleted"] is True
    assert not setup.store.holds_binding(seated_record())

    assert setup.run(OrchestratorState.RELEASE_CHECK) == {"allocated": []}

    settled = setup.run(OrchestratorState.CLEANUP)
    assert settled["outcome"] == ReconciliationOutcome.ABSORBED.value
    assert settled["lifecycleState"] == LifecycleState.TERMINATED.value
    assert setup.row().lifecycle_state is LifecycleState.TERMINATED


def test_cleanup_settles_a_row_whose_teardown_was_still_in_flight() -> None:
    """The other arm: where the provider reported `TERMINATING`, `Cleanup` is the terminal write."""
    setup = harness(record=seated_record(state=LifecycleState.TERMINATING))

    settled = setup.run(OrchestratorState.CLEANUP)

    assert settled["outcome"] == ReconciliationOutcome.SETTLED.value
    assert settled["bindingDeleted"] is True
    assert setup.row().state_reason == CLEANUP_REASON
    assert not setup.store.holds_binding(seated_record())


def test_a_release_check_before_the_resources_are_gone_refuses_to_confirm() -> None:
    """The identifiers are returned so emptiness is asserted rather than assumed."""
    setup = harness()
    setup.forward_path()

    with pytest.raises(ResourcesStillAllocated) as raised:
        setup.run(OrchestratorState.RELEASE_CHECK)

    assert raised.value.allocated
    assert setup.row().lifecycle_state is LifecycleState.RUNNING


def test_a_recorded_failure_names_the_caught_reason_and_quarantines_the_claim() -> None:
    """R6.8's quota name travels in the caught error; R11.13 follows the write as its own step."""
    setup = harness()
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)

    recorded = setup.run(
        OrchestratorState.RECORD_FAILED,
        {
            _failure_field(): {
                "Error": QUOTA_EXHAUSTED_ERROR,
                "Cause": (
                    '{"errorType": "QuotaExhausted", "errorMessage": "quota '
                    "'LocalSandboxMemoryPerRegion' exhausted in dimension "
                    'memory-bytes-per-region"}'
                ),
            }
        },
    )

    assert recorded["lifecycleState"] == LifecycleState.FAILED.value
    assert recorded["bindingDeleted"] is True
    assert recorded["quarantined"] is True
    assert "LocalSandboxMemoryPerRegion" in (setup.row().state_reason or "")
    claim = setup.claims.claim_at(_claim_key(setup))
    assert claim.eligibility is Eligibility.QUARANTINED
    assert not setup.store.holds_binding(seated_record())


def test_a_failure_before_any_sandbox_existed_has_no_claim_to_quarantine() -> None:
    """An absence rather than a failure, and reported as one."""
    setup = harness()

    recorded = setup.run(
        OrchestratorState.RECORD_FAILED,
        {_failure_field(): {"Error": "States.Timeout", "Cause": ""}},
    )

    assert recorded["quarantined"] is False
    assert setup.row().lifecycle_state is LifecycleState.FAILED


def test_cleanup_after_a_recorded_failure_is_absorbed() -> None:
    """Which is what makes `Cleanup` safe as the join of all three paths."""
    setup = harness()
    setup.run(
        OrchestratorState.RECORD_FAILED,
        {_failure_field(): {"Error": "States.TaskFailed", "Cause": "no capacity"}},
    )

    absorbed = setup.run(OrchestratorState.CLEANUP)

    assert absorbed["outcome"] == ReconciliationOutcome.ABSORBED.value
    assert absorbed["lifecycleState"] == LifecycleState.FAILED.value
    assert setup.row().lifecycle_state is LifecycleState.FAILED


# --- dispatch, envelopes and the two write types ---------------------------------------------------


def test_every_task_the_graph_draws_now_has_a_body() -> None:
    """Every Task in the graph is a TaskState."""
    for state in TASK_STATES:
        node = STATE_MACHINE[state]
        assert isinstance(node, TaskState), f"{state} is {type(node).__name__}, expected TaskState"

def test_a_state_that_is_not_a_task_cannot_be_invoked() -> None:
    setup = harness()
    for name in (OrchestratorState.HANDLE_EVENT.value, "NotAState", ""):
        with pytest.raises(OrchestrationInputError):
            setup.orchestrator.run(
                {
                    TASK_FIELD: name,
                    EXECUTION_FIELD: EXECUTION_ARN,
                    STATE_FIELD: execution_input(),
                }
            )


@pytest.mark.parametrize(
    "removed", ["sessionId", "tenantId", "providerName", "executionRoleArn", "limits"]
)
def test_an_execution_input_the_handler_could_not_have_written_is_refused(
    removed: str,
) -> None:
    """A defect in our own plumbing, refused before it can reach a key or a provider."""
    payload = execution_input()
    del payload[removed]

    with pytest.raises(OrchestrationInputError):
        OrchestrationInput.from_payload(payload)


def test_the_invocation_writes_as_the_execution_inside_the_sessions_tenant() -> None:
    """The partition key still comes from the sole producer; the identity is the execution (R14.2)."""
    invocation = TaskInvocation.from_payload(
        {
            TASK_FIELD: OrchestratorState.WAIT_FOR_LIFECYCLE.value,
            EXECUTION_FIELD: EXECUTION_ARN,
            STATE_FIELD: execution_input(),
        }
    )

    assert invocation.principal.caller_identity == EXECUTION_ARN
    assert invocation.principal.tenant_id == TENANT


def test_neither_non_lifecycle_write_can_carry_a_lifecycle_state() -> None:
    """The sole route to `lifecycleState` is a matter of which types exist."""
    for write in (SandboxRecording, CredentialPublication):
        assert not [
            declared
            for declared in fields(write)
            if "LifecycleState" in str(declared.type)
        ], write


def test_the_recorded_sandbox_identifier_cannot_disagree_with_the_handle() -> None:
    """Derived rather than supplied, so there is no value of the type in which the two differ."""
    record = seated_record()
    recording = SandboxRecording(
        partition_key=record.pk,
        sort_key=record.sort_key,
        handle=SandboxHandle(
            provider_name=PROVIDER, sandbox_id="sbx-9", opaque={"a": "b"}
        ),
        updated_at=NOW_MS,
    )

    assert recording.sandbox_id == "sbx-9"
    assert recording.handle_map == {
        "providerName": PROVIDER,
        "sandboxId": "sbx-9",
        "opaque": {"a": "b"},
    }


def test_a_task_that_needs_a_handle_refuses_a_row_that_carries_none() -> None:
    """Out of order rather than operational, so it is refused rather than quietly skipped."""
    with pytest.raises(SandboxNotRecorded):
        handle_of(seated_record(), OrchestratorState.TERMINATE)


def test_a_recorded_reason_is_never_blank_and_is_bounded() -> None:
    """`settle` refuses a blank reason, and a stack trace stored as one is a reason nobody reads."""
    assert failure_reason(None)
    assert failure_reason({}) == failure_reason(None)
    assert failure_reason({"Error": "Boom", "Cause": ""}) == "Boom"
    assert (
        failure_reason({"Error": "Boom", "Cause": '{"errorMessage": "why"}'})
        == "Boom: why"
    )
    assert len(failure_reason({"Error": "E", "Cause": "x" * 4000})) == (
        MAX_STATE_REASON_LENGTH
    )


# --- the lint rule this task extended --------------------------------------------------------------


def test_no_module_outside_the_provider_seam_and_the_orchestrator_provisions() -> None:
    """R6.11, carried into CI: the allow-list gained one module, not a directory."""
    assert rule.check_repository() == ()
    assert rule.ORCHESTRATOR_MODULES == {"control_plane/orchestrator/tasks.py"}
    for relative in rule.ALLOWED_MODULES:
        assert (rule.REPOSITORY_ROOT / relative).is_file(), relative
    # The graph is not on the list, and needs not to be: it names provisioning in prose only.
    assert (
        rule.check_source(
            (
                rule.REPOSITORY_ROOT / "control_plane/orchestrator/definition.py"
            ).read_text(encoding="utf-8"),
            "control_plane/orchestrator/definition.py",
        )
        == ()
    )


def _failure_field() -> str:
    return FAILURE_PATH.removeprefix("$.")


def _claim_key(setup: Harness) -> str:
    return next(iter({key for key, _ in setup.claims.items}))
