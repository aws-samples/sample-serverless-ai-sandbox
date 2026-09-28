# kiro-classification: public
"""The idle policy written onto a Sandbox, and how a suspended Session is reported.

Every assertion here is deterministic and no test draws inputs. Property 20 — Reaper convergence and
lifecycle reconciliation over drawn state sequences — and Property 38 — a binding outliving its
Session by no path — are phase 9's own tasks and own files; what this file establishes is the
behaviour those drawn sequences will be quantified over.

No test reads a clock. The one write here goes through
:class:`~control_plane.lifecycle.LifecycleReconciler` with an injected clock, and the idle policy
itself is deliberately timeless: enforcement of the durations belongs to the compute service and to
the Reaper, so there is nothing in this module for a wall clock to make flaky.

Four assertions carry more than their example:

- `test_a_non_positive_duration_cannot_be_represented` asserts R10.3 at the **constructor**. Every
  function that takes an `IdlePolicy` therefore takes one that has already passed the rule, which is
  why `applied_to` performs no duration check of its own.
- `test_applying_a_policy_asks_the_provider_one_question` counts provider calls. Applying an idle
  policy neither provisions nor ends anything, and the two methods it may never reach —
  `provision` and `issue_connection` — are the two a repository lint rule forbids this file from even
  defining, so the recording double below cannot accidentally admit them.
- `test_every_suspension_report_mirrors_onto_a_live_state` walks the whole admitted set rather than
  the one state a suspension settles into, which is what makes "a suspension cannot delete an
  Affinity_Key binding" a claim about the path rather than about one example.
- `test_the_cost_posture_is_total_over_every_lifecycle_state` walks the lifecycle enum. A state added
  later fails here rather than being silently attributed a cost nobody priced.

The store double and the Session row come from `tests/test_control_plane_lifecycle.py`, and the
creation harness from `tests/test_control_plane_creation.py`, so the condition expressions and the
execution input asserted here are the ones those files already hold to the design.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import TYPE_CHECKING, Any

import pytest

from control_plane.api.admission import (
    AUTO_RESUME_FIELD as ADMITTED_AUTO_RESUME_FIELD,
)
from control_plane.api.admission import (
    IDLE_SECONDS_FIELD as ADMITTED_IDLE_SECONDS_FIELD,
)
from control_plane.api.admission import (
    SUSPENDED_SECONDS_FIELD as ADMITTED_SUSPENDED_SECONDS_FIELD,
)
from control_plane.api.resolution import LOSER_BRANCHES, LoserBranch
from control_plane.idle_policy import (
    AUTO_RESUME_FIELD,
    EXECUTION_INPUT_LIMITS_FIELD,
    IDLE_SECONDS_FIELD,
    SUSPENDED_SECONDS_FIELD,
    AutoResumeUnsupported,
    IdlePolicy,
    IdlePolicyRejected,
    SuspensionUnsupported,
    idle_policy_for,
    idle_policy_from_execution_input,
)
from control_plane.lifecycle import PROVIDER_STATE_MIRROR
from control_plane.providers.base import (
    ProviderCapabilities,
    SandboxSpec,
    SandboxState,
    SuspendFidelity,
)
from control_plane.providers.fargate_task import FargateTaskProvider
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.records import LifecycleState
from control_plane.suspension import (
    LIFECYCLE_COST_POSTURE,
    SUSPENDED_COST_POSTURE,
    SUSPENSION_REPORT_STATES,
    NotASuspensionReport,
    cost_posture_for,
    record_suspension,
)
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    DeploymentProfile,
    reset_resolver_cache,
)
from tests.test_control_plane_creation import (
    TENANT,
    RecordingStarter,
    create,
    operations,
)
from tests.test_control_plane_lifecycle import (
    ADVANCE_SESSION,
    FakeLifecycleStore,
    reconciler,
    report,
    session_record,
)

if TYPE_CHECKING:
    from control_plane.lifecycle import Reconciliation
    from control_plane.providers.base import SandboxHandle, SandboxStatus
    from control_plane.state.records import SessionRecord

#: The policy every test below starts from. Three values that are nothing like each other, so a test
#: asserting one field cannot pass by reading another.
IDLE_SECONDS = 111
SUSPENDED_SECONDS = 222

#: The durations R10.3 refuses, and the values that are not durations at all. One list, because the
#: module admits one set — a positive integer number of seconds — and refuses everything else with
#: one exception.
INADMISSIBLE_DURATIONS: list[Any] = [0, -1, -300, True, False, 300.0, "300", None]


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """One Tenant, resolved from the deployment rather than from a request.

    Needed because one test drives the real `CreateSession` handler in order to revalidate the
    execution input that handler actually emits. Duplicated from the creation and resolution test
    modules on purpose while phase 9 is being written concurrently; folding the three into
    `tests/harness/` is a follow-up for one agent working alone.
    """
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


def policy(**overrides: Any) -> IdlePolicy:
    """The policy under test. `**overrides` is untyped so a test can offer a value the type forbids."""
    values: dict[str, Any] = {
        "idle_seconds_before_suspend": IDLE_SECONDS,
        "suspended_seconds_before_terminate": SUSPENDED_SECONDS,
        "auto_resume": True,
    }
    values.update(overrides)
    return IdlePolicy(**values)


def spec(**overrides: Any) -> SandboxSpec:
    """A complete Sandbox specification, whose idle fields are deliberately not the policy's.

    The seam requires all three, so a spec always arrives carrying something; these values are
    nothing a test expects, so an application that failed to replace them fails visibly.
    """
    base = SandboxSpec(
        session_id="ses-1",
        tenant_id="tnt-1",
        image_ref="sandbox-image:1",
        memory_bytes=512 * 1024 * 1024,
        vcpu_millis=2_000,
        max_duration_seconds=3_600,
        idle_seconds_before_suspend=9_999,
        suspended_seconds_before_terminate=8_888,
        auto_resume=False,
        exposed_ports=(8080,),
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        egress_attachment_ref="attachment-1",
        egress_endpoint="proxy.example.com",
        start_config=b"{}",
        start_config_ref=None,
        tags={"tenantId": "tnt-1", "sessionId": "ses-1"},
    )
    return replace(base, **overrides)


def execution_limits(**overrides: Any) -> dict[str, Any]:
    """An execution input carrying the admitted-limits map the `CreateSession` handler emits."""
    limits: dict[str, Any] = {
        "maxDurationSeconds": 3_600,
        IDLE_SECONDS_FIELD: IDLE_SECONDS,
        SUSPENDED_SECONDS_FIELD: SUSPENDED_SECONDS,
        AUTO_RESUME_FIELD: True,
        "memoryBytes": 512 * 1024 * 1024,
    }
    limits.update(overrides)
    return {"sessionId": "ses-1", EXECUTION_INPUT_LIMITS_FIELD: limits}


class RecordingProvider(LocalFirecrackerProvider):
    """A provider that records which of its lifecycle methods an application of a policy reached.

    `provision` and `issue_connection` are absent, and that is the point rather than an omission:
    `ci/lint_rules/orchestrated_provisioning.py` and `ci/lint_rules/sole_credential_issuer.py` reject
    a *definition* of either outside the Compute_Provider seam, so this double cannot record calls to
    the two methods applying an idle policy must never make. The four it does record are the ones
    that would end or move a Sandbox.
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def capabilities(self) -> ProviderCapabilities:
        self.calls.append("capabilities")
        return super().capabilities()

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        self.calls.append("describe")
        return super().describe(handle)

    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        self.calls.append("suspend")
        return super().suspend(handle)

    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        self.calls.append("resume")
        return super().resume(handle)

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        self.calls.append("terminate")
        return super().terminate(handle)


class NonSuspendingProvider(FargateTaskProvider):
    """A provider declaring it cannot suspend at all.

    No registered provider declares `SuspendFidelity.NONE`, so the capability is reached by narrowing
    a real provider's declaration rather than by inventing a whole double: everything else about the
    capability set stays the one `fargate-task` publishes.
    """

    def capabilities(self) -> ProviderCapabilities:
        return replace(super().capabilities(), suspend_fidelity=SuspendFidelity.NONE)


# --- the three values R10.2 names ------------------------------------------------------------------


def test_the_policy_is_the_three_values_the_requirement_names() -> None:
    """Idle duration before suspension, suspended duration before termination, automatic resume."""
    record = session_record(state=LifecycleState.RUNNING)

    read = idle_policy_for(record)

    assert read.idle_seconds_before_suspend == record.idle_seconds
    assert read.suspended_seconds_before_terminate == record.suspended_seconds
    assert read.auto_resume == record.auto_resume


def test_the_policy_travels_under_the_field_names_admission_validated() -> None:
    """One vocabulary from the request body to the execution input.

    The two spellings are deliberately independent — this module is on the provisioning path and does
    not import the API package to borrow three strings — so the thing that has to hold is that they
    agree, and this is where that is held.
    """
    assert IDLE_SECONDS_FIELD == ADMITTED_IDLE_SECONDS_FIELD
    assert SUSPENDED_SECONDS_FIELD == ADMITTED_SUSPENDED_SECONDS_FIELD
    assert AUTO_RESUME_FIELD == ADMITTED_AUTO_RESUME_FIELD


@pytest.mark.parametrize("offered", INADMISSIBLE_DURATIONS)
def test_a_non_positive_duration_cannot_be_represented(offered: Any) -> None:
    """R10.3, at the constructor, for both durations.

    There is no value of `IdlePolicy` that violates the rule, which is what lets every function
    downstream accept one without re-checking it.
    """
    with pytest.raises(IdlePolicyRejected) as idle:
        policy(idle_seconds_before_suspend=offered)
    assert idle.value.field_name == IDLE_SECONDS_FIELD

    with pytest.raises(IdlePolicyRejected) as suspended:
        policy(suspended_seconds_before_terminate=offered)
    assert suspended.value.field_name == SUSPENDED_SECONDS_FIELD


@pytest.mark.parametrize("offered", [1, 0, "true", None])
def test_an_auto_resume_decision_that_is_not_a_decision_is_refused(
    offered: Any,
) -> None:
    """R10.2 requires the policy to record *whether* automatic resume is enabled.

    `1` and `0` are the cases that matter: `bool` is a subclass of `int`, so an integer here would
    configure a lifecycle guarantee as truthiness.
    """
    with pytest.raises(IdlePolicyRejected) as rejected:
        policy(auto_resume=offered)
    assert rejected.value.field_name == AUTO_RESUME_FIELD


# --- application onto the Sandbox (R10.2) ----------------------------------------------------------


def test_the_policy_reaches_the_sandbox_at_provisioning() -> None:
    """The three fields on the spec handed to `provision` are this policy's, and are validated."""
    applied = policy().applied_to(spec(), provider=LocalFirecrackerProvider())

    assert applied.idle_seconds_before_suspend == IDLE_SECONDS
    assert applied.suspended_seconds_before_terminate == SUSPENDED_SECONDS
    assert applied.auto_resume is True


def test_applying_a_policy_changes_nothing_else_about_the_sandbox() -> None:
    """Every other field of the specification is the one the orchestrator assembled.

    Read off the dataclass's own field list rather than a list written here, so a field added to the
    seam is covered without an edit.
    """
    original = spec()

    result = policy().applied_to(original, provider=LocalFirecrackerProvider())
    replaced = {
        "idle_seconds_before_suspend",
        "suspended_seconds_before_terminate",
        "auto_resume",
    }

    for field in fields(SandboxSpec):
        if field.name in replaced:
            continue
        assert getattr(result, field.name) == getattr(original, field.name), field.name


def test_applying_a_policy_asks_the_provider_one_question() -> None:
    """`capabilities()` and nothing else: applying a policy starts, suspends and stops nothing.

    A suspended Session retains filesystem *and* memory state and may be resumed by a request
    arriving (R13.2, R10.5), so a policy application that ended anything would empty the Sandbox
    auto-resume promises is intact.
    """
    provider = RecordingProvider()

    policy().applied_to(spec(), provider=provider)

    assert provider.calls == ["capabilities"]


def test_a_provider_that_cannot_suspend_refuses_the_policy() -> None:
    """An idle duration before suspension describes an event that provider will never reach."""
    provider = NonSuspendingProvider()

    with pytest.raises(SuspensionUnsupported) as refused:
        policy().applied_to(spec(), provider=provider)

    assert refused.value.provider_name == provider.name
    assert refused.value.capability == "suspend"


def test_auto_resume_is_refused_by_a_provider_that_declares_it_cannot() -> None:
    """R10.5 promises a resume on an arriving request; `fargate-task` declares it has no endpoint.

    Refused before any Sandbox exists, which is where the seam says a missing capability surfaces.
    """
    provider = FargateTaskProvider()
    assert provider.capabilities().auto_resume_on_request is False

    with pytest.raises(AutoResumeUnsupported) as refused:
        policy(auto_resume=True).applied_to(spec(), provider=provider)

    assert refused.value.provider_name == provider.name


def test_that_same_provider_accepts_a_policy_that_does_not_enable_auto_resume() -> None:
    """The refusal is of the guarantee, not of the provider: a policy it can honour is applied."""
    applied = policy(auto_resume=False).applied_to(
        spec(), provider=FargateTaskProvider()
    )

    assert applied.auto_resume is False
    assert applied.idle_seconds_before_suspend == IDLE_SECONDS


# --- the orchestrator's revalidation (R10.3) -------------------------------------------------------


def test_the_orchestrator_revalidates_the_execution_input() -> None:
    """The happy path: three reads off the admitted-limits map, before any provision call."""
    assert idle_policy_from_execution_input(execution_limits()) == policy()


def test_the_execution_input_the_handler_emits_revalidates() -> None:
    """The tie between the two halves of the split, asserted against the real creation path.

    Validation stays in the handler so a `400` costs no execution; the orchestrator revalidates. That
    only holds if the payload the handler actually emits is one this module admits, so the payload
    here is captured from `CreateSession` rather than written by hand.
    """
    starter = RecordingStarter()
    requested = {
        IDLE_SECONDS_FIELD: IDLE_SECONDS,
        SUSPENDED_SECONDS_FIELD: SUSPENDED_SECONDS,
        AUTO_RESUME_FIELD: False,
    }

    create(operations(starter=starter), requested)

    (payload,) = starter.executions.values()
    assert idle_policy_from_execution_input(payload) == policy(auto_resume=False)


@pytest.mark.parametrize("field_name", [IDLE_SECONDS_FIELD, SUSPENDED_SECONDS_FIELD])
@pytest.mark.parametrize("offered", INADMISSIBLE_DURATIONS)
def test_an_out_of_range_execution_input_fails_the_execution(
    field_name: str, offered: Any
) -> None:
    """A policy no handler should have admitted fails the execution rather than provisioning.

    A `ValueError`, so the task Lambda raising it fails rather than retrying a value that cannot
    become valid.
    """
    with pytest.raises(IdlePolicyRejected) as rejected:
        idle_policy_from_execution_input(execution_limits(**{field_name: offered}))

    assert rejected.value.field_name == field_name


def test_an_execution_input_carrying_no_limits_map_fails_the_execution() -> None:
    """Refused as one failure rather than surfacing as a `TypeError` from a downstream read."""
    with pytest.raises(IdlePolicyRejected) as rejected:
        idle_policy_from_execution_input({"sessionId": "ses-1"})

    assert rejected.value.field_name == EXECUTION_INPUT_LIMITS_FIELD


def test_an_execution_input_that_records_no_auto_resume_decision_fails() -> None:
    """Absent is not "off": the decision is declared configuration, so defaulting it here would
    invent one."""
    limits = execution_limits()
    del limits[EXECUTION_INPUT_LIMITS_FIELD][AUTO_RESUME_FIELD]

    with pytest.raises(IdlePolicyRejected) as rejected:
        idle_policy_from_execution_input(limits)

    assert rejected.value.field_name == AUTO_RESUME_FIELD


# --- suspended-state reporting (R10.4) -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Suspended:
    """One recorded suspension: the store it was written to, the row, and the outcome."""

    store: FakeLifecycleStore
    record: SessionRecord
    outcome: Reconciliation


def suspend_from(state: LifecycleState) -> Suspended:
    """Seat a Session in `state`, then record a provider-reported suspension against it."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=state))
    outcome = record_suspension(
        reconciler(store), record, report(SandboxState.SUSPENDED)
    )
    return Suspended(store=store, record=record, outcome=outcome)


def test_a_suspended_sandbox_is_reported_suspended() -> None:
    """R10.4's first clause: the state an operator and every response read is `SUSPENDED`."""
    suspension = suspend_from(LifecycleState.RUNNING)

    assert suspension.outcome.state is LifecycleState.SUSPENDED
    assert (
        suspension.store.row(suspension.record).lifecycle_state
        is LifecycleState.SUSPENDED
    )


def test_a_suspension_is_one_live_write_and_the_binding_survives() -> None:
    """`/suspend` ends nothing, so the reconnect handle a suspended Session exists for stays.

    One `advance-session` step: the live write, with no binding deletion beside it. A settlement
    would have deleted the binding of the Session a caller is most likely about to reconnect to.
    """
    suspension = suspend_from(LifecycleState.RUNNING)

    assert suspension.store.steps == [(ADVANCE_SESSION,)]
    assert suspension.outcome.binding_deleted is False
    assert suspension.store.holds_binding(suspension.record)


def test_every_suspension_report_mirrors_onto_a_live_state() -> None:
    """The structural half: no suspension report can produce a write that deletes a binding.

    Asserted over the whole admitted set rather than the one state a suspension settles into, and
    also asserted at import in `control_plane/suspension.py` so a change to the mirror fails the
    build rather than this test.
    """
    for reported in SUSPENSION_REPORT_STATES:
        assert not PROVIDER_STATE_MIRROR[reported].is_terminal, reported


def test_the_admitted_reports_are_the_suspension_and_the_state_it_settles_into() -> (
    None
):
    assert SUSPENSION_REPORT_STATES == {
        SandboxState.SUSPENDING,
        SandboxState.SUSPENDED,
    }


#: Every provider report the suspension path refuses, in the enum's own definition order so the
#: parametrisation is deterministic without a sort.
NON_SUSPENSION_REPORTS = [
    state for state in SandboxState if state not in SUSPENSION_REPORT_STATES
]


@pytest.mark.parametrize("reported", NON_SUSPENSION_REPORTS)
def test_a_report_that_is_not_a_suspension_is_refused(reported: SandboxState) -> None:
    """Every other report reaches the general reconciler, so this path stays the one it documents."""
    store = FakeLifecycleStore()
    record = store.seat(session_record(state=LifecycleState.RUNNING))

    with pytest.raises(NotASuspensionReport):
        record_suspension(reconciler(store), record, report(reported))

    assert store.steps == []


def test_a_suspension_reported_after_termination_is_absorbed() -> None:
    """A Reaper that terminated the Session mid-poll is the ordinary way this happens (R10.7)."""
    suspension = suspend_from(LifecycleState.TERMINATED)

    assert suspension.outcome.state is LifecycleState.TERMINATED
    assert suspension.outcome.binding_deleted is False


# --- what a suspended Session costs (R10.4) --------------------------------------------------------


def test_the_cost_posture_is_total_over_every_lifecycle_state() -> None:
    """No default branch, so a state added later is priced deliberately or fails the build."""
    assert set(LIFECYCLE_COST_POSTURE) == set(LifecycleState)


def test_a_suspended_session_is_charged_for_snapshot_storage_and_not_compute() -> None:
    """R10.4's second clause, which is the whole of the near-zero-idle-cost objective."""
    posture = cost_posture_for(LifecycleState.SUSPENDED)

    assert posture == SUSPENDED_COST_POSTURE
    assert posture.snapshot_storage_billed is True
    assert posture.compute_billed is False


def test_suspended_is_the_only_state_charged_for_a_snapshot() -> None:
    """Every other state either holds a scheduled MicroVM or holds nothing at all."""
    charged = {
        state
        for state, posture in LIFECYCLE_COST_POSTURE.items()
        if posture.snapshot_storage_billed
    }

    assert charged == {LifecycleState.SUSPENDED}


def test_a_suspension_in_flight_is_still_charged_for_compute() -> None:
    """`SUSPENDING` is mid-flush: the MicroVM is still running and there is no snapshot yet."""
    posture = cost_posture_for(LifecycleState.SUSPENDING)

    assert posture.compute_billed is True
    assert posture.snapshot_storage_billed is False


# --- the auto-resume path stays the provider's (R6.20, R10.5) --------------------------------------


def test_resolving_a_suspended_session_returns_a_credential_and_issues_no_resume() -> (
    None
):
    """R6.20, restated from this side: nothing here adds a resume to the reconnect path.

    The first request the caller delivers to the endpoint is what resumes the Sandbox, so a
    resolution mints a credential and leaves the Session suspended. Asserted against the branch table
    itself so a change to it fails here as well as in the resolution suite.
    """
    assert LOSER_BRANCHES[LifecycleState.SUSPENDED] is LoserBranch.RETURN_CREDENTIAL
