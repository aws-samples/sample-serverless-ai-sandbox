# kiro-classification: public
"""The task bodies the Session_Orchestrator's state machine invokes, one method per `Task` state.

:mod:`control_plane.orchestrator.definition` is the graph; this module is what each of its `Task`
states does. The two are kept apart for one reason: the graph is data that anything may import, and
**this** is the module that provisions. R6.11 puts provisioning inside a started execution and
nowhere else, so `ci/lint_rules/orchestrated_provisioning.py` refuses a `provision` call outside the
Compute_Provider seam unless the module is named in its `ORCHESTRATOR_MODULES` allow-list. This file
is the first entry that list has ever had, and it is the one reviewed line the rule's docstring
anticipated. Keeping the definition out of it means the graph, which most callers want, imports no
provisioning code at all.

## Every lifecycle state is written by :mod:`control_plane.lifecycle` and by nothing here

That is the load-bearing claim of this module, and it is structural rather than remembered:

- A **provider report** is mirrored by :meth:`~control_plane.lifecycle.LifecycleReconciler.reconcile`,
  which picks the write type from the mirrored state's terminality. `RUNNING ↔ SUSPENDED` observed on
  the poll, and `TERMINATING`/`TERMINATED` returned by `provider.terminate`, all arrive this way.
- A **terminal state this component decided on** — provisioning refused, a `/run` hook that did not
  return 200, a claim collision, teardown completed — goes through
  :meth:`~control_plane.lifecycle.LifecycleReconciler.settle`, which cannot omit the Affinity_Key
  binding deletion of R10.16.
- The **two live transitions no provider reports** — `ORCHESTRATING → PROVISIONING` before a Sandbox
  exists, and `STARTING → RUNNING` as the credential is published — are built by
  :func:`~control_plane.lifecycle.live_transition_for` and committed through the reconciler's own
  store. :class:`~control_plane.lifecycle.LiveTransition` refuses a terminal state at construction,
  so this route cannot write one however it is called.

The store is reached *through* the reconciler rather than injected beside it, so a deployment cannot
end up with live transitions going to one store and settlements to another.

The two writes this module makes that are **not** lifecycle writes — recording the Sandbox handle and
publishing the credential — are expressed as :class:`SandboxRecording` and
:class:`CredentialPublication`, neither of which has a field that could carry a lifecycle state. The
sole route to `lifecycleState` is therefore a matter of which types exist, not of which call sites
behaved.

## Ordering, and the two windows it chooses

**`PROVISIONING` is written before `provider.provision` is called.** A row that said `ORCHESTRATING`
while a Sandbox was being created would misreport the Session for the whole of the provisioning
latency, which R14.2 asks an operator to be able to read. And if that write is refused because the
row went terminal in the meantime, the refusal *stops the provision*, which is the outcome worth
having: no Sandbox is created for a Session that has already been terminated.

**The credential is published before the row reaches `RUNNING`.** The design makes publication part of
the `STARTING → RUNNING` transition, so `AwaitReady` deliberately does not mirror the report that ends
its wait — it hands readiness to :meth:`SessionOrchestrator.publish_credential`, which writes the
credential and then the state. No instant therefore exists in which the row is `RUNNING` and carries
no credential, which is the instant a creating handler waiting on this Session would misread.

The reverse window is accepted: a row in `STARTING` that already carries a credential. That is
harmless and is what the design calls the readiness signal — the `/run` hook has returned 200, so a
caller who connects on it is served.

## What this module does not do

**It does not decide the idle policy, and it does not validate one.** R10.2's three values reach a
Sandbox through :meth:`~control_plane.idle_policy.IdlePolicy.applied_to`, which is task 9.2's, and
:meth:`SessionOrchestrator.provision_sandbox` calls it rather than assigning the three fields itself.
That module owns the revalidation the design requires of the orchestrator, and owns the capability
refusals that must happen before a Sandbox exists. Nothing about the policy is spelled twice here.

**It does not quarantine inside the terminal write.** R11.13's quarantine accompanies a `FAILED` write
and is a separate step, for the reason `control_plane/lifecycle.py` gives: the claim item sits outside
every Tenant partition and is written with a different role, so the two cannot share a transaction —
and a claim-ledger failure must not block the write that stops a billable Sandbox. So
:meth:`SessionOrchestrator.record_failed` settles first and quarantines second.

**It does not decide where the counts go.** `EmitCounts` builds a
:class:`~control_plane.observability.SandboxCountReport` for the Session this execution governs and
hands it to a :class:`~control_plane.observability.SandboxCountMetrics` seam (R14.4). The dispatch
table is total over the graph's `Task` states, asserted at import, so a task added to the graph
without a body here fails the build.

**It does not shape the continuation handoff, only order it.** The types, the derivations and the two
seams a duration-ceiling handoff needs are :mod:`control_plane.orchestrator.continuation`; what lives
here is :meth:`SessionOrchestrator.continue_session`, because the ordering of the handoff turns on
`provider.terminate` and this is the module that may reach a Compute_Provider. That method is also the
one teardown in this file that deliberately does **not** hand the provider's report to the
reconciler: a handoff terminates a Sandbox without terminating its Session, and settling it would
delete the Affinity_Key binding R6.24 requires to survive.

**It does not sweep.** The Reaper is task 9.3 and shares no state source with this module.
"""

from __future__ import annotations

import os

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from control_plane.allocation.ledger import (
    SandboxAlreadyClaimed,
    SandboxClaimLedger,
    SandboxNotClaimed,
)
from control_plane.allocation.tags import sandbox_tags
from control_plane.api.lookup import SessionLookup
from control_plane.credentials import ConnectionIssuer
from control_plane.idle_policy import (
    idle_policy_for,
    idle_policy_from_execution_input,
)
from control_plane.lifecycle import (
    LifecycleConditionFailed,
    LifecycleReconciler,
    Reconciliation,
    SessionRecordAbsent,
)
from control_plane.observability import (
    RUNNING_METRIC_NAME,
    SUSPENDED_METRIC_NAME,
    SandboxCountMetrics,
    SandboxCountReport,
)
from control_plane.orchestrator.continuation import (
    CONTINUATION_REASON,
    ContinuationAlreadyRecorded,
    ContinuationHandoff,
    ContinuationHandoffs,
    ContinuationNotEnabled,
    continuation_artifact_reference,
    continuation_record_for,
    handoff_for,
)
from control_plane.orchestrator.definition import (
    EXECUTION_FIELD,
    FAILURE_PATH,
    GOVERNANCE_PATH,
    GOVERNING_BRANCHES,
    POLL_INTERVAL_FIELD,
    QUOTA_EXHAUSTED_ERROR,
    RESOURCES_STILL_ALLOCATED_ERROR,
    SANDBOX_ALREADY_CLAIMED_ERROR,
    STATE_FIELD,
    TASK_FIELD,
    TASK_STATES,
    GovernanceDecision,
    OrchestratorState,
)
from control_plane.providers.base import (
    ComputeProvider,
    QuotaExhausted,
    SandboxHandle,
    SandboxSpec,
    SandboxState,
)
from control_plane.state.keys import ItemShapeError, session_sort_key
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = [
    "CLEANUP_REASON",
    "MAX_STATE_REASON_LENGTH",
    "PROVISIONING_REASON",
    "PUBLICATION_REASON",
    "CredentialPublication",
    "OrchestrationInput",
    "OrchestrationInputError",
    "OrchestrationRowStore",
    "OrchestratorSettings",
    "ReadinessNotReached",
    "ResourcesStillAllocated",
    "SandboxNotRecorded",
    "SandboxRecording",
    "SandboxStartupFailed",
    "SessionOrchestrator",
    "TaskInvocation",
    "failure_reason",
    "handle_of",
]

_MILLISECONDS_PER_SECOND: Final = 1000

#: The field of the execution state a caught error lands in, derived from the path the state
#: machine's catchers write to so the two cannot drift apart.
_FAILURE_FIELD: Final = FAILURE_PATH.removeprefix("$.")

#: The field `Observe` writes its result to, derived from the graph's own result path for the same
#: reason. `EmitCounts` reads the state out of it rather than reading the row again (R14.4).
_GOVERNANCE_FIELD: Final = GOVERNANCE_PATH.removeprefix("$.")

#: What an `EmitCounts` result says when the invocation carried no observation to count.
_NO_OBSERVATION_RECORDED: Final = "the invocation carried no observation to count"

#: The `stateReason` of `ORCHESTRATING → PROVISIONING`. A constant rather than a literal at the call
#: site, for the reason :data:`~control_plane.api.creation.ORCHESTRATION_STARTED_REASON` is one.
PROVISIONING_REASON: Final = "the orchestration is provisioning the Sandbox"

#: The `stateReason` of `STARTING → RUNNING`, which is the transition publication is part of (R6.12).
PUBLICATION_REASON: Final = (
    "the /run hook returned 200 and the connection credential is published"
)

#: The `stateReason` a completed teardown records.
CLEANUP_REASON: Final = "terminated by the Session_Orchestrator; release_check reported nothing allocated (R10.9)"

#: Bound on a recorded reason. A caught error's cause can carry a whole stack trace, and a
#: `stateReason` an operator cannot read is barely better than no reason at all (R14.2).
MAX_STATE_REASON_LENGTH: Final = 1024

_TRUNCATION_MARKER: Final = "…"

_NO_ERROR_RECORDED: Final = "the orchestration failed without recording an error"


class OrchestrationInputError(ValueError):
    """The execution input is not one the Control_Plane handler could have written.

    A defect rather than an operational condition: the `CreateSession` handler composes this payload
    from a Session row it has just written, so a missing or malformed field means something other
    than that handler started this execution. A `ValueError`, so a task Lambda raising it fails the
    execution rather than being retried against a value that cannot become valid.
    """


class SandboxNotRecorded(Exception):
    """A task that needs the Sandbox handle ran against a row that carries none.

    Reached only out of order — every task that needs a handle sits after `Provision` recorded one —
    so it is a defect, and it is refused rather than absorbed. A task that quietly did nothing here
    would leave a billable Sandbox with nothing left in the execution to stop it.
    """

    def __init__(self, session_id: str, task: OrchestratorState) -> None:
        super().__init__(
            f"{task.value} needs the Sandbox handle of Session {session_id!r}, and the row "
            f"carries none"
        )
        self.session_id = session_id
        self.task = task


class SandboxStartupFailed(Exception):
    """The Sandbox reached a terminal state before it began serving (R6.14, R13.7).

    The `/run` hook returning non-200 arrives here, including the failed state restore R13.7 names,
    because a provider reports it as a Sandbox that failed and carries the reason. The reason travels
    on this exception so that the `FAILED` row records what the backend said rather than a sentence
    this module composed.
    """

    def __init__(self, session_id: str, state: SandboxState, reason: str) -> None:
        super().__init__(
            f"Session {session_id!r} reached {state.value} before it served a request: {reason}"
        )
        self.session_id = session_id
        self.state = state
        self.reason = reason


class ReadinessNotReached(Exception):
    """The readiness wait exhausted its attempts with the Sandbox still starting.

    Bounded rather than open-ended: a `Task` state that polls forever holds a Lambda invocation open
    until its own timeout kills it, which produces a `States.Timeout` with nothing recorded about
    what was being waited for.
    """

    def __init__(self, session_id: str, state: SandboxState, attempts: int) -> None:
        super().__init__(
            f"Session {session_id!r} was still {state.value} after {attempts} readiness "
            f"attempts, so the /run hook had not returned 200"
        )
        self.session_id = session_id
        self.state = state
        self.attempts = attempts


class ResourcesStillAllocated(Exception):
    """`release_check` reported resources still allocated to a terminated Sandbox (R10.9).

    The class name is the error name the state machine retries and then fails on, which is asserted
    at the bottom of this module.
    """

    def __init__(self, session_id: str, allocated: tuple[str, ...]) -> None:
        super().__init__(
            f"Session {session_id!r} still holds {list(allocated)} after termination, so no "
            f"confirmation of release is possible yet"
        )
        self.session_id = session_id
        self.allocated = allocated


@dataclass(frozen=True, slots=True)
class OrchestrationInput:
    """The execution input, parsed once.

    Every field comes from the `CreateSession` handler's execution input, which it composes from the
    Session row. There is no credential and no partition key on it: the key is derived through
    :func:`~control_plane.tenancy.pk_for`, the sole producer, and the credential is minted by this
    orchestration after `/run` has returned 200 (R6.12).

    The three idle-policy values are deliberately **absent** from this type. They are read from the
    same payload by :func:`~control_plane.idle_policy.idle_policy_from_execution_input`, which
    revalidates them (R10.3) and is the only thing that may turn them into a policy, so a second
    reading of them here would be a second chance to get R10.2 wrong.
    """

    session_id: str
    tenant_id: str
    provider_name: str
    execution_role_arn: str
    max_duration_seconds: int
    memory_bytes: int
    exposed_ports: tuple[int, ...]
    generation: int
    persistence: bool = False
    affinity_key: str = ""  # shared workspace key — same key = same workspace
    principal_id: str = ""  # authenticated caller for workspace scoping

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> OrchestrationInput:
        """Parse the execution input.

        Raises:
            OrchestrationInputError: a field is absent or is not of the shape the handler writes.
        """
        limits = payload.get("limits")
        if not isinstance(limits, Mapping):
            raise OrchestrationInputError("limits is missing or not a map")
        return cls(
            session_id=_text(payload, "sessionId"),
            tenant_id=_text(payload, "tenantId"),
            provider_name=_text(payload, "providerName"),
            execution_role_arn=_text(payload, "executionRoleArn"),
            max_duration_seconds=_whole(limits, "maxDurationSeconds"),
            memory_bytes=_whole(limits, "memoryBytes"),
            exposed_ports=_ports(payload.get("exposedPorts")),
            generation=_whole(payload, "generation"),
            persistence=bool(payload.get("persistence", False)),
            affinity_key=str(payload.get("affinityKey", "")),
            principal_id=str(payload.get("principalId", "")),
        )


@dataclass(frozen=True, slots=True)
class TaskInvocation:
    """One Lambda invocation of one `Task` state, as the state machine shapes it.

    The three fields are the envelope every `Task` state's `Parameters` block builds: which task, the
    execution ARN from the Step Functions context object, and the accumulated execution state.

    The execution ARN is why it is here. It becomes the `caller_identity` of the principal this
    orchestration writes as, so the partition key still comes from
    :func:`~control_plane.tenancy.pk_for` and the calling principal R14.2 wants on a lifecycle audit
    record is the execution that governs the Session rather than a service name.
    """

    task: OrchestratorState
    execution_id: str
    state: Mapping[str, Any]
    task_token: str = ""  # Step Functions .waitForTaskToken integration token

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> TaskInvocation:
        """Parse one invocation.

        Raises:
            OrchestrationInputError: the envelope is malformed, or names a state that is not a task.
        """
        name = _text(payload, TASK_FIELD)
        try:
            task = OrchestratorState(name)
        except ValueError:
            raise OrchestrationInputError(
                f"{name!r} is not an orchestrator state"
            ) from None
        if task not in TASK_STATES:
            raise OrchestrationInputError(f"{name!r} is not a Task state")
        state = payload.get(STATE_FIELD)
        if not isinstance(state, Mapping):
            raise OrchestrationInputError(f"{STATE_FIELD} is missing or not a map")
        return cls(task=task, execution_id=_text(payload, EXECUTION_FIELD), state=state, task_token=str(payload.get("taskToken", "")))

    @property
    def orchestration(self) -> OrchestrationInput:
        """The execution input carried by the accumulated state."""
        return OrchestrationInput.from_payload(self.state)

    @property
    def principal(self) -> AuthenticatedPrincipal:
        """The principal this orchestration writes as: the execution, in the Session's Tenant."""
        return AuthenticatedPrincipal(
            caller_identity=self.execution_id,
            tenant_id=self.orchestration.tenant_id,
        )

    @property
    def failure(self) -> object:
        """The caught error the state machine wrote to `$.failure`, if this task follows one."""
        return self.state.get(_FAILURE_FIELD)


@dataclass(frozen=True, slots=True)
class SandboxRecording:
    """The write that records which Sandbox belongs to this Session.

    **It carries no lifecycle state**, and that is the point: the row's state is moved by
    :mod:`control_plane.lifecycle` and by nothing else, so this write has no field through which one
    could travel.

    :attr:`sandbox_id` is a property of :attr:`handle` rather than a field of its own, so the flat
    attribute and the nested handle cannot name two different Sandboxes — the shape
    :attr:`~control_plane.api.creation.OrchestrationStart.state_created_at` established for a derived
    index key.
    """

    partition_key: str
    sort_key: str
    handle: SandboxHandle
    updated_at: int

    @property
    def sandbox_id(self) -> str:
        """The `sandboxId` attribute, derived so it cannot disagree with the handle."""
        return self.handle.sandbox_id

    @property
    def handle_map(self) -> dict[str, Any]:
        """The `sandboxHandle` attribute, in the shape the credential issuer reads back."""
        return {
            "providerName": self.handle.provider_name,
            "sandboxId": self.handle.sandbox_id,
            "opaque": dict(self.handle.opaque),
        }


@dataclass(frozen=True, slots=True)
class CredentialPublication:
    """The credential publication of R6.12, and nothing besides.

    Like :class:`SandboxRecording` it carries no lifecycle state. Publication and the
    `STARTING → RUNNING` transition are two writes in one task, in that order, and this type is what
    makes the first of them incapable of performing the second.
    """

    partition_key: str
    sort_key: str
    connection: ConnectionDescriptor
    published_at: int


class OrchestrationRowStore(Protocol):
    """The two non-lifecycle writes this orchestration performs on the Session row.

    A structural type, so the offline suite drives every task against an in-memory store keyed as
    DynamoDB is, with no deployed resource and no network. Each method's contract is stated as the
    condition expression it carries, in the posture
    :class:`~control_plane.lifecycle.SessionLifecycleStore` takes, because the conditions *are* the
    guarantees: an implementation that dropped one would still satisfy both signatures.

    Both writes touch one item in the Session's own Tenant partition, so the confinement R11.3
    requires applies without a second check, and both carry the same non-terminal condition every
    lifecycle write carries. A terminal row is a Session whose Sandbox is gone; recording a handle on
    one, or publishing a credential onto one, would advertise something that no longer exists.
    """

    def record_sandbox(self, recording: SandboxRecording) -> None:
        """`SET sandboxHandle = :handle, sandboxId = :id, updatedAt = :at`.

        `ConditionExpression: attribute_exists(pk) AND NOT lifecycleState IN (:terminated, :failed)`.

        Raises:
            LifecycleConditionFailed: the row is absent, or it is already terminal.
        """
        ...

    def publish_connection(self, publication: CredentialPublication) -> None:
        """`SET connection = :connection, connectionPublishedAt = :at, updatedAt = :at` (R6.12).

        `ConditionExpression: attribute_exists(pk) AND NOT lifecycleState IN (:terminated, :failed)`.

        Raises:
            LifecycleConditionFailed: the row is absent, or it is already terminal.
        """
        ...


@dataclass(frozen=True, slots=True)
class OrchestratorSettings:
    """The deployment-configured values the tasks read, none of them with a literal default.

    Every one is a CDK context value, in the same posture as
    :class:`~control_plane.api.creation.CreationSettings`: a default here would be a second source
    for a number the deployment owns.

    `continuation_lead_seconds` is how long before the duration ceiling the handoff begins. It is the
    one number the governing loop's `continue` decision turns on; everything else about the handoff is
    :mod:`control_plane.orchestrator.continuation`, and whether continuation happens at all is
    declared on the Session row rather than here.

    `egress_attachment_ref` is the Egress_Controller's network attachment, opaque and passed through
    to the provider without being parsed. It is required and has no default: a MicroVM provisioned
    without a connector has unrestricted internet access rather than an incomplete one, so an unset
    connector is an ungoverned Sandbox and not a deployment stage. The IaC_Package always supplies
    it, and `lambda-microvm` refuses a spec without it.
    """

    image_ref: str
    vcpu_millis: int
    poll_interval_seconds: int
    readiness_attempts: int
    readiness_interval_seconds: int
    continuation_lead_seconds: int
    egress_attachment_ref: str
    egress_endpoint: str = ""  # NLB proxy DNS — passed to runtime for https_proxy env
    # S3 Files persistent storage — set when the deployment has S3 Files configured
    s3files_filesystem_id: str = ""
    s3files_access_point_id: str = ""
    s3files_mount_target_ips: str = ""  # comma-separated IPs

    def __post_init__(self) -> None:
        if not self.image_ref:
            raise ValueError("image_ref must not be empty")
        if not self.egress_attachment_ref:
            raise ValueError("egress_attachment_ref must not be empty")
        for name in (
            "vcpu_millis",
            "poll_interval_seconds",
            "readiness_attempts",
            "readiness_interval_seconds",
            "continuation_lead_seconds",
        ):
            value = getattr(self, name)
            if value <= 0:
                raise ValueError(f"{name} must be positive: {value}")


def handle_of(record: SessionRecord, task: OrchestratorState) -> SandboxHandle:
    """Rebuild the provider handle recorded on the Session row.

    Every task after `Provision` reads the handle from the row rather than from the execution state,
    so the row is the single source of which Sandbox this Session owns and the two cannot disagree
    about it.

    The reading duplicates :mod:`control_plane.credentials`'s private one, which cannot be imported
    without widening the sole issuer's surface. **Consolidation candidate**: one reader on
    :class:`~control_plane.state.records.SessionRecord` would serve both.

    Raises:
        SandboxNotRecorded: the row carries no handle.
        ItemShapeError: it carries a malformed one, which is a defect rather than an absence.
    """
    stored = record.sandbox_handle
    if stored is None:
        raise SandboxNotRecorded(record.session_id, task)
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


def failure_reason(failure: object) -> str:
    """Compose the `stateReason` a caught error records (R6.8, R6.14, R14.2).

    The state machine's catchers write `{"Error": ..., "Cause": ...}` to `$.failure`, and a Lambda
    cause is a JSON document whose `errorMessage` is the exception's own message. That message is
    where the exhausted quota name R6.8 requires actually lives —
    :class:`~control_plane.providers.base.QuotaExhausted` names it — so the reason is read from the
    error rather than composed here, exactly as
    :func:`~control_plane.lifecycle.reason_for_report` prefers the provider's own words.

    Truncated to :data:`MAX_STATE_REASON_LENGTH`, because a stack trace stored as a reason is a
    reason nobody reads. Never blank, because
    :func:`~control_plane.lifecycle.settlement_for` refuses a transition that records no reason and
    an execution that failed must still be able to record that it did.
    """
    if not isinstance(failure, Mapping):
        return _NO_ERROR_RECORDED
    error = str(failure.get("Error") or "").strip()
    message = _cause_message(failure.get("Cause"))
    joined = f"{error}: {message}" if error and message else error or message
    if not joined:
        return _NO_ERROR_RECORDED
    if len(joined) > MAX_STATE_REASON_LENGTH:
        keep = MAX_STATE_REASON_LENGTH - len(_TRUNCATION_MARKER)
        return joined[:keep] + _TRUNCATION_MARKER
    return joined


def _cause_message(cause: object) -> str:
    """The human-readable half of a caught error's cause.

    A Lambda cause is a JSON document; anything else is passed through as it stands rather than
    discarded, because a cause this function does not recognise is still the only account of the
    failure that exists.
    """
    if not isinstance(cause, str) or not cause.strip():
        return ""
    try:
        decoded = json.loads(cause)
    except ValueError:
        return cause.strip()
    if isinstance(decoded, Mapping):
        message = decoded.get("errorMessage")
        if isinstance(message, str) and message.strip():
            return message.strip()
    return cause.strip()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _text(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise OrchestrationInputError(f"{name} is missing or not a non-empty string")
    return value


def _whole(payload: Mapping[str, Any], name: str) -> int:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise OrchestrationInputError(f"{name} is missing or not an integer")
    return value


def _ports(value: object) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise OrchestrationInputError("exposedPorts is not a list")
    for element in value:
        if isinstance(element, bool) or not isinstance(element, int):
            raise OrchestrationInputError("exposedPorts contains a non-port element")
    return tuple(sorted({int(element) for element in value}))


@dataclass(frozen=True, slots=True)
class SessionOrchestrator:
    """The bodies of the state machine's `Task` states, one method each.

    Every collaborator is injected and every one is a seam the offline suite satisfies in memory, so
    the whole orchestration runs with no deployed resource and no network. `sleep` is injected for the
    same reason the creation wait injects one: the readiness poll is a real wait in a deployment and
    no wait at all in a test.

    There is no `SessionLifecycleStore` field. Live transitions are committed through
    `reconciler.store`, so one store serves both them and the settlements.
    """

    provider: ComputeProvider
    store: OrchestrationRowStore
    lookup: SessionLookup
    reconciler: LifecycleReconciler
    ledger: SandboxClaimLedger
    issuer: ConnectionIssuer
    continuation: ContinuationHandoffs
    counts: SandboxCountMetrics
    settings: OrchestratorSettings
    clock: Callable[[], datetime] = _utc_now
    sleep: Callable[[float], None] = time.sleep

    # -- dispatch ---------------------------------------------------------------------------------

    def run(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Run the task this invocation names.

        One entry point for every `Task` state, so a deployment may back them with one Lambda
        function or with one per state and neither arrangement changes this module.

        Raises:
            OrchestrationInputError: the envelope is malformed or names a state that is not a task.
        """
        invocation = TaskInvocation.from_payload(payload)
        return _TASK_BODIES[invocation.task](self, invocation)

    # -- provisioning -----------------------------------------------------------------------------

    def provision_sandbox(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Provision the Sandbox for this Session, inside the started execution (R6.11).

        `PROVISIONING` is written first, so the row reports what is happening for the whole of the
        provisioning latency and so a Session that has already gone terminal is never provisioned:
        the write's own condition refuses, and the refusal propagates rather than being absorbed.

        The idle policy is revalidated and applied by :mod:`control_plane.idle_policy` (R10.2, R10.3),
        which also refuses a provider that cannot deliver it — before a Sandbox exists.

        The reported state is deliberately **not** mirrored onto the row here, and the row stays in
        `PROVISIONING` until the readiness wait moves it. A provider that provisions straight to
        `RUNNING` would otherwise take the row to `RUNNING` before any credential existed, which is
        the one window publication is ordered to avoid. Nothing is lost by not mirroring it: the next
        task's first act is `describe`, so the row reaches the reported state a moment later anyway.

        Dying after the provision call and before the handle is recorded leaves a row in
        `PROVISIONING` with no handle, which is the design's remaining orphan case and is exactly what
        the Reaper's orphan pass and `provider.discover` recover using the tags R11.7 puts on every
        Sandbox.

        Raises:
            QuotaExhausted: the backend refused because a service quota is exhausted (R6.8). The
                state machine catches it by name and the recorded reason carries the quota.
            IdlePolicyRejected: the execution input carries a policy R10.3 refuses.
            CapabilityUnsupported: the provider cannot deliver the configured idle policy.
            LifecycleConditionFailed: the Session went terminal before its Sandbox existed.
        """
        orchestration = invocation.orchestration
        record = self._record(invocation)
        policy = idle_policy_from_execution_input(invocation.state)
        self._advance(
            record, state=LifecycleState.PROVISIONING, reason=PROVISIONING_REASON
        )

        status = self.provider.provision(
            policy.applied_to(
                self._specification(orchestration, record), provider=self.provider
            )
        )

        self.store.record_sandbox(
            SandboxRecording(
                partition_key=record.pk,
                sort_key=record.sort_key,
                handle=status.handle,
                updated_at=self._now(),
            )
        )
        return {
            "providerName": status.handle.provider_name,
            "sandboxId": status.handle.sandbox_id,
            "sandboxState": status.state.value,
            "lifecycleState": LifecycleState.PROVISIONING.value,
        }

    def claim_sandbox(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Allocate this Sandbox to this Session, once and for all (R11.1, R11.10).

        The ledger's conditional write is the arbitration, and the ledger also terminates the
        duplicate a lost race leaves behind, before the exception reaches here. So this task neither
        checks first nor cleans up after: it claims, and reports.

        Raises:
            SandboxAlreadyClaimed: another Session holds the claim. The state machine catches it by
                name and records this Session `FAILED` with the reason, which says whether the
                duplicate was terminated.
        """
        orchestration = invocation.orchestration
        record = self._record(invocation)
        claim = self.ledger.claim(
            handle=handle_of(record, invocation.task),
            session_id=orchestration.session_id,
            tenant_id=orchestration.tenant_id,
            tags=sandbox_tags(
                tenant_id=orchestration.tenant_id, session_id=orchestration.session_id
            ),
            claimed_at=self._now(),
        )
        return {"claimedAt": claim.claimed_at, "eligibility": claim.eligibility.value}

    def await_ready(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Poll `provider.describe` until the `/run` hook has returned 200 (R7.8).

        A provider reporting `RUNNING` is the signal: R7.8's readiness gate admits no request before
        `/run` has returned, so a Sandbox reporting running is one that is serving.

        The report that ends the wait is deliberately **not** mirrored here. Publication is part of
        the `STARTING → RUNNING` transition, so the row reaches `RUNNING` in
        :meth:`publish_credential`, after the credential is on it. Every earlier report *is* mirrored
        (R6.7), so an operator watching a slow start sees `PROVISIONING` and `STARTING` as they
        happen.

        Transient errors from the provider (HTTP 502, 503, connection resets) are caught and
        retried within the polling loop rather than propagated, since the MicroVM may still be
        starting and the service API is eventually consistent.

        Raises:
            SandboxStartupFailed: the Sandbox reached a terminal state first, which is where a
                non-200 `/run` and a failed state restore arrive (R13.7).
            ReadinessNotReached: the attempts were exhausted with the Sandbox still starting.
        """
        import logging
        logger = logging.getLogger(__name__)

        record = self._record(invocation)
        handle = handle_of(record, invocation.task)
        attempts = self.settings.readiness_attempts
        state = SandboxState.PENDING
        transient_errors = 0
        max_transient_errors = 5  # tolerate up to 5 consecutive transient failures

        for attempt in range(1, attempts + 1):
            try:
                status = self.provider.describe(handle)
                transient_errors = 0  # reset on success
            except Exception as exc:
                # Treat as transient if it looks like a server-side error (502, 503, etc.)
                transient_errors += 1
                error_msg = str(exc)
                is_transient = any(code in error_msg for code in ("502", "503", "504", "ServiceUnavailable", "InternalServerError"))

                if is_transient and transient_errors <= max_transient_errors:
                    logger.warning(
                        "await_ready: transient error on attempt %d/%d (consecutive: %d): %s",
                        attempt, attempts, transient_errors, error_msg[:200],
                    )
                    if attempt < attempts:
                        self.sleep(self.settings.readiness_interval_seconds)
                    continue
                # Not transient or too many consecutive failures — propagate
                raise

            state = status.state
            if state is SandboxState.RUNNING:
                return {"attempts": attempt, "sandboxState": state.value}
            if GOVERNING_BRANCHES[state] is GovernanceDecision.TEAR_DOWN:
                raise SandboxStartupFailed(
                    record.session_id,
                    state,
                    status.state_reason or f"the provider reported {state.value}",
                )
            self.reconciler.reconcile(self._record(invocation), status)
            if attempt < attempts:
                self.sleep(self.settings.readiness_interval_seconds)
        raise ReadinessNotReached(record.session_id, state, attempts)

    def publish_credential(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Mint the credential and publish it onto the Session row, then reach `RUNNING` (R6.12).

        The mint is :class:`~control_plane.credentials.ConnectionIssuer`, the sole issuer, and it
        takes the record and nothing else — so this task cannot widen the credential's port set or
        stretch its lifetime, having no argument through which to try.

        The credential is written before the state, so no instant exists in which the row is
        `RUNNING` and carries no credential. The reverse — `STARTING` with a credential on it — is the
        readiness signal the design describes, and is why publication is a distinct task rather than a
        side effect of the readiness wait: it is the one step the creating handler is waiting on.
        """
        record = self._record(invocation)
        connection = self.issuer.issue(record)
        published_at = self._now()
        self.store.publish_connection(
            CredentialPublication(
                partition_key=record.pk,
                sort_key=record.sort_key,
                connection=connection,
                published_at=published_at,
            )
        )
        self._advance(record, state=LifecycleState.RUNNING, reason=PUBLICATION_REASON)
        return {
            "publishedAt": published_at,
            "expiresAt": connection.expires_at,
            "ports": list(connection.ports),
            "lifecycleState": LifecycleState.RUNNING.value,
        }

    # -- callback-based lifecycle wait (replaces the polling loop) ---------------------------

    def wait_for_lifecycle(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Store the Step Functions task token and pause.

        The state machine enters ``WaitForLifecycle(.waitForTaskToken)``. This task
        receives the token from Step Functions, stores it on the session record in
        DynamoDB, and returns. The state machine then pauses at zero cost until the
        API Handler or Reaper calls ``sfn.send_task_success(taskToken, payload)``.

        The token is extracted from the invocation context (Step Functions passes it
        as part of the task input when the integration type is ``.waitForTaskToken``).
        """
        record = self._record(invocation)
        # The task token is passed by Step Functions in the invocation context
        task_token = invocation.task_token
        if task_token:
            # Store the token on the session record for the API Handler/Reaper to read
            self._store_task_token(record, task_token)
        return {
            "sessionId": record.session_id,
            "taskTokenStored": bool(task_token),
            "lifecycleState": record.lifecycle_state.value,
        }

    def _store_task_token(self, record: SessionRecord, token: str) -> None:
        """Write the task token to the session's DDB record."""
        import os
        import boto3
        table_name = os.environ.get("TABLE_NAME", "")
        if not table_name:
            return
        ddb = boto3.resource("dynamodb").Table(table_name)  # nosemgrep  # nosec
        ddb.update_item(
            Key={"pk": record.pk, "sk": record.sort_key},
            UpdateExpression="SET taskToken = :t",
            ExpressionAttributeValues={":t": token},
        )

    def record_suspended(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Mirror SUSPENDED state to DDB after a suspend callback.

        Writes SUSPENDED directly rather than relying on provider.describe,
        because the provider may still report a transitional state (SUSPENDING)
        when the callback arrives.
        """
        from control_plane.state.records import LifecycleState
        record = self._record(invocation)
        mirrored = self.reconciler.reconcile(
            record,
            type("_Status", (), {"state": type("_", (), {"value": "SUSPENDED"})(), "reason": "user-initiated suspend"})(),
        ) if False else None  # Skip provider describe — write directly
        # Direct DDB update for the lifecycle state
        import os, time, boto3
        table_name = os.environ.get("TABLE_NAME", "")
        if table_name:
            now = int(time.time() * 1000)
            boto3.resource("dynamodb").Table(table_name).update_item(  # nosemgrep  # nosec
                Key={"pk": record.pk, "sk": record.sort_key},
                UpdateExpression="SET lifecycleState = :state, updatedAt = :now",
                ConditionExpression="attribute_exists(pk) AND NOT lifecycleState IN (:t1, :t2)",
                ExpressionAttributeValues={":state": "SUSPENDED", ":now": now, ":t1": "TERMINATED", ":t2": "FAILED"},
            )
        return {
            "sessionId": record.session_id,
            "lifecycleState": "SUSPENDED",
        }

    def record_resumed(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Mirror RUNNING state to DDB after a resume callback.

        Writes RUNNING directly rather than relying on provider.describe,
        because the provider may still report PENDING/STARTING while the
        /resume hook runs (especially with persistence/NFS re-mount).
        """
        record = self._record(invocation)
        import os, time, boto3
        table_name = os.environ.get("TABLE_NAME", "")
        if table_name:
            now = int(time.time() * 1000)
            boto3.resource("dynamodb").Table(table_name).update_item(  # nosemgrep  # nosec
                Key={"pk": record.pk, "sk": record.sort_key},
                UpdateExpression="SET lifecycleState = :state, updatedAt = :now",
                ExpressionAttributeValues={":state": "RUNNING", ":now": now, ":t1": "TERMINATED", ":t2": "FAILED"},
                ConditionExpression="attribute_exists(pk) AND NOT lifecycleState IN (:t1, :t2)",
            )
        return {
            "sessionId": record.session_id,
            "lifecycleState": "RUNNING",
        }

    # -- the governing loop (legacy, kept for reference) -------------------------------------------

    def observe(self, invocation: TaskInvocation) -> dict[str, Any]:
        """One turn of the governing loop: describe, mirror, decide.

        The mirror is R6.7 and it is what records `RUNNING ↔ SUSPENDED`: auto-resume is the
        provider's (R10.5), so the orchestration observes the transition rather than mediating it and
        a resume does not depend on this execution being healthy.

        The result carries the poll interval, so the state machine's `Wait` reads a configured value
        out of the execution rather than a number frozen into the definition.
        """
        record = self._record(invocation)
        status = self.provider.describe(handle_of(record, invocation.task))
        mirrored = self.reconciler.reconcile(record, status)
        decision = self._decision(record, status.state, mirrored)
        return {
            "decision": decision.value,
            POLL_INTERVAL_FIELD: self.settings.poll_interval_seconds,
            "sandboxState": status.state.value,
            "lifecycleState": mirrored.state.value,
            "outcome": mirrored.outcome.value,
        }

    def emit_counts(self, invocation: TaskInvocation) -> dict[str, Any]:
        """One point towards the running and suspended Sandbox counts (R14.4).

        This Session's contribution, not the fleet's: each governed execution emits one point per poll
        turn and the fleet count is the `Sum` over one interval, which is what `EmitCounts` sitting
        *inside* the governing loop makes possible. A task that queried the fleet would need a scan of
        the State_Store per Session per interval to say what the sum already says.

        The state is read from the observation the loop is already acting on rather than from a fresh
        read: the graph reaches `EmitCounts` only through `Observe → Govern → Wait`, so
        `$.governance` is always populated here, and a metric derived from a second read could
        disagree with the decision the loop just took. It is the *provider-reported* state that
        decides which count this Session joins, because the near-zero idle cost claim is about what is
        billable.

        **Nothing here can fail the loop.** `EmitCounts` has no catcher, so a raise would fail the
        execution and hand a perfectly healthy Session to the Reaper in order to record that it was
        running. An unemittable observation and a sink that refused the document both return
        `emitted: false` instead, which is visible in the execution history and in
        :attr:`~control_plane.observability.SandboxCountEmitter.dropped`.
        """
        orchestration = invocation.orchestration
        report = self._count_report(invocation, orchestration)
        if report is None:
            return {"emitted": False, "reason": _NO_OBSERVATION_RECORDED}
        emitted = True
        try:
            self.counts.record_counts(report)
        except Exception:  # noqa: BLE001 - a metric must not tear down a healthy Session
            emitted = False
        return {
            "emitted": emitted,
            RUNNING_METRIC_NAME: report.running,
            SUSPENDED_METRIC_NAME: report.suspended,
            "sandboxState": report.sandbox_state.value,
            "lifecycleState": report.lifecycle_state.value,
        }

    def _count_report(
        self, invocation: TaskInvocation, orchestration: OrchestrationInput
    ) -> SandboxCountReport | None:
        """The observation `Observe` recorded, or None if this invocation carries none.

        None rather than a raise, and None rather than a zero: a Session whose state cannot be read
        contributes to neither count, and reporting it as neither running nor suspended by *emitting*
        would be indistinguishable from a Session that is genuinely neither.
        """
        governance = invocation.state.get(_GOVERNANCE_FIELD)
        if not isinstance(governance, Mapping):
            return None
        try:
            return SandboxCountReport(
                session_id=orchestration.session_id,
                tenant_id=orchestration.tenant_id,
                sandbox_state=SandboxState(governance["sandboxState"]),
                lifecycle_state=LifecycleState(governance["lifecycleState"]),
                observed_at=self._now(),
            )
        except (KeyError, ValueError, TypeError):
            return None

    def continue_session(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Hand this Session from the Sandbox it has to the one that will restore its state (R10.11).

        Five steps, and the order is the requirement rather than a preference. Getting it wrong loses
        caller state or leaks a billable Sandbox, so each step is placed against the one failure it
        prevents:

        1. **`CONTINUING` first, before anything is done to the outgoing Sandbox.** The row reports
           what is happening for the whole of the handoff, which R14.2 asks an operator to be able
           to read, and — the load-bearing half — a row that went terminal underneath this handoff
           refuses the write and the refusal *stops the teardown*, at the one moment when nothing has
           yet been torn down. A Session the Reaper settled while the governing loop was deciding is
           therefore not handed off; it is recorded failed by the graph's catcher and cleaned up.
        2. **Quiesce**, so a request in flight at the ceiling meets a refusal rather than being
           half-served. It reports rather than raises, and a Sandbox that does not acknowledge does
           not abandon the handoff; see :class:`~control_plane.orchestrator.continuation.SandboxQuiesce`.
        3. **Terminate, and wait for it.** The declared path set is archived *by the `/terminate`
           hook* (R13.3), to the reference generation *N* was handed at `/run`, so this call is the
           step that persists the state and it must complete before anything provisions. The
           `Continue → Provision` edge in the graph is what guarantees that: this task returns before
           the replacement is created, so there is no arrangement in which a new Sandbox exists while
           the old one's archive is still being written.
        4. **Record the handoff**, after the archive exists and never before, so a continuation
           record only ever names an artifact that was written. Conditional on its own absence, so a
           replay absorbs.
        5. **Increment the generation and drop the outgoing Sandbox**, conditional on
           `generation = :outgoing`. That condition is the idempotence: a replayed handoff finds the
           row already advanced and is refused rather than incrementing twice.

        **The provider's report is deliberately not mirrored.** Every other teardown in this module
        hands the report to :class:`~control_plane.lifecycle.LifecycleReconciler`, which settles a
        terminal state and deletes the Affinity_Key binding with it (R10.16). Here that would be
        exactly wrong: the Sandbox is terminal, the *Session* is not, and deleting the binding is the
        one thing R6.24 forbids on this path. `CONTINUING` being a record-only lifecycle state — no
        provider can report it — is what makes leaving the row there sound rather than stale.

        Before any of the five, a handoff that already completed is recognised and reported. That
        check earns its place rather than being defensive: step 5 drops the outgoing handle, so a
        replay after it succeeded has no Sandbox to name, and reading a handle first would refuse a
        Session whose handoff in fact worked. See
        :meth:`~control_plane.orchestrator.continuation.ContinuationHandoffs.applied_handoff`.

        **No new Sandbox comes into being here, retried or not.** This task neither provisions nor
        claims. The replacement is created by `Provision`, which carries no retrier and is reached
        once per traversal of the governing choice, and it takes a **new** claim: the claim key is
        `H#<provider>#<sandboxId>` and the replacement has an identifier of its own, so the outgoing
        Sandbox's claim is neither reused nor reopened (R11.10).

        If the archive was never written — a provider that reported `FAILED` from `terminate`, a
        `/terminate` hook whose store write overran its share of the deadline — the replacement's
        `/run` hook fails its restore and reports it, which `AwaitReady` raises as
        :class:`SandboxStartupFailed` and the graph records with the provider's own reason (R13.7).
        That is a visible failure with a cause, which is the outcome worth having; starting the
        replacement empty and reporting success is not.

        Raises:
            ContinuationNotEnabled: the row declared no continuation, so no archive was configured
                and there is nothing to hand over.
            SandboxNotRecorded: the row carries no handle, so there is no Sandbox to hand off from.
            LifecycleConditionFailed: the Session went terminal before the handoff began, in which
                case nothing has been torn down.
        """
        record = self._record(invocation)
        if not record.continuation_enabled:
            raise ContinuationNotEnabled(record.session_id)

        settled = self.continuation.applied_handoff(record)
        if settled is not None:
            # A replay of a handoff that reached step 5. The outgoing Sandbox is gone and the row no
            # longer names it, so there is nothing to read a handle for — which is why this is
            # detected *before* `handle_of` rather than absorbed from the exception it would raise.
            return self._handoff_result(
                record,
                outgoing_generation=settled.generation - 1,
                generation=record.generation,
                archived=settled.artifact_reference,
                sandbox_state=None,
                quiesced=False,
                recorded=False,
                applied=False,
            )

        handle = handle_of(record, invocation.task)
        handoff = handoff_for(record, at=self._now())
        archived = continuation_artifact_reference(record, handoff.outgoing_generation)

        self._advance(
            record, state=LifecycleState.CONTINUING, reason=CONTINUATION_REASON
        )
        quiesced = self.continuation.quiescer.quiesce(record)
        status = self.provider.terminate(handle)
        recorded = self._record_handoff(record, handoff)
        generation, applied = self._apply_handoff(invocation, handoff)

        return self._handoff_result(
            record,
            outgoing_generation=handoff.outgoing_generation,
            generation=generation,
            archived=archived,
            sandbox_state=status.state.value,
            quiesced=quiesced,
            recorded=recorded,
            applied=applied,
        )

    # -- teardown ---------------------------------------------------------------------------------

    def terminate(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Terminate the Sandbox, and mirror whatever the provider reports back.

        `provider.terminate` is idempotent, so this converges with a Reaper sweep that reached the
        same Session first rather than conflicting with it. The reported state goes through the
        reconciler, which settles it when it is terminal — deleting the binding with it (R10.16) —
        and records `TERMINATING` when the teardown is still in flight.
        """
        record = self._record(invocation)
        status = self.provider.terminate(handle_of(record, invocation.task))
        mirrored = self.reconciler.reconcile(record, status)
        return {
            "sandboxState": status.state.value,
            "lifecycleState": mirrored.state.value,
            "outcome": mirrored.outcome.value,
            "bindingDeleted": mirrored.binding_deleted,
        }

    def release_check(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Confirm that no Sandbox, network interface or endpoint remains allocated (R10.9).

        The provider returns the identifiers still allocated, so emptiness is asserted rather than
        inferred from a terminate call having succeeded. A non-empty answer raises, which the state
        machine retries with backoff before failing the execution as `ResourcesRetained`.

        Raises:
            ResourcesStillAllocated: something is still allocated to this Session.
        """
        record = self._record(invocation)
        allocated = tuple(
            self.provider.release_check(handle_of(record, invocation.task))
        )
        if allocated:
            raise ResourcesStillAllocated(record.session_id, allocated)
        return {"allocated": []}

    def record_failed(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Record the Session `FAILED` with the caught reason, then quarantine its claim.

        Two steps, in this order, and the order is the requirement. The settlement stops the Session
        and deletes its binding (R6.14, R10.16); the quarantine marks the Sandbox ineligible for any
        later allocation (R11.13). They cannot share a transaction — the claim item sits outside every
        Tenant partition and is written with a different role — and keeping them separate is what
        stops a claim-ledger failure from blocking the write that ends a billable Session.

        A Session that failed before it claimed anything has no claim to quarantine, which is an
        absence rather than a failure and is reported as one.
        """
        record = self._record(invocation)
        reason = failure_reason(invocation.failure)
        settled = self.reconciler.settle(
            record, state=LifecycleState.FAILED, reason=reason
        )
        return {
            "lifecycleState": settled.state.value,
            "outcome": settled.outcome.value,
            "bindingDeleted": settled.binding_deleted,
            "reason": reason,
            "quarantined": self._quarantine(record),
        }

    def cleanup(self, invocation: TaskInvocation) -> dict[str, Any]:
        """Settle the terminal state and delete the Affinity_Key binding with it (R10.16).

        The join of all three paths, and it is safe as one because a terminal lifecycle state absorbs
        in the store. Reaching it after :meth:`record_failed` finds the row already `FAILED`, so the
        settlement is refused by its own condition and reported as absorbed rather than replacing the
        diagnostic state with the routine one.
        """
        record = self._record(invocation)
        settled = self.reconciler.settle(
            record, state=LifecycleState.TERMINATED, reason=CLEANUP_REASON
        )
        return {
            "lifecycleState": settled.state.value,
            "outcome": settled.outcome.value,
            "bindingDeleted": settled.binding_deleted,
        }

    # -- reading, writing and deciding ------------------------------------------------------------

    def _record(self, invocation: TaskInvocation) -> SessionRecord:
        """Read the Session row, in the Session's own Tenant partition.

        Each `Task` state is its own invocation, so each reads the row rather than trusting a copy
        threaded through the execution state: the row is where every other component writes, and a
        stale copy is how an orchestration talks itself into terminating a Session that was resumed.

        Raises:
            SessionRecordAbsent: there is no row at this Session's key, which is a defect. Nothing in
                this design deletes a Session row, so re-creating one here — as a partial item, from
                an execution input — would replace the record R6.6 requires to be complete.
        """
        orchestration = invocation.orchestration
        partition_key = pk_for(invocation.principal)
        sort_key = session_sort_key(orchestration.session_id)
        item = self.lookup.read_session(partition_key=partition_key, sort_key=sort_key)
        if item is None:
            raise SessionRecordAbsent(partition_key, sort_key)
        return SessionRecord.from_item(item)

    def _specification(
        self, orchestration: OrchestrationInput, record: SessionRecord
    ) -> SandboxSpec:
        """Assemble the Sandbox specification, tags included.

        The tags come from :func:`~control_plane.allocation.tags.sandbox_tags`, the sole producer, so
        every Sandbox this orchestration creates is attributable to its Tenant and Session and is
        reachable by `provider.discover` if its handle is never recorded (R11.7).

        The three idle-policy fields are seeded from the Session row, which
        :class:`~control_plane.state.records.SessionRecord` has already refused to hold a non-positive
        value in, and are then replaced by
        :meth:`~control_plane.idle_policy.IdlePolicy.applied_to` with the policy revalidated from the
        execution input. That is the one route those values take to a Sandbox (R10.2).

        The start configuration is derived from the row by
        :meth:`~control_plane.orchestrator.continuation.ContinuationHandoffs.start_configuration`
        rather than supplied by a caller. That is what carries both halves of R10.11: the `persist`
        request naming this generation's archive destination and the declared path set, and — for a
        generation a handoff produced — the `restore` request naming the archive the previous one
        wrote. There is no parameter through which anything could name a different archive, which is
        the same shape that makes :class:`~control_plane.credentials.ConnectionIssuer` the sole issuer.
        """
        configuration = self.continuation.start_configuration(record)
        policy = idle_policy_for(record)
        return SandboxSpec(
            session_id=orchestration.session_id,
            tenant_id=orchestration.tenant_id,
            image_ref=self.settings.image_ref,
            memory_bytes=orchestration.memory_bytes,
            vcpu_millis=self.settings.vcpu_millis,
            max_duration_seconds=orchestration.max_duration_seconds,
            idle_seconds_before_suspend=policy.idle_seconds_before_suspend,
            suspended_seconds_before_terminate=policy.suspended_seconds_before_terminate,
            auto_resume=policy.auto_resume,
            exposed_ports=orchestration.exposed_ports,
            execution_role_arn=orchestration.execution_role_arn,
            egress_attachment_ref=self.settings.egress_attachment_ref,
            egress_endpoint=self.settings.egress_endpoint,
            s3files_filesystem_id=self.settings.s3files_filesystem_id if orchestration.persistence else "",
            s3files_access_point_id=self._resolve_access_point(orchestration) if orchestration.persistence else "",
            s3files_mount_target_ip=(self.settings.s3files_mount_target_ips.split(",")[0] if self.settings.s3files_mount_target_ips else "") if orchestration.persistence else "",
            start_config=configuration.document,
            start_config_ref=configuration.reference,
            tags=sandbox_tags(
                tenant_id=orchestration.tenant_id, session_id=orchestration.session_id
            ),
        )

    def _resolve_access_point(self, orchestration: OrchestrationInput) -> str:
        """Resolve or create an S3 Files access point for workspace isolation.

        With ``affinityKey``: the workspace is scoped to ``/<tenantId>/<affinityKey>/``.
        Sessions with the same ``(tenantId, affinityKey)`` share the same workspace and
        access point. The AP ID is stored in DDB so subsequent sessions reuse it.

        Without ``affinityKey``: the workspace is scoped to ``/<tenantId>/<sessionId>/``
        (isolated per session, not shared).

        Falls back to the shared AP on any error.
        """
        if not self.settings.s3files_filesystem_id:
            return self.settings.s3files_access_point_id

        import boto3

        # Determine the root path and lookup key
        # Include principalId for per-user isolation within a tenant
        pid = orchestration.principal_id or "default"
        # Sanitize: replace characters that are invalid in S3 paths
        pid_safe = pid.replace("/", "_").replace(":", "_")[:64]

        if orchestration.affinity_key:
            root_path = f"/{orchestration.tenant_id}/{pid_safe}/{orchestration.affinity_key}"
            lookup_key = f"AP#{orchestration.tenant_id}#{pid_safe}#{orchestration.affinity_key}"
        else:
            root_path = f"/{orchestration.tenant_id}/{pid_safe}/{orchestration.session_id}"
            lookup_key = ""  # No lookup — always create new

        # If affinity key, try to find an existing AP in DDB
        if lookup_key:
            try:
                table = boto3.resource("dynamodb").Table(
                    os.environ.get("TABLE_NAME", "")
                )
                resp = table.get_item(Key={"pk": lookup_key, "sk": "ACCESS_POINT"})
                existing_ap = resp.get("Item", {}).get("accessPointId", "")
                if existing_ap:
                    return existing_ap
            except Exception:  # nosec B110
                pass

        # Create a new AP
        try:
            s3files = boto3.client("s3files", region_name="us-east-1")
            token = f"ws-{orchestration.session_id[:20]}"
            resp = s3files.create_access_point(
                fileSystemId=self.settings.s3files_filesystem_id,
                clientToken=token,
                rootDirectory={
                    "path": root_path,
                    "creationPermissions": {
                        "ownerUid": 0,
                        "ownerGid": 0,
                        "permissions": "0755",
                    },
                },
                posixUser={"uid": 0, "gid": 0},
            )
            ap_id = resp.get("accessPointId", "")
            if not ap_id:
                return self.settings.s3files_access_point_id

            # Store the mapping for affinity key reuse
            if lookup_key:
                try:
                    table = boto3.resource("dynamodb").Table(
                        os.environ.get("TABLE_NAME", "")
                    )
                    table.put_item(Item={
                        "pk": lookup_key,
                        "sk": "ACCESS_POINT",
                        "accessPointId": ap_id,
                        "rootPath": root_path,
                        "tenantId": orchestration.tenant_id,
                        "affinityKey": orchestration.affinity_key,
                        "fileSystemId": self.settings.s3files_filesystem_id,
                    })
                except Exception:  # nosec B110
                    pass  # AP created but mapping not stored — next session will create a new one

            return ap_id
        except Exception:  # nosec B110
            pass

        return self.settings.s3files_access_point_id

    def _advance(
        self, record: SessionRecord, *, state: LifecycleState, reason: str
    ) -> None:
        """Commit one live transition this component decided on.

        The three of them — `ORCHESTRATING → PROVISIONING`, `STARTING → RUNNING` and the `CONTINUING`
        a handoff begins with — are the only lifecycle writes in this module that no provider report
        produced, so they go through :meth:`~control_plane.lifecycle.LifecycleReconciler.advance`,
        which builds the write, commits it and emits its audit record (R14.2).
        :class:`~control_plane.lifecycle.LiveTransition` refuses a terminal state at construction, so
        this route cannot write one whatever it is passed.

        A condition failure is **not** absorbed here. Both call sites are about to do something to a
        Sandbox — provision one, publish a credential for one — and a row that has gone terminal
        underneath them is a reason to stop rather than a note to add to a result. The state machine
        catches it and records the failure.

        Raises:
            LifecycleConditionFailed: the row is absent, or it is already terminal.
        """
        self.reconciler.advance(record, state=state, reason=reason)

    def _decision(
        self,
        record: SessionRecord,
        state: SandboxState,
        mirrored: Reconciliation,
    ) -> GovernanceDecision:
        """Decide what the governing loop does about one observation.

        The order is the decision and it matters. An observed teardown wins, because a Session whose
        Sandbox is going away has nothing left to govern, and so does a record that is already
        terminal — an absorbed mirror write means some other component settled this Session while the
        loop was running. The duration ceiling comes next, so an overdue Session tears down rather
        than starting a handoff it has no time for. Continuation is third, and only where the
        deployment enabled it. Anything else keeps polling, and that answer comes from
        :data:`~control_plane.orchestrator.definition.GOVERNING_BRANCHES`, which is total over every
        state a provider can report.
        """
        branch = GOVERNING_BRANCHES[state]
        if branch is GovernanceDecision.TEAR_DOWN or mirrored.state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            return GovernanceDecision.TEAR_DOWN
        remaining = self._remaining_seconds(record)
        if remaining <= 0:
            return GovernanceDecision.TEAR_DOWN
        if (
            record.continuation_enabled
            and remaining <= self.settings.continuation_lead_seconds
        ):
            return GovernanceDecision.CONTINUE
        return branch

    def _remaining_seconds(self, record: SessionRecord) -> int:
        """Whole seconds left of this Session's configured maximum duration.

        Floored, so a Session is never governed as though it had a fraction of a second more than it
        does, and computed from the row's own `createdAt` and `maxDurationSeconds` rather than from
        `reapDeadline`, because the Reaper's deadline carries grace margins this decision must not
        inherit.
        """
        deadline = (
            record.created_at + record.max_duration_seconds * _MILLISECONDS_PER_SECOND
        )
        return (deadline - self._now()) // _MILLISECONDS_PER_SECOND

    @staticmethod
    def _handoff_result(
        record: SessionRecord,
        *,
        outgoing_generation: int,
        generation: int,
        archived: str,
        sandbox_state: str | None,
        quiesced: bool,
        recorded: bool,
        applied: bool,
    ) -> dict[str, Any]:
        """One shape for both arms of :meth:`continue_session`, replay included.

        `sandboxState` is `None` on the replay arm and that is the honest value rather than a gap: the
        outgoing Sandbox is gone, the row no longer names it, and no provider was asked. A key set
        that varied between the two arms would make an operator's reading of execution history depend
        on which arm ran.
        """
        return {
            "outgoingGeneration": outgoing_generation,
            "generation": generation,
            "applied": applied,
            "handoffRecorded": recorded,
            "quiesced": quiesced,
            "artifactReference": archived,
            "continuationPaths": list(record.continuation_paths),
            "sandboxState": sandbox_state,
            "lifecycleState": LifecycleState.CONTINUING.value,
            # R6.24, carried in the result rather than only in a comment: the Session identifier is
            # stable across a handoff, so the binding that names it is correct untouched and nothing
            # on this path writes it.
            "sessionId": record.session_id,
            "bindingRetained": True,
        }

    def _record_handoff(
        self, record: SessionRecord, handoff: ContinuationHandoff
    ) -> bool:
        """Write the continuation record for the incoming generation, or report it already there.

        The write is conditional on the item's absence, so a replayed handoff absorbs rather than
        rewriting a record whose `createdAt` would then describe the replay instead of the handoff.
        Reported as `False` rather than raised, for the reason an absorbed lifecycle write is: this is
        the mechanism converging, and a caller told only that something failed would have to read the
        item to find out whether anything is wrong.
        """
        try:
            self.continuation.store.record_continuation(
                continuation_record_for(record, handoff, at=self._now())
            )
        except ContinuationAlreadyRecorded:
            return False
        return True

    def _apply_handoff(
        self, invocation: TaskInvocation, handoff: ContinuationHandoff
    ) -> tuple[int, bool]:
        """Advance the row onto the incoming generation, reporting the generation it now holds.

        The write's condition on the outgoing generation is the idempotence, so a refusal is the
        ordinary replay case rather than an error. It is *not* assumed to mean the replay case: the
        row is re-read and its own generation reported, because the same condition also excludes a row
        that went terminal, and reporting the incoming generation for one of those would be a claim
        this task cannot support.
        """
        try:
            self.continuation.store.apply_continuation(handoff)
        except LifecycleConditionFailed:
            return self._record(invocation).generation, False
        return handoff.incoming_generation, True

    def _quarantine(self, record: SessionRecord) -> bool:
        """Quarantine this Session's Sandbox claim (R11.13), or report that it holds none."""
        try:
            handle = handle_of(record, OrchestratorState.RECORD_FAILED)
        except SandboxNotRecorded:
            # The Session failed before a Sandbox existed. There is nothing to make ineligible.
            return False
        try:
            self.ledger.quarantine_for_session_failure(handle)
        except SandboxNotClaimed:
            # It failed before, or during, its claim. There is no allocation to constrain.
            return False
        return True

    def _now(self) -> int:
        """Epoch milliseconds, the unit every recorded timestamp in the State_Store uses."""
        moment = self.clock()
        if moment.tzinfo is None:
            raise ValueError("the orchestrator's clock must return an aware datetime")
        return int(moment.timestamp() * _MILLISECONDS_PER_SECOND)


#: The body of every `Task` state the graph draws. Total over
#: :data:`~control_plane.orchestrator.definition.TASK_STATES`, asserted at import, so a task added to
#: the graph with no body fails the build rather than an execution.
_TASK_BODIES: Final[
    Mapping[
        OrchestratorState,
        Callable[[SessionOrchestrator, TaskInvocation], dict[str, Any]],
    ]
] = {
    OrchestratorState.PROVISION: SessionOrchestrator.provision_sandbox,
    OrchestratorState.CLAIM_SANDBOX: SessionOrchestrator.claim_sandbox,
    OrchestratorState.AWAIT_READY: SessionOrchestrator.await_ready,
    OrchestratorState.PUBLISH_CREDENTIAL: SessionOrchestrator.publish_credential,
    OrchestratorState.WAIT_FOR_LIFECYCLE: SessionOrchestrator.wait_for_lifecycle,
    OrchestratorState.RECORD_SUSPENDED: SessionOrchestrator.record_suspended,
    OrchestratorState.RECORD_RESUMED: SessionOrchestrator.record_resumed,
    OrchestratorState.CONTINUE: SessionOrchestrator.continue_session,
    OrchestratorState.TERMINATE: SessionOrchestrator.terminate,
    OrchestratorState.RELEASE_CHECK: SessionOrchestrator.release_check,
    OrchestratorState.RECORD_FAILED: SessionOrchestrator.record_failed,
    OrchestratorState.CLEANUP: SessionOrchestrator.cleanup,
}

if set(_TASK_BODIES) != TASK_STATES:  # pragma: no cover - import-time invariant
    _bodyless = sorted(state.value for state in TASK_STATES - set(_TASK_BODIES))
    _unknown = sorted(state.value for state in set(_TASK_BODIES) - TASK_STATES)
    raise AssertionError(
        f"Task states with no body: {_bodyless}; bodies for no Task state: {_unknown}"
    )

if (
    ResourcesStillAllocated.__name__ != RESOURCES_STILL_ALLOCATED_ERROR
    or QuotaExhausted.__name__ != QUOTA_EXHAUSTED_ERROR
    or SandboxAlreadyClaimed.__name__ != SANDBOX_ALREADY_CLAIMED_ERROR
):  # pragma: no cover - import-time invariant
    # Step Functions matches a catcher against the exception's class name, so those three strings in
    # the definition and these three classes are one fact spelled twice. A rename on either side
    # would leave a catcher matching nothing, and the symptom would be a Session left running by a
    # dead execution rather than a test failure.
    raise AssertionError(
        "an error name in the state machine no longer matches the exception it catches"
    )
