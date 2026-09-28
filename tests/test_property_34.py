# kiro-classification: public
"""Property 34: creation orders the execution before the Sandbox and reports through the record.

Five acceptance criteria, one recorded call sequence. R6.10 and R6.11 order the execution against
every Sandbox; R6.12 puts the credential on the row inside the Session's Tenant scope once `/run`
has returned 200; R6.13 makes the handler read what it returns from that row rather than from a
provider call of its own; R6.14 makes a failed provisioning a terminal row with a reason the
handler's error repeats. Each is a statement about an *order of events*, so this property asserts
over a sequence rather than over a final state.

## What is being quantified over, and why each dimension is here

| Dimension | Values | What it discriminates |
| --- | --- | --- |
| the request body | durations, idle and suspended timeouts, exposed port sets, all admissible | the port set reaches the credential, so the published and returned descriptors vary |
| the creation contract | `synchronous`, `asynchronous` | whether the handler waits at all — R6.13 must hold under both |
| the caller | `POST /sessions`, the get-or-create create branch | R6.11 is a claim about *every* Sandbox, and `create()` has two callers |
| the fault point | admission, the row write, either side of `StartExecution`, publication | a failure at step N leaves none of step N+1's effects |
| the provider outcome | success, quota, transport, claim collision, readiness timeout, `/run` non-200 | R6.14's reason is provider-supplied, and a refused `/run` must publish nothing |
| publication inside the budget | yes, no | the asynchronous fallback is not a failure and loses no work |

The body space is deliberately restricted to bodies admission *admits*. What a rejected body costs
is Property 11's claim about the rule and Property 12's claim about the write, and restating it here
would make this test agree with a defect in the module it is checking. The rejection still appears —
as :attr:`FaultPoint.ADMISSION`, which is step 1 of the five steps the design's `fault_point()` draws
over, so it is quantified as a *position in the sequence* rather than as a property of the body.

## Where this property sits against the two halves already in place

`ci/lint_rules/orchestrated_provisioning.py` discharges the ordering **statically**: it fails the
build if `provision` is called or defined outside the Compute_Provider seam, so no Control_Plane
module can provision at all. Property 12 discharges the write's precedence and completeness by
sampling a real provider's Sandbox population at the instant of the first write. Neither of those
says anything about what happens *inside* the started execution, and R6.12 through R6.14 are entirely
about that: which task publishes the credential, where it publishes it, what the handler is allowed
to read, and what a failure leaves behind. So this property adds the runtime half, and adds it as an
ordered log across both actors:

- **The handler's collaborators are instrumented.** :class:`InstrumentedProvider` records *every*
  attribute the handler reaches for, so a provisioning call under any spelling — or any other
  provider call the handler made itself — is recorded and attributed to the handler. The property
  asserts the handler touched `limits` and nothing else.
- **The execution is modelled, because phase 10 has not built it.**
  `ORCHESTRATOR_MODULES` in that lint rule is still empty, so there is no orchestrator module to
  drive. :class:`Orchestration` is the design's four provisioning tasks — provision, `/run`, mint,
  publish — as an object advanced one task at a time by the polling wait's own injected `sleep`.
  That is what makes "the credential is published inside the wait budget" and "it is not" two drawn
  arms of one deterministic model with no clock and no thread in either. It reaches the provider
  through :meth:`InstrumentedProvider.call`, keyed by
  :data:`~ci.lint_rules.orchestrated_provisioning.PROVISION_METHOD`, so the recorded name is the one
  the lint rule protects while this file contains no `provision` call for that rule to reject. When
  phase 10 lands, its module joins the rule's allow-list and this model is what its behaviour is
  compared against.
- **The mint is shared and counted.** The same :class:`~tests.test_connection_credentials
  .RecordingMint` instance backs the issuer the modelled execution uses *and* the issuer
  :class:`~control_plane.api.resolution.ResolutionOperations` holds. So "the handler's own call log
  contains no `issue_connection`" is observed rather than constructed: every mint that actually
  happened is compared against the number the execution performed, and a handler that minted one
  would show up as an unattributed mint. The structural half of the same claim is that
  :class:`~control_plane.api.creation.CreationOperations` declares no mint collaborator at all, and
  `ci/lint_rules/sole_credential_issuer.py` keeps it that way.

## The oracles

`test_every_drawn_arm_is_reached_by_name` walks the fault points and the provider outcomes by
construction and asserts each arm's distinguishing evidence, because nothing in a passing Hypothesis
run says which arms it visited. The `test_the_checker_rejects_*` tests feed the checker the evidence
a plausible wrong implementation would have left — the execution started before the row was written,
a Sandbox provisioned with no execution behind it, a credential published before `/run` returned 200,
a response carrying a descriptor the row does not, and a mint the handler performed itself — so the
property is known to be able to fail. None of them draws anything.

Nothing here sleeps, spawns a thread, or reads a wall clock: the wait's clock, sleep and jitter are
injected, one fixed instant serves the handler, the issuer and the mint, and the jitter draw is the
midpoint of the interval the wait asks for.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Final, cast

from hypothesis import given, settings
from hypothesis import strategies as st

from ci.lint_rules.orchestrated_provisioning import PROVISION_METHOD
from ci.lint_rules.sole_credential_issuer import MINT_METHOD
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
    OrchestrationStart,
    execution_name_for,
)
from control_plane.api.creation_wait import (
    CreationContract,
    CreationWaitSettings,
    SessionProvisioningFailed,
    wait_for_contract,
)
from control_plane.api.handlers import OperationRequest, OperationResult
from control_plane.api.resolution import (
    AFFINITY_KEY_FIELD,
    RESOLUTION_FIELD,
    ResolutionOperations,
    ResolutionOutcome,
)
from control_plane.api.routes import Operation
from control_plane.credentials import (
    SANDBOX_PROTOCOL_CONTROL_PORT,
    ConnectionIssuer,
    CredentialPolicy,
)
from control_plane.providers.base import ProviderLimits
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import (
    SEPARATOR,
    SESSION_PREFIX,
    ItemShapeError,
    session_sort_key,
)
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.state.table import SORT_KEY_ATTRIBUTE
from control_plane.tenancy import AuthenticatedPrincipal, pk_for
from tests.harness import MINIMUM_EXAMPLES
from tests.test_connection_credentials import RecordingMint
from tests.test_control_plane_resolution import FakeStore, RecordingStarter

if TYPE_CHECKING:
    from control_plane.providers.base import ComputeProvider

# --- The deployment around the handler, standing in for CDK context values ------------------

#: The one instant the handler's clock, the issuer's clock and the mint all read. Fixed rather than
#: drawn: what a creation timestamp becomes is Property 12's claim, and a second instant here would
#: only introduce a way for the issuer's Session remainder to disagree with the record's own
#: `createdAt` for reasons this property is not about.
NOW_MS: Final = 1_700_000_000_000
NOW: Final = datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)

POLICY: Final = AdmissionPolicy(
    default_duration_seconds=3600,
    default_idle_seconds=300,
    default_suspended_seconds=600,
    default_auto_resume=True,
)

SETTINGS: Final = CreationSettings(
    memory_bytes=512 * 1024 * 1024,
    execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
    artifact_retention_days=7,
    reap_shard_count=8,
)

#: Read from a real provider rather than restated, so a boundary is a provider's boundary.
_LIMITS: Final = LocalFirecrackerProvider().limits()

#: The provider the handler is configured with. Its name reaches the Session row and the Sandbox
#: handle the modelled execution writes, so both name one provider.
PROVIDER_NAME: Final = LocalFirecrackerProvider.name

#: The integration timeout and the configured wait budget. The budget is a whole number of poll
#: intervals so the number of reads a wait performs is arithmetic rather than approximate: five
#: sleeps, which is one more than the four tasks a publication takes.
INTEGRATION_TIMEOUT_SECONDS: Final = 10.0
WAIT_BUDGET_SECONDS: Final = 1.0

#: An Affinity_Key of the shape a caller's agent framework supplies, carrying the sort-key delimiter
#: because the digest is what makes that safe.
AFFINITY_KEY: Final = "thread#9f3"

#: The recorded call names. Spelled once so the collaborators and the checker cannot disagree, and
#: the two that name protected operations are imported from the lint rules that protect them rather
#: than written out here.
ROW_WRITE_PUT: Final = "put_new_session"
ROW_WRITE_CLAIM: Final = "claim_binding"
START_EXECUTION: Final = "start_execution"
MARK_ORCHESTRATION_STARTED: Final = "mark_orchestration_started"
READ_SESSION: Final = "read_session"
READ_BINDING: Final = "read_binding"
LIMITS: Final = "limits"
PROVISION: Final = PROVISION_METHOD
RUN_HOOK: Final = "run-hook"
RUN_HOOK_RETURNED_200: Final = "run-hook-200"
MINT: Final = MINT_METHOD
PUBLISH_CONNECTION: Final = "publish-connection"
RECORD_PROVISIONED: Final = "record-provisioned"
RECORD_FAILED: Final = "record-failed"

#: The two spellings of step 2. Which one a creation uses is the only difference between the direct
#: path's plain conditional `Put` and the get-or-create path's two-item transaction.
ROW_WRITES: Final = frozenset({ROW_WRITE_PUT, ROW_WRITE_CLAIM})

#: The one provider attribute the creation path may reach. `name` is a field read rather than a call
#: and so is not recorded; everything else this provider is asked for is.
PERMITTED_HANDLER_PROVIDER_CALLS: Final = frozenset({LIMITS})


class Actor(Enum):
    """Who made a recorded call: the request handler, or the execution it started.

    Attribution is by *who was on the stack*, not by which object recorded it — the modelled
    execution sets the current actor for the duration of each task and the actor is the handler at
    every other moment. So a provider call or a mint the handler itself performed is recorded
    against the handler even though the handler and the execution share every collaborator.
    """

    HANDLER = "handler"
    ORCHESTRATION = "orchestration"


@dataclass(frozen=True, slots=True)
class Call:
    """One recorded call: who made it, what it was, and which Session it concerned."""

    actor: Actor
    name: str
    session_id: str | None = None


@dataclass
class CallLog:
    """The single ordered log both actors record into."""

    actor: Actor = Actor.HANDLER
    calls: list[Call] = field(default_factory=list)

    def record(self, name: str, session_id: str | None = None) -> None:
        self.calls.append(Call(actor=self.actor, name=name, session_id=session_id))

    @contextmanager
    def as_orchestration(self) -> Iterator[None]:
        """Attribute everything recorded inside this block to the started execution."""
        previous = self.actor
        self.actor = Actor.ORCHESTRATION
        try:
            yield
        finally:
            self.actor = previous


# --- The drawn dimensions -------------------------------------------------------------------


class Caller(Enum):
    """Which of the two callers of `CreationOperations.create` this creation went through.

    R6.11 is a claim about *every* Sandbox, so the get-or-create create branch is in the domain
    rather than being Property 35's business alone: it is the second caller of the one method that
    writes a Session row and starts an execution, and a claim about ordering that held for only one
    of them would be no claim at all.
    """

    DIRECT = "post-sessions"
    GET_OR_CREATE = "resolve-create-branch"


class FaultPoint(Enum):
    """Where this creation fails: an index over the handler's steps and the execution's tasks.

    Two of these are not failures of a call but the *handler ending between* two calls, which is the
    orphan window the design's ordering exists to bound. They are drawn separately from the calls
    that fail, because "the row write raised" and "the row was written and nothing followed" leave
    different evidence and only the second one leaves a row.
    """

    NONE = "none"
    #: Step 1 refuses the body, so nothing is written and nothing is started.
    ADMISSION = "admission"
    #: Step 2 raises. No row, and therefore no execution and no Sandbox.
    ROW_WRITE = "row-write"
    #: The handler ends between step 2 and step 3: a row in `PENDING` with no execution.
    AFTER_ROW_WRITE = "after-row-write"
    #: Step 3 raises. The row survives complete and `PENDING`, and no execution exists.
    START_EXECUTION = "start-execution"
    #: The handler ends between step 3 and the execution's first task. The execution proceeds.
    AFTER_START_EXECUTION = "after-start-execution"
    #: The credential was minted and the write publishing it failed.
    PUBLICATION = "publication"


#: The two fault points at which the handler ends rather than a call failing.
_HANDLER_DEATHS: Final = frozenset(
    {FaultPoint.AFTER_ROW_WRITE, FaultPoint.AFTER_START_EXECUTION}
)


class Stage(Enum):
    """The task of the modelled execution at which a provider outcome is observed."""

    PROVISION = "provision"
    RUN_HOOK = "run-hook"


@dataclass(frozen=True, slots=True)
class OrchestrationFailure:
    """A provider-side failure: where it surfaced, and the reason it is recorded under."""

    stage: Stage
    reason: str


class ProvisionOutcome(Enum):
    """The provider outcomes the design's `provision_outcome()` draws.

    Each non-success member carries a reason in the *provider's* wording rather than the
    Control_Plane's, which is what R6.8 and R6.14 require of a recorded reason: a quota exhaustion
    names the exhausted quota the provider named.
    """

    SUCCESS = "success"
    QUOTA_EXHAUSTED = "quota-exhausted"
    TRANSPORT_FAILURE = "transport-failure"
    CLAIM_COLLISION = "claim-collision"
    READINESS_TIMEOUT = "readiness-timeout"
    RUN_HOOK_REFUSED = "run-hook-refused"


PROVISION_FAILURES: Final[Mapping[ProvisionOutcome, OrchestrationFailure]] = {
    ProvisionOutcome.QUOTA_EXHAUSTED: OrchestrationFailure(
        Stage.PROVISION,
        "quota 'ConcurrentSandboxMemoryBytes' exhausted in dimension "
        "memory-bytes-per-region",
    ),
    ProvisionOutcome.TRANSPORT_FAILURE: OrchestrationFailure(
        Stage.PROVISION,
        "the Compute_Provider was unreachable while provisioning: connection reset by peer",
    ),
    ProvisionOutcome.CLAIM_COLLISION: OrchestrationFailure(
        Stage.PROVISION,
        "the Sandbox was already claimed by another Session",
    ),
    ProvisionOutcome.READINESS_TIMEOUT: OrchestrationFailure(
        Stage.RUN_HOOK,
        "the Sandbox did not become ready before the readiness deadline",
    ),
    ProvisionOutcome.RUN_HOOK_REFUSED: OrchestrationFailure(
        Stage.RUN_HOOK,
        "the /run hook returned 503 rather than 200",
    ),
}

#: The reason a publication failure is recorded under. Not a provider outcome: the Sandbox is up and
#: `/run` returned 200, and what failed is the write that would have told the caller so.
PUBLICATION_FAILED_REASON: Final = (
    "the connection credential could not be published to the State_Store"
)


class HandlerDied(Exception):
    """The handler's invocation ended between two steps, leaving whatever had committed.

    Not an error a caller sees. It stands in for the case the design's ordering is chosen to bound —
    a handler that stops existing partway through — so the property can assert that a failure at
    step N leaves none of step N+1's effects.
    """


#: Failures `StartExecution` and the row write can fail with. Ordinary error types rather than a
#: marker class of this file's own, because a failure the handler could recognise by type is not the
#: failure being modelled.
TRANSPORT_FAILURE_KINDS: Final = (ConnectionError, TimeoutError, OSError, RuntimeError)
TRANSPORT_FAILURE_MESSAGES: Final = (
    "connection reset by peer",
    "the call timed out",
    "",
)


@dataclass(frozen=True, slots=True)
class HandlerFailure:
    """A drawn failure of one of the handler's own calls."""

    kind: type[Exception]
    message: str

    def build(self) -> Exception:
        return self.kind(self.message)


#: The admissible `maxDurationSeconds` domain: absent, both declared bounds, and values between
#: them. Every one of these is admitted, so the fault-point axis is the only source of a rejection.
ADMITTED_DURATIONS: Final[tuple[int | None, ...]] = (
    None,
    _LIMITS.min_duration_seconds,
    _LIMITS.min_duration_seconds + 1,
    3600,
    _LIMITS.max_duration_seconds // 2,
    _LIMITS.max_duration_seconds - 1,
    _LIMITS.max_duration_seconds,
)

#: The admissible idle and suspended domain. R10.3's boundary is zero, so the smallest admitted
#: value sits directly above it.
ADMITTED_SHORT_DURATIONS: Final[tuple[int | None, ...]] = (None, 1, 2, 300, 86_400)

#: Declared port sets, including the empty set, duplicates, the boundary ports, and the control port
#: both alone and beside others — the credential's port set is the declared set together with the
#: control port, deduplicated, so a Session that declares it exercises that union collapsing.
ADMITTED_PORT_SETS: Final[tuple[tuple[int, ...] | None, ...]] = (
    None,
    (),
    (8080,),
    (9000, 8080),
    (8080, 8080),
    (1, 65_535),
    (SANDBOX_PROTOCOL_CONTROL_PORT,),
    (SANDBOX_PROTOCOL_CONTROL_PORT, 8080),
    (8080, 8081, 8082, 8083),
)

#: Tenant identifiers, all values `require_tenant_id` accepts. The partition the credential is
#: published under is derived from this, so it is drawn rather than fixed.
TENANTS: Final = ("tenant-a", "tenant-b", "T-0000000001", "tenant.with-punctuation")

#: ULID-shaped Session identifiers in the Crockford alphabet `new_session_id` draws from. Fixed
#: values rather than generated ones, so a shrunk counterexample names the same Session twice.
SESSION_IDS: Final = (
    "01JCREATIONAAAAAAAAAAAAAAA",
    "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
    "01JQPVXK9TG2MB4H7YWZ3NRSDF",
)

#: The body admission refuses, used by :attr:`FaultPoint.ADMISSION` alone.
REJECTED_BODY: Final[Mapping[str, Any]] = {
    MAX_DURATION_FIELD: _LIMITS.max_duration_seconds + 1
}


@dataclass(frozen=True, slots=True)
class CreationCase:
    """One drawn creation: the request, the deployment's contract, and the outcomes it meets."""

    body: Mapping[str, Any]
    tenant_id: str
    session_id: str
    caller: Caller
    contract: CreationContract
    fault: FaultPoint
    outcome: ProvisionOutcome
    publishes_in_budget: bool
    handler_failure: HandlerFailure

    @property
    def principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            caller_identity=f"arn:aws:sts::123456789012:assumed-role/C/{self.tenant_id}",
            tenant_id=self.tenant_id,
        )

    @property
    def operation(self) -> Operation:
        return (
            Operation.CREATE_SESSION
            if self.caller is Caller.DIRECT
            else Operation.RESOLVE_SESSION
        )

    @property
    def row_write(self) -> str:
        """The recorded name of step 2 on this caller's path."""
        return ROW_WRITE_PUT if self.caller is Caller.DIRECT else ROW_WRITE_CLAIM

    @property
    def request_body(self) -> Mapping[str, Any]:
        """The body as sent: the drawn one, or the refused one on the admission fault point."""
        body = dict(REJECTED_BODY if self.fault is FaultPoint.ADMISSION else self.body)
        if self.caller is Caller.GET_OR_CREATE:
            body[AFFINITY_KEY_FIELD] = AFFINITY_KEY
        return body

    @property
    def failure(self) -> OrchestrationFailure | None:
        """The provider-side failure this creation's execution meets, if any."""
        return PROVISION_FAILURES.get(self.outcome)

    def fails_at(self, stage: Stage) -> OrchestrationFailure | None:
        failure = self.failure
        return failure if failure is not None and failure.stage is stage else None

    @property
    def waits(self) -> bool:
        """Whether the deployment's contract has the handler wait for a credential at all."""
        return self.contract is CreationContract.SYNCHRONOUS

    @property
    def reaches_the_wait(self) -> bool:
        """Whether the handler survives its first three steps and reaches step 4 at all.

        A handler that ended at the row write or around `StartExecution` never waited, so nothing it
        did or failed to do can be a report of what the execution went on to do.
        """
        return self.fault in {FaultPoint.NONE, FaultPoint.PUBLICATION}

    @property
    def execution_runs_in_the_wait(self) -> bool:
        """Whether the execution advances while the handler is still waiting on the row."""
        return self.reaches_the_wait and self.waits and self.publishes_in_budget


# --- The generators -------------------------------------------------------------------------


def admitted_create_request() -> st.SearchStrategy[dict[str, Any]]:
    """Draw a `CreateSession` body across the space of bodies admission admits.

    Every field is drawn in three modes — omitted, present as null, and present with a value —
    because admission treats the first two alike and a client that serialises an unset option as
    null is the reason both must be reachable. Only admissible values are drawn: the rejection is a
    fault *point*, so it is quantified over as a position in the sequence rather than as a body.
    """
    return st.fixed_dictionaries(
        {},
        optional={
            MAX_DURATION_FIELD: st.sampled_from(ADMITTED_DURATIONS),
            IDLE_SECONDS_FIELD: st.sampled_from(ADMITTED_SHORT_DURATIONS),
            SUSPENDED_SECONDS_FIELD: st.sampled_from(ADMITTED_SHORT_DURATIONS),
            AUTO_RESUME_FIELD: st.one_of(st.none(), st.booleans()),
            EXPOSED_PORTS_FIELD: st.one_of(
                st.sampled_from(ADMITTED_PORT_SETS).map(
                    lambda ports: None if ports is None else list(ports)
                ),
                st.lists(st.integers(min_value=1, max_value=65_535), max_size=4),
            ),
        },
    )


def fault_point() -> st.SearchStrategy[FaultPoint]:
    """Draw the point at which this creation fails, including not failing at all."""
    return st.sampled_from(FaultPoint)


def provision_outcome() -> st.SearchStrategy[ProvisionOutcome]:
    """Draw what the Compute_Provider and the `/run` hook did inside the execution."""
    return st.sampled_from(ProvisionOutcome)


def creation_case() -> st.SearchStrategy[CreationCase]:
    """Draw a create request crossed with the fault point and the provider outcome it meets."""
    return st.builds(
        CreationCase,
        body=admitted_create_request(),
        tenant_id=st.sampled_from(TENANTS),
        session_id=st.sampled_from(SESSION_IDS),
        caller=st.sampled_from(Caller),
        contract=st.sampled_from(CreationContract),
        fault=fault_point(),
        outcome=provision_outcome(),
        publishes_in_budget=st.booleans(),
        handler_failure=st.builds(
            HandlerFailure,
            kind=st.sampled_from(TRANSPORT_FAILURE_KINDS),
            message=st.sampled_from(TRANSPORT_FAILURE_MESSAGES),
        ),
    )


# --- The collaborators ----------------------------------------------------------------------


@dataclass
class FaultInjector:
    """The one place a drawn fault is turned into a raised exception.

    The instance it raised is kept so the caller can recognise its own drawn failure and re-raise
    anything else. Catching the type would swallow a genuine defect that happened to be an
    `OSError`.
    """

    point: FaultPoint
    failure: HandlerFailure
    raised: BaseException | None = None

    def trip(self, point: FaultPoint) -> None:
        """Fail here if this is the drawn fault point, otherwise do nothing."""
        if self.point is not point:
            return
        error: Exception = (
            HandlerDied(f"the handler ended at {point.value}")
            if point in _HANDLER_DEATHS
            else self.failure.build()
        )
        self.raised = error
        raise error


def _unreached(*args: Any, **kwargs: Any) -> None:
    """What an unexpected provider attribute returns once its use has been recorded."""
    del args, kwargs


@dataclass
class InstrumentedProvider:
    """The Compute_Provider seam, recording every attribute anyone reaches for.

    `limits()` is the one call the creation path is permitted, and it is recorded like any other so
    the permission is asserted rather than assumed. Any other attribute falls through to
    `__getattr__`, which records it against whichever actor is on the stack — so a provisioning call
    from the handler under any spelling is caught by the property rather than only by the lint rule.

    :meth:`call` is how the modelled execution provisions. It takes the operation name as data, so
    the recorded name is the one `ci/lint_rules/orchestrated_provisioning.py` protects while this
    module contains no call for that rule to reject.
    """

    log: CallLog
    published_limits: ProviderLimits
    name: str = PROVIDER_NAME

    def limits(self) -> ProviderLimits:
        self.log.record(LIMITS)
        return self.published_limits

    def call(self, operation: str, *, session_id: str) -> None:
        """Perform a named provider operation for one Session, recording it in order."""
        self.log.record(operation, session_id)

    def __getattr__(self, attribute: str) -> Any:
        if attribute.startswith("_"):
            raise AttributeError(attribute)
        self.log.record(attribute)
        return _unreached


#: `S#`, the Session row sort-key prefix, assembled from the key module's own parts rather than
#: written out, so this file cannot disagree with the key structure it reads.
_SESSION_KEY_PREFIX: Final = f"{SESSION_PREFIX}{SEPARATOR}"


def _session_id_of(item: Mapping[str, Any]) -> str:
    """The Session identifier of a row item, read out of its sort key."""
    return _session_id_in(str(item[SORT_KEY_ATTRIBUTE]))


def _session_id_in(sort_key: str) -> str:
    """The Session identifier a Session row's sort key names."""
    return sort_key.split(SEPARATOR, 1)[-1]


@dataclass
class InstrumentedStore(FakeStore):
    """The State_Store, keyed as DynamoDB is, with every call recorded and ordered.

    `FakeStore` is imported rather than rewritten: it already serialises the conditional writes and
    the two-item transaction the get-or-create path needs, and both creation paths have to reach one
    store for the recorded sequence to be one sequence. What is added here is the actor-attributed
    log, the fault injection at the two handler-side write points, and the three writes the modelled
    execution performs.
    """

    calls: CallLog = field(default_factory=CallLog)
    faults: FaultInjector = field(
        default_factory=lambda: FaultInjector(
            point=FaultPoint.NONE, failure=HandlerFailure(RuntimeError, "")
        )
    )
    #: The lifecycle state on the row when the handler finished writing it. The response's own
    #: `lifecycleState` is compared against this, so the comparison is an observation of the row
    #: rather than a restatement of which state the handler chooses.
    state_after_mark: str | None = None
    published_key: tuple[str, str] | None = None

    # -- the handler's two writes -------------------------------------------------------------

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        self.calls.record(ROW_WRITE_PUT, _session_id_of(item))
        self.faults.trip(FaultPoint.ROW_WRITE)
        super().put_new_session(item)

    def claim_binding(
        self, *, session_item: Mapping[str, Any], binding_item: Mapping[str, Any]
    ) -> None:
        self.calls.record(ROW_WRITE_CLAIM, _session_id_of(session_item))
        self.faults.trip(FaultPoint.ROW_WRITE)
        super().claim_binding(session_item=session_item, binding_item=binding_item)

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        # Tripped before anything is recorded or written: the handler ended between `StartExecution`
        # returning and this update, so this update did not happen.
        self.faults.trip(FaultPoint.AFTER_START_EXECUTION)
        self.calls.record(MARK_ORCHESTRATION_STARTED, _session_id_in(start.sort_key))
        super().mark_orchestration_started(start)
        self.state_after_mark = str(
            self.items[(start.partition_key, start.sort_key)]["lifecycleState"]
        )

    # -- the reads ----------------------------------------------------------------------------

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.calls.record(READ_SESSION, _session_id_in(sort_key))
        return super().read_session(partition_key=partition_key, sort_key=sort_key)

    def read_binding(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.calls.record(READ_BINDING)
        return super().read_binding(partition_key=partition_key, sort_key=sort_key)

    # -- the three writes the execution performs ----------------------------------------------

    def record_provisioned(
        self, *, partition_key: str, session_id: str, handle: Mapping[str, str]
    ) -> None:
        """Name the Sandbox on the row, as the provisioning task does once it has one."""
        row = self._row(partition_key, session_id, RECORD_PROVISIONED)
        row["sandboxHandle"] = dict(handle)
        row["sandboxId"] = handle["sandboxId"]
        row["lifecycleState"] = LifecycleState.STARTING.value

    def publish_connection(
        self,
        *,
        partition_key: str,
        session_id: str,
        connection: ConnectionDescriptor,
    ) -> None:
        """Publish the credential onto the row inside the Session's Tenant scope (R6.12)."""
        row = self._row(partition_key, session_id, PUBLISH_CONNECTION)
        row["lifecycleState"] = LifecycleState.RUNNING.value
        row["connection"] = connection.to_map()
        row["connectionPublishedAt"] = NOW_MS
        self.published_key = (partition_key, session_sort_key(session_id))

    def record_failed(
        self, *, partition_key: str, session_id: str, reason: str
    ) -> None:
        """Record the Session failed with the reason identifying the failure (R6.14)."""
        row = self._row(partition_key, session_id, RECORD_FAILED)
        row["lifecycleState"] = LifecycleState.FAILED.value
        row["stateReason"] = reason

    def _row(self, partition_key: str, session_id: str, call: str) -> dict[str, Any]:
        key = (partition_key, session_sort_key(session_id))
        self.calls.record(call, session_id)
        self.keys_touched.append(key)
        return self.items[key]

    # -- what the checker reads ---------------------------------------------------------------

    def session_items(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            dict(item)
            for key, item in sorted(self.items.items())
            if key[1].startswith(_SESSION_KEY_PREFIX)
        )


@dataclass
class FaultInjectingStarter(RecordingStarter):
    """`StartExecution`, recorded, and failing at either of the two drawn points around it.

    `RecordingStarter` is imported rather than rewritten: it already behaves as Step Functions does
    for a repeated name, which is what makes "exactly one execution per Session" assertable. Arming
    the execution here rather than in the harness is the point — the modelled execution becomes
    advanceable only once a `StartExecution` has actually returned, so no task of it can run before
    one has (R6.11).
    """

    calls: CallLog = field(default_factory=CallLog)
    faults: FaultInjector = field(
        default_factory=lambda: FaultInjector(
            point=FaultPoint.NONE, failure=HandlerFailure(RuntimeError, "")
        )
    )
    driver: WaitDriver | None = None
    execution: Orchestration | None = None

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        # The handler ended between the row write and this call, so this call was never issued and
        # is not recorded.
        self.faults.trip(FaultPoint.AFTER_ROW_WRITE)
        self.calls.record(START_EXECUTION, str(payload["sessionId"]))
        self.faults.trip(FaultPoint.START_EXECUTION)
        arn = super().start_execution(name=name, payload=payload)
        if self.driver is not None:
            self.driver.execution = self.execution
        return arn


@dataclass
class WaitDriver:
    """The monotonic clock, the sleep and the jitter draw the polling wait runs on.

    The world moves while the handler waits, and this is where that happens: one task of the started
    execution runs per sleep. So a publication inside the budget and a publication after it are the
    same model driven for a different number of intervals, with no thread whose outcome depends on
    the scheduler and no wall clock anywhere.

    `frozen` is the arm in which nothing advances during the wait, which is how the budget is made to
    expire; the execution is then drained after the handler has returned, because an execution
    outlives the request that started it.
    """

    frozen: bool = False
    now: float = 0.0
    execution: Orchestration | None = None

    def read(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        if self.frozen or self.execution is None:
            return
        self.execution.advance()

    def jitter(self, low: float, high: float) -> float:
        """The midpoint of the interval the wait asked for: inside the contract, and fixed."""
        return (low + high) / 2


class Task(Enum):
    """The four ordered tasks of the modelled Session_Orchestrator execution."""

    PROVISION = "provision"
    RUN_HOOK = "run-hook"
    MINT = "mint"
    PUBLISH = "publish"


@dataclass
class Orchestration:
    """The execution, as the design's provisioning tasks in the order the requirements fix them.

    Provision, `/run`, mint, publish. The order is the substance: nothing provisions until this
    object has been armed by a returned `StartExecution` (R6.11), and nothing is published until
    `/run` has returned 200 (R6.12), so the mint is a separate task rather than folded into the
    publication.
    """

    case: CreationCase
    log: CallLog
    store: InstrumentedStore
    provider: InstrumentedProvider
    issuer: ConnectionIssuer
    partition_key: str
    remaining: list[Task] = field(default_factory=lambda: list(Task))
    mints: int = 0
    stopped: bool = False
    minted: ConnectionDescriptor | None = None

    def advance(self) -> None:
        """Run the next task, if this execution has one left and has not failed."""
        if self.stopped or not self.remaining:
            return
        task = self.remaining.pop(0)
        with self.log.as_orchestration():
            self._perform(task)

    def drain(self) -> None:
        """Run every remaining task, standing in for an execution outliving its request."""
        while not self.stopped and self.remaining:
            self.advance()

    def _perform(self, task: Task) -> None:
        if task is Task.PROVISION:
            self._provision()
        elif task is Task.RUN_HOOK:
            self._run_hook()
        elif task is Task.MINT:
            self._mint()
        else:
            self._publish()

    def _provision(self) -> None:
        session_id = self.case.session_id
        self.provider.call(PROVISION, session_id=session_id)
        failure = self.case.fails_at(Stage.PROVISION)
        if failure is not None:
            self._fail(failure.reason)
            return
        self.store.record_provisioned(
            partition_key=self.partition_key,
            session_id=session_id,
            handle={
                "providerName": PROVIDER_NAME,
                "sandboxId": f"sandbox-{session_id}",
                "vm": "1",
            },
        )

    def _run_hook(self) -> None:
        session_id = self.case.session_id
        self.log.record(RUN_HOOK, session_id)
        failure = self.case.fails_at(Stage.RUN_HOOK)
        if failure is not None:
            self._fail(failure.reason)
            return
        self.log.record(RUN_HOOK_RETURNED_200, session_id)

    def _mint(self) -> None:
        session_id = self.case.session_id
        item = self.store.read_session(
            partition_key=self.partition_key, sort_key=session_sort_key(session_id)
        )
        if item is None:  # pragma: no cover - the row is written before the execution
            raise AssertionError(f"no Session row to mint against: {session_id}")
        self.log.record(MINT, session_id)
        self.minted = self.issuer.issue(SessionRecord.from_item(item))
        self.mints += 1

    def _publish(self) -> None:
        if self.case.fault is FaultPoint.PUBLICATION:
            self._fail(PUBLICATION_FAILED_REASON)
            return
        if self.minted is None:  # pragma: no cover - the mint task precedes this one
            raise AssertionError("nothing was minted to publish")
        self.store.publish_connection(
            partition_key=self.partition_key,
            session_id=self.case.session_id,
            connection=self.minted,
        )

    def _fail(self, reason: str) -> None:
        self.store.record_failed(
            partition_key=self.partition_key,
            session_id=self.case.session_id,
            reason=reason,
        )
        self.stopped = True


# --- What one creation left behind ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReportedError:
    """How the handler ended, when it did not return a response."""

    #: `"admission"`, `"provisioning-failed"` or `"drawn-fault"`.
    kind: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Observation:
    """The evidence one creation leaves, and the whole input of the checker."""

    calls: tuple[Call, ...]
    executions: tuple[str, ...]
    rows: tuple[Mapping[str, Any], ...]
    row_when_returned: Mapping[str, Any] | None
    state_after_mark: str | None
    published_key: tuple[str, str] | None
    keys_touched: tuple[tuple[str, str], ...]
    payload: Mapping[str, Any] | None
    status: int | None
    error: ReportedError | None
    mints_performed: int
    mints_by_the_execution: int

    def names(self, actor: Actor | None = None) -> tuple[str, ...]:
        """The recorded call names, optionally restricted to one actor's own calls."""
        return tuple(
            call.name for call in self.calls if actor is None or call.actor is actor
        )


def _wait_settings(case: CreationCase) -> CreationWaitSettings:
    return CreationWaitSettings(
        contract=case.contract,
        integration_timeout_seconds=INTEGRATION_TIMEOUT_SECONDS,
        wait_budget_seconds=WAIT_BUDGET_SECONDS,
    )


def observe(case: CreationCase) -> Observation:
    """Run one creation through the drawn caller and record everything both actors did."""
    log = CallLog()
    faults = FaultInjector(point=case.fault, failure=case.handler_failure)
    principal = case.principal
    partition_key = pk_for(principal)

    store = InstrumentedStore(calls=log, faults=faults)
    provider = InstrumentedProvider(log=log, published_limits=_LIMITS)
    # One mint behind both issuers, so a credential minted anywhere is counted once and attributed.
    mint = RecordingMint(now=NOW)
    issuer = ConnectionIssuer(mint=mint, policy=CredentialPolicy(), clock=lambda: NOW)
    driver = WaitDriver(frozen=not case.publishes_in_budget)
    execution = Orchestration(
        case=case,
        log=log,
        store=store,
        provider=provider,
        issuer=issuer,
        partition_key=partition_key,
    )
    starter = FaultInjectingStarter(
        calls=log, faults=faults, driver=driver, execution=execution
    )
    creation = CreationOperations(
        provider=cast("ComputeProvider", provider),
        policy=POLICY,
        settings=SETTINGS,
        store=store,
        orchestration=starter,
        wait=wait_for_contract(
            _wait_settings(case),
            lookup=store,
            clock=driver.read,
            sleep=driver.sleep,
            jitter=driver.jitter,
        ),
        clock=lambda: NOW,
        session_ids=lambda: case.session_id,
    )
    request = OperationRequest(
        operation=case.operation, principal=principal, body=case.request_body
    )

    result: OperationResult | None = None
    error: ReportedError | None = None
    try:
        result = _invoke(case, creation, store, issuer, request)
    except SessionAdmissionRejected:
        error = ReportedError(kind="admission")
    except SessionProvisioningFailed as failed:
        error = ReportedError(kind="provisioning-failed", reason=failed.reason)
    except Exception as raised:
        if raised is not faults.raised:
            raise
        error = ReportedError(kind="drawn-fault")

    # Snapshotted before the drain: the descriptor a caller received has to equal the one on the row
    # at the moment it was handed over, not the one a later publication put there.
    row_when_returned = _session_row(store, partition_key, case.session_id)
    if starter.executions:
        # An execution outlives the request that started it, whether or not the handler waited.
        execution.drain()

    return Observation(
        calls=tuple(log.calls),
        executions=tuple(sorted(starter.executions)),
        rows=store.session_items(),
        row_when_returned=row_when_returned,
        state_after_mark=store.state_after_mark,
        published_key=store.published_key,
        keys_touched=tuple(store.keys_touched),
        payload=None if result is None else dict(result.payload),
        status=None if result is None else result.status,
        error=error,
        mints_performed=len(mint.calls),
        mints_by_the_execution=execution.mints,
    )


def _invoke(
    case: CreationCase,
    creation: CreationOperations,
    store: InstrumentedStore,
    issuer: ConnectionIssuer,
    request: OperationRequest,
) -> OperationResult:
    """Dispatch to the drawn caller of `create`.

    The resolution operation is handed the *same* issuer, so its create branch minting a credential
    of its own — which R6.13 forbids — would be counted as a mint the execution did not perform.
    """
    if case.caller is Caller.DIRECT:
        return creation.create_session(request)
    return ResolutionOperations(
        creation=creation, bindings=store, lookup=store, issuer=issuer
    ).resolve_session(request)


def _session_row(
    store: InstrumentedStore, partition_key: str, session_id: str
) -> Mapping[str, Any] | None:
    item = store.items.get((partition_key, session_sort_key(session_id)))
    return None if item is None else dict(item)


# --- The checker ----------------------------------------------------------------------------

#: The response fields each caller's payload may carry, and no others. `generation` and the
#: resolution outcome belong to the get-or-create response shape alone.
PAYLOAD_FIELDS: Final[Mapping[Caller, frozenset[str]]] = {
    Caller.DIRECT: frozenset({"sessionId", "lifecycleState", "connection"}),
    Caller.GET_OR_CREATE: frozenset(
        {"sessionId", "generation", "lifecycleState", "connection", RESOLUTION_FIELD}
    ),
}


def violations(observed: Observation, case: CreationCase) -> tuple[str, ...]:
    """Every way this observation falls short of Property 34, in one pass.

    Returned rather than asserted one at a time, so a counterexample reports the whole shortfall
    instead of only whichever conjunct happened to be checked first.
    """
    faults: list[str] = []
    faults.extend(_ordering_faults(observed, case))
    faults.extend(_execution_faults(observed, case))
    faults.extend(_publication_faults(observed, case))
    faults.extend(_reporting_faults(observed, case))
    faults.extend(_orphan_faults(observed, case))
    faults.extend(_failure_reason_faults(observed, case))
    return tuple(faults)


def _first(observed: Observation, name: str) -> int | None:
    names = observed.names()
    return names.index(name) if name in names else None


def _ordering_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """The row before the execution, the execution before every Sandbox (R6.10, R6.11)."""
    row_write = _first(observed, case.row_write)
    started = _first(observed, START_EXECUTION)
    if started is not None and (row_write is None or row_write > started):
        yield (
            f"the execution was started before the Session row was written: "
            f"{list(observed.names())}"
        )

    for index, call in enumerate(observed.calls):
        if call.name != PROVISION:
            continue
        if call.actor is Actor.HANDLER:
            yield f"the handler provisioned a Sandbox itself, at call {index}"
        if not _started_before(observed, index, call.session_id):
            yield (
                f"a Sandbox was provisioned for Session {call.session_id} with no "
                f"successful StartExecution before it: {list(observed.names())}"
            )

    handler_provider_calls = {
        call.name
        for call in observed.calls
        if call.actor is Actor.HANDLER and call.name not in _STORE_AND_STARTER_CALLS
    }
    unexpected = handler_provider_calls - PERMITTED_HANDLER_PROVIDER_CALLS
    if unexpected:
        yield f"the handler reached the Compute_Provider for {sorted(unexpected)}"


#: The recorded names that belong to the State_Store and the orchestration starter rather than to
#: the Compute_Provider. Anything else the handler is recorded as calling was a provider call.
_STORE_AND_STARTER_CALLS: Final = frozenset(
    {
        ROW_WRITE_PUT,
        ROW_WRITE_CLAIM,
        MARK_ORCHESTRATION_STARTED,
        READ_SESSION,
        READ_BINDING,
        START_EXECUTION,
        PUBLISH_CONNECTION,
        RECORD_PROVISIONED,
        RECORD_FAILED,
    }
)


def _started_before(observed: Observation, index: int, session_id: str | None) -> bool:
    """Whether a successful `StartExecution` for this Session precedes call `index`."""
    return any(
        call.name == START_EXECUTION
        and call.session_id == session_id
        and execution_name_for(str(session_id)) in observed.executions
        for call in observed.calls[:index]
    )


def _execution_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """Exactly one execution per created Session, named for that Session (R6.10)."""
    expected_name = execution_name_for(case.session_id)
    for name in observed.executions:
        if name != expected_name:
            yield f"an execution named {name!r} was started, not {expected_name!r}"
    started_ok = case.fault not in {
        FaultPoint.ADMISSION,
        FaultPoint.ROW_WRITE,
        FaultPoint.AFTER_ROW_WRITE,
        FaultPoint.START_EXECUTION,
    }
    wanted = 1 if started_ok else 0
    if len(observed.executions) != wanted:
        yield (
            f"{len(observed.executions)} execution(s) exist for one Session, expected "
            f"{wanted} at fault point {case.fault.value}"
        )
    if len(observed.rows) > 1:
        yield f"{len(observed.rows)} Session rows exist for one creation"


def _publication_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """The credential follows a 200 from `/run`, and lands in this Session's partition (R6.12)."""
    published = _first(observed, PUBLISH_CONNECTION)
    ready = _first(observed, RUN_HOOK_RETURNED_200)
    if published is not None and ready is None:
        yield "a credential was published although /run never returned 200"
    if published is not None and ready is not None and published < ready:
        yield f"the credential was published before /run returned 200: {published} < {ready}"
    if ready is None and any("connection" in row for row in observed.rows):
        yield "a row carries a connection credential although /run never returned 200"

    partition_key = pk_for(case.principal)
    if published is not None:
        wanted = (partition_key, session_sort_key(case.session_id))
        if observed.published_key != wanted:
            yield (
                f"the credential was published at {observed.published_key!r}, not under "
                f"this Session's own Tenant partition {wanted!r}"
            )
    foreign = {key for key in observed.keys_touched if key[0] != partition_key}
    if foreign:
        yield f"keys outside the caller's partition were touched: {sorted(foreign)}"


def _reporting_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """The response is derived from the record and from nothing else (R6.13)."""
    if observed.mints_performed != observed.mints_by_the_execution:
        yield (
            f"{observed.mints_performed} credential(s) were minted but the execution "
            f"performed {observed.mints_by_the_execution}, so the handler minted one itself"
        )
    payload = observed.payload
    if payload is None:
        return

    unexpected = set(payload) - PAYLOAD_FIELDS[case.caller]
    if unexpected:
        yield f"the response carries fields outside the record's: {sorted(unexpected)}"
    row = observed.row_when_returned
    if row is None:
        yield "a response was returned for a Session with no row in the store"
        return
    if payload.get("sessionId") != _session_id_of(row):
        yield f"the response names Session {payload.get('sessionId')!r}, not the row's"
    if payload.get("lifecycleState") != observed.state_after_mark:
        yield (
            f"the response reports lifecycle state {payload.get('lifecycleState')!r}, "
            f"which is not the {observed.state_after_mark!r} the handler wrote"
        )
    if case.caller is Caller.GET_OR_CREATE:
        if payload.get(RESOLUTION_FIELD) != ResolutionOutcome.CREATED.value:
            yield f"the response reports {payload.get(RESOLUTION_FIELD)!r}, not a creation"
        if payload.get("generation") != row.get("generation"):
            yield "the response's generation is not the row's"

    connection = payload.get("connection")
    wanted_status = (
        HTTPStatus.CREATED if connection is not None else HTTPStatus.ACCEPTED
    )
    if observed.status != wanted_status:
        yield f"the response status was {observed.status}, expected {int(wanted_status)}"
    if connection is None:
        if "connection" in row:
            yield "the row carried a published credential the response omitted"
        return
    if connection != row.get("connection"):
        yield (
            "the descriptor the response carries is not the one published on the row: "
            f"{connection!r} against {row.get('connection')!r}"
        )
    try:
        ConnectionDescriptor.from_map(connection)
    except (ItemShapeError, ValueError) as error:
        yield f"the returned descriptor is not a whole connection descriptor: {error}"


def _orphan_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """A failure at step N leaves none of step N+1's effects."""
    names = set(observed.names())
    if case.fault is FaultPoint.ADMISSION:
        if names - {LIMITS}:
            yield f"a refused request reached {sorted(names - {LIMITS})}"
        if observed.rows:
            yield f"a refused request left {len(observed.rows)} row(s) in the store"
        return

    if case.fault is FaultPoint.ROW_WRITE:
        if observed.rows:
            yield "a failed row write left a Session row behind"
        for forbidden in (START_EXECUTION, PROVISION, MINT, PUBLISH_CONNECTION):
            if forbidden in names:
                yield f"a failed row write was followed by {forbidden}"
        return

    if len(observed.rows) != 1:
        yield f"the store holds {len(observed.rows)} Session rows, not one"
        return
    row = observed.rows[0]
    try:
        SessionRecord.from_item(row)
    except (ItemShapeError, ValueError) as error:
        yield f"the row left in the store is not a whole Session record: {error}"
        return

    if case.fault is FaultPoint.AFTER_ROW_WRITE:
        if names & {START_EXECUTION, PROVISION, MINT, PUBLISH_CONNECTION}:
            yield (
                "the handler ended before StartExecution, yet the log carries "
                f"{sorted(names & {START_EXECUTION, PROVISION, MINT, PUBLISH_CONNECTION})}"
            )
        yield from _no_execution_recorded(
            row, "the handler ended before StartExecution"
        )
        return

    if case.fault is FaultPoint.START_EXECUTION:
        if names & {PROVISION, MINT, PUBLISH_CONNECTION}:
            yield (
                "StartExecution failed, yet the log carries "
                f"{sorted(names & {PROVISION, MINT, PUBLISH_CONNECTION})}"
            )
        yield from _no_execution_recorded(row, "StartExecution failed")
        return

    if case.fault is FaultPoint.AFTER_START_EXECUTION:
        yield from _no_execution_recorded(
            row, "the handler ended before recording the execution"
        )
        if observed.payload is not None:
            yield "the handler returned a response after ending mid-creation"
        return

    if case.fault is FaultPoint.PUBLICATION and "connection" in row:
        yield "a failed publication left a credential on the row"


def _no_execution_recorded(row: Mapping[str, Any], because: str) -> Iterator[str]:
    """The row records no governing execution, which is what makes it the Reaper's to reclaim."""
    if row.get("orchestrationExecutionArn") is not None:
        yield f"{because}, yet the row names an execution"
    if row.get("lifecycleState") not in {
        LifecycleState.PENDING.value,
        LifecycleState.STARTING.value,
        LifecycleState.RUNNING.value,
        LifecycleState.FAILED.value,
    }:
        yield f"{because}, and the row is {row.get('lifecycleState')!r}"


def _failure_reason_faults(observed: Observation, case: CreationCase) -> Iterator[str]:
    """A failed provisioning is terminal with a reason, and the error names it (R6.14)."""
    expected = _expected_reason(case)
    if expected is None:
        return
    row = observed.rows[0] if observed.rows else None
    if row is None:
        yield "a failed provisioning left no row to record the failure on"
        return
    if not _reached_the_execution(case):
        return
    if row.get("lifecycleState") != LifecycleState.FAILED.value:
        yield (
            f"provisioning failed, yet the row is {row.get('lifecycleState')!r} rather "
            f"than {LifecycleState.FAILED.value}"
        )
    if row.get("stateReason") != expected:
        yield (
            f"the recorded reason is {row.get('stateReason')!r}, which does not name the "
            f"failure {expected!r}"
        )
    if "connection" in row:
        yield "a failed provisioning left a credential on the row"

    if not case.execution_runs_in_the_wait:
        # The handler had already returned, or never waited, so the failure is on the row alone.
        return
    if observed.error is None or observed.error.kind != "provisioning-failed":
        yield (
            "provisioning failed inside the wait, yet the handler did not report it: "
            f"{observed.error!r}"
        )
    elif observed.error.reason != expected:
        yield (
            f"the handler's error names {observed.error.reason!r} rather than the "
            f"recorded reason {expected!r}"
        )


def _expected_reason(case: CreationCase) -> str | None:
    """The reason this creation's execution records, or `None` when it records none."""
    if not _reached_the_execution(case):
        return None
    if case.failure is not None:
        return case.failure.reason
    if case.fault is FaultPoint.PUBLICATION:
        return PUBLICATION_FAILED_REASON
    return None


def _reached_the_execution(case: CreationCase) -> bool:
    """Whether a `StartExecution` returned, so the execution's tasks could run at all."""
    return case.fault not in {
        FaultPoint.ADMISSION,
        FaultPoint.ROW_WRITE,
        FaultPoint.AFTER_ROW_WRITE,
        FaultPoint.START_EXECUTION,
    }


# --- The property ---------------------------------------------------------------------------

#: Seven fault points crossed with six provider outcomes, two contracts, two callers and two
#: publication timings is 336 cells before the body space is counted, so the design's floor of 100
#: would leave most of the cross product unvisited. Every example is a few dozen dictionary
#: operations against an in-process store — no subprocess, no socket, no sleep — so four times the
#: floor costs a fraction of the suite's 300 second budget.
EXAMPLES: Final = 4 * MINIMUM_EXAMPLES


# Feature: aws-serverless-agent-sandbox, Property 34: For all create requests, for all
# fault-injection points over the Control_Plane handler's steps, and for all provider outcomes, the
# recorded call sequence contains no provision call that is not preceded by a successful
# StartExecution for the same Session; a Sandbox provisioned for a Session carries a published
# connection credential written under that Session's Tenant partition only after its /run hook
# returned 200; the descriptor the handler returns is equal to the published one and the handler's
# own call log contains no issue_connection; and when provisioning fails, the Session record is
# terminal with a reason naming the failure mode and the handler's error names that same reason.
@given(case=creation_case())
@settings(max_examples=EXAMPLES)
def test_creation_orders_the_execution_before_the_sandbox(case: CreationCase) -> None:
    observed = observe(case)
    faults = violations(observed, case)
    assert not faults, (
        f"caller={case.caller.value} contract={case.contract.value} "
        f"fault={case.fault.value} outcome={case.outcome.value} "
        f"in-budget={case.publishes_in_budget} body={dict(case.body)!r}: "
        + "; ".join(faults)
    )


# --- The oracles, which draw nothing --------------------------------------------------------

#: One body every rule admits, carrying a port set the control port is not in, so the credential's
#: port set is the union rather than either side of it.
ADMITTED_BODY: Final[Mapping[str, Any]] = {
    MAX_DURATION_FIELD: 7200,
    IDLE_SECONDS_FIELD: 300,
    EXPOSED_PORTS_FIELD: [9000, 8080, 9000],
}


def case_for(
    *,
    caller: Caller = Caller.DIRECT,
    contract: CreationContract = CreationContract.SYNCHRONOUS,
    fault: FaultPoint = FaultPoint.NONE,
    outcome: ProvisionOutcome = ProvisionOutcome.SUCCESS,
    publishes_in_budget: bool = True,
) -> CreationCase:
    """One case with everything but the named dimensions held fixed."""
    return CreationCase(
        body=ADMITTED_BODY,
        tenant_id=TENANTS[0],
        session_id=SESSION_IDS[0],
        caller=caller,
        contract=contract,
        fault=fault,
        outcome=outcome,
        publishes_in_budget=publishes_in_budget,
        handler_failure=HandlerFailure(ConnectionError, "connection reset by peer"),
    )


def test_the_happy_path_publishes_then_reports_in_that_order() -> None:
    """The sequence the requirements fix, read off one log for both callers.

    This is the arm every other arm is a truncation of, so the whole order is asserted by name:
    admission reads the provider's limits, the row is written, the execution starts, and only then
    does anything provision, run, mint and publish — after which the handler returns the descriptor
    it read from the row.
    """
    for caller in Caller:
        case = case_for(caller=caller)
        observed = observe(case)
        assert violations(observed, case) == (), caller

        # The wait reads the row once before its first sleep, and one task of the execution runs per
        # sleep after that, so a read separates every pair of tasks.
        assert observed.names() == (
            LIMITS,
            case.row_write,
            START_EXECUTION,
            MARK_ORCHESTRATION_STARTED,
            READ_SESSION,
            PROVISION,
            RECORD_PROVISIONED,
            READ_SESSION,
            RUN_HOOK,
            RUN_HOOK_RETURNED_200,
            READ_SESSION,
            # The mint task reads the row it mints against, which is where the Sandbox handle the
            # credential names comes from.
            READ_SESSION,
            MINT,
            READ_SESSION,
            PUBLISH_CONNECTION,
            READ_SESSION,
        ), caller
        assert observed.status == HTTPStatus.CREATED, caller
        assert observed.payload is not None
        assert observed.payload["connection"] == observed.rows[0]["connection"], caller
        # The credential is scoped to the declared ports together with the control port, which is
        # the one thing the drawn port sets vary and the response has to carry unchanged.
        assert observed.payload["connection"]["ports"] == [
            SANDBOX_PROTOCOL_CONTROL_PORT,
            8080,
            9000,
        ], caller
        assert observed.mints_performed == 1, caller
        assert observed.mints_by_the_execution == 1, caller


def test_every_drawn_arm_is_reached_by_name() -> None:
    """Each fault point and each provider outcome, entered by construction and identified.

    A property whose failure arms were unreachable would pass while asserting only the success path,
    and nothing in a passing Hypothesis run says which arms it visited. So each arm is entered here
    and its distinguishing evidence is asserted.
    """
    for fault, outcome, caller in itertools.product(
        tuple(FaultPoint), tuple(ProvisionOutcome), tuple(Caller)
    ):
        case = case_for(fault=fault, outcome=outcome, caller=caller)
        observed = observe(case)
        arm = f"fault={fault.value} outcome={outcome.value} caller={caller.value}"
        assert violations(observed, case) == (), arm

        names = set(observed.names())
        if fault is FaultPoint.ADMISSION:
            assert observed.error == ReportedError(kind="admission"), arm
            assert observed.rows == (), arm
        elif fault is FaultPoint.ROW_WRITE:
            assert observed.error == ReportedError(kind="drawn-fault"), arm
            assert observed.rows == (), arm
            assert START_EXECUTION not in names, arm
        elif fault in _HANDLER_DEATHS:
            assert observed.error == ReportedError(kind="drawn-fault"), arm
            assert observed.payload is None, arm
            assert len(observed.rows) == 1, arm
        elif fault is FaultPoint.START_EXECUTION:
            assert observed.error == ReportedError(kind="drawn-fault"), arm
            assert observed.executions == (), arm
            assert PROVISION not in names, arm
        elif outcome is not ProvisionOutcome.SUCCESS:
            # The provider outcome is met before the publication is reached, so it decides the
            # recorded reason whatever the fault point downstream of it was drawn as.
            failure = PROVISION_FAILURES[outcome]
            assert observed.rows[0]["stateReason"] == failure.reason, arm
            assert (RUN_HOOK in names) is (failure.stage is Stage.RUN_HOOK), arm
            assert PUBLISH_CONNECTION not in names, arm
            assert observed.error is not None, arm
            assert observed.error.reason == failure.reason, arm
        elif fault is FaultPoint.PUBLICATION:
            assert PROVISION in names and MINT in names, arm
            assert PUBLISH_CONNECTION not in names, arm
            assert observed.rows[0]["stateReason"] == PUBLICATION_FAILED_REASON, arm
        else:
            assert observed.status == HTTPStatus.CREATED, arm


def test_the_asynchronous_contract_reports_no_credential_and_loses_no_work() -> None:
    """R10.14: an absent `connection` is the contract's own shape, never a failure.

    The execution still provisions and still publishes; what the asynchronous contract removes is the
    wait, not the data path, so the credential is on the row afterwards and the caller polls for it.
    """
    case = case_for(contract=CreationContract.ASYNCHRONOUS)
    observed = observe(case)

    assert violations(observed, case) == ()
    assert observed.status == HTTPStatus.ACCEPTED
    assert observed.payload is not None
    assert "connection" not in observed.payload
    assert observed.row_when_returned is not None
    assert "connection" not in observed.row_when_returned
    # Nothing was lost: the row and the execution both preceded the response.
    assert observed.executions == (execution_name_for(case.session_id),)
    assert "connection" in observed.rows[0]
    assert observed.published_key == (
        pk_for(case.principal),
        session_sort_key(case.session_id),
    )


def test_a_publication_after_the_budget_is_the_same_fallback_and_not_an_error() -> None:
    """The synchronous contract's budget expiring degrades to the asynchronous shape."""
    case = case_for(publishes_in_budget=False)
    observed = observe(case)

    assert violations(observed, case) == ()
    assert observed.status == HTTPStatus.ACCEPTED
    assert observed.payload is not None
    assert "connection" not in observed.payload
    # Six reads by the wait — one before the first sleep and one after each of the five intervals
    # the budget affords — and a seventh by the mint task once the execution ran.
    assert observed.names().count(READ_SESSION) == 7
    assert "connection" in observed.rows[0]


def test_the_provider_outcome_table_covers_every_non_success_outcome() -> None:
    """An outcome added to the drawn set without a recorded reason fails here."""
    assert set(PROVISION_FAILURES) == set(ProvisionOutcome) - {ProvisionOutcome.SUCCESS}
    assert {failure.stage for failure in PROVISION_FAILURES.values()} == set(Stage)


def test_the_checker_rejects_an_execution_started_before_the_row() -> None:
    """The ordering inversion R6.10 exists to exclude."""
    case = case_for()
    observed = observe(case)
    assert violations(observed, case) == ()

    inverted = replace(
        observed,
        calls=tuple(
            sorted(
                observed.calls,
                key=lambda call: 0 if call.name == START_EXECUTION else 1,
            )
        ),
    )
    faults = violations(inverted, case)
    assert any("started before the Session row" in fault for fault in faults), faults


def test_the_checker_rejects_a_sandbox_provisioned_with_no_execution_behind_it() -> (
    None
):
    """R6.11's whole content: a Sandbox that no started execution governs."""
    case = case_for()
    observed = observe(case)

    ungoverned = replace(observed, executions=())
    faults = violations(ungoverned, case)
    assert any("no successful StartExecution before it" in f for f in faults), faults

    by_the_handler = replace(
        observed,
        calls=tuple(
            replace(call, actor=Actor.HANDLER) if call.name == PROVISION else call
            for call in observed.calls
        ),
    )
    faults = violations(by_the_handler, case)
    assert any("the handler provisioned a Sandbox itself" in f for f in faults), faults


def test_the_checker_rejects_a_credential_published_before_run_returned_200() -> None:
    """R6.12: the 200 is what makes the Sandbox reachable, so it cannot follow the publication."""
    case = case_for()
    observed = observe(case)
    reordered = tuple(
        call for call in observed.calls if call.name != RUN_HOOK_RETURNED_200
    ) + (Call(actor=Actor.ORCHESTRATION, name=RUN_HOOK_RETURNED_200),)

    faults = violations(replace(observed, calls=reordered), case)
    assert any("published before /run returned 200" in fault for fault in faults), (
        faults
    )


def test_the_checker_rejects_a_credential_published_outside_the_tenant_partition() -> (
    None
):
    """R6.12's scope half, asserted over the key the publication addressed."""
    case = case_for()
    observed = observe(case)
    # Another Tenant's partition, produced by the sole producer rather than spelled out, so this
    # test cannot disagree with the key structure it is asserting about.
    somebody_else = pk_for(replace(case, tenant_id=TENANTS[1]).principal)
    elsewhere = replace(
        observed, published_key=(somebody_else, session_sort_key(case.session_id))
    )

    faults = violations(elsewhere, case)
    assert any("not under this Session's own Tenant" in fault for fault in faults), (
        faults
    )


def test_the_checker_rejects_a_response_the_record_does_not_support() -> None:
    """R6.13: a descriptor the row does not carry, and a mint the handler performed itself."""
    case = case_for()
    observed = observe(case)
    assert observed.payload is not None

    invented = dict(observed.payload)
    invented["connection"] = dict(observed.payload["connection"]) | {
        "authHeaderValue": "fake-token-the-row-never-carried"
    }
    faults = violations(replace(observed, payload=invented), case)
    assert any("is not the one published on the row" in f for f in faults), faults

    minted_twice = replace(observed, mints_performed=observed.mints_performed + 1)
    faults = violations(minted_twice, case)
    assert any("the handler minted one itself" in fault for fault in faults), faults

    borrowed = dict(observed.payload) | {"sessionId": "01JSOMEOTHERSESSIONAAAAAAA"}
    faults = violations(replace(observed, payload=borrowed), case)
    assert any("not the row's" in fault for fault in faults), faults


def test_the_checker_rejects_a_failure_the_row_and_the_error_disagree_about() -> None:
    """R6.14: one reason, recorded on the row and repeated by the error."""
    case = case_for(outcome=ProvisionOutcome.QUOTA_EXHAUSTED)
    observed = observe(case)
    assert violations(observed, case) == ()

    silent = replace(
        observed,
        rows=tuple(
            {key: value for key, value in row.items() if key != "stateReason"}
            for row in observed.rows
        ),
    )
    faults = violations(silent, case)
    assert any("does not name the failure" in fault for fault in faults), faults

    reworded = replace(
        observed, error=ReportedError(kind="provisioning-failed", reason="it broke")
    )
    faults = violations(reworded, case)
    assert any("rather than the recorded reason" in fault for fault in faults), faults


def test_the_checker_rejects_an_orphan_left_by_a_failed_step() -> None:
    """A failure at step N leaving step N+1's effects, at each of the two write points."""
    refused = case_for(fault=FaultPoint.ADMISSION)
    observed = observe(refused)
    assert violations(observed, refused) == ()
    wrote_anyway = replace(
        observed,
        calls=(Call(actor=Actor.HANDLER, name=ROW_WRITE_PUT, session_id="x"),),
    )
    faults = violations(wrote_anyway, refused)
    assert any("a refused request reached" in fault for fault in faults), faults

    lost_write = case_for(fault=FaultPoint.ROW_WRITE)
    observed = observe(lost_write)
    assert violations(observed, lost_write) == ()
    started_anyway = replace(
        observed,
        calls=(
            *observed.calls,
            Call(actor=Actor.HANDLER, name=START_EXECUTION, session_id="x"),
        ),
    )
    faults = violations(started_anyway, lost_write)
    assert any("was followed by start_execution" in fault for fault in faults), faults
