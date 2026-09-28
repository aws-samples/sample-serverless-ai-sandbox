# kiro-classification: public
"""The Session_Orchestrator's Standard state machine, as a graph that is assertable offline.

R10.1 makes the Session_Orchestrator an AWS Step Functions **Standard** workflow, and the design's
Session_Orchestrator section draws the task and choice graph it runs: provision, claim, await
readiness, publish the credential, the governing poll loop, terminate, release check, and cleanup.
This module is that graph, declared as data. :func:`to_asl` renders it into an Amazon States Language
definition for the IaC_Package; nothing here calls AWS, reads an environment variable or needs a
deployed resource, so the whole graph is constructible and assertable in the offline suite.

## Why the graph is data rather than a JSON file

A definition committed as JSON is a definition nothing can check. The claims this graph has to keep
are structural — every fallible task records the Session as failed, every path out of teardown
deletes the binding, the poll loop has no branch that silently does nothing — and each of them is a
statement about edges. Expressed as :data:`STATE_MACHINE`, they are import-time assertions; expressed
as JSON, they are things a reviewer hopes somebody noticed. The six invariants asserted at the bottom
of this module are the ones that would otherwise decay silently.

## The node types make an invalid state unrepresentable

There is no single `StateNode` with an optional `Next` and an optional `Choices`. There are five
types, one per Amazon States Language state kind, and each carries exactly the fields its kind
admits: :class:`SucceedState` and :class:`FailState` have no successor to leave dangling,
:class:`ChoiceState` has branches and no `Next`, and :class:`TaskState` has a `Next` and cannot have
branches. A graph in which a terminal state carries a successor therefore has nowhere to live, which
is the posture :class:`~control_plane.lifecycle.LiveTransition` established for lifecycle writes.

## The one choice, and why it branches on a decision rather than on a state

The design draws the governing loop's choice as `Choice: current state`. It is expressed here as a
choice over :class:`GovernanceDecision`, which the `Observe` task produces from
:data:`GOVERNING_BRANCHES` — a mapping total over every state a Compute_Provider can report.

That is a deliberate resolution of an ambiguity rather than a departure. Branching on the reported
state inside the state machine would put the branch table in two places: once in Amazon States
Language string comparisons, once in the Python that has to decide the same thing when it evaluates
the duration ceiling and the continuation lead. Two copies of a branch table over nine provider
states is two copies that can disagree, and the one in JSON is the copy no test can quantify over.
So the table lives in Python, total and asserted, and the state machine branches on its answer.

**The choice carries no `Default`.** An input matching no rule fails the execution with
`States.NoChoiceMatched` rather than falling into a fallback, which is the same reasoning that keeps
:data:`~control_plane.lifecycle.PROVIDER_STATE_MIRROR` and
:data:`~control_plane.api.resolution.LOSER_BRANCHES` free of one: a decision added later must fail
loudly, and here it fails at the import assertion before it can ever fail in a deployment.

## What the graph says about failure

Every task on the forward path — provision, claim, await readiness, publish — carries a catcher to
`RecordFailed`, and that is asserted rather than reviewed (R6.14). `RecordFailed` then joins the same
`Cleanup` state the teardown path reaches, so the binding deletion of R10.16 sits on the failure path
as well as the success path, exactly as the design requires: a Session that failed to provision is
the case where a binding left behind would send the next reconnect to a Session that will never run.

`Cleanup` is a safe join because a terminal lifecycle state absorbs in the store. Reaching it after
`RecordFailed` has already settled `FAILED` finds the row terminal, so the settlement is refused by
its own condition and reported as :attr:`~control_plane.lifecycle.ReconciliationOutcome.ABSORBED`
rather than overwriting the diagnostic state with the routine one.

**`ResourcesRetained` is the one `Fail` state, and it is the only path that ends without cleanup.**
R10.9 requires confirmation that no Sandbox, network interface or endpoint remains allocated. When
`release_check` keeps returning identifiers, the retrier exhausts and the execution fails, leaving
the row `TERMINATING` and the binding in place — which is a failed orchestration, and failed
orchestrations are precisely what cleanup layers 2 and 3 exist for. Routing it to `Cleanup` instead
would record a Session as `TERMINATED` while resources it owns are still allocated, which is the one
thing R10.9 asks the orchestrator not to do.

Provisioning failure, by contrast, ends in `Succeed`. The execution governed the Session correctly;
the Session failed. Making it an execution failure would bury the `ResourcesRetained` signal among
routine quota rejections, and an operator watching execution failures would learn nothing from
either.

## What is deliberately not here

The graph names `EmitCounts` and `Continue` because the design draws them, and the body of neither is
here: the running and suspended counts are R14.4's and the handoff is the duration-ceiling
continuation, and both live in :mod:`control_plane.orchestrator.tasks` with every other `Task` body.
Both are `Task` states with a resource the IaC_Package supplies, so they are wired without this module
changing. The idle policy written onto the Sandbox at provisioning is applied inside the `Provision`
task, not in the graph.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar, Final

from control_plane.providers.base import SandboxState

__all__ = [
    "EXECUTION_FIELD",
    "FAILURE_PATH",
    "GOVERNANCE_PATH",
    "GOVERNING_BRANCHES",
    "POLL_INTERVAL_FIELD",
    "QUOTA_EXHAUSTED_ERROR",
    "RELEASE_CHECK_BACKOFF_RATE",
    "RELEASE_CHECK_INTERVAL_SECONDS",
    "RELEASE_CHECK_MAX_ATTEMPTS",
    "RESOURCES_RETAINED_ERROR",
    "RESOURCES_STILL_ALLOCATED_ERROR",
    "SANDBOX_ALREADY_CLAIMED_ERROR",
    "START_AT",
    "STATE_FIELD",
    "STATE_MACHINE",
    "TASK_FIELD",
    "TASK_STATES",
    "TERMINAL_STATES",
    "TRANSIENT_INVOCATION_ERRORS",
    "Catcher",
    "ChoiceState",
    "FailState",
    "GovernanceDecision",
    "OrchestratorState",
    "Retrier",
    "StateKind",
    "StateNode",
    "SucceedState",
    "TaskState",
    "WaitState",
    "targets_of",
    "to_asl",
]


class OrchestratorState(Enum):
    """The states of the Session_Orchestrator, named as they appear in execution history.

    The value *is* the Amazon States Language state name, so a name in a CloudWatch view, in an
    execution history entry and in this enum are one string rather than three that have to agree.
    """

    #: `provider.provision`, inside the started execution and nowhere else (R6.11).
    PROVISION = "Provision"
    #: The conditional claim that makes one Sandbox belong to one Session, ever (R11.1, R11.10).
    CLAIM_SANDBOX = "ClaimSandbox"
    #: Poll `provider.describe` until the `/run` hook has returned 200 (R7.8).
    AWAIT_READY = "AwaitReady"
    #: Mint the connection credential and publish it onto the Session row (R6.12).
    PUBLISH_CREDENTIAL = "PublishCredential"
    #: Callback-based lifecycle wait: pauses until the API Handler or Reaper sends a signal.
    WAIT_FOR_LIFECYCLE = "WaitForLifecycle"
    #: Handle the lifecycle event returned by the callback.
    HANDLE_EVENT = "HandleEvent"
    #: Record a user-initiated suspension before re-entering the wait.
    RECORD_SUSPENDED = "RecordSuspended"
    #: Record a resume before re-entering the wait.
    RECORD_RESUMED = "RecordResumed"
    #: The duration-ceiling handoff (R10.11).
    CONTINUE = "Continue"
    #: `provider.terminate`, reached on a limit, on an observed terminate, or on a caught failure.
    TERMINATE = "Terminate"
    #: `provider.release_check`, retried with backoff before the execution gives up (R10.9).
    RELEASE_CHECK = "ReleaseCheck"
    #: Record the Session `FAILED` with the reason the caught error carried (R6.8, R6.14).
    RECORD_FAILED = "RecordFailed"
    #: Settle the terminal state and delete the Affinity_Key binding with it (R10.16).
    CLEANUP = "Cleanup"
    #: The execution governed this Session to the end of its life.
    TERMINATED = "Terminated"
    #: Resources remained allocated after teardown, so the execution fails rather than lying.
    RESOURCES_RETAINED = "ResourcesRetained"


class StateKind(Enum):
    """The Amazon States Language state kinds this graph uses, spelled as `Type` values."""

    TASK = "Task"
    CHOICE = "Choice"
    WAIT = "Wait"
    SUCCEED = "Succeed"
    FAIL = "Fail"


class GovernanceDecision(Enum):
    """What one turn of the governing loop concluded.

    Three decisions, and the loop's choice is total over them, so a decision added here without a
    branch fails the import assertion rather than reaching `States.NoChoiceMatched` in a deployment.
    """

    #: The Sandbox is alive and within every limit: wait, emit the counts, look again.
    KEEP_POLLING = "keep-polling"
    #: The duration ceiling is close and continuation is enabled (R10.11).
    CONTINUE = "continue"
    #: A limit was reached, or a terminal state was observed. Either way, tear down.
    TEAR_DOWN = "tear-down"
    #: User-initiated suspension.
    SUSPEND = "suspend"
    #: User-initiated resume (from suspended wait).
    RESUME = "resume"


#: Every state a Compute_Provider can report, mapped onto what the governing loop does about it.
#:
#: Total over :class:`~control_plane.providers.base.SandboxState`, asserted at import, for the reason
#: :data:`~control_plane.lifecycle.PROVIDER_STATE_MIRROR` is: a provider state added later must fail
#: the build rather than fall into a fallback that would leave the loop polling a Sandbox that has
#: gone away, or tearing down one that is merely starting.
#:
#: The two record-only lifecycle states have no entry because they have no provider state to be
#: reported as, which is the whole reason this table is keyed on the provider's enum rather than on
#: :class:`~control_plane.state.records.LifecycleState`. `SUSPENDED` keeps polling rather than
#: terminating: R10.4 makes a suspended Session a running Session that costs less, and the
#: suspended-duration limit belongs to the Reaper (R10.7).
GOVERNING_BRANCHES: Final[Mapping[SandboxState, GovernanceDecision]] = {
    SandboxState.PENDING: GovernanceDecision.KEEP_POLLING,
    SandboxState.STARTING: GovernanceDecision.KEEP_POLLING,
    SandboxState.RUNNING: GovernanceDecision.KEEP_POLLING,
    SandboxState.SUSPENDING: GovernanceDecision.KEEP_POLLING,
    SandboxState.SUSPENDED: GovernanceDecision.KEEP_POLLING,
    SandboxState.RESUMING: GovernanceDecision.KEEP_POLLING,
    # An observed teardown, however it started. `TERMINATING` is here rather than under the poll
    # because it is one-way: waiting on it spends interval after interval arriving at a Sandbox that
    # is going away, and `provider.terminate` is idempotent, so joining the teardown converges.
    SandboxState.TERMINATING: GovernanceDecision.TEAR_DOWN,
    SandboxState.TERMINATED: GovernanceDecision.TEAR_DOWN,
    SandboxState.FAILED: GovernanceDecision.TEAR_DOWN,
}

#: The field naming which task a Lambda invocation is serving. Present so one dispatching function
#: can back every `Task` state, and legible in an execution history entry either way.
TASK_FIELD: Final = "task"

#: The execution ARN, injected from the Step Functions context object. It is the calling principal
#: R14.2 requires on a lifecycle audit record, and it is the value that makes every write this
#: orchestration performs attributable to the execution that governs the Session.
EXECUTION_FIELD: Final = "executionId"

#: The accumulated execution state, which begins as the Control_Plane handler's execution input.
STATE_FIELD: Final = "state"

#: Where a caught error lands, and therefore where `RecordFailed` reads the reason it records.
FAILURE_PATH: Final = "$.failure"

#: Where the `Observe` task's decision lands. The loop's choice and the `Wait` state both read it.
GOVERNANCE_PATH: Final = "$.governance"

#: The field of that result carrying the configured poll interval, so the interval is deployment
#: configuration flowing through the execution rather than a number frozen into the definition.
POLL_INTERVAL_FIELD: Final = "pollIntervalSeconds"

#: The error a release check raises while resources remain allocated (R10.9). Retried with backoff.
#:
#: Step Functions matches a catcher against the *class name* of the exception a task Lambda raised,
#: so this string and :class:`~control_plane.orchestrator.tasks.ResourcesStillAllocated` are one fact
#: spelled twice. That module asserts the two agree at import, which is where the same is asserted for
#: the two error names below: a rename on either side would otherwise leave a catcher matching
#: nothing, and the symptom would be a Session left running by a dead execution.
RESOURCES_STILL_ALLOCATED_ERROR: Final = "ResourcesStillAllocated"

#: The provider's refusal for an exhausted service quota (R6.8), caught by name so execution history
#: says which arm of the provisioning failure fired.
QUOTA_EXHAUSTED_ERROR: Final = "QuotaExhausted"

#: The claim ledger's refusal when another Session already holds this Sandbox (R11.1, R11.10).
SANDBOX_ALREADY_CLAIMED_ERROR: Final = "SandboxAlreadyClaimed"

#: The error the execution fails with once that retrier is exhausted.
RESOURCES_RETAINED_ERROR: Final = "ResourcesRetained"

RELEASE_CHECK_INTERVAL_SECONDS: Final = 5
RELEASE_CHECK_MAX_ATTEMPTS: Final = 5
RELEASE_CHECK_BACKOFF_RATE: Final = 2.0

#: The Lambda invocation failures that say nothing about the task's own logic. Retried everywhere
#: except on `Provision`, whose retry could leave a second billable Sandbox behind; see
#: :data:`STATE_MACHINE`.
TRANSIENT_INVOCATION_ERRORS: Final[tuple[str, ...]] = (
    "Lambda.ServiceException",
    "Lambda.AWSLambdaException",
    "Lambda.SdkClientException",
    "Lambda.TooManyRequestsException",
)

_TRANSIENT_INTERVAL_SECONDS: Final = 2
_TRANSIENT_MAX_ATTEMPTS: Final = 3
_TRANSIENT_BACKOFF_RATE: Final = 2.0

#: The state every execution starts in. Provisioning is the first thing the orchestration does,
#: which is the whole of R6.11: there is no earlier point at which a Sandbox could come into being.
START_AT: Final = OrchestratorState.PROVISION


@dataclass(frozen=True, slots=True)
class Retrier:
    """One Amazon States Language retrier: which errors, how often, how far apart."""

    errors: tuple[str, ...]
    interval_seconds: int
    max_attempts: int
    backoff_rate: float

    def __post_init__(self) -> None:
        if not self.errors:
            raise ValueError("a retrier must name at least one error")
        if self.interval_seconds <= 0:
            raise ValueError(
                f"interval_seconds must be positive: {self.interval_seconds}"
            )
        if self.max_attempts <= 0:
            raise ValueError(f"max_attempts must be positive: {self.max_attempts}")
        if self.backoff_rate < 1:
            raise ValueError(f"backoff_rate must be at least 1: {self.backoff_rate}")

    def to_asl(self) -> dict[str, Any]:
        return {
            "ErrorEquals": list(self.errors),
            "IntervalSeconds": self.interval_seconds,
            "MaxAttempts": self.max_attempts,
            "BackoffRate": self.backoff_rate,
        }


@dataclass(frozen=True, slots=True)
class Catcher:
    """One Amazon States Language catcher, and the state it routes to.

    `target` is an :class:`OrchestratorState` rather than a string, so a catcher cannot name a state
    the graph does not contain and the reachability assertion below has something to walk.
    """

    errors: tuple[str, ...]
    target: OrchestratorState
    result_path: str = FAILURE_PATH

    def __post_init__(self) -> None:
        if not self.errors:
            raise ValueError("a catcher must name at least one error")

    def to_asl(self) -> dict[str, Any]:
        return {
            "ErrorEquals": list(self.errors),
            "ResultPath": self.result_path,
            "Next": self.target.value,
        }


@dataclass(frozen=True, slots=True)
class TaskState:
    """A `Task` state: one Lambda invocation, its successor, its retriers and its catchers.

    The resource ARN is not a field. It is supplied by :func:`to_asl` from the mapping the
    IaC_Package holds, so this graph states which tasks exist and the deployment states where they
    live — and a deployment that omits one is refused rather than rendering a definition with a
    missing `Resource`.

    When ``wait_for_task_token`` is ``True``, the state uses the ``.waitForTaskToken``
    integration pattern. The task token is passed in the Parameters and the state machine
    pauses until ``SendTaskSuccess`` is called.
    """

    kind: ClassVar[StateKind] = StateKind.TASK

    next_state: OrchestratorState
    result_path: str
    comment: str
    retriers: tuple[Retrier, ...] = ()
    catchers: tuple[Catcher, ...] = ()
    wait_for_task_token: bool = False

    def to_asl(
        self, state: OrchestratorState, resource: str | None = None
    ) -> dict[str, Any]:
        if (
            resource is None
        ):  # pragma: no cover - to_asl supplies one for every Task state
            raise ValueError("a Task state needs the resource ARN of its task")

        if self.wait_for_task_token:
            # .waitForTaskToken integration: the state machine pauses until
            # SendTaskSuccess is called with the task token.
            asl: dict[str, Any] = {
                "Type": self.kind.value,
                "Comment": self.comment,
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": resource,
                    "Payload": {
                        TASK_FIELD: state.value,
                        f"{EXECUTION_FIELD}.$": "$$.Execution.Id",
                        f"{STATE_FIELD}.$": "$",
                        "taskToken.$": "$$.Task.Token",
                    },
                },
                "ResultPath": self.result_path,
                "Next": self.next_state.value,
            }
        else:
            asl: dict[str, Any] = {
                "Type": self.kind.value,
                "Comment": self.comment,
                "Resource": resource,
                "Parameters": {
                    TASK_FIELD: state.value,
                    f"{EXECUTION_FIELD}.$": "$$.Execution.Id",
                    f"{STATE_FIELD}.$": "$",
                },
                "ResultPath": self.result_path,
                "Next": self.next_state.value,
            }
        if self.retriers:
            asl["Retry"] = [retrier.to_asl() for retrier in self.retriers]
        if self.catchers:
            asl["Catch"] = [catcher.to_asl() for catcher in self.catchers]
        return asl


@dataclass(frozen=True, slots=True)
class ChoiceState:
    """A `Choice` state over :class:`GovernanceDecision`, with no `Default`.

    The absence of a default is the point, and it is why the branch table is a mapping keyed on the
    enum: the import assertion below requires one branch per decision, so the graph cannot be
    rendered with a decision that has nowhere to go.
    """

    kind: ClassVar[StateKind] = StateKind.CHOICE

    variable: str
    branches: Mapping[GovernanceDecision, OrchestratorState]
    comment: str

    def to_asl(
        self, state: OrchestratorState, resource: str | None = None
    ) -> dict[str, Any]:
        del state, resource
        return {
            "Type": self.kind.value,
            "Comment": self.comment,
            "Choices": [
                {
                    "Variable": self.variable,
                    "StringEquals": decision.value,
                    "Next": self.branches[decision].value,
                }
                # Iterated over the enum rather than over the mapping, so the rendered order is the
                # declaration order of the decisions and two renderings cannot differ.
                for decision in GovernanceDecision
                if decision in self.branches
            ],
        }


@dataclass(frozen=True, slots=True)
class WaitState:
    """A `Wait` state whose duration arrives as data on the execution state.

    `SecondsPath` rather than `Seconds`: the poll interval is one of the design's declared
    configuration values, so freezing it into the definition would make changing it a definition
    change rather than a context change.
    """

    kind: ClassVar[StateKind] = StateKind.WAIT

    seconds_path: str
    next_state: OrchestratorState
    comment: str

    def to_asl(
        self, state: OrchestratorState, resource: str | None = None
    ) -> dict[str, Any]:
        del state, resource
        return {
            "Type": self.kind.value,
            "Comment": self.comment,
            "SecondsPath": self.seconds_path,
            "Next": self.next_state.value,
        }


@dataclass(frozen=True, slots=True)
class SucceedState:
    """A `Succeed` state. It has no successor field, so it cannot acquire one."""

    kind: ClassVar[StateKind] = StateKind.SUCCEED

    comment: str

    def to_asl(
        self, state: OrchestratorState, resource: str | None = None
    ) -> dict[str, Any]:
        del state, resource
        return {"Type": self.kind.value, "Comment": self.comment}


@dataclass(frozen=True, slots=True)
class FailState:
    """A `Fail` state, carrying the error name an operator alarms on."""

    kind: ClassVar[StateKind] = StateKind.FAIL

    error: str
    cause: str

    def to_asl(
        self, state: OrchestratorState, resource: str | None = None
    ) -> dict[str, Any]:
        del state, resource
        return {"Type": self.kind.value, "Error": self.error, "Cause": self.cause}


#: One of the five node kinds. A union rather than one type with optional fields, so a state's kind
#: determines exactly which attributes it has.
StateNode = TaskState | ChoiceState | WaitState | SucceedState | FailState


def targets_of(node: StateNode) -> tuple[OrchestratorState, ...]:
    """Return every state this node can hand control to, catchers included.

    Ordinary control flow first, then the catchers, so a traversal reports the forward path before
    the failure paths.
    """
    if isinstance(node, TaskState):
        return (node.next_state, *(catcher.target for catcher in node.catchers))
    if isinstance(node, ChoiceState):
        return tuple(
            node.branches[decision]
            for decision in GovernanceDecision
            if decision in node.branches
        )
    if isinstance(node, WaitState):
        return (node.next_state,)
    return ()


_RECORD_THE_FAILURE: Final = Catcher(
    errors=("States.ALL",), target=OrchestratorState.RECORD_FAILED
)

#: A retrier for the invocation failures that say nothing about the task itself.
_TRANSIENT: Final = Retrier(
    errors=TRANSIENT_INVOCATION_ERRORS,
    interval_seconds=_TRANSIENT_INTERVAL_SECONDS,
    max_attempts=_TRANSIENT_MAX_ATTEMPTS,
    backoff_rate=_TRANSIENT_BACKOFF_RATE,
)

#: The tasks whose failure must leave the Session recorded `FAILED` (R6.14). Asserted below to carry
#: a catcher routing to `RecordFailed`, so the guarantee is a property of the graph rather than of
#: whoever last edited it.
_FALLIBLE_FORWARD_TASKS: Final[frozenset[OrchestratorState]] = frozenset(
    {
        OrchestratorState.PROVISION,
        OrchestratorState.CLAIM_SANDBOX,
        OrchestratorState.AWAIT_READY,
        OrchestratorState.PUBLISH_CREDENTIAL,
    }
)

#: The graph the design's Session_Orchestrator section draws, as data.
STATE_MACHINE: Final[Mapping[OrchestratorState, StateNode]] = {
    # No retrier. Every other task retries a transient invocation failure; this one must not, because
    # a `provision` that failed after the backend accepted it has left a Sandbox behind, and a retry
    # would provision a second one. The claim ledger keeps the second from being allocated and the
    # Reaper finds it by the tags R11.7 requires, but the cheapest fix is not to create it.
    OrchestratorState.PROVISION: TaskState(
        next_state=OrchestratorState.CLAIM_SANDBOX,
        result_path="$.sandbox",
        comment="provider.provision, inside the started execution (R6.11)",
        catchers=(
            # Named separately from States.ALL so execution history says which arm fired without
            # anybody parsing an error message. Both route to the same state, which is the design's
            # two arrows into RecordFailed.
            Catcher(
                errors=(QUOTA_EXHAUSTED_ERROR,),
                target=OrchestratorState.RECORD_FAILED,
            ),
            _RECORD_THE_FAILURE,
        ),
    ),
    # The design draws a `TerminateDuplicate` state between this one and cleanup. There is no such
    # state here, and the omission is deliberate rather than an oversight: task 6.14 put the
    # duplicate's termination *inside* `SandboxClaimLedger.claim`, which stops the Sandbox a losing
    # caller provisioned before `SandboxAlreadyClaimed` is raised at all. A separate state would
    # therefore either do nothing or terminate a Sandbox the winner now owns. The node's outgoing edge
    # is preserved: the collision is caught by name and routed to `RecordFailed`, whose reason carries
    # the ledger's own account of whether the duplicate was terminated, and which reaches `Cleanup`.
    OrchestratorState.CLAIM_SANDBOX: TaskState(
        next_state=OrchestratorState.AWAIT_READY,
        result_path="$.claim",
        comment="conditional write on H#provider#sandboxId (R11.1, R11.10)",
        retriers=(_TRANSIENT,),
        catchers=(
            Catcher(
                errors=(SANDBOX_ALREADY_CLAIMED_ERROR,),
                target=OrchestratorState.RECORD_FAILED,
            ),
            _RECORD_THE_FAILURE,
        ),
    ),
    OrchestratorState.AWAIT_READY: TaskState(
        next_state=OrchestratorState.PUBLISH_CREDENTIAL,
        result_path="$.readiness",
        comment="poll provider.describe until the /run hook has returned 200 (R7.8)",
        retriers=(_TRANSIENT,),
        catchers=(_RECORD_THE_FAILURE,),
    ),
    OrchestratorState.PUBLISH_CREDENTIAL: TaskState(
        next_state=OrchestratorState.WAIT_FOR_LIFECYCLE,
        result_path="$.connection",
        comment="mint and publish the credential onto the Session row (R6.12)",
        retriers=(_TRANSIENT,),
        catchers=(_RECORD_THE_FAILURE,),
    ),
    # --- Callback-based lifecycle wait (replaces the polling loop for running sessions) ---
    OrchestratorState.WAIT_FOR_LIFECYCLE: TaskState(
        next_state=OrchestratorState.HANDLE_EVENT,
        result_path="$.lifecycle",
        comment="waitForTaskToken: pause until API Handler or Reaper sends a callback",
        retriers=(_TRANSIENT,),
        catchers=(_RECORD_THE_FAILURE,),
        wait_for_task_token=True,
    ),
    OrchestratorState.HANDLE_EVENT: ChoiceState(
        variable="$.lifecycle.decision",
        branches={
            GovernanceDecision.TEAR_DOWN: OrchestratorState.TERMINATE,
            GovernanceDecision.CONTINUE: OrchestratorState.CONTINUE,
            GovernanceDecision.SUSPEND: OrchestratorState.RECORD_SUSPENDED,
            GovernanceDecision.RESUME: OrchestratorState.RECORD_RESUMED,
            GovernanceDecision.KEEP_POLLING: OrchestratorState.WAIT_FOR_LIFECYCLE,
        },
        comment="route the lifecycle event: tear-down, continue, suspend, resume, or re-wait",
    ),
    OrchestratorState.RECORD_SUSPENDED: TaskState(
        next_state=OrchestratorState.WAIT_FOR_LIFECYCLE,
        result_path="$.suspended",
        comment="mirror SUSPENDED state to DDB, then re-enter the callback wait",
        retriers=(_TRANSIENT,),
    ),
    OrchestratorState.RECORD_RESUMED: TaskState(
        next_state=OrchestratorState.WAIT_FOR_LIFECYCLE,
        result_path="$.resumed",
        comment="mirror RESUMED/RUNNING state to DDB, then re-enter the callback wait",
        retriers=(_TRANSIENT,),
    ),




    OrchestratorState.CONTINUE: TaskState(
        next_state=OrchestratorState.PROVISION,
        result_path="$.continuation",
        comment="duration-ceiling handoff (R10.11); the binding is untouched (R6.24)",
        retriers=(_TRANSIENT,),
        catchers=(_RECORD_THE_FAILURE,),
    ),
    OrchestratorState.TERMINATE: TaskState(
        next_state=OrchestratorState.RELEASE_CHECK,
        result_path="$.termination",
        comment="provider.terminate, idempotent and convergent with the Reaper",
        retriers=(_TRANSIENT,),
    ),
    OrchestratorState.RELEASE_CHECK: TaskState(
        next_state=OrchestratorState.CLEANUP,
        result_path="$.release",
        comment="provider.release_check: assert emptiness rather than trust terminate (R10.9)",
        retriers=(
            _TRANSIENT,
            Retrier(
                errors=(RESOURCES_STILL_ALLOCATED_ERROR,),
                interval_seconds=RELEASE_CHECK_INTERVAL_SECONDS,
                max_attempts=RELEASE_CHECK_MAX_ATTEMPTS,
                backoff_rate=RELEASE_CHECK_BACKOFF_RATE,
            ),
        ),
        catchers=(
            Catcher(
                errors=(RESOURCES_STILL_ALLOCATED_ERROR,),
                target=OrchestratorState.RESOURCES_RETAINED,
            ),
        ),
    ),
    OrchestratorState.RECORD_FAILED: TaskState(
        next_state=OrchestratorState.CLEANUP,
        result_path="$.failed",
        comment="record FAILED with the caught reason (R6.8, R6.14) and quarantine the claim (R11.13)",
        retriers=(_TRANSIENT,),
    ),
    OrchestratorState.CLEANUP: TaskState(
        next_state=OrchestratorState.TERMINATED,
        result_path="$.cleanup",
        comment="settle the terminal state and delete the Affinity_Key binding with it (R10.16)",
        retriers=(_TRANSIENT,),
    ),
    OrchestratorState.TERMINATED: SucceedState(
        comment="the execution governed this Session to the end of its life",
    ),
    OrchestratorState.RESOURCES_RETAINED: FailState(
        error=RESOURCES_RETAINED_ERROR,
        cause=(
            "provider.release_check still reported allocated resources after the configured "
            "retries, so the execution fails rather than recording a Session as terminated while "
            "resources it owns remain allocated (R10.9)"
        ),
    ),
}

#: The `Task` states, which are exactly the states the IaC_Package must supply a resource for.
TASK_STATES: Final[frozenset[OrchestratorState]] = frozenset(
    state for state, node in STATE_MACHINE.items() if isinstance(node, TaskState)
)

#: The states that hand control to nothing. Derived rather than listed, so a state that stopped
#: being terminal — or started being one — changes this set and fails the assertion below.
TERMINAL_STATES: Final[frozenset[OrchestratorState]] = frozenset(
    state for state, node in STATE_MACHINE.items() if not targets_of(node)
)


def _reachable() -> frozenset[OrchestratorState]:
    """Every state reachable from :data:`START_AT`, following control flow and catchers."""
    seen: set[OrchestratorState] = set()
    pending = [START_AT]
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        pending.extend(targets_of(STATE_MACHINE[state]))
    return frozenset(seen)


if set(STATE_MACHINE) != set(
    OrchestratorState
):  # pragma: no cover - import-time invariant
    _undefined = sorted(
        state.value for state in OrchestratorState if state not in STATE_MACHINE
    )
    raise AssertionError(f"orchestrator states with no node: {_undefined}")

if set(GOVERNING_BRANCHES) != set(
    SandboxState
):  # pragma: no cover - import-time invariant
    _ungoverned = sorted(
        state.value for state in SandboxState if state not in GOVERNING_BRANCHES
    )
    raise AssertionError(f"provider states with no governing branch: {_ungoverned}")

_HANDLE_EVENT = STATE_MACHINE[OrchestratorState.HANDLE_EVENT]
if not isinstance(_HANDLE_EVENT, ChoiceState) or set(_HANDLE_EVENT.branches) != set(
    GovernanceDecision
):  # pragma: no cover - import-time invariant
    raise AssertionError(
        "HandleEvent must carry one branch per GovernanceDecision"
    )

if _reachable() != set(OrchestratorState):  # pragma: no cover - import-time invariant
    _unreachable = sorted(
        state.value for state in set(OrchestratorState) - _reachable()
    )
    raise AssertionError(f"orchestrator states no execution can reach: {_unreachable}")

if TERMINAL_STATES != {
    OrchestratorState.TERMINATED,
    OrchestratorState.RESOURCES_RETAINED,
}:  # pragma: no cover - import-time invariant
    # A third ending, or one of these two acquiring a successor, changes what an execution's outcome
    # means to an operator. That is a design decision and it fails the build here.
    raise AssertionError(
        f"the executions endings have changed: "
        f"{sorted(state.value for state in TERMINAL_STATES)}"
    )

for _state in sorted(_FALLIBLE_FORWARD_TASKS, key=lambda member: member.value):
    _node = STATE_MACHINE[_state]
    if not isinstance(_node, TaskState) or OrchestratorState.RECORD_FAILED not in {
        catcher.target for catcher in _node.catchers
    }:  # pragma: no cover - import-time invariant
        raise AssertionError(
            f"{_state.value} can fail without the Session being recorded FAILED (R6.14)"
        )


def to_asl(
    task_resources: Mapping[OrchestratorState, str], *, comment: str | None = None
) -> dict[str, Any]:
    """Render the Amazon States Language definition, given a resource ARN for every `Task` state.

    The mapping must cover :data:`TASK_STATES` exactly. Both halves are refused: a missing entry
    would render a state with no `Resource`, and an extra one is a deployment that believes in a task
    this graph does not have — which is how a task quietly stops being invoked.

    Args:
        task_resources: the Lambda function ARN backing each `Task` state.
        comment: the definition's own comment, for an operator reading it in the console.

    Raises:
        ValueError: the mapping does not cover exactly the `Task` states.
    """
    supplied = set(task_resources)
    if supplied != TASK_STATES:
        missing = sorted(state.value for state in TASK_STATES - supplied)
        unknown = sorted(state.value for state in supplied - TASK_STATES)
        raise ValueError(
            f"a resource is needed for exactly the Task states; missing {missing}, "
            f"unknown {unknown}"
        )
    return {
        "Comment": comment
        or "Session_Orchestrator: provision, publish and govern one Session (R10.1)",
        "StartAt": START_AT.value,
        "States": {
            state.value: STATE_MACHINE[state].to_asl(state, task_resources.get(state))
            for state in OrchestratorState
        },
    }
