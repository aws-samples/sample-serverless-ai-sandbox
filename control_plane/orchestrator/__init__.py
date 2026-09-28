# kiro-classification: public
"""The Session_Orchestrator: the Standard state machine, and the bodies of its tasks (R10.1).

Two modules, and the split is deliberate.

- :mod:`control_plane.orchestrator.definition` is the graph the design draws — every state, every
  edge, every retrier and catcher — as data, with six invariants asserted at import and
  :func:`~control_plane.orchestrator.definition.to_asl` rendering it for the IaC_Package. It imports
  no provisioning code, so anything that wants to reason about the lifecycle graph can.
- :mod:`control_plane.orchestrator.tasks` is what each `Task` state does, and it is the **one module
  in this repository that may call `provider.provision`** (R6.11). It is named in
  `ci/lint_rules/orchestrated_provisioning.py`'s `ORCHESTRATOR_MODULES` allow-list, which is the
  reviewed decision that this code runs inside a started execution.

- :mod:`control_plane.orchestrator.continuation` is the duration-ceiling handoff (R10.11): the two
  seams it needs, the writes it performs and the derivation of the archive reference both halves of it
  share. It provisions nothing and terminates nothing, so it is not on that allow-list; the ordering
  of the handoff's steps is in `tasks.py` because it turns on `provider.terminate`.

Nothing in any of the three calls AWS at import time, reads an environment variable or needs a
deployed resource, so the whole orchestration is constructible and drivable in the offline suite.

Every lifecycle state any of them records goes through :mod:`control_plane.lifecycle`. The idle policy
goes through :mod:`control_plane.idle_policy`. The Reaper and the running and suspended counts are
their own tasks; the graph names the states they fill.
"""

from control_plane.orchestrator.continuation import (
    CONTINUATION_ARTIFACT_ID,
    CONTINUATION_REASON,
    ContinuationAlreadyRecorded,
    ContinuationHandoff,
    ContinuationHandoffs,
    ContinuationNotEnabled,
    ContinuationStore,
    SandboxQuiesce,
    StartConfiguration,
    continuation_artifact_reference,
    continuation_record_for,
    handoff_for,
)
from control_plane.orchestrator.definition import (
    FAILURE_PATH,
    GOVERNANCE_PATH,
    GOVERNING_BRANCHES,
    QUOTA_EXHAUSTED_ERROR,
    RESOURCES_RETAINED_ERROR,
    RESOURCES_STILL_ALLOCATED_ERROR,
    SANDBOX_ALREADY_CLAIMED_ERROR,
    START_AT,
    STATE_MACHINE,
    TASK_STATES,
    TERMINAL_STATES,
    Catcher,
    ChoiceState,
    FailState,
    GovernanceDecision,
    OrchestratorState,
    Retrier,
    StateKind,
    SucceedState,
    TaskState,
    WaitState,
    targets_of,
    to_asl,
)
from control_plane.orchestrator.tasks import (
    CLEANUP_REASON,
    PROVISIONING_REASON,
    PUBLICATION_REASON,
    CredentialPublication,
    OrchestrationInput,
    OrchestrationInputError,
    OrchestrationRowStore,
    OrchestratorSettings,
    ReadinessNotReached,
    ResourcesStillAllocated,
    SandboxNotRecorded,
    SandboxRecording,
    SandboxStartupFailed,
    SessionOrchestrator,
    TaskInvocation,
    failure_reason,
    handle_of,
)

__all__ = [
    "CLEANUP_REASON",
    "CONTINUATION_ARTIFACT_ID",
    "CONTINUATION_REASON",
    "FAILURE_PATH",
    "GOVERNANCE_PATH",
    "GOVERNING_BRANCHES",
    "PROVISIONING_REASON",
    "PUBLICATION_REASON",
    "QUOTA_EXHAUSTED_ERROR",
    "RESOURCES_RETAINED_ERROR",
    "RESOURCES_STILL_ALLOCATED_ERROR",
    "SANDBOX_ALREADY_CLAIMED_ERROR",
    "START_AT",
    "STATE_MACHINE",
    "TASK_STATES",
    "TERMINAL_STATES",
    "Catcher",
    "ChoiceState",
    "ContinuationAlreadyRecorded",
    "ContinuationHandoff",
    "ContinuationHandoffs",
    "ContinuationNotEnabled",
    "ContinuationStore",
    "CredentialPublication",
    "FailState",
    "GovernanceDecision",
    "OrchestrationInput",
    "OrchestrationInputError",
    "OrchestrationRowStore",
    "OrchestratorSettings",
    "OrchestratorState",
    "ReadinessNotReached",
    "ResourcesStillAllocated",
    "Retrier",
    "SandboxNotRecorded",
    "SandboxQuiesce",
    "SandboxRecording",
    "SandboxStartupFailed",
    "SessionOrchestrator",
    "StartConfiguration",
    "StateKind",
    "SucceedState",
    "TaskInvocation",
    "TaskState",
    "WaitState",
    "continuation_artifact_reference",
    "continuation_record_for",
    "failure_reason",
    "handle_of",
    "handoff_for",
    "targets_of",
    "to_asl",
]
