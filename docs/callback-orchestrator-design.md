<!-- kiro-classification: public -->

# Callback Orchestrator Design

Replace the Session_Orchestrator's 15-second polling loop with a callback pattern
using Step Functions `waitForTaskToken`. Sessions pause at zero cost until a lifecycle
event triggers the next state transition.

## Problem

The current orchestrator runs a polling loop (Observe → Govern → Wait → EmitCounts)
every 15 seconds for the entire session lifetime. This costs ~$0.024/session-hour (based on AWS Step Functions Standard Workflow pricing, us-east-1, 2026-09) in
Step Functions transitions plus Lambda invocations — unnecessary given that:

- The platform handles idle suspension autonomously (no polling needed)
- User-initiated lifecycle events go through the API Handler
- Timer-based deadlines are enforced by the Reaper

## Design

### State machine (before → after)

**Before (polling):**
```
Provision → Claim → AwaitReady → PublishCredential
  → [Observe → Govern → Wait(15s) → EmitCounts → Observe ...]  ← loops every 15s
  → Terminate → ReleaseCheck → Cleanup → Terminated
```

**After (callback):**
```
Provision → Claim → AwaitReady → PublishCredential
  → WaitForLifecycle(.waitForTaskToken)  ← PAUSED, $0
  → HandleEvent(choice)
      ├─ tear-down → Terminate → ReleaseCheck → Cleanup → Terminated
      ├─ suspend → RecordSuspended → WaitForLifecycle  ← PAUSED again
      └─ resume → RecordResumed → WaitForLifecycle     ← PAUSED again
```

### WaitForLifecycle state

A Task state using `.waitForTaskToken`. The orchestrator Lambda:
1. Receives the task token from Step Functions (in the event payload)
2. Stores the token in DynamoDB on the session record (`taskToken` attribute)
3. Returns — the state machine pauses

### Who sends callbacks

**API Handler** — for user-initiated lifecycle events:
- `POST /suspend` → reads task token from DDB → `sfn.send_task_success(token, {"decision": "suspend"})`
- `POST /resume` → reads task token from DDB → `sfn.send_task_success(token, {"decision": "resume"})`
- `POST /terminate` → reads task token from DDB → `sfn.send_task_success(token, {"decision": "tear-down"})`

**Reaper** — for timer-based events:
- Max duration exceeded → `sfn.send_task_success(token, {"decision": "tear-down", "reason": "max-duration"})`
- Suspended too long → `sfn.send_task_success(token, {"decision": "tear-down", "reason": "suspended-too-long"})`

### Reaper state sync (new)

The polling loop's other job was mirroring the MicroVM's actual state (RUNNING ↔ SUSPENDED)
into DynamoDB. Without it, DDB stays stale when the platform auto-suspends a MicroVM.

The Reaper (already a scheduled Lambda) is extended with a **state sync pass**:
1. Query DDB for sessions where `lifecycleState = RUNNING`
2. Call `provider.describe(handle)` for each in a batch
3. If the provider reports SUSPENDED, update DDB to reflect SUSPENDED
4. If `suspended_seconds` has expired, send the task token callback for tear-down

This runs once per Reaper sweep interval (configurable, default 5 minutes).

### Reaper sweep interval (configurable)

The sweep interval becomes a CDK context parameter (`reaperSweepIntervalSeconds`):
- Dev/demo: 300s (5 minutes) — default
- Production with strict SLAs: 60s (1 minute)
- Cost-sensitive: 600s (10 minutes)

One sweep checks ALL sessions in one DDB query + batch describe. Cost is proportional
to sweep frequency, not to session count. At 100 concurrent sessions:
- Current: 100 × 4 transitions × 4/min = 1,600 transitions/min
- Callback: 1 Lambda invocation + 1 DDB query per sweep interval

### Cost comparison

| Scenario | Current (polling) | Callback |
|----------|-------------------|----------|
| 1-hour session | ~970 transitions ($0.024) | ~15 transitions ($0.0004) |
| 8-hour session | ~7,700 transitions ($0.19) | ~15 transitions ($0.0004) |
| 1000 sessions × 1hr | $24/hr | $0.40/hr |
| Idle/suspended session | Same as active | $0 (paused) |

### What stays the same

- Step Functions Standard Workflow (visual debugger, execution history)
- Provision → Claim → AwaitReady → PublishCredential flow
- Terminate → ReleaseCheck → Cleanup → Terminated flow
- Error handling and catchers (RecordFailed path)
- Reaper's existing deadline-based sweep (max_duration, orphan detection)
- Platform-level idle suspension and auto-resume

### What changes

| Component | Change |
|-----------|--------|
| `definition.py` | Replace Observe/Govern/Wait/EmitCounts loop with WaitForLifecycle + HandleEvent |
| `tasks.py` | New `wait_for_lifecycle` task (stores token, returns). Remove `observe`, `emit_counts` |
| API Handler | Add `sfn.send_task_success` calls on suspend/resume/terminate |
| Reaper | Add state sync pass: describe active sessions, update DDB, send expired callbacks |
| CDK | Add `reaperSweepIntervalSeconds` context param, update state machine definition |
| DDB schema | Add `taskToken` attribute to session records |

### Risks and mitigations

**Lost task token**: If the DDB write storing the token fails, the session is stuck until
the Step Functions execution timeout. Mitigation: the token write is part of the
WaitForLifecycle task body — if it fails, the task fails and the state machine retries
or enters the error path.

**Callback delivery failure**: If `send_task_success` fails (throttle, network error),
the lifecycle event is lost. Mitigation: the API Handler retries the callback. The Reaper
catches any sessions that slip through on its next sweep (max_duration backstop).

**DDB state staleness**: Between Reaper syncs, DDB may show RUNNING while the platform
has suspended the MicroVM. Mitigation: this is cosmetic for the user (the sandbox still
works), and the Reaper sync catches it within the sweep interval. The max_duration
deadline is a hard backstop regardless of state.

**Metrics gap**: The EmitCounts task (running/suspended CloudWatch metrics) is removed
from the per-session loop. Mitigation: the Reaper's state sync can emit the same metrics
once per sweep, based on the batch describe results. Less granular (5-minute resolution
vs 15-second) but sufficient for dashboards.

### Migration path

1. Deploy the new state machine definition alongside the old one (canary)
2. New sessions use the callback pattern; existing sessions continue polling
3. Once validated, remove the polling path
4. The old Observe/Govern/Wait/EmitCounts states remain in the definition as dead code
   until all old executions complete (max 8 hours)

### Future: Lambda Durable Functions

This design is a stepping stone. If Lambda Durable Functions mature and prove cost-
effective, the Step Functions state machine can be replaced entirely with a single
durable Lambda function using `context.waitForCallback()`. The callback pattern
established here (API Handler + Reaper as callback senders) carries over directly.
