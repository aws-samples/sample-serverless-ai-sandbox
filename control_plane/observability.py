# kiro-classification: public
"""The Control_Plane's two Tier 1 signals: the lifecycle audit record (R14.2) and the counts (R14.4).

Both follow the split :mod:`runtime.observability` established. Composing a record **validates and
raises**, because a record that cannot identify what it describes is a defect in this repository's
own code and belongs in a test. Writing one **swallows and counts**, because a broken transport is
operational: the design chooses embedded metric format over `PutMetricData` so that emitting a signal
cannot introduce a synchronous failure into a lifecycle transition, and a `/terminate` that raised
because a sink was unreachable would hold a billable Sandbox allocated in order to record that it was
being released. `dropped` is readable so that "the sink is broken" is distinguishable from "nothing
happened".

Correlation (R14.3) rests on the identifiers below and on nothing added later. The Session identifier
appears in the audit record, in the Step Functions execution name, and as the second segment of the
Sandbox log stream :meth:`~runtime.observability.LogDestination.of` composes; the Tenant identifier is
that stream's first segment. So an audit record names the `<tenantId>/<sessionId>` prefix of the
stream to read, and the generation is the one segment an operator does not need to know in advance.

The record's timestamp is the lifecycle write's own `updatedAt` rather than a second clock reading, so
an audit record and the row it moved carry the identical number and join by equality.

One sink type serves both signals, because both are one JSON line in the Control_Plane's own log
stream: CloudWatch extracts metrics from an embedded-metric document written there, so a metric needs
no client and no separate transport.
"""

from __future__ import annotations

import enum
import json
import sys
from dataclasses import dataclass
from typing import Final, Protocol, TextIO, runtime_checkable

from control_plane.providers.base import SandboxState
from control_plane.state.records import LifecycleState

__all__ = [
    "AUDIT_EVENT",
    "MAX_PRINCIPAL_LENGTH",
    "MAX_REASON_LENGTH",
    "METRIC_NAMESPACE",
    "METRIC_UNIT",
    "RUNNING_METRIC_NAME",
    "SUSPENDED_METRIC_NAME",
    "AuditRecordRefused",
    "LifecycleAuditRecord",
    "LifecycleAuditor",
    "RecordSink",
    "SandboxCountEmitter",
    "SandboxCountMetrics",
    "SandboxCountReport",
    "SandboxCountState",
    "StreamRecordSink",
    "embedded_metric_document",
]

#: The `event` every audit record carries, so one filter over the Control_Plane's log group returns
#: the lifecycle chain and nothing else.
AUDIT_EVENT: Final = "session.lifecycle.transition"

#: Bound on the recorded reason, which arrives from a caught error's message and can carry a whole
#: stack trace. The same bound :data:`~control_plane.orchestrator.tasks.MAX_STATE_REASON_LENGTH`
#: applies to the row's own `stateReason`, so the record and the row truncate alike.
MAX_REASON_LENGTH: Final = 1_024

#: Bound on the calling principal, which is an execution ARN or an assumed-role ARN.
MAX_PRINCIPAL_LENGTH: Final = 2_048

#: One namespace for the whole deployment, so the dashboard of task 11.5 has one place to look.
METRIC_NAMESPACE: Final = "AwsServerlessAgentSandbox"

#: Sandboxes the provider reports running, and Sandboxes it reports suspended (R14.4). Each governed
#: Session contributes one point per poll turn, so the fleet count is the `Sum` over one poll
#: interval — which is why neither metric is dimensioned per Session or per Tenant: a dimension of
#: that cardinality would put the fleet total out of reach and charge for every Session separately.
RUNNING_METRIC_NAME: Final = "SandboxesRunning"
SUSPENDED_METRIC_NAME: Final = "SandboxesSuspended"

METRIC_UNIT: Final = "Count"

_TRUNCATION_MARKER: Final = "…"


class AuditRecordRefused(ValueError):
    """A record cannot attribute the transition it describes, so it is refused rather than emitted.

    A defect: every field it needs comes off a row this Control_Plane wrote. Raised while composing,
    before anything is written, so it is met in the suite rather than in a lifecycle path.
    """


def _require_present(name: str, value: str, limit: int) -> str:
    if not value:
        raise AuditRecordRefused(f"{name} must not be empty")
    if len(value) > limit:
        raise AuditRecordRefused(f"{name} exceeds {limit} characters: {len(value)}")
    return value


def _bounded(value: str) -> str:
    """Truncate a reason with a marker, so a shortened one is not read as a complete one."""
    if len(value) <= MAX_REASON_LENGTH:
        return value
    return value[: MAX_REASON_LENGTH - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


@dataclass(frozen=True, slots=True)
class LifecycleAuditRecord:
    """One Session lifecycle transition, with everything R14.2 requires on it.

    Frozen, and built only by :meth:`LifecycleAuditor.record_for`, which is the one producer of the
    `principal` field: a record composed elsewhere could attribute a transition to a caller this
    process never authenticated.

    A record whose two states are equal is refused. A report that mirrors the state a row already
    holds is not a transition, and admitting one would put a self-loop into the chain R14.3 asks an
    operator to follow.
    """

    session_id: str
    tenant_id: str
    previous_state: LifecycleState
    new_state: LifecycleState
    reason: str
    occurred_at: int
    principal: str

    def __post_init__(self) -> None:
        _require_present("session_id", self.session_id, MAX_PRINCIPAL_LENGTH)
        _require_present("tenant_id", self.tenant_id, MAX_PRINCIPAL_LENGTH)
        _require_present("principal", self.principal, MAX_PRINCIPAL_LENGTH)
        if self.previous_state is self.new_state:
            raise AuditRecordRefused(
                f"{self.new_state.value} is the state the row already holds, so there is no "
                f"transition to record"
            )
        if isinstance(self.occurred_at, bool) or not isinstance(self.occurred_at, int):
            raise AuditRecordRefused(f"occurred_at must be an integer: {self.occurred_at!r}")
        if self.occurred_at <= 0:
            raise AuditRecordRefused(f"occurred_at must be positive: {self.occurred_at}")

    @property
    def payload(self) -> dict[str, str | int]:
        """The record as it is emitted. Identity first, so a raw log stream reads in order."""
        return {
            "event": AUDIT_EVENT,
            "timestamp": self.occurred_at,
            "tenantId": self.tenant_id,
            "sessionId": self.session_id,
            "previousState": self.previous_state.value,
            "newState": self.new_state.value,
            "principal": self.principal,
            "reason": _bounded(self.reason),
        }

    def render(self) -> str:
        """One line of ASCII, because a log line is read by machines more often than by people."""
        return json.dumps(self.payload, ensure_ascii=True, separators=(",", ":"))


@runtime_checkable
class RecordSink(Protocol):
    """Writes one rendered JSON line to the Control_Plane's log stream.

    One method, because that is the entire dependency: this module decides what a line says and the
    deployment holds the transport. An implementation must not block, and must not be relied on to
    avoid raising — both emitters below guard against that.
    """

    def write(self, line: str) -> None:
        """Write one rendered JSON object."""
        ...


class StreamRecordSink:
    """Writes one JSON object per line to a text stream, `sys.stdout` by default.

    That is what a Lambda function's stdout already is: CloudWatch Logs collects it, and extracts
    metrics from an embedded-metric document in it, so this is the deployed sink as well as the one
    the offline suite drives with an `io.StringIO`.
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        """Bind the stream. None means `sys.stdout`, read at write time so a redirect still works."""
        self._stream = stream

    def write(self, line: str) -> None:
        """Write one line, flushed, because a Lambda invocation can be frozen after it returns."""
        stream = sys.stdout if self._stream is None else self._stream
        stream.write(f"{line}\n")
        stream.flush()


class LifecycleAuditor:
    """Emits one structured audit record per Session lifecycle transition (R14.2).

    One per request or per orchestration invocation, because the calling principal is a property of
    the caller rather than of the process. The principal is held here rather than passed per record
    for the same reason: one producer, so no call site can attribute a transition to another caller.

    The principal is an identity string rather than an
    :class:`~control_plane.tenancy.AuthenticatedPrincipal`, because the Reaper sweeps across Tenants
    with its own role and has no one Tenant to name. The Tenant on a record is the Tenant of the
    Session being transitioned, read off the row.
    """

    def __init__(self, *, principal: str, sink: RecordSink | None = None) -> None:
        """Bind the calling principal and the sink.

        The principal is validated here, before any transition, so a misconfigured deployment fails
        at construction rather than at the first thing worth auditing.
        """
        self._principal = _require_present("principal", principal, MAX_PRINCIPAL_LENGTH)
        self._sink = StreamRecordSink() if sink is None else sink
        self._dropped = 0

    @property
    def principal(self) -> str:
        """The calling principal every record this auditor emits is attributed to."""
        return self._principal

    @property
    def dropped(self) -> int:
        """Records the sink refused. Non-zero means the transport is broken, not the Session."""
        return self._dropped

    def record_for(
        self,
        *,
        session_id: str,
        tenant_id: str,
        previous_state: LifecycleState,
        new_state: LifecycleState,
        reason: str,
        occurred_at: int,
    ) -> LifecycleAuditRecord:
        """Compose and validate one record, stamping the calling principal.

        Separate from :meth:`emit` so that what a record contains is assertable without a sink.

        Raises:
            AuditRecordRefused: the record cannot attribute the transition, or describes none.
        """
        return LifecycleAuditRecord(
            session_id=session_id,
            tenant_id=tenant_id,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
            occurred_at=occurred_at,
            principal=self._principal,
        )

    def emit(
        self,
        *,
        session_id: str,
        tenant_id: str,
        previous_state: LifecycleState,
        new_state: LifecycleState,
        reason: str,
        occurred_at: int,
    ) -> None:
        """Write one record, and never fail the transition because the sink did.

        A sink failure increments :attr:`dropped` and returns. An
        :class:`AuditRecordRefused` from :meth:`record_for` is deliberately not caught: it is raised
        before anything is written and it is a defect in this repository's own code.
        """
        record = self.record_for(
            session_id=session_id,
            tenant_id=tenant_id,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
            occurred_at=occurred_at,
        )
        try:
            self._sink.write(record.render())
        except Exception:  # noqa: BLE001 - a broken sink must not fail a lifecycle transition
            self._dropped += 1


class SandboxCountState(enum.Enum):
    """The two states R14.4 counts. Everything else a provider reports counts as neither."""

    RUNNING = "running"
    SUSPENDED = "suspended"


#: Which provider-reported state each counted state is. Keyed on the *provider's* enum rather than on
#: the recorded lifecycle state, because the near-zero idle cost claim is about what is billable: a
#: Sandbox the provider reports running is billable whatever the row says about it.
_COUNTED_STATES: Final[dict[SandboxState, SandboxCountState]] = {
    SandboxState.RUNNING: SandboxCountState.RUNNING,
    SandboxState.SUSPENDED: SandboxCountState.SUSPENDED,
}


@dataclass(frozen=True, slots=True)
class SandboxCountReport:
    """One governed Session's contribution to the running and suspended counts (R14.4).

    A whole report rather than two counters, the shape
    :class:`~control_plane.reaper.SweepMetrics` established: the relationship between the numbers is
    what an emitter needs to be able to see. :attr:`running` and :attr:`suspended` are derived rather
    than supplied, so no caller can report a Sandbox as both or as neither when it is one.
    """

    session_id: str
    tenant_id: str
    sandbox_state: SandboxState
    lifecycle_state: LifecycleState
    observed_at: int

    def __post_init__(self) -> None:
        _require_present("session_id", self.session_id, MAX_PRINCIPAL_LENGTH)
        _require_present("tenant_id", self.tenant_id, MAX_PRINCIPAL_LENGTH)
        if self.observed_at <= 0:
            raise AuditRecordRefused(f"observed_at must be positive: {self.observed_at}")

    @property
    def counted(self) -> SandboxCountState | None:
        """Which count this Session contributes to, or None for a state R14.4 counts neither way."""
        return _COUNTED_STATES.get(self.sandbox_state)

    @property
    def running(self) -> int:
        return 1 if self.counted is SandboxCountState.RUNNING else 0

    @property
    def suspended(self) -> int:
        return 1 if self.counted is SandboxCountState.SUSPENDED else 0


class SandboxCountMetrics(Protocol):
    """Where the running and suspended counts go (R14.4).

    One method taking the whole report, for the reason
    :class:`~control_plane.reaper.SweepMetrics` gives. An implementation must not raise: the caller is
    a `Task` state inside the governing loop, and a metric that could fail that task could tear down
    a healthy Session in order to record that it was running.
    """

    def record_counts(self, report: SandboxCountReport) -> None:
        """Emit one point for each of the two counts."""
        ...


def embedded_metric_document(
    *,
    values: dict[str, int],
    timestamp_ms: int,
    properties: dict[str, str],
) -> str:
    """Render one embedded-metric-format document, as a single JSON line.

    `Dimensions` is one empty set, so each metric aggregates at the namespace level and a `Sum` over
    one poll interval is the fleet count. The Session and Tenant travel as properties rather than
    dimensions: they make a document searchable without multiplying metric cardinality.
    """
    return json.dumps(
        {
            "_aws": {
                "Timestamp": timestamp_ms,
                "CloudWatchMetrics": [
                    {
                        "Namespace": METRIC_NAMESPACE,
                        "Dimensions": [[]],
                        "Metrics": [
                            {"Name": name, "Unit": METRIC_UNIT} for name in values
                        ],
                    }
                ],
            },
            **values,
            **properties,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


class SandboxCountEmitter:
    """Writes the running and suspended counts as one embedded-metric document (R14.4).

    Satisfies :class:`SandboxCountMetrics`, and it is what makes the near-zero idle cost claim rest
    on an observed count: a suspended Session emits `SandboxesSuspended` and stops emitting
    `SandboxesRunning`, so the two series are the evidence rather than the assertion.

    Embedded metric format, so there is no `PutMetricData` call to be throttled and nothing here that
    a lifecycle transition waits on. A sink failure is still counted and swallowed, because the sink
    is a transport this module does not own.
    """

    def __init__(self, sink: RecordSink | None = None) -> None:
        self._sink = StreamRecordSink() if sink is None else sink
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """Documents the sink refused. Non-zero means the counts are understated."""
        return self._dropped

    def document_for(self, report: SandboxCountReport) -> str:
        """The document this report emits. Separate from :meth:`record_counts` so it is assertable."""
        return embedded_metric_document(
            values={
                RUNNING_METRIC_NAME: report.running,
                SUSPENDED_METRIC_NAME: report.suspended,
            },
            timestamp_ms=report.observed_at,
            properties={
                "tenantId": report.tenant_id,
                "sessionId": report.session_id,
                "sandboxState": report.sandbox_state.value,
                "lifecycleState": report.lifecycle_state.value,
            },
        )

    def record_counts(self, report: SandboxCountReport) -> None:
        """Write one document, and never raise into the governing loop."""
        document = self.document_for(report)
        try:
            self._sink.write(document)
        except Exception:  # noqa: BLE001 - a broken sink must not fail the governing loop
            self._dropped += 1
