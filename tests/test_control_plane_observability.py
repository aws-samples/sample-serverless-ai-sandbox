"""The lifecycle audit record (R14.2) and the running and suspended counts (R14.4), in isolation.

Example-based throughout. Property 24 (the audit chain is contiguous and correlatable) and Property 25
(quota consumption) are both paused in favour of example tests: contiguity is followed end to end over
one Session in `tests/test_control_plane_lifecycle.py`, and what this file pins is the shape of one
record and one metric document, plus the two refusals that make a malformed one impossible to emit.

The sinks here are the whole transport. `RecordingSink` collects rendered lines so a test asserts what
would reach CloudWatch Logs rather than what a mock was called with, and `BrokenSink` is the deployed
failure this module's central claim is about: a transport that is down must cost a counter and nothing
else.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from typing import Any, Final

import pytest

from control_plane.observability import (
    AUDIT_EVENT,
    MAX_REASON_LENGTH,
    METRIC_NAMESPACE,
    RUNNING_METRIC_NAME,
    SUSPENDED_METRIC_NAME,
    AuditRecordRefused,
    LifecycleAuditor,
    SandboxCountEmitter,
    SandboxCountReport,
    SandboxCountState,
    StreamRecordSink,
)
from control_plane.providers.base import SandboxState
from control_plane.state.records import LifecycleState

TENANT: Final = "tenant-a"
SESSION_ID: Final = "01HB0000000000000000000000"
PRINCIPAL: Final = (
    "arn:aws:states:us-east-1:123456789012:execution:SessionOrchestrator:session-1"
)
NOW_MS: Final = 1_700_000_090_000


@dataclass
class RecordingSink:
    """Every line the emitter wrote, in order."""

    lines: list[str] = field(default_factory=list)

    def write(self, line: str) -> None:
        self.lines.append(line)

    @property
    def documents(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]

    @property
    def only(self) -> dict[str, Any]:
        assert len(self.lines) == 1, f"expected one line, got {len(self.lines)}"
        return self.documents[0]


class BrokenSink:
    """A transport that is down. What every `emit` here must survive."""

    def write(self, line: str) -> None:
        raise OSError("the log transport is unreachable")


def auditor(sink: Any = None) -> LifecycleAuditor:
    return LifecycleAuditor(principal=PRINCIPAL, sink=sink)


def count_report(
    *,
    sandbox_state: SandboxState = SandboxState.RUNNING,
    lifecycle_state: LifecycleState = LifecycleState.RUNNING,
) -> SandboxCountReport:
    return SandboxCountReport(
        session_id=SESSION_ID,
        tenant_id=TENANT,
        sandbox_state=sandbox_state,
        lifecycle_state=lifecycle_state,
        observed_at=NOW_MS,
    )


# --- the audit record ------------------------------------------------------------------------------


def test_a_record_carries_every_field_r14_2_names() -> None:
    """Session, Tenant, previous state, new state, timestamp and calling principal, on one record."""
    sink = RecordingSink()
    auditor(sink).emit(
        session_id=SESSION_ID,
        tenant_id=TENANT,
        previous_state=LifecycleState.STARTING,
        new_state=LifecycleState.RUNNING,
        reason="the /run hook returned 200",
        occurred_at=NOW_MS,
    )

    assert sink.only == {
        "event": AUDIT_EVENT,
        "timestamp": NOW_MS,
        "tenantId": TENANT,
        "sessionId": SESSION_ID,
        "previousState": LifecycleState.STARTING.value,
        "newState": LifecycleState.RUNNING.value,
        "principal": PRINCIPAL,
        "reason": "the /run hook returned 200",
    }


def test_the_principal_is_the_auditors_and_no_callers() -> None:
    """`record_for` takes no principal, so no call site can attribute a transition to another one."""
    fields: dict[str, Any] = {
        "session_id": SESSION_ID,
        "tenant_id": TENANT,
        "previous_state": LifecycleState.PENDING,
        "new_state": LifecycleState.ORCHESTRATING,
        "reason": "an execution is governing this Session",
        "occurred_at": NOW_MS,
    }
    reaper = "arn:aws:iam::123456789012:role/Reaper"

    assert auditor().record_for(**fields).principal == PRINCIPAL
    assert LifecycleAuditor(principal=reaper).record_for(**fields).principal == reaper


def test_a_record_of_a_state_the_row_already_holds_is_refused() -> None:
    """Not a transition, and a self-loop in the chain R14.3 asks an operator to follow."""
    with pytest.raises(AuditRecordRefused, match="already holds"):
        auditor().record_for(
            session_id=SESSION_ID,
            tenant_id=TENANT,
            previous_state=LifecycleState.RUNNING,
            new_state=LifecycleState.RUNNING,
            reason="provider reported running",
            occurred_at=NOW_MS,
        )


@pytest.mark.parametrize("absent", ["session_id", "tenant_id"])
def test_a_record_that_cannot_identify_its_session_is_refused(absent: str) -> None:
    """A defect: both identifiers come off a row this Control_Plane wrote."""
    fields: dict[str, Any] = {"session_id": SESSION_ID, "tenant_id": TENANT}
    fields[absent] = ""

    with pytest.raises(AuditRecordRefused, match=absent):
        auditor().record_for(
            previous_state=LifecycleState.STARTING,
            new_state=LifecycleState.RUNNING,
            reason="the /run hook returned 200",
            occurred_at=NOW_MS,
            **fields,
        )


def test_an_auditor_with_no_principal_fails_at_construction() -> None:
    """Before any transition, rather than at the first thing worth auditing."""
    with pytest.raises(AuditRecordRefused, match="principal"):
        LifecycleAuditor(principal="")


def test_a_long_reason_is_truncated_with_a_marker_rather_than_refused() -> None:
    """A caught error's message can be a stack trace; that is operational, not a defect."""
    sink = RecordingSink()
    auditor(sink).emit(
        session_id=SESSION_ID,
        tenant_id=TENANT,
        previous_state=LifecycleState.RUNNING,
        new_state=LifecycleState.FAILED,
        reason="x" * (MAX_REASON_LENGTH * 2),
        occurred_at=NOW_MS,
    )

    reason = sink.only["reason"]
    assert len(reason) == MAX_REASON_LENGTH
    assert reason.endswith("…")


def test_a_broken_sink_costs_a_counter_and_nothing_else() -> None:
    # The design's reason for embedded metric format over PutMetricData, applied to a log write: a
    # Sandbox must not stay allocated because the record of its release could not be written.
    over = auditor(BrokenSink())
    for _ in range(3):
        over.emit(
            session_id=SESSION_ID,
            tenant_id=TENANT,
            previous_state=LifecycleState.RUNNING,
            new_state=LifecycleState.TERMINATED,
            reason="terminated by the Session_Orchestrator",
            occurred_at=NOW_MS,
        )

    assert over.dropped == 3


def test_the_stream_sink_writes_one_flushed_line_per_record() -> None:
    """One JSON object per line is what a collected Lambda stdout already is."""
    stream = io.StringIO()
    auditor(StreamRecordSink(stream)).emit(
        session_id=SESSION_ID,
        tenant_id=TENANT,
        previous_state=LifecycleState.SUSPENDED,
        new_state=LifecycleState.RESUMING,
        reason="provider reported resuming",
        occurred_at=NOW_MS,
    )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["newState"] == LifecycleState.RESUMING.value


# --- the counts ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "counted", "running", "suspended"),
    [
        (SandboxState.RUNNING, SandboxCountState.RUNNING, 1, 0),
        (SandboxState.SUSPENDED, SandboxCountState.SUSPENDED, 0, 1),
        (SandboxState.STARTING, None, 0, 0),
        (SandboxState.SUSPENDING, None, 0, 0),
        (SandboxState.TERMINATED, None, 0, 0),
    ],
)
def test_a_session_contributes_to_at_most_one_count(
    state: SandboxState,
    counted: SandboxCountState | None,
    running: int,
    suspended: int,
) -> None:
    """R14.4 counts two states. A Sandbox in a third counts towards neither rather than towards one."""
    report = count_report(sandbox_state=state)

    assert report.counted is counted
    assert (report.running, report.suspended) == (running, suspended)


def test_the_count_follows_the_provider_rather_than_the_row() -> None:
    """The idle-cost claim is about what is billable, and a running Sandbox is billable.

    A row a Reaper sweep has already settled while this loop was mid-turn still has a Sandbox the
    provider reports running, and that Sandbox costs money until the terminate lands.
    """
    report = count_report(
        sandbox_state=SandboxState.RUNNING, lifecycle_state=LifecycleState.TERMINATED
    )

    assert report.running == 1


def test_the_document_is_embedded_metric_format_over_both_counts() -> None:
    """One document per turn carrying both metrics, so the two series are always comparable."""
    sink = RecordingSink()
    SandboxCountEmitter(sink).record_counts(
        count_report(sandbox_state=SandboxState.SUSPENDED)
    )

    document = sink.only
    metadata = document["_aws"]["CloudWatchMetrics"][0]
    assert document["_aws"]["Timestamp"] == NOW_MS
    assert metadata["Namespace"] == METRIC_NAMESPACE
    assert [metric["Name"] for metric in metadata["Metrics"]] == [
        RUNNING_METRIC_NAME,
        SUSPENDED_METRIC_NAME,
    ]
    assert document[RUNNING_METRIC_NAME] == 0
    assert document[SUSPENDED_METRIC_NAME] == 1


def test_neither_count_is_dimensioned_per_session_or_per_tenant() -> None:
    """A fleet total is a `Sum` over one interval, which a per-Session dimension would put out of
    reach — so the identifiers travel as properties instead."""
    sink = RecordingSink()
    SandboxCountEmitter(sink).record_counts(count_report())

    document = sink.only
    assert document["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [[]]
    assert document["sessionId"] == SESSION_ID
    assert document["tenantId"] == TENANT


def test_the_fleet_count_is_the_sum_of_one_point_per_governed_session() -> None:
    """Three executions, three documents; running and suspended add up to the fleet."""
    sink = RecordingSink()
    emitter = SandboxCountEmitter(sink)
    for state in (SandboxState.RUNNING, SandboxState.RUNNING, SandboxState.SUSPENDED):
        emitter.record_counts(count_report(sandbox_state=state))

    documents = sink.documents
    assert sum(document[RUNNING_METRIC_NAME] for document in documents) == 2
    assert sum(document[SUSPENDED_METRIC_NAME] for document in documents) == 1


def test_a_broken_metric_sink_costs_a_counter_and_nothing_else() -> None:
    """The emitter is called from inside the governing loop; it must not raise into it."""
    emitter = SandboxCountEmitter(BrokenSink())

    emitter.record_counts(count_report())

    assert emitter.dropped == 1


def test_a_report_that_cannot_name_its_session_is_refused() -> None:
    """The same fail-closed posture as the audit record: a defect, raised where it is composed."""
    with pytest.raises(AuditRecordRefused):
        SandboxCountReport(
            session_id="",
            tenant_id=TENANT,
            sandbox_state=SandboxState.RUNNING,
            lifecycle_state=LifecycleState.RUNNING,
            observed_at=NOW_MS,
        )
