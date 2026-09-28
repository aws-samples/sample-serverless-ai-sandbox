# kiro-classification: public
"""The Session-identifying log emitter: the two names, the record shape, and what it refuses.

Deterministic throughout, and offline by construction: the only sink used here is a
`StreamLogSink` over an `io.StringIO`, so nothing reaches CloudWatch Logs and nothing needs a
network. The property that quantifies over Sessions and asserts the audit chain is correlatable
is Property 24, which is its own task in phase 11; these are the examples underneath it, plus the
two refusals that a property over well-formed Sessions would never generate — a Tenant identifier
carrying a separator, and a record asked to carry a field the boundary does not admit.
"""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from runtime.app import HOOK_PATH_PREFIX, create_app
from runtime.observability import (
    EMITTABLE_FIELDS,
    LOG_GROUP_PREFIX,
    MAX_FIELD_LENGTH,
    MAX_LOG_NAME_LENGTH,
    RESERVED_FIELDS,
    LogDestination,
    LogFieldRefused,
    LogLevel,
    LogNamingError,
    LogSink,
    SessionIdentity,
    SessionLogEmitter,
    StreamLogSink,
)
from runtime.readiness import RuntimePhase

FIXED_MOMENT = datetime(2025, 3, 4, 5, 6, 7, 890123, tzinfo=UTC)


def identity(
    *,
    environment: str = "prod",
    tenant_id: str = "acme",
    session_id: str = "sess-1",
    generation: int = 1,
) -> SessionIdentity:
    return SessionIdentity(
        environment=environment,
        tenant_id=tenant_id,
        session_id=session_id,
        generation=generation,
    )


def emitter_over(stream: io.StringIO, **overrides: Any) -> SessionLogEmitter:
    return SessionLogEmitter(
        identity=identity(**overrides),
        sink=StreamLogSink(stream),
        clock=lambda: FIXED_MOMENT,
    )


def records_in(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


# --- The two names, which are the requirement ---------------------------------------------


def test_the_destination_is_the_designs_group_and_stream() -> None:
    destination = LogDestination.of(
        identity(
            environment="prod", tenant_id="acme", session_id="sess-1", generation=3
        )
    )
    assert destination.log_group == "/aws/sandbox/prod"
    assert destination.log_stream == "acme/sess-1/3"


def test_the_stream_carries_tenant_session_and_generation_in_that_order() -> None:
    stream_name = LogDestination.of(identity(generation=7)).log_stream
    assert stream_name.split("/") == ["acme", "sess-1", "7"]


def test_a_continuation_writes_to_a_different_stream_under_the_same_session() -> None:
    # R6.24: the Session identifier survives a continuation and the generation increments, so
    # two generations of one Session are distinguishable by stream and correlatable by name.
    first = LogDestination.of(identity(generation=1))
    second = LogDestination.of(identity(generation=2))
    assert first.log_group == second.log_group
    assert first.log_stream != second.log_stream
    assert second.log_stream == "acme/sess-1/2"


def test_the_group_prefix_is_read_from_the_module_rather_than_spelled_by_a_caller() -> (
    None
):
    assert LogDestination.of(identity()).log_group.startswith(f"{LOG_GROUP_PREFIX}/")


@pytest.mark.parametrize(
    "field",
    ["environment", "tenant_id", "session_id"],
)
def test_a_separator_in_any_segment_is_refused(field: str) -> None:
    # The load-bearing refusal: `acme/eu` would move the generation out of its own segment and
    # make one Session's stream name resolve to another's.
    segments: dict[str, str] = {
        "environment": "prod",
        "tenant_id": "acme",
        "session_id": "sess-1",
    }
    segments[field] = "acme/eu"
    with pytest.raises(LogNamingError, match="add a segment"):
        SessionIdentity(generation=1, **segments)


@pytest.mark.parametrize("value", ["a*b", "a:b", "a b", "a\tb", ""])
def test_a_segment_cloudwatch_refuses_is_refused_here(value: str) -> None:
    with pytest.raises(LogNamingError):
        identity(tenant_id=value)


@pytest.mark.parametrize("generation", [0, -1, True])
def test_a_generation_that_names_no_sandbox_is_refused(generation: object) -> None:
    with pytest.raises(LogNamingError, match="generation"):
        SessionIdentity(
            environment="prod",
            tenant_id="acme",
            session_id="sess-1",
            generation=generation,  # type: ignore[arg-type]
        )


def test_a_name_longer_than_cloudwatch_accepts_is_refused() -> None:
    with pytest.raises(LogNamingError, match="log stream name"):
        LogDestination.of(identity(session_id="s" * (MAX_LOG_NAME_LENGTH + 1)))


# --- Reading the identity the provider carried in ------------------------------------------


def test_the_identity_is_read_from_the_sandbox_environment() -> None:
    resolved = SessionIdentity.from_environment(
        {
            "SANDBOX_ENVIRONMENT": "staging",
            "SANDBOX_TENANT_ID": "acme",
            "SANDBOX_SESSION_ID": "sess-9",
            "SANDBOX_GENERATION": "4",
        }
    )
    assert resolved == identity(
        environment="staging", tenant_id="acme", session_id="sess-9", generation=4
    )


@pytest.mark.parametrize(
    "absent",
    [
        "SANDBOX_ENVIRONMENT",
        "SANDBOX_TENANT_ID",
        "SANDBOX_SESSION_ID",
        "SANDBOX_GENERATION",
    ],
)
def test_an_incomplete_environment_names_what_is_missing(absent: str) -> None:
    source = {
        "SANDBOX_ENVIRONMENT": "prod",
        "SANDBOX_TENANT_ID": "acme",
        "SANDBOX_SESSION_ID": "sess-1",
        "SANDBOX_GENERATION": "1",
    }
    del source[absent]
    with pytest.raises(LogNamingError, match=absent):
        SessionIdentity.from_environment(source)


def test_a_generation_that_is_not_a_number_is_refused_by_name() -> None:
    with pytest.raises(LogNamingError, match="SANDBOX_GENERATION"):
        SessionIdentity.from_environment(
            {
                "SANDBOX_ENVIRONMENT": "prod",
                "SANDBOX_TENANT_ID": "acme",
                "SANDBOX_SESSION_ID": "sess-1",
                "SANDBOX_GENERATION": "second",
            }
        )


# --- The record ----------------------------------------------------------------------------


def test_every_record_carries_the_session_identity() -> None:
    stream = io.StringIO()
    emitter_over(stream).emit("hook.run")
    (record,) = records_in(stream)
    assert record["tenantId"] == "acme"
    assert record["sessionId"] == "sess-1"
    assert record["generation"] == 1
    assert record["event"] == "hook.run"
    assert record["level"] == "INFO"
    assert record["timestamp"] == "2025-03-04T05:06:07.890123+00:00"


def test_a_record_is_one_line_of_json() -> None:
    stream = io.StringIO()
    over = emitter_over(stream)
    over.emit("hook.run")
    over.emit("hook.suspend", level=LogLevel.WARNING)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["event"] for line in lines] == [
        "hook.run",
        "hook.suspend",
    ]


def test_the_instance_identifier_appears_only_once_it_is_bound() -> None:
    stream = io.StringIO()
    over = emitter_over(stream)
    over.emit("hook.run")
    over.bind_instance("0123456789abcdef")
    over.emit("hook.suspend")
    before, after = records_in(stream)
    # Absent rather than null before `/run` generated one: a record cannot claim a writer that
    # did not exist when it was written.
    assert "instanceId" not in before
    assert after["instanceId"] == "0123456789abcdef"


def test_the_instance_identifier_is_bound_once() -> None:
    over = emitter_over(io.StringIO())
    over.bind_instance("0123456789abcdef")
    with pytest.raises(LogNamingError, match="already carries"):
        over.bind_instance("fedcba9876543210")


def test_the_instance_identifier_is_not_part_of_the_stream_name() -> None:
    # R14.3 correlation constructs the stream name from the Session row, and the Control_Plane
    # cannot know an identifier generated inside the MicroVM (R7.12). So the name is fixed by
    # the identity and the identifier travels in the record instead.
    over = emitter_over(io.StringIO())
    before = over.destination
    over.bind_instance("0123456789abcdef")
    assert over.destination == before
    assert "0123456789abcdef" not in over.destination.log_stream


def test_a_declared_detail_field_is_carried() -> None:
    stream = io.StringIO()
    emitter_over(stream).emit(
        "hook.terminate",
        detail={"hook": "terminate", "status": 200, "truncated": False},
    )
    (record,) = records_in(stream)
    assert record["hook"] == "terminate"
    assert record["status"] == 200
    assert record["truncated"] is False


def test_a_field_outside_the_allow_list_is_refused() -> None:
    over = emitter_over(io.StringIO())
    with pytest.raises(LogFieldRefused, match="not a field the Sandbox_Runtime emits"):
        over.emit("hook.run", detail={"authHeaderValue": "secret"})


@pytest.mark.parametrize(
    "field",
    [
        "stdout",
        "stderr",
        "output",
        "path",
        "argv",
        "environment",
        "handle",
        "credential",
    ],
)
def test_no_field_exists_for_attacker_controlled_or_secret_content(field: str) -> None:
    assert field not in EMITTABLE_FIELDS


def test_no_detail_field_can_overwrite_the_identity() -> None:
    assert not (EMITTABLE_FIELDS & RESERVED_FIELDS)


def test_bytes_are_refused_by_name() -> None:
    over = emitter_over(io.StringIO())
    with pytest.raises(LogFieldRefused, match="does not emit byte values"):
        over.emit("hook.run", detail={"reason": b"process output"})  # type: ignore[dict-item]


def test_a_long_reason_is_truncated_with_a_marker() -> None:
    stream = io.StringIO()
    emitter_over(stream).emit("hook.run", detail={"reason": "x" * 5_000})
    (record,) = records_in(stream)
    assert record["reason"].endswith("...[truncated]")
    assert record["reason"].startswith("x" * MAX_FIELD_LENGTH)


@pytest.mark.parametrize("event", ["", "Hook.Run", "hook run", "hook-run", "hook/run"])
def test_an_event_name_outside_the_vocabulary_is_refused(event: str) -> None:
    over = emitter_over(io.StringIO())
    with pytest.raises(LogNamingError):
        over.emit(event)


def test_a_naive_clock_moment_is_read_as_utc() -> None:
    stream = io.StringIO()
    SessionLogEmitter(
        identity=identity(),
        sink=StreamLogSink(stream),
        clock=lambda: datetime(2025, 1, 2, 3, 4, 5),  # noqa: DTZ001 - the case under test
    ).emit("hook.run")
    (record,) = records_in(stream)
    assert record["timestamp"] == "2025-01-02T03:04:05+00:00"


# --- The sink is a seam, and a broken one must not fail a transition ----------------------


class BrokenSink:
    """A sink whose transport is unreachable, which is the ordinary production failure."""

    def write(self, destination: LogDestination, record: str) -> None:
        raise OSError("the log transport is unreachable")


def test_a_sink_failure_is_counted_and_not_raised() -> None:
    over = SessionLogEmitter(
        identity=identity(), sink=BrokenSink(), clock=lambda: FIXED_MOMENT
    )
    over.emit("hook.terminate")
    over.emit("hook.terminate")
    assert over.dropped == 2


def test_a_refused_field_is_raised_rather_than_counted() -> None:
    # The two failures are not the same kind of thing: a broken transport is operational and a
    # field the boundary does not admit is a defect in this repository's code.
    over = SessionLogEmitter(
        identity=identity(), sink=BrokenSink(), clock=lambda: FIXED_MOMENT
    )
    with pytest.raises(LogFieldRefused):
        over.emit("hook.run", detail={"sessionId": "somebody-elses"})
    assert over.dropped == 0


def test_the_stream_sink_satisfies_the_seam() -> None:
    assert isinstance(StreamLogSink(io.StringIO()), LogSink)


def test_the_sink_is_given_the_destination_with_every_write() -> None:
    seen: list[LogDestination] = []

    class Recording:
        def write(self, destination: LogDestination, record: str) -> None:
            seen.append(destination)

    over = SessionLogEmitter(
        identity=identity(), sink=Recording(), clock=lambda: FIXED_MOMENT
    )
    over.emit("hook.run")
    assert seen == [LogDestination.of(identity())]


# --- The four hooks emit, and the record describes the outcome ----------------------------


class NoopActions:
    """Lifecycle actions that succeed and do nothing, so the records are the only variable."""

    async def apply_configuration(self, payload: bytes) -> None:
        return None

    async def quiesce_and_flush(self) -> None:
        return None

    async def refresh_egress_identity(self) -> None:
        return None

    async def persist_artifacts(self) -> None:
        return None


def run[T](coroutine: Coroutine[object, object, T]) -> T:
    return asyncio.run(coroutine)


def app_with(stream: io.StringIO) -> Starlette:
    return create_app(actions=NoopActions(), emitter=emitter_over(stream))


def test_each_hook_records_its_transition_under_the_session_stream() -> None:
    stream = io.StringIO()
    with TestClient(app_with(stream)) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/suspend").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/resume").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == 200

    records = records_in(stream)
    assert [record["event"] for record in records] == [
        "hook.run",
        "hook.suspend",
        "hook.resume",
        "hook.terminate",
    ]
    assert [record["outcome"] for record in records] == [
        "serving",
        "suspended",
        "serving",
        "terminated",
    ]
    # The phase is read from the gate after the transition, so it is the outcome and not the
    # intention. `/resume` lands back in `serving`; `/terminate` is terminal.
    assert [record["phase"] for record in records] == [
        RuntimePhase.SERVING,
        RuntimePhase.SUSPENDED,
        RuntimePhase.SERVING,
        RuntimePhase.TERMINATED,
    ]
    assert {record["sessionId"] for record in records} == {"sess-1"}


def test_a_refused_second_run_is_recorded_as_a_refusal() -> None:
    stream = io.StringIO()
    with TestClient(app_with(stream)) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 409

    first, second = records_in(stream)
    assert first["outcome"] == "serving"
    assert second["outcome"] == "refused"
    assert second["level"] == "WARNING"
    assert second["status"] == 409
    # The phase did not move, which is the fact the record exists to carry.
    assert second["phase"] == RuntimePhase.SERVING
    assert second["reason"]


def test_a_failed_run_is_recorded_as_an_error_carrying_its_reason() -> None:
    class FailingActions(NoopActions):
        async def apply_configuration(self, payload: bytes) -> None:
            raise RuntimeError(
                "the configuration names a port this runtime cannot expose"
            )

    stream = io.StringIO()
    app = create_app(actions=FailingActions(), emitter=emitter_over(stream))
    with TestClient(app) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 500

    (record,) = records_in(stream)
    assert record["level"] == "ERROR"
    assert record["outcome"] == "failed"
    assert record["phase"] == RuntimePhase.FAILED
    assert "cannot expose" in record["reason"]


def test_a_runtime_with_no_emitter_serves_its_hooks_unchanged() -> None:
    # The emitter is optional, and its absence changes no hook's behaviour.
    with TestClient(create_app(actions=NoopActions())) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == 200


def test_a_broken_sink_does_not_fail_a_terminate() -> None:
    # The design's reason for embedded metric format over PutMetricData, applied to a log write:
    # a Sandbox must not stay allocated because the record of its release could not be written.
    over = SessionLogEmitter(
        identity=identity(), sink=BrokenSink(), clock=lambda: FIXED_MOMENT
    )
    with TestClient(create_app(actions=NoopActions(), emitter=over)) as client:
        assert client.post(f"{HOOK_PATH_PREFIX}/run", content=b"{}").status_code == 200
        assert client.post(f"{HOOK_PATH_PREFIX}/terminate").status_code == 200
    assert over.dropped == 2


def test_the_run_hook_binds_the_generated_instance_identifier() -> None:
    from runtime.lifecycle import SandboxLifecycle

    stream = io.StringIO()
    over = emitter_over(stream)
    actions = SandboxLifecycle(emitter=over)

    async def scenario() -> None:
        await actions.apply_configuration(b"{}")

    run(scenario())
    values = actions.values
    assert values is not None
    assert over.instance_id == values.instance_id

    over.emit("hook.run")
    (record,) = records_in(stream)
    assert record["instanceId"] == values.instance_id


def test_the_emitter_is_readable_off_the_application() -> None:
    # Which is how the server entrypoint reaches the destination it is writing under.
    app = app_with(io.StringIO())
    assert isinstance(app.state.emitter, SessionLogEmitter)
    assert app.state.emitter.destination.log_group == "/aws/sandbox/prod"
