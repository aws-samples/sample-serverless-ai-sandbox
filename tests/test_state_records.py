# kiro-classification: public
"""The five item shapes: round-trips, the TTL restriction and the recorded invariants."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from control_plane.state import (
    AffinityKeyBindingRecord,
    ArtifactIndexEntry,
    ConnectionDescriptor,
    ContinuationRecord,
    Eligibility,
    ItemKind,
    ItemShapeError,
    LifecycleState,
    SandboxClaimRecord,
    SessionRecord,
    affinity_key_digest,
    claim_partition_key,
    kind_of_item,
)
from control_plane.state.table import (
    DEADLINE_INDEX,
    PARTITION_KEY_ATTRIBUTE,
    TTL_ATTRIBUTE,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

# A partition key from the Control_Plane's sole producer, called the way a handler calls it: these
# records are addressed with what `pk_for` returns and with nothing spelled by hand.
TENANT_PK = pk_for(
    AuthenticatedPrincipal(
        caller_identity="arn:aws:sts::123456789012:assumed-role/Caller/session",
        tenant_id="tenant-a",
    )
)
SESSION_ID = "01JD7Q2M9K4X8V3B0T5C6Y7E1F"


def a_session(**overrides: Any) -> SessionRecord:
    fields: dict[str, Any] = {
        "pk": TENANT_PK,
        "session_id": SESSION_ID,
        "tenant_id": "tenant-a",
        "provider_name": "lambda-microvms",
        "lifecycle_state": LifecycleState.PENDING,
        "created_at": 1700000000000,
        "updated_at": 1700000000000,
        "max_duration_seconds": 3600,
        "idle_seconds": 300,
        "suspended_seconds": 1800,
        "auto_resume": True,
        "memory_bytes": 2 * 1024**3,
        "execution_role_arn": "arn:aws:iam::111122223333:role/session-01JD",
        "reap_shard": 3,
        "reap_deadline": 1700003600000,
        "artifact_retention_days": 30,
        "exposed_ports": (8080, 3000),
    }
    fields.update(overrides)
    return SessionRecord(**fields)


def a_descriptor() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        base_url="https://endpoint.example",
        auth_header_name="X-aws-proxy-auth",
        auth_header_value="<jwe>",
        ports=(8080, 3000),
        expires_at="2026-06-22T10:15:00Z",
    )


def test_session_record_round_trips_including_the_published_credential() -> None:
    record = a_session(
        lifecycle_state=LifecycleState.RUNNING,
        state_reason="run hook returned 200",
        sandbox_handle={"microVmId": "mv-1"},
        sandbox_id="sbx-1",
        orchestration_execution_arn="arn:aws:states:::execution/01JD",
        connection=a_descriptor(),
        connection_published_at=1700000005000,
        affinity_key_digest=affinity_key_digest("task-42"),
        generation=2,
        egress_generation=4,
        continuation_enabled=True,
        continuation_paths=("/workspace",),
    )
    assert SessionRecord.from_item(record.to_item()) == record


def test_session_item_carries_the_keys_and_the_index_sort_key() -> None:
    item = a_session(lifecycle_state=LifecycleState.RUNNING).to_item()
    assert item[PARTITION_KEY_ATTRIBUTE] == TENANT_PK
    assert item["sk"] == f"S#{SESSION_ID}"
    assert item["stateCreatedAt"] == "RUNNING#1700000000000"
    assert kind_of_item(item) is ItemKind.SESSION


def test_absent_optional_attributes_are_omitted_rather_than_written_as_null() -> None:
    item = a_session().to_item()
    for absent in (
        "connection",
        "connectionPublishedAt",
        "sandboxHandle",
        "sandboxId",
        "orchestrationExecutionArn",
        "affinityKeyDigest",
        "stateReason",
    ):
        assert absent not in item


def test_a_settled_session_omits_the_reap_deadline_and_round_trips_without_it() -> None:
    """`deadline-index` is sparse, so the attribute must be *absent* rather than null.

    A null would still place the item in the index, which is the difference between a settled
    Session leaving the Reaper's read path and staying in it forever.
    """
    settled = a_session(
        lifecycle_state=LifecycleState.TERMINATED,
        state_reason="max duration reached",
        reap_deadline=None,
    )
    item = settled.to_item()
    assert DEADLINE_INDEX.sort_key not in item
    assert SessionRecord.from_item(item) == settled
    assert SessionRecord.from_item(item).reap_deadline is None


def test_a_live_session_still_carries_the_reap_deadline() -> None:
    item = a_session(lifecycle_state=LifecycleState.RUNNING).to_item()
    assert item[DEADLINE_INDEX.sort_key] == 1700003600000


def test_only_the_binding_carries_the_ttl_attribute() -> None:
    binding = AffinityKeyBindingRecord(
        pk=TENANT_PK,
        affinity_key_digest=affinity_key_digest("task-42"),
        session_id=SESSION_ID,
        bound_at=1700000000000,
        expires_at=1700003600000,
    )
    items = [
        a_session(
            connection=a_descriptor(), connection_published_at=1700000005000
        ).to_item(),
        ArtifactIndexEntry(
            pk=TENANT_PK,
            session_id=SESSION_ID,
            artifact_id="stdout",
            s3_key="k",
            size_bytes=12,
        ).to_item(),
        ContinuationRecord(
            pk=TENANT_PK,
            session_id=SESSION_ID,
            generation=1,
            artifact_reference="s3://b/k",
            created_at=1700000000000,
        ).to_item(),
        SandboxClaimRecord(
            pk=claim_partition_key("lambda-microvms", "sbx-1"),
            session_id=SESSION_ID,
            tenant_id="tenant-a",
            claimed_at=1700000000000,
        ).to_item(),
    ]
    assert all(TTL_ATTRIBUTE not in item for item in items)
    assert binding.to_item()[TTL_ATTRIBUTE] == 1700003600000


def test_the_credentials_own_expiry_is_nested_and_is_not_the_ttl_attribute() -> None:
    item = a_session(connection=a_descriptor(), connection_published_at=1).to_item()
    # DynamoDB reads TTL from a top-level attribute only, so an expiring credential cannot delete
    # the Session row that carries it.
    assert TTL_ATTRIBUTE not in item
    assert item["connection"]["expiresAt"] == "2026-06-22T10:15:00Z"


def test_binding_round_trips_and_holds_only_a_session_identifier() -> None:
    binding = AffinityKeyBindingRecord(
        pk=TENANT_PK,
        affinity_key_digest=affinity_key_digest("task-42"),
        session_id=SESSION_ID,
        bound_at=1700000000000,
        expires_at=1700003600000,
    )
    item = binding.to_item()
    assert AffinityKeyBindingRecord.from_item(item) == binding
    assert kind_of_item(item) is ItemKind.AFFINITY_KEY_BINDING
    # No credential, no lifecycle state, no Sandbox handle and no generation to fall out of step.
    assert set(item) == {"pk", "sk", "sessionId", "boundAt", TTL_ATTRIBUTE}


def test_artifact_entry_round_trips_and_shares_the_sessions_key_prefix() -> None:
    entry = ArtifactIndexEntry(
        pk=TENANT_PK,
        session_id=SESSION_ID,
        artifact_id="stdout",
        s3_key=f"tenants/tenant-a/sessions/{SESSION_ID}/1/stdout",
        size_bytes=4096,
        truncated=True,
    )
    item = entry.to_item()
    assert item["sk"].startswith(f"S#{SESSION_ID}#A#")
    assert ArtifactIndexEntry.from_item(item) == entry
    assert kind_of_item(item) is ItemKind.ARTIFACT_INDEX_ENTRY


def test_continuation_record_round_trips_per_generation() -> None:
    record = ContinuationRecord(
        pk=TENANT_PK,
        session_id=SESSION_ID,
        generation=3,
        artifact_reference=f"s3://bucket/tenants/tenant-a/sessions/{SESSION_ID}/3/state.tar",
        created_at=1700000000000,
    )
    item = record.to_item()
    assert item["sk"] == f"S#{SESSION_ID}#C#3"
    assert ContinuationRecord.from_item(item) == record
    assert kind_of_item(item) is ItemKind.CONTINUATION


def test_claim_record_round_trips_outside_any_tenant_partition() -> None:
    claim = SandboxClaimRecord(
        pk=claim_partition_key("lambda-microvms", "sbx-1"),
        session_id=SESSION_ID,
        tenant_id="tenant-a",
        claimed_at=1700000000000,
        eligibility=Eligibility.USED,
    )
    item = claim.to_item()
    assert item["sk"] == "CLAIM"
    assert not item["pk"].startswith("T")
    assert SandboxClaimRecord.from_item(item) == claim
    assert kind_of_item(item) is ItemKind.SANDBOX_CLAIM


def test_quarantine_requires_a_reason_and_a_reason_requires_quarantine() -> None:
    with pytest.raises(ValueError):
        SandboxClaimRecord(
            pk=claim_partition_key("lambda-microvms", "sbx-1"),
            session_id=SESSION_ID,
            tenant_id="tenant-a",
            claimed_at=1,
            eligibility=Eligibility.QUARANTINED,
        )
    with pytest.raises(ValueError):
        SandboxClaimRecord(
            pk=claim_partition_key("lambda-microvms", "sbx-1"),
            session_id=SESSION_ID,
            tenant_id="tenant-a",
            claimed_at=1,
            eligibility=Eligibility.NEVER_RUN,
            quarantine_reason="session-failed",
        )


def test_eligibility_defaults_to_never_run() -> None:
    claim = SandboxClaimRecord(
        pk=claim_partition_key("lambda-microvms", "sbx-1"),
        session_id=SESSION_ID,
        tenant_id="tenant-a",
        claimed_at=1,
    )
    assert claim.eligibility is Eligibility.NEVER_RUN


@pytest.mark.parametrize(
    "overrides",
    [
        {"idle_seconds": 0},
        {"suspended_seconds": 0},
        {"idle_seconds": -1},
        {"max_duration_seconds": 0},
    ],
)
def test_idle_and_suspended_durations_must_be_positive(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        a_session(**overrides)


def test_an_out_of_range_exposed_port_is_rejected() -> None:
    with pytest.raises(ValueError):
        a_session(exposed_ports=(70000,))


def test_stored_decimals_are_read_back_as_integers() -> None:
    # DynamoDB returns numbers as Decimal; a record must not care which numeric form it was given.
    item = a_session().to_item()
    item["createdAt"] = Decimal(item["createdAt"])
    item["reapShard"] = Decimal(item["reapShard"])
    assert SessionRecord.from_item(item).reap_shard == 3


def test_a_non_integral_number_is_refused() -> None:
    item = a_session().to_item()
    item["memoryBytes"] = 1.5
    with pytest.raises(ValueError):
        SessionRecord.from_item(item)


@pytest.mark.parametrize(
    ("state", "terminal"),
    [
        (LifecycleState.TERMINATED, True),
        (LifecycleState.FAILED, True),
        (LifecycleState.RUNNING, False),
        (LifecycleState.TERMINATING, False),
    ],
)
def test_terminal_states_are_terminated_and_failed(
    state: LifecycleState, terminal: bool
) -> None:
    assert state.is_terminal is terminal


def test_a_malformed_item_raises_one_error_type() -> None:
    item = a_session().to_item()
    del item["providerName"]
    with pytest.raises(ItemShapeError):
        SessionRecord.from_item(item)


def test_a_record_refuses_an_item_of_another_shape() -> None:
    binding_item = AffinityKeyBindingRecord(
        pk=TENANT_PK,
        affinity_key_digest=affinity_key_digest("task-42"),
        session_id=SESSION_ID,
        bound_at=1,
        expires_at=2,
    ).to_item()
    with pytest.raises(ValueError):
        SessionRecord.from_item(binding_item)
    with pytest.raises(ValueError):
        ArtifactIndexEntry.from_item(binding_item)
    with pytest.raises(ValueError):
        SandboxClaimRecord.from_item(binding_item)
