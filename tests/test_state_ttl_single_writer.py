# kiro-classification: public
"""The TTL single-writer rule: one item shape sets `expiresAt` and no other one may (R13.8).

TTL expiry reaching a Session row, an artifact index entry or a claim item would delete the only
record of a billable Sandbox, so the guarantee is not "the binding has a TTL" but "nothing else
does". These assertions are therefore quantified over every item shape
:mod:`control_plane.state.records` defines, discovered from the module rather than listed, so a
sixth shape that sets the attribute — or one that is added and never exercised — fails the suite.
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any

from control_plane.state import records as records_module
from control_plane.state.keys import (
    ItemKind,
    affinity_key_digest,
    claim_partition_key,
    kind_of_item,
)
from control_plane.state.records import (
    AffinityKeyBindingRecord,
    ArtifactIndexEntry,
    ConnectionDescriptor,
    ContinuationRecord,
    Eligibility,
    LifecycleState,
    SandboxClaimRecord,
    SessionRecord,
)
from control_plane.state.table import TTL_ATTRIBUTE
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

#: Addressed with what the Control_Plane's sole partition-key producer returns, as elsewhere in the
#: suite: nothing here spells a Tenant partition key by hand.
TENANT_PK = pk_for(
    AuthenticatedPrincipal(
        caller_identity="arn:aws:sts::123456789012:assumed-role/Caller/session",
        tenant_id="tenant-a",
    )
)
SESSION_ID = "01JD7Q2M9K4X8V3B0T5C6Y7E1F"
DIGEST = affinity_key_digest("task-42")

#: The only record type permitted to write the TTL attribute.
TTL_WRITER = AffinityKeyBindingRecord

#: How the TTL attribute can be named inside an item producer's source, so the source-level check
#: catches a conditional write no constructed instance happens to exercise.
TTL_SPELLINGS = ("TTL_ATTRIBUTE", f'"{TTL_ATTRIBUTE}"', f"'{TTL_ATTRIBUTE}'")


def _descriptor() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        base_url="https://endpoint.example",
        auth_header_name="X-aws-proxy-auth",
        auth_header_value="<jwe>",
        ports=(8080, 3000),
        expires_at="2026-06-22T10:15:00Z",
    )


def _session(**overrides: Any) -> SessionRecord:
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
    }
    fields.update(overrides)
    return SessionRecord(**fields)


def _item_record_types() -> dict[str, type[Any]]:
    """Every item shape the records module defines, discovered rather than listed.

    An item shape is a dataclass declared in that module which converts itself to a stored
    attribute map. :class:`ConnectionDescriptor` is deliberately not one: it converts to a *nested*
    map (``to_map``) and never becomes an item of its own, which is why its own `expiresAt` is not
    the table's TTL attribute.
    """
    return {
        name: value
        for name, value in vars(records_module).items()
        if inspect.isclass(value)
        and value.__module__ == records_module.__name__
        and dataclasses.is_dataclass(value)
        and hasattr(value, "to_item")
    }


def _instances() -> dict[type[Any], tuple[Any, ...]]:
    """Two instances per item shape: one minimal, one with every optional attribute populated.

    The maximal form matters because an optional attribute is where a stray top-level `expiresAt`
    would plausibly appear.
    """
    return {
        SessionRecord: (
            _session(),
            _session(
                lifecycle_state=LifecycleState.RUNNING,
                state_reason="run hook returned 200",
                sandbox_handle={"microVmId": "mv-1"},
                sandbox_id="sbx-1",
                orchestration_execution_arn="arn:aws:states:::execution/01JD",
                connection=_descriptor(),
                connection_published_at=1700000005000,
                affinity_key_digest=DIGEST,
                exposed_ports=(8080, 3000),
                generation=2,
                egress_generation=4,
                continuation_enabled=True,
                continuation_paths=("/workspace",),
            ),
        ),
        ArtifactIndexEntry: (
            ArtifactIndexEntry(
                pk=TENANT_PK,
                session_id=SESSION_ID,
                artifact_id="stdout",
                s3_key=f"tenants/tenant-a/sessions/{SESSION_ID}/1/stdout",
                size_bytes=0,
            ),
            ArtifactIndexEntry(
                pk=TENANT_PK,
                session_id=SESSION_ID,
                artifact_id="stderr",
                s3_key=f"tenants/tenant-a/sessions/{SESSION_ID}/1/stderr",
                size_bytes=4096,
                truncated=True,
            ),
        ),
        ContinuationRecord: (
            ContinuationRecord(
                pk=TENANT_PK,
                session_id=SESSION_ID,
                generation=0,
                artifact_reference="s3://bucket/state.tar",
                created_at=0,
            ),
            ContinuationRecord(
                pk=TENANT_PK,
                session_id=SESSION_ID,
                generation=3,
                artifact_reference=f"s3://bucket/tenants/tenant-a/sessions/{SESSION_ID}/3/state.tar",
                created_at=1700000000000,
            ),
        ),
        AffinityKeyBindingRecord: (
            AffinityKeyBindingRecord(
                pk=TENANT_PK,
                affinity_key_digest=DIGEST,
                session_id=SESSION_ID,
                bound_at=0,
                expires_at=0,
            ),
            AffinityKeyBindingRecord(
                pk=TENANT_PK,
                affinity_key_digest=DIGEST,
                session_id=SESSION_ID,
                bound_at=1700000000000,
                expires_at=1700003600000,
            ),
        ),
        SandboxClaimRecord: (
            SandboxClaimRecord(
                pk=claim_partition_key("lambda-microvms", "sbx-1"),
                session_id=SESSION_ID,
                tenant_id="tenant-a",
                claimed_at=1700000000000,
            ),
            SandboxClaimRecord(
                pk=claim_partition_key("lambda-microvms", "sbx-2"),
                session_id=SESSION_ID,
                tenant_id="tenant-a",
                claimed_at=1700000000000,
                eligibility=Eligibility.QUARANTINED,
                quarantine_reason="session-failed",
            ),
        ),
    }


def test_every_item_shape_the_module_defines_is_exercised_here() -> None:
    # Discovery rather than a list: a sixth item shape fails here until it is exercised below,
    # which is what stops the TTL assertions from silently covering only the original five.
    assert set(_item_record_types().values()) == set(_instances())


def test_the_item_kinds_and_the_item_shapes_stay_in_step() -> None:
    produced = {
        kind_of_item(instance.to_item())
        for instances in _instances().values()
        for instance in instances
    }
    assert produced == set(ItemKind)
    assert len(_item_record_types()) == len(ItemKind)


def test_exactly_one_item_shape_writes_the_ttl_attribute() -> None:
    writers = {
        type(instance)
        for instances in _instances().values()
        for instance in instances
        if TTL_ATTRIBUTE in instance.to_item()
    }
    assert writers == {TTL_WRITER}


def test_no_other_item_shape_carries_the_ttl_attribute_in_either_form() -> None:
    for record_type, instances in _instances().items():
        if record_type is TTL_WRITER:
            continue
        for instance in instances:
            assert TTL_ATTRIBUTE not in instance.to_item(), record_type.__name__


def test_the_ttl_attribute_can_only_reach_the_binding_kind() -> None:
    # Keyed on the classification of the stored item rather than on the Python type, because TTL
    # expiry acts on stored items: the guarantee has to hold for an item nothing here constructed.
    for instances in _instances().values():
        for instance in instances:
            item = instance.to_item()
            carries_ttl = TTL_ATTRIBUTE in item
            assert carries_ttl is (kind_of_item(item) is ItemKind.AFFINITY_KEY_BINDING)


def test_no_other_item_producer_even_names_the_ttl_attribute() -> None:
    # A conditional write would escape the instance-level checks above, so the item producers are
    # read as source too: naming the attribute at all is the thing only the binding may do.
    naming_it = {
        name
        for name, record_type in _item_record_types().items()
        if any(
            spelling in inspect.getsource(record_type.to_item)
            for spelling in TTL_SPELLINGS
        )
    }
    assert naming_it == {TTL_WRITER.__name__}


def test_the_bindings_ttl_value_is_a_top_level_number() -> None:
    # DynamoDB expires an item only on a top-level Number attribute holding epoch seconds, so a
    # string or a nested value would make cleanup layer 3 silently inert (R13.8).
    item = _instances()[TTL_WRITER][1].to_item()
    value = item[TTL_ATTRIBUTE]
    assert isinstance(value, int) and not isinstance(value, bool)


def test_the_credential_expiry_is_nested_and_is_never_an_item_of_its_own() -> None:
    item = _session(connection=_descriptor(), connection_published_at=1).to_item()
    # Same attribute name, different scope: nested inside `connection`, so a published credential
    # expiring cannot delete the Session row that carries it.
    assert item["connection"][TTL_ATTRIBUTE] == "2026-06-22T10:15:00Z"
    assert TTL_ATTRIBUTE not in item
    assert ConnectionDescriptor not in _item_record_types().values()
    assert not hasattr(ConnectionDescriptor, "to_item")
