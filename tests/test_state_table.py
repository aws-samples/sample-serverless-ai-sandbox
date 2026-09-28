# kiro-classification: public
"""The single table, its two indexes and its TTL attribute."""

from __future__ import annotations

import pytest

from control_plane.state import table as t


def test_table_is_single_with_composite_key_and_on_demand_capacity() -> None:
    assert t.PARTITION_KEY_ATTRIBUTE == "pk"
    assert t.SORT_KEY_ATTRIBUTE == "sk"
    assert t.BILLING_MODE == "PAY_PER_REQUEST"
    assert t.POINT_IN_TIME_RECOVERY_ENABLED is True


def test_ttl_attribute_is_expires_at() -> None:
    assert t.TTL_ATTRIBUTE == "expiresAt"


def test_there_are_exactly_two_indexes_with_the_designed_key_schemas() -> None:
    assert [index.name for index in t.INDEXES] == [
        "deadline-index",
        "tenant-state-index",
    ]

    # The Reaper's only read path is sharded rather than Tenant-scoped (R10.8).
    assert (t.DEADLINE_INDEX.partition_key, t.DEADLINE_INDEX.sort_key) == (
        "reapShard",
        "reapDeadline",
    )
    # ListSessions reads the Tenant partition itself, so the LeadingKeys condition still applies.
    assert t.TENANT_STATE_INDEX.partition_key == t.PARTITION_KEY_ATTRIBUTE
    assert t.TENANT_STATE_INDEX.sort_key == "stateCreatedAt"


def test_the_reaper_index_projects_what_a_sweep_needs() -> None:
    projected = set(t.DEADLINE_INDEX.non_key_attributes)
    # `affinityKeyDigest` is what lets cleanup layer 2 delete a binding without scanning (R10.17).
    assert {"tenantId", "lifecycleState", "affinityKeyDigest", "sandboxId"} <= projected


def test_every_key_attribute_is_declared_with_its_type() -> None:
    expected = {t.PARTITION_KEY_ATTRIBUTE, t.SORT_KEY_ATTRIBUTE}
    for index in t.INDEXES:
        expected |= {index.partition_key, index.sort_key}
    assert set(t.ATTRIBUTE_DEFINITIONS) == expected
    assert t.ATTRIBUTE_DEFINITIONS[t.PARTITION_KEY_ATTRIBUTE] is t.AttributeType.STRING
    assert t.ATTRIBUTE_DEFINITIONS["reapDeadline"] is t.AttributeType.NUMBER


def test_the_ttl_attribute_is_not_a_key_attribute() -> None:
    # A TTL attribute in a key schema would make expiry structural rather than best-effort.
    assert t.TTL_ATTRIBUTE not in t.ATTRIBUTE_DEFINITIONS


@pytest.mark.parametrize(
    ("projection", "non_key"),
    [
        (t.ProjectionType.INCLUDE, ()),
        (t.ProjectionType.ALL, ("tenantId",)),
        (t.ProjectionType.KEYS_ONLY, ("tenantId",)),
    ],
)
def test_index_projection_and_attribute_list_must_agree(
    projection: t.ProjectionType, non_key: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError):
        t.IndexDefinition(
            name="x-index",
            partition_key="a",
            sort_key="b",
            projection=projection,
            non_key_attributes=non_key,
        )
