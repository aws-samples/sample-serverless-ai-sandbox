# kiro-classification: public
"""The single State_Store table, its two indexes and its TTL attribute (R13.1, R10.8).

One declarative definition, consumed by `StateStack` when it synthesises the table and by the
offline suite when it asserts that the synthesised key schema matches the design. Keeping the
schema in one module is what makes "the table, both indexes and the TTL attribute synthesise
identically under either Deployment_Profile" checkable rather than merely stated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AttributeType(str, Enum):
    """DynamoDB key attribute types, limited to the two this schema uses."""

    STRING = "S"
    NUMBER = "N"


class ProjectionType(str, Enum):
    """DynamoDB index projection types."""

    ALL = "ALL"
    KEYS_ONLY = "KEYS_ONLY"
    INCLUDE = "INCLUDE"


@dataclass(frozen=True, slots=True)
class IndexDefinition:
    """A global secondary index of the State_Store table."""

    name: str
    partition_key: str
    sort_key: str
    projection: ProjectionType
    non_key_attributes: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.projection is ProjectionType.INCLUDE and not self.non_key_attributes:
            raise ValueError(
                f"index {self.name!r} projects INCLUDE with no non-key attributes"
            )
        if self.projection is not ProjectionType.INCLUDE and self.non_key_attributes:
            raise ValueError(
                f"index {self.name!r} names non-key attributes under {self.projection.value}"
            )


# The logical table name. The deployed name is stack-derived; this is the name the inline session
# policy template and the offline synthesis assertions refer to.
TABLE_LOGICAL_NAME = "sessions"

#: The partition key attribute. For every Tenant-scoped item its value is `T#<tenantId>`, produced
#: by the sole partition-key producer in the Control_Plane and by nothing else. The Sandbox claim
#: item is the one item type whose partition key is not Tenant-scoped; see
#: :func:`control_plane.state.keys.claim_partition_key`.
PARTITION_KEY_ATTRIBUTE = "pk"

#: The sort key attribute. A caller-supplied identifier can only ever reach this key.
SORT_KEY_ATTRIBUTE = "sk"

#: The TTL attribute. Only the Affinity_Key binding item sets it, so TTL expiry cannot reach a
#: Session row, an artifact index entry or a claim item (R13.8). The single-writer rule is asserted
#: separately in the offline suite, quantified over every item shape rather than spot-checked, in
#: `tests/test_state_ttl_single_writer.py`.
TTL_ATTRIBUTE = "expiresAt"

#: On-demand capacity: Session arrival is bursty and operator-driven, and there is no baseline to
#: provision against.
BILLING_MODE = "PAY_PER_REQUEST"

#: Point-in-time recovery, because the Session row is the only record of a billable Sandbox.
POINT_IN_TIME_RECOVERY_ENABLED = True

#: The Reaper's only read path (R10.8). Partition key is the shard number rather than a Tenant key:
#: the Reaper is a system component operating across Tenants, and a Tenant-scoped read path would
#: force it either to enumerate Tenants or to scan the table.
DEADLINE_INDEX = IndexDefinition(
    name="deadline-index",
    partition_key="reapShard",
    sort_key="reapDeadline",
    projection=ProjectionType.INCLUDE,
    # Exactly what the Reaper needs to classify a due row, terminate its Sandbox, delete its
    # binding and reconcile the claim, so a sweep is one bounded query and no follow-up reads.
    # The table's own key attributes are projected into every index by DynamoDB, so `sk` — and
    # with it the Session identifier — is present without being named here.
    non_key_attributes=(
        "tenantId",
        "lifecycleState",
        # `stateCreatedAt` is derived from `lifecycleState` and `createdAt`, and DynamoDB cannot
        # compose a string in an update expression, so a lifecycle write must supply it. `createdAt`
        # is projected here for that reason alone: without it the Reaper's terminal write would need
        # a `GetItem` per due row, and a sweep is a single bounded query by design.
        "createdAt",
        "providerName",
        "sandboxId",
        "sandboxHandle",
        "affinityKeyDigest",
        "orchestrationExecutionArn",
        "egressGeneration",
        "generation",
    ),
)

#: ListSessions with a lifecycle-state filter. Partition key is the Tenant partition key itself, so
#: the `dynamodb:LeadingKeys` condition that confines a table read confines an index read too.
TENANT_STATE_INDEX = IndexDefinition(
    name="tenant-state-index",
    partition_key=PARTITION_KEY_ATTRIBUTE,
    sort_key="stateCreatedAt",
    # ListSessions returns Session views, so a projection narrower than ALL would turn one query
    # into a query plus a GetItem per row.
    projection=ProjectionType.ALL,
)

INDEXES: tuple[IndexDefinition, ...] = (DEADLINE_INDEX, TENANT_STATE_INDEX)

#: Every attribute that appears in a key schema, table or index, with its type. DynamoDB requires
#: exactly this set to be declared and no more.
ATTRIBUTE_DEFINITIONS: dict[str, AttributeType] = {
    PARTITION_KEY_ATTRIBUTE: AttributeType.STRING,
    SORT_KEY_ATTRIBUTE: AttributeType.STRING,
    DEADLINE_INDEX.partition_key: AttributeType.NUMBER,
    DEADLINE_INDEX.sort_key: AttributeType.NUMBER,
    TENANT_STATE_INDEX.sort_key: AttributeType.STRING,
}
