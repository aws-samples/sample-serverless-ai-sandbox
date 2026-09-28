# kiro-classification: public
"""State_Store table, index and record definitions.

This package holds the *shape* of the State_Store and nothing that talks to it: the single
DynamoDB table, its two global secondary indexes, its TTL attribute, and the five item shapes
the design's Key structure and Data Models sections define (R13.1, R10.8).

The partition key of every Tenant-scoped item is supplied by the caller and is never
constructed here. Exactly one function in the Control_Plane produces a Tenant partition key,
and it takes only the authenticated principal.

:mod:`control_plane.state.artifacts` is deliberately not re-exported here. It talks to the
store rather than describing its shape, and it derives its Tenant-first prefixes from the
authenticated principal, so it depends on :mod:`control_plane.tenancy` — which already depends
on this package's key module. Importing it from this file would make the two packages import
each other during initialisation. Import it from its own module.
"""

from control_plane.state.keys import (
    CLAIM_SORT_KEY,
    ItemKind,
    ItemShapeError,
    affinity_key_digest,
    artifact_sort_key,
    binding_sort_key,
    claim_partition_key,
    continuation_sort_key,
    kind_of_item,
    session_sort_key,
    tenant_state_sort_key,
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
from control_plane.state.table import (
    ATTRIBUTE_DEFINITIONS,
    BILLING_MODE,
    DEADLINE_INDEX,
    INDEXES,
    PARTITION_KEY_ATTRIBUTE,
    POINT_IN_TIME_RECOVERY_ENABLED,
    SORT_KEY_ATTRIBUTE,
    TABLE_LOGICAL_NAME,
    TENANT_STATE_INDEX,
    TTL_ATTRIBUTE,
    AttributeType,
    IndexDefinition,
    ProjectionType,
)

__all__ = [
    "ATTRIBUTE_DEFINITIONS",
    "BILLING_MODE",
    "CLAIM_SORT_KEY",
    "DEADLINE_INDEX",
    "INDEXES",
    "PARTITION_KEY_ATTRIBUTE",
    "POINT_IN_TIME_RECOVERY_ENABLED",
    "SORT_KEY_ATTRIBUTE",
    "TABLE_LOGICAL_NAME",
    "TENANT_STATE_INDEX",
    "TTL_ATTRIBUTE",
    "AffinityKeyBindingRecord",
    "ArtifactIndexEntry",
    "AttributeType",
    "ConnectionDescriptor",
    "ContinuationRecord",
    "Eligibility",
    "IndexDefinition",
    "ItemKind",
    "ItemShapeError",
    "LifecycleState",
    "ProjectionType",
    "SandboxClaimRecord",
    "SessionRecord",
    "affinity_key_digest",
    "artifact_sort_key",
    "binding_sort_key",
    "claim_partition_key",
    "continuation_sort_key",
    "kind_of_item",
    "session_sort_key",
    "tenant_state_sort_key",
]
