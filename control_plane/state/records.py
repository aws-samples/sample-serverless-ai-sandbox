# kiro-classification: public
"""The five State_Store item shapes the design's Data Models section defines.

Each record converts to and from the attribute map DynamoDB stores. Absent optional attributes
are omitted rather than written as null, so `attribute_not_exists` conditions mean what they say.

Only :class:`AffinityKeyBindingRecord` carries the table's TTL attribute. That is the whole point
of the restriction recorded in :mod:`control_plane.state.table`: a TTL attribute on a Session row
would delete the one record every recovery path in this design depends on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any

from control_plane.state.keys import (
    ARTIFACT_INFIX,
    CLAIM_SORT_KEY,
    CONTINUATION_INFIX,
    SEPARATOR,
    SESSION_PREFIX,
    ItemShapeError,
    artifact_sort_key,
    binding_sort_key,
    continuation_sort_key,
    session_sort_key,
    tenant_state_sort_key,
)
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
    TTL_ATTRIBUTE,
)


class LifecycleState(str, Enum):
    """The values recorded in `lifecycleState` and reported by the Control_Plane (R6.7).

    These are the states an operator observes. `ORCHESTRATING` is a state of the Session record
    rather than of a Sandbox, so it maps to no provider-side state.
    """

    PENDING = "PENDING"
    ORCHESTRATING = "ORCHESTRATING"
    PROVISIONING = "PROVISIONING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUSPENDING = "SUSPENDING"
    SUSPENDED = "SUSPENDED"
    RESUMING = "RESUMING"
    CONTINUING = "CONTINUING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        """Terminal states are absorbing: no transition leaves them."""
        return self in TERMINAL_LIFECYCLE_STATES


TERMINAL_LIFECYCLE_STATES: frozenset[LifecycleState] = frozenset(
    {LifecycleState.TERMINATED, LifecycleState.FAILED}
)


class Eligibility(str, Enum):
    """Whether a claimed Sandbox may ever be allocated again (R11.12, R11.13).

    Three values rather than a boolean because a future pre-warmed pool must distinguish a Sandbox
    that has never executed anything from one that has. The transitions are one-way:
    `never-run → used` when `/run` is invoked, and either state → `quarantined`. There is no edge
    back.
    """

    NEVER_RUN = "never-run"
    USED = "used"
    QUARANTINED = "quarantined"


def _string(item: Mapping[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str):
        raise ItemShapeError(f"{name} is missing or not a string")
    return value


def _optional_string(item: Mapping[str, Any], name: str) -> str | None:
    value = item.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ItemShapeError(f"{name} is not a string")
    return value


def _int(item: Mapping[str, Any], name: str) -> int:
    value = item.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ItemShapeError(f"{name} is missing or not a number")
    as_int = int(value)
    if as_int != value:
        raise ItemShapeError(f"{name} is not an integer: {value!r}")
    return as_int


def _optional_int(item: Mapping[str, Any], name: str) -> int | None:
    return None if item.get(name) is None else _int(item, name)


def _bool(item: Mapping[str, Any], name: str) -> bool:
    value = item.get(name)
    if not isinstance(value, bool):
        raise ItemShapeError(f"{name} is missing or not a boolean")
    return value


def _int_tuple(item: Mapping[str, Any], name: str) -> tuple[int, ...]:
    value = item.get(name, [])
    if not isinstance(value, (list, tuple)):
        raise ItemShapeError(f"{name} is not a list")
    return tuple(_int({name: element}, name) for element in value)


def _string_tuple(item: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = item.get(name, [])
    if not isinstance(value, (list, tuple)):
        raise ItemShapeError(f"{name} is not a list")
    for element in value:
        if not isinstance(element, str):
            raise ItemShapeError(f"{name} contains a non-string element: {element!r}")
    return tuple(value)


def _require_positive(name: str, value: int) -> None:
    if value <= 0:
        raise ItemShapeError(f"{name} must be greater than zero: {value}")


def _require_non_negative(name: str, value: int) -> None:
    if value < 0:
        raise ItemShapeError(f"{name} must not be negative: {value}")


def _split_composite(sort_key: str, infix: str, described_as: str) -> tuple[str, str]:
    """Split `S#<sessionId>#<infix>#<tail>` into the Session identifier and the tail.

    The identifiers are read back out of the sort key rather than stored again beside it, so an
    item cannot carry a key and an attribute that disagree about which Session it belongs to.
    """
    parts = sort_key.split(SEPARATOR)
    if len(parts) != 4 or parts[0] != SESSION_PREFIX or parts[2] != infix:
        raise ItemShapeError(f"not a {described_as} sort key: {sort_key!r}")
    return parts[1], parts[3]


@dataclass(frozen=True, slots=True)
class ConnectionDescriptor:
    """The connection credential the Session_Orchestrator publishes onto the Session row.

    Stored in the form it is returned to the caller, so the Control_Plane reads it from the
    State_Store and returns it unchanged rather than reconstructing it (R6.13).

    `expires_at` is the credential's own expiry, nested inside the `connection` map. It is **not**
    the table's TTL attribute: DynamoDB reads TTL from a top-level attribute only, which is why a
    published credential expiring cannot delete the Session row that carries it.
    """

    base_url: str
    auth_header_name: str
    auth_header_value: str
    ports: tuple[int, ...]
    expires_at: str

    def to_map(self) -> dict[str, Any]:
        return {
            "baseUrl": self.base_url,
            "authHeaderName": self.auth_header_name,
            "authHeaderValue": self.auth_header_value,
            "ports": list(self.ports),
            "expiresAt": self.expires_at,
        }

    @classmethod
    def from_map(cls, value: Mapping[str, Any]) -> ConnectionDescriptor:
        return cls(
            base_url=_string(value, "baseUrl"),
            auth_header_name=_string(value, "authHeaderName"),
            auth_header_value=_string(value, "authHeaderValue"),
            ports=_int_tuple(value, "ports"),
            expires_at=_string(value, "expiresAt"),
        )


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """The single authoritative record for a Session.

    `pk` is supplied by the caller and must be the value the Control_Plane's sole partition-key
    producer returned for the authenticated principal. Nothing in this module builds it.
    """

    pk: str
    session_id: str
    tenant_id: str
    provider_name: str
    lifecycle_state: LifecycleState
    created_at: int
    updated_at: int
    max_duration_seconds: int
    idle_seconds: int
    suspended_seconds: int
    auto_resume: bool
    memory_bytes: int
    execution_role_arn: str
    reap_shard: int
    #: `None` once the Session is settled. `deadline-index` is sparse, so a row without this
    #: attribute is not in the index and no later sweep returns it.
    reap_deadline: int | None
    artifact_retention_days: int
    exposed_ports: tuple[int, ...] = ()
    generation: int = 1
    egress_generation: int = 1
    continuation_enabled: bool = False
    continuation_paths: tuple[str, ...] = ()
    persistence: bool = False  # S3 Files workspace mount requested
    workspace_affinity_key: str = ""  # shared workspace key for persistence
    principal_id: str = ""  # authenticated caller identity for workspace scoping
    state_reason: str | None = None
    sandbox_handle: Mapping[str, Any] | None = None
    sandbox_id: str | None = None
    orchestration_execution_arn: str | None = None
    task_token: str | None = None  # Step Functions waitForTaskToken callback token
    connection: ConnectionDescriptor | None = None
    connection_published_at: int | None = None
    affinity_key_digest: str | None = None

    def __post_init__(self) -> None:
        _require_positive("max_duration_seconds", self.max_duration_seconds)
        # R10.3: every configured idle and suspended duration is greater than zero seconds.
        _require_positive("idle_seconds", self.idle_seconds)
        _require_positive("suspended_seconds", self.suspended_seconds)
        _require_non_negative("memory_bytes", self.memory_bytes)
        _require_positive("generation", self.generation)
        _require_positive("egress_generation", self.egress_generation)
        _require_non_negative("reap_shard", self.reap_shard)
        if self.reap_deadline is not None:
            _require_non_negative("reap_deadline", self.reap_deadline)
        _require_non_negative("artifact_retention_days", self.artifact_retention_days)
        for port in self.exposed_ports:
            if not 1 <= port <= 65535:
                raise ItemShapeError(
                    f"exposed_ports contains an out-of-range port: {port}"
                )

    @property
    def sort_key(self) -> str:
        return session_sort_key(self.session_id)

    @property
    def state_created_at(self) -> str:
        """The `tenant-state-index` sort key, derived rather than independently assigned."""
        return tenant_state_sort_key(self.lifecycle_state.value, self.created_at)

    def to_item(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            PARTITION_KEY_ATTRIBUTE: self.pk,
            SORT_KEY_ATTRIBUTE: self.sort_key,
            TENANT_STATE_INDEX.sort_key: self.state_created_at,
            "tenantId": self.tenant_id,
            "providerName": self.provider_name,
            "lifecycleState": self.lifecycle_state.value,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "maxDurationSeconds": self.max_duration_seconds,
            "idleSeconds": self.idle_seconds,
            "suspendedSeconds": self.suspended_seconds,
            "autoResume": self.auto_resume,
            "exposedPorts": list(self.exposed_ports),
            "memoryBytes": self.memory_bytes,
            "generation": self.generation,
            "egressGeneration": self.egress_generation,
            "continuationEnabled": self.continuation_enabled,
            "persistence": self.persistence,
            "workspaceAffinityKey": self.workspace_affinity_key,
            "principalId": self.principal_id,
            "continuationPaths": list(self.continuation_paths),
            "executionRoleArn": self.execution_role_arn,
            "reapShard": self.reap_shard,
            "artifactRetentionDays": self.artifact_retention_days,
        }
        if self.reap_deadline is not None:
            item["reapDeadline"] = self.reap_deadline
        if self.state_reason is not None:
            item["stateReason"] = self.state_reason
        if self.sandbox_handle is not None:
            item["sandboxHandle"] = dict(self.sandbox_handle)
        if self.sandbox_id is not None:
            item["sandboxId"] = self.sandbox_id
        if self.orchestration_execution_arn is not None:
            item["orchestrationExecutionArn"] = self.orchestration_execution_arn
        if self.task_token is not None:
            item["taskToken"] = self.task_token
        if self.connection is not None:
            item["connection"] = self.connection.to_map()
        if self.connection_published_at is not None:
            item["connectionPublishedAt"] = self.connection_published_at
        if self.affinity_key_digest is not None:
            item["affinityKeyDigest"] = self.affinity_key_digest
        return item

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> SessionRecord:
        sort_key = _string(item, SORT_KEY_ATTRIBUTE)
        prefix = f"{SESSION_PREFIX}{SEPARATOR}"
        if not sort_key.startswith(prefix) or SEPARATOR in sort_key[len(prefix) :]:
            raise ItemShapeError(f"not a Session sort key: {sort_key!r}")
        connection = item.get("connection")
        handle = item.get("sandboxHandle")
        if handle is not None and not isinstance(handle, Mapping):
            raise ItemShapeError("sandboxHandle is not a map")
        if connection is not None and not isinstance(connection, Mapping):
            raise ItemShapeError("connection is not a map")
        return cls(
            pk=_string(item, PARTITION_KEY_ATTRIBUTE),
            session_id=sort_key[len(prefix) :],
            tenant_id=_string(item, "tenantId"),
            provider_name=_string(item, "providerName"),
            lifecycle_state=LifecycleState(_string(item, "lifecycleState")),
            created_at=_int(item, "createdAt"),
            updated_at=_int(item, "updatedAt"),
            max_duration_seconds=_int(item, "maxDurationSeconds"),
            idle_seconds=_int(item, "idleSeconds"),
            suspended_seconds=_int(item, "suspendedSeconds"),
            auto_resume=_bool(item, "autoResume"),
            memory_bytes=_int(item, "memoryBytes"),
            execution_role_arn=_string(item, "executionRoleArn"),
            reap_shard=_int(item, "reapShard"),
            reap_deadline=_optional_int(item, "reapDeadline"),
            artifact_retention_days=_int(item, "artifactRetentionDays"),
            exposed_ports=_int_tuple(item, "exposedPorts"),
            generation=_int(item, "generation"),
            egress_generation=_int(item, "egressGeneration"),
            continuation_enabled=_bool(item, "continuationEnabled"),
            persistence=item.get("persistence", False),
            workspace_affinity_key=item.get("workspaceAffinityKey", ""),
            principal_id=item.get("principalId", ""),
            continuation_paths=_string_tuple(item, "continuationPaths"),
            state_reason=_optional_string(item, "stateReason"),
            sandbox_handle=None if handle is None else dict(handle),
            sandbox_id=_optional_string(item, "sandboxId"),
            orchestration_execution_arn=_optional_string(
                item, "orchestrationExecutionArn"
            ),
            connection=None
            if connection is None
            else ConnectionDescriptor.from_map(connection),
            connection_published_at=_optional_int(item, "connectionPublishedAt"),
            affinity_key_digest=_optional_string(item, "affinityKeyDigest"),
            task_token=_optional_string(item, "taskToken"),
        )


@dataclass(frozen=True, slots=True)
class ArtifactIndexEntry:
    """One Session output artifact, written during the `/terminate` hook (R13.3).

    `truncated` records that the artifact write hit its bounded deadline. The marker exists so a
    hung terminate hook cannot leave a billable Sandbox allocated while the write blocks teardown.
    """

    pk: str
    session_id: str
    artifact_id: str
    s3_key: str
    size_bytes: int
    truncated: bool = False

    def __post_init__(self) -> None:
        _require_non_negative("size_bytes", self.size_bytes)

    @property
    def sort_key(self) -> str:
        return artifact_sort_key(self.session_id, self.artifact_id)

    def to_item(self) -> dict[str, Any]:
        return {
            PARTITION_KEY_ATTRIBUTE: self.pk,
            SORT_KEY_ATTRIBUTE: self.sort_key,
            "s3Key": self.s3_key,
            "sizeBytes": self.size_bytes,
            "truncated": self.truncated,
        }

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> ArtifactIndexEntry:
        session_id, artifact_id = _split_composite(
            _string(item, SORT_KEY_ATTRIBUTE), ARTIFACT_INFIX, "artifact index entry"
        )
        return cls(
            pk=_string(item, PARTITION_KEY_ATTRIBUTE),
            session_id=session_id,
            artifact_id=artifact_id,
            s3_key=_string(item, "s3Key"),
            size_bytes=_int(item, "sizeBytes"),
            truncated=_bool(item, "truncated"),
        )


@dataclass(frozen=True, slots=True)
class ContinuationRecord:
    """The artifact reference a duration-ceiling handoff restores from (R10.11).

    One record per generation, so the handoff that produced a given Sandbox is recoverable after
    the fact rather than only while the orchestration is alive.
    """

    pk: str
    session_id: str
    generation: int
    artifact_reference: str
    created_at: int

    def __post_init__(self) -> None:
        _require_non_negative("generation", self.generation)
        _require_non_negative("created_at", self.created_at)

    @property
    def sort_key(self) -> str:
        return continuation_sort_key(self.session_id, self.generation)

    def to_item(self) -> dict[str, Any]:
        return {
            PARTITION_KEY_ATTRIBUTE: self.pk,
            SORT_KEY_ATTRIBUTE: self.sort_key,
            "artifactReference": self.artifact_reference,
            "createdAt": self.created_at,
        }

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> ContinuationRecord:
        session_id, generation = _split_composite(
            _string(item, SORT_KEY_ATTRIBUTE), CONTINUATION_INFIX, "continuation record"
        )
        if not generation.isdigit():
            raise ItemShapeError(
                f"continuation generation is not a number: {generation!r}"
            )
        return cls(
            pk=_string(item, PARTITION_KEY_ATTRIBUTE),
            session_id=session_id,
            generation=int(generation),
            artifact_reference=_string(item, "artifactReference"),
            created_at=_int(item, "createdAt"),
        )


@dataclass(frozen=True, slots=True)
class AffinityKeyBindingRecord:
    """The reconnect handle for a multi-turn agent task (R6.15, R6.16).

    It holds a Session identifier and nothing else that could fall out of step: no credential, no
    lifecycle state, no Sandbox handle and no generation. That is why the binding survives
    continuation untouched (R6.24), and why it is correct by having nothing to keep in sync.

    This is the only item type that carries the table's TTL attribute (R13.8).
    """

    pk: str
    affinity_key_digest: str
    session_id: str
    bound_at: int
    expires_at: int

    def __post_init__(self) -> None:
        _require_non_negative("bound_at", self.bound_at)
        _require_non_negative("expires_at", self.expires_at)

    @property
    def sort_key(self) -> str:
        return binding_sort_key(self.affinity_key_digest)

    def to_item(self) -> dict[str, Any]:
        return {
            PARTITION_KEY_ATTRIBUTE: self.pk,
            SORT_KEY_ATTRIBUTE: self.sort_key,
            "sessionId": self.session_id,
            "boundAt": self.bound_at,
            TTL_ATTRIBUTE: self.expires_at,
        }

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> AffinityKeyBindingRecord:
        sort_key = _string(item, SORT_KEY_ATTRIBUTE)
        digest = sort_key.split(SEPARATOR, 1)[-1]
        if binding_sort_key(digest) != sort_key:
            raise ItemShapeError(f"not an Affinity_Key binding sort key: {sort_key!r}")
        return cls(
            pk=_string(item, PARTITION_KEY_ATTRIBUTE),
            affinity_key_digest=digest,
            session_id=_string(item, "sessionId"),
            bound_at=_int(item, "boundAt"),
            expires_at=_int(item, TTL_ATTRIBUTE),
        )


@dataclass(frozen=True, slots=True)
class SandboxClaimRecord:
    """The ledger that makes "one Sandbox, one Session, ever" a conditional-write invariant (R11.10).

    Its partition key names a provider and a Sandbox rather than a Tenant, because the uniqueness
    it expresses must hold across Tenants. It is written by the orchestrator's own role, never
    returned to a caller, and carries no Session content beyond the identifiers that attribute the
    claim.
    """

    pk: str
    session_id: str
    tenant_id: str
    claimed_at: int
    eligibility: Eligibility = Eligibility.NEVER_RUN
    quarantine_reason: str | None = field(default=None)

    def __post_init__(self) -> None:
        _require_non_negative("claimed_at", self.claimed_at)
        if self.eligibility is Eligibility.QUARANTINED and not self.quarantine_reason:
            raise ItemShapeError("a quarantined claim must carry a quarantine reason")
        if self.eligibility is not Eligibility.QUARANTINED and self.quarantine_reason:
            raise ItemShapeError(
                "a quarantine reason is present only when eligibility is quarantined"
            )

    @property
    def sort_key(self) -> str:
        return CLAIM_SORT_KEY

    def to_item(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            PARTITION_KEY_ATTRIBUTE: self.pk,
            SORT_KEY_ATTRIBUTE: CLAIM_SORT_KEY,
            "sessionId": self.session_id,
            "tenantId": self.tenant_id,
            "claimedAt": self.claimed_at,
            "eligibility": self.eligibility.value,
        }
        if self.quarantine_reason is not None:
            item["quarantineReason"] = self.quarantine_reason
        return item

    @classmethod
    def from_item(cls, item: Mapping[str, Any]) -> SandboxClaimRecord:
        if _string(item, SORT_KEY_ATTRIBUTE) != CLAIM_SORT_KEY:
            raise ItemShapeError("not a Sandbox claim sort key")
        return cls(
            pk=_string(item, PARTITION_KEY_ATTRIBUTE),
            session_id=_string(item, "sessionId"),
            tenant_id=_string(item, "tenantId"),
            claimed_at=_int(item, "claimedAt"),
            eligibility=Eligibility(_string(item, "eligibility")),
            quarantine_reason=_optional_string(item, "quarantineReason"),
        )
