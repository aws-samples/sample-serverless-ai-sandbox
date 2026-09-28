# kiro-classification: public
"""Key construction for the State_Store, sort keys and the one system partition key.

The Tenant partition key is deliberately absent from this module. Exactly one function in the
Control_Plane produces it, its only argument is the authenticated principal, and nothing here
builds a Tenant-scoped partition key from an identifier. A caller-supplied identifier can only
ever become a **sort** key, which is what the constructors below produce.

The Sandbox claim item is the single exception, and its partition key names a provider and a
Sandbox rather than a Tenant, so it is built here (R11.10).
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from enum import Enum
from typing import Any

from control_plane.state.table import SORT_KEY_ATTRIBUTE


class ItemShapeError(ValueError):
    """A stored item, or a key component, does not have the shape the design fixes.

    One error type for every malformed-item case, so a caller that reads the State_Store has one
    thing to catch whether the defect is a missing attribute, a wrong type or a forged key.
    """


#: Component separator. Every key shape in the design uses it, so no identifier may contain it.
SEPARATOR = "#"

SESSION_PREFIX = "S"
ARTIFACT_INFIX = "A"
CONTINUATION_INFIX = "C"
BINDING_PREFIX = "K"
CLAIM_PARTITION_PREFIX = "H"

#: The Sandbox claim item's sort key is the literal `CLAIM`: one claim per Sandbox, forever.
CLAIM_SORT_KEY = "CLAIM"


class ItemKind(Enum):
    """The five item shapes the State_Store holds."""

    SESSION = "session"
    ARTIFACT_INDEX_ENTRY = "artifact-index-entry"
    CONTINUATION = "continuation"
    AFFINITY_KEY_BINDING = "affinity-key-binding"
    SANDBOX_CLAIM = "sandbox-claim"


def _require_key_component(name: str, value: str) -> str:
    """Reject an identifier that could forge a different key shape.

    An identifier carrying the separator would let one item type's key be spelled as another's,
    which is a confusion no downstream check would notice.
    """
    if not value:
        raise ItemShapeError(f"{name} must not be empty")
    if SEPARATOR in value:
        raise ItemShapeError(f"{name} must not contain {SEPARATOR!r}: {value!r}")
    return value


def affinity_key_digest(affinity_key: str | bytes) -> str:
    """Return `base64url(sha256(affinityKey))`, unpadded.

    The raw Affinity_Key is never stored, so a caller-chosen value never reaches a key or an
    attribute. The digest is fixed-length and separator-free, which is what lets it sit in a sort
    key without a length or content guard.
    """
    raw = (
        affinity_key.encode("utf-8") if isinstance(affinity_key, str) else affinity_key
    )
    if not raw:
        raise ItemShapeError("affinity_key must not be empty")
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def session_sort_key(session_id: str) -> str:
    """`S#<sessionId>` — the Session row inside its Tenant partition."""
    return (
        f"{SESSION_PREFIX}{SEPARATOR}{_require_key_component('session_id', session_id)}"
    )


def artifact_sort_key(session_id: str, artifact_id: str) -> str:
    """`S#<sessionId>#A#<artifactId>` — one artifact index entry.

    Sharing the Session's sort-key prefix is what makes a Session's artifacts a range query
    rather than a scan.
    """
    return SEPARATOR.join(
        (
            SESSION_PREFIX,
            _require_key_component("session_id", session_id),
            ARTIFACT_INFIX,
            _require_key_component("artifact_id", artifact_id),
        )
    )


def continuation_sort_key(session_id: str, generation: int) -> str:
    """`S#<sessionId>#C#<generation>` — the handoff record for one continuation."""
    if generation < 0:
        raise ItemShapeError(f"generation must not be negative: {generation}")
    return SEPARATOR.join(
        (
            SESSION_PREFIX,
            _require_key_component("session_id", session_id),
            CONTINUATION_INFIX,
            str(generation),
        )
    )


def binding_sort_key(digest: str) -> str:
    """`K#<base64url(sha256(affinityKey))>` — the Affinity_Key binding.

    The binding lives inside the Tenant partition, so a cross-tenant resolution is an operation
    for which the handler holds no credentials rather than a check that could be forgotten
    (R6.16, R11.11).
    """
    return f"{BINDING_PREFIX}{SEPARATOR}{_require_key_component('digest', digest)}"


def claim_partition_key(provider_name: str, sandbox_id: str) -> str:
    """`H#<providerName>#<sandboxId>` — the one key shape outside a Tenant partition.

    Uniqueness of a Sandbox must hold across all Sessions and therefore across Tenants, which a
    Tenant-partitioned item cannot express (R11.10).
    """
    return SEPARATOR.join(
        (
            CLAIM_PARTITION_PREFIX,
            _require_key_component("provider_name", provider_name),
            _require_key_component("sandbox_id", sandbox_id),
        )
    )


def tenant_state_sort_key(lifecycle_state: str, created_at: int) -> str:
    """`<lifecycleState>#<createdAt>` — the `tenant-state-index` sort key.

    A derived attribute on the Session row rather than a query-time expression, because a DynamoDB
    index sort key must be a stored attribute. Ordering within one state is by creation time.
    """
    _require_key_component("lifecycle_state", lifecycle_state)
    if created_at < 0:
        raise ItemShapeError(f"created_at must not be negative: {created_at}")
    return f"{lifecycle_state}{SEPARATOR}{created_at}"


def kind_of_item(item: Mapping[str, Any]) -> ItemKind:
    """Classify a stored item by its keys alone.

    Used by the offline suite, which asserts invariants that hold per item type — the TTL
    single-writer rule among them — over items it did not construct.
    """
    sort_key = item.get(SORT_KEY_ATTRIBUTE)
    if not isinstance(sort_key, str):
        raise ItemShapeError("item has no string sort key")

    if sort_key == CLAIM_SORT_KEY:
        return ItemKind.SANDBOX_CLAIM
    if sort_key.startswith(f"{BINDING_PREFIX}{SEPARATOR}"):
        return ItemKind.AFFINITY_KEY_BINDING
    if sort_key.startswith(f"{SESSION_PREFIX}{SEPARATOR}"):
        parts = sort_key.split(SEPARATOR)
        if len(parts) == 2:
            return ItemKind.SESSION
        if len(parts) == 4 and parts[2] == ARTIFACT_INFIX:
            return ItemKind.ARTIFACT_INDEX_ENTRY
        if len(parts) == 4 and parts[2] == CONTINUATION_INFIX:
            return ItemKind.CONTINUATION
    raise ItemShapeError(f"unrecognised sort key: {sort_key!r}")
