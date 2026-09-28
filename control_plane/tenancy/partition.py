# kiro-classification: public
"""The sole producer of a Tenant partition key (R11.2, R11.3).

Layer 1 of the three layers that make cross-tenant access structurally impossible: key derivation
has one source. :func:`pk_for` takes the authenticated principal and nothing else, so no Tenant
identifier can arrive from a request body, a path parameter, a query string or a header, and a
caller-supplied identifier can only ever become a **sort** key
(:mod:`control_plane.state.keys`).

Layers 2 and 3 are outside this module and outside code: the per-request `SessionDataAccessRole`
whose inline session policy pins `dynamodb:LeadingKeys` to one partition, and a read that cannot
distinguish another Tenant's Session from one that never existed. This module is therefore not
itself the security boundary. It is what keeps the boundary's precondition true — one spelling of
the key — and the lint rule in `ci/lint_rules/tenant_partition_key.py`, with the test beside it,
is what keeps this the only spelling.
"""

from __future__ import annotations

from typing import Final

from control_plane.tenancy.principal import AuthenticatedPrincipal

#: The Tenant partition key prefix. The Tenant identifier is the first element of the partition key
#: and nothing precedes it, which is what allows the `dynamodb:LeadingKeys` condition to exist at
#: all. Named here and read by :func:`pk_for` alone: the lint rule rejects a reference to this name
#: from any other module, because an imported prefix is a second producer with extra steps.
TENANT_PARTITION_PREFIX: Final = "T#"


def pk_for(principal: AuthenticatedPrincipal) -> str:
    """Return the partition key of every Tenant-scoped item this principal may address.

    The only argument is the authenticated principal. That is the whole point: a cross-tenant read
    is not a check someone could forget to write, it is an operation for which no code path exists.
    """
    return f"{TENANT_PARTITION_PREFIX}{principal.tenant_id}"
