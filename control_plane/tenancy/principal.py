# kiro-classification: public
"""The authenticated principal one Control_Plane request carries (R11.2).

Every Session is associated with exactly one Tenant at creation, and the identifier of that
Tenant reaches the State_Store only through this object. It is built once per request from the
identity the `AWS_IAM` authorizer has already verified, together with the Tenant identifier the
Tenant resolver derived from that identity. No request body, path parameter, query string or
header contributes to either field.

Validation lives here rather than at the point of use, so a Tenant identifier that could forge a
different key shape is rejected before it can reach a key at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: Bound on a Tenant identifier. DynamoDB and IAM both allow far more; a Tenant identifier is a
#: deployment-time constant or a verified principal attribute, so a longer value is a defect
#: rather than a Tenant.
MAX_TENANT_ID_LENGTH: Final = 256

#: Bound on a verified caller identity, which is an ARN or an equivalent identity string.
MAX_CALLER_IDENTITY_LENGTH: Final = 2048


class TenantIdentifierError(ValueError):
    """A principal field is absent, or is not a value that may become part of a key."""


def _require_present(name: str, value: str, limit: int) -> str:
    if not value:
        raise TenantIdentifierError(f"{name} must not be empty")
    if len(value) > limit:
        raise TenantIdentifierError(f"{name} exceeds {limit} characters: {len(value)}")
    return value


def require_tenant_id(value: str) -> str:
    """Reject a Tenant identifier that cannot safely become the first element of a key.

    The separator is refused because a Tenant identifier carrying it would let one Tenant's
    partition key be spelled as a different key shape, and because the `dynamodb:LeadingKeys`
    condition confining a request pins one exact string. Whitespace and non-printable characters
    are refused for the same reason a policy document is easier to review than to debug.

    Public rather than private because the Tenant resolver applies it to its own inputs: the
    deployment-time constant of one profile and the verified principal attribute of the other are
    both Tenant identifiers, and both are better refused where they enter the Control_Plane than
    at the key they would otherwise forge.
    """
    # Deferred deliberately. `control_plane.state` depends on this package for `pk_for`, so a
    # module-level import here would make the two packages import-order dependent. The separator
    # is still read from the module that owns it rather than restated, and the import is one
    # `sys.modules` lookup after the first call.
    from control_plane.state.keys import SEPARATOR

    _require_present("tenant_id", value, MAX_TENANT_ID_LENGTH)
    if SEPARATOR in value:
        raise TenantIdentifierError(
            f"tenant_id must not contain {SEPARATOR!r}: {value!r}"
        )
    if any(character.isspace() or not character.isprintable() for character in value):
        raise TenantIdentifierError(
            f"tenant_id must be printable and free of whitespace: {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """The verified caller of one request, and the Tenant that caller resolved to.

    Frozen, because the Tenant of a request is settled before any handler code runs: a principal
    whose `tenant_id` could be reassigned would make the per-request credentials and the keys they
    address two independently mutable things.
    """

    caller_identity: str
    tenant_id: str

    def __post_init__(self) -> None:
        _require_present(
            "caller_identity", self.caller_identity, MAX_CALLER_IDENTITY_LENGTH
        )
        require_tenant_id(self.tenant_id)


@dataclass(frozen=True, slots=True)
class VerifiedCallerIdentity:
    """The identity the `AWS_IAM` authorizer verified, before any Tenant has been resolved.

    This is the sole input of the Tenant resolver, and it holds two fields because there are only
    two things a resolver may read: who the authorizer says the caller is, and — under
    `multi-tenant` — the Tenant attribute carried on that verified identity. A request body, path
    parameter, query string or header has no field here to arrive through, which is what makes
    R11.17 a property of the type rather than a rule someone has to remember.

    `tenant_id` is left unvalidated at construction on purpose. Validation belongs to the resolver
    that reads it, so that :class:`~control_plane.tenancy.resolver.FixedTenantResolver` genuinely
    ignores this field: an identity a `multi-tenant` deployment would reject must still be
    constructible, or the `single-tenant` path would depend on a value it never reads.
    """

    caller_identity: str
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        _require_present(
            "caller_identity", self.caller_identity, MAX_CALLER_IDENTITY_LENGTH
        )
