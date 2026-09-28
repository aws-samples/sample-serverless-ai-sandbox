# kiro-classification: public
"""Tenant identity, Tenant resolution, and the one partition key derived from them (R11.2, R11.3).

`tenant_of` is the single call by which a handler learns the Tenant of a request, and the resolver
behind it is the only object in the Control_Plane that has ever seen the Deployment_Profile
(R11.16-R11.18). `pk_for` is the only function that produces a Tenant partition key, and the
authenticated principal is its only argument. Everything Tenant-scoped in the State_Store is
addressed with what it returns.

`TENANT_PARTITION_PREFIX` is deliberately absent from this package's exports. Re-exporting it would
invite a second producer to be written one import away from the first, which is exactly what the
lint rule in `ci/lint_rules/tenant_partition_key.py` exists to prevent.
"""

from control_plane.tenancy.partition import pk_for
from control_plane.tenancy.principal import (
    MAX_CALLER_IDENTITY_LENGTH,
    MAX_TENANT_ID_LENGTH,
    AuthenticatedPrincipal,
    TenantIdentifierError,
    VerifiedCallerIdentity,
    require_tenant_id,
)
from control_plane.tenancy.resolver import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    DeploymentProfile,
    DeploymentProfileError,
    FixedTenantResolver,
    PrincipalTenantResolver,
    TenantResolver,
    current_resolver,
    reset_resolver_cache,
    resolver_for,
    resolver_from_environment,
    tenant_of,
)

__all__ = [
    "DEPLOYMENT_PROFILE_VARIABLE",
    "MAX_CALLER_IDENTITY_LENGTH",
    "MAX_TENANT_ID_LENGTH",
    "TENANT_ID_VARIABLE",
    "AuthenticatedPrincipal",
    "DeploymentProfile",
    "DeploymentProfileError",
    "FixedTenantResolver",
    "PrincipalTenantResolver",
    "TenantIdentifierError",
    "TenantResolver",
    "VerifiedCallerIdentity",
    "current_resolver",
    "pk_for",
    "require_tenant_id",
    "reset_resolver_cache",
    "resolver_for",
    "resolver_from_environment",
    "tenant_of",
]
