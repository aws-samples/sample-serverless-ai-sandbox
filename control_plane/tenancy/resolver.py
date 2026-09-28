# kiro-classification: public
"""Tenant resolution, and the two resolvers the Deployment_Profile selects between (R11.16-R11.18).

Every handler reaches a Tenant identifier the same way under both profiles: it calls
:func:`tenant_of` with the identity the `AWS_IAM` authorizer verified, and hands the result to
`AuthenticatedPrincipal`, whose `pk_for` produces the one partition key the request may address.
The profile decides which resolver the execution environment holds and nothing else; it reaches no
handler, no key and no policy template, which is what makes R11.18 and R11.19 true rather than
asserted.

The two resolvers are the same derivation with a constant function in place of a lookup.
:class:`FixedTenantResolver` ignores its argument and returns the deployment-time constant, so
under `single-tenant` the Tenant of a Session is derived from no request content at all (R11.17).
:class:`PrincipalTenantResolver` returns the Tenant identifier carried on the verified identity,
which the authorizer established before any handler ran.

Neither resolver has a parameter a request field could arrive through: the sole argument is a
:class:`~control_plane.tenancy.principal.VerifiedCallerIdentity`, which has no body, path, query or
header field to hold one. A caller therefore cannot name a Tenant under either profile — under
`single-tenant` because the one value came from the stack, and under `multi-tenant` because the
value comes from a principal the authorizer already verified.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol, runtime_checkable

from control_plane.tenancy.principal import (
    TenantIdentifierError,
    VerifiedCallerIdentity,
    require_tenant_id,
)

#: The handler environment variable naming the resolved Deployment_Profile. `ControlPlaneStack`
#: writes it; no request can reach it.
DEPLOYMENT_PROFILE_VARIABLE: Final = "DEPLOYMENT_PROFILE"

#: The handler environment variable carrying the deployment-time Tenant identifier used under
#: `single-tenant`. Written by the same stack that pins `dynamodb:LeadingKeys` to it, so the key a
#: handler may address and the Tenant it resolves have one source.
TENANT_ID_VARIABLE: Final = "TENANT_ID"


class DeploymentProfileError(ValueError):
    """The Deployment_Profile configuration of a deployment is not one this code can serve.

    Raised at the point the resolver is built, which is once per execution environment, so a
    deployment configured with a value nobody declared fails on its first request rather than
    resolving some Tenant nobody chose.
    """


class DeploymentProfile(Enum):
    """The tenancy configuration of one deployment: exactly two lowercase literals (R11.15)."""

    SINGLE_TENANT = "single-tenant"
    MULTI_TENANT = "multi-tenant"

    @classmethod
    def from_configuration(cls, value: str | None) -> DeploymentProfile:
        """Resolve a configuration value to a profile, defaulting an absent one (R11.16).

        Absent means unset, empty or whitespace, because an environment variable set to the empty
        string is how "unset" reaches a Lambda handler. Anything else must be one of the two
        literals exactly: a near miss such as `Single-Tenant` is a value the operator believes they
        declared, so it fails loudly instead of silently becoming the default.
        """
        if value is None or not value.strip():
            return cls.SINGLE_TENANT
        try:
            return cls(value)
        except ValueError:
            accepted = ", ".join(repr(profile.value) for profile in cls)
            raise DeploymentProfileError(
                f"{DEPLOYMENT_PROFILE_VARIABLE} must be one of {accepted}; "
                f"received {value!r}"
            ) from None


@runtime_checkable
class TenantResolver(Protocol):
    """Derives the Tenant identifier of one request from the verified caller identity alone.

    One method, one argument. The interface is what keeps the profile out of the call site: a
    handler holding a `TenantResolver` cannot tell which profile built it, and has no branch it
    could write if it could.
    """

    def resolve(self, verified_caller_identity: VerifiedCallerIdentity) -> str:
        """Return the Tenant identifier this request is scoped to."""
        ...


@dataclass(frozen=True, slots=True)
class FixedTenantResolver:
    """Returns one deployment-time Tenant identifier, whatever the caller (R11.17).

    The constant is validated here, when the resolver is built, so a deployment whose Tenant
    identifier could not become a partition key fails at its first request rather than at the
    first write.
    """

    tenant_id: str

    def __post_init__(self) -> None:
        require_tenant_id(self.tenant_id)

    def resolve(self, verified_caller_identity: VerifiedCallerIdentity) -> str:
        """Return the deployment-time constant, reading nothing from the identity.

        The argument is accepted and discarded, which is the whole of R11.17: with the identity
        unread, no request content can influence the Tenant of a Session, and the call site is the
        same call site the `multi-tenant` profile uses.
        """
        return self.tenant_id


@dataclass(frozen=True, slots=True)
class PrincipalTenantResolver:
    """Returns the Tenant identifier carried on the verified caller identity.

    Stateless, because the deployment holds no Tenant list: the authorizer has already verified
    the principal, and the Tenant attribute on that principal is the derivation. A resolver
    holding a roster would be a second source of truth for who a caller is.
    """

    def resolve(self, verified_caller_identity: VerifiedCallerIdentity) -> str:
        """Return the identity's own Tenant identifier, failing closed when it has none.

        An identity the authorizer verified but that carries no Tenant attribute is a deployment
        whose principals were provisioned without one. There is no safe default — falling back to
        any Tenant would hand one caller another's partition — so this raises and the request
        fails.
        """
        tenant_id = verified_caller_identity.tenant_id
        if tenant_id is None:
            raise TenantIdentifierError(
                "verified caller identity carries no tenant_id: "
                f"{verified_caller_identity.caller_identity!r}"
            )
        return require_tenant_id(tenant_id)


def resolver_for(
    profile: DeploymentProfile, fixed_tenant_id: str | None = None
) -> TenantResolver:
    """Build the resolver one profile selects.

    This is the only place the profile value is read, and it is read once per execution
    environment. Under `multi-tenant` a `fixed_tenant_id` is accepted and unused: the resolver
    returns the principal's Tenant identifier, so a constant it never reads cannot change any
    outcome, and rejecting it would couple this function to which environment variables a stack
    happens to write.
    """
    if profile is DeploymentProfile.MULTI_TENANT:
        return PrincipalTenantResolver()
    if fixed_tenant_id is None or not fixed_tenant_id:
        raise DeploymentProfileError(
            f"{DeploymentProfile.SINGLE_TENANT.value} requires "
            f"{TENANT_ID_VARIABLE}, which is absent"
        )
    return FixedTenantResolver(fixed_tenant_id)


def resolver_from_environment(
    environment: Mapping[str, str] | None = None,
) -> TenantResolver:
    """Build the resolver from the stack-written environment, `os.environ` by default."""
    source = os.environ if environment is None else environment
    return resolver_for(
        DeploymentProfile.from_configuration(source.get(DEPLOYMENT_PROFILE_VARIABLE)),
        source.get(TENANT_ID_VARIABLE),
    )


_RESOLVER: TenantResolver | None = None


def current_resolver() -> TenantResolver:
    """Return the resolver of this execution environment, building it on first use.

    Built once and held, because the profile and the Tenant constant are deployment values that
    cannot change while a handler is warm, and because a per-request rebuild would put an
    environment read on every request for a value that cannot differ between them.
    """
    global _RESOLVER
    if _RESOLVER is None:
        _RESOLVER = resolver_from_environment()
    return _RESOLVER


def reset_resolver_cache() -> None:
    """Discard the held resolver.

    For the offline suite, which exercises both profiles in one process. Production has no reason
    to call it: an execution environment serves one deployment.
    """
    global _RESOLVER
    _RESOLVER = None


def tenant_of(verified_caller_identity: VerifiedCallerIdentity) -> str:
    """Return the Tenant identifier of one request — the single call every handler makes.

    The argument is the verified caller identity and nothing else. Both profiles run this same
    resolution, and the identifier it returns is the `tenant_id` that `AuthenticatedPrincipal`
    carries and `pk_for` consumes (R11.18).
    """
    return current_resolver().resolve(verified_caller_identity)
