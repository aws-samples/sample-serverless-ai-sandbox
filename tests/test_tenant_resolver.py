# kiro-classification: public
"""The Deployment_Profile selects a resolver and nothing else reaches the Tenant of a request.

Three claims are checked here. An absent profile resolves to `single-tenant` (R11.16). Under
`single-tenant` the resolver ignores the identity entirely, so the Tenant is derived from no
request content (R11.17). And both profiles run the same call, producing the `tenant_id` that
`AuthenticatedPrincipal` carries and `pk_for` consumes, so what the Tenant identifier is used for
does not vary with the profile (R11.18).

Property 44 owns the synthesised-deployment half of R11.18 and R11.19; these are the resolution
half, stated against the code that runs in the handler.

**Validates: Requirements 11.16, 11.17, 11.18**
"""

from __future__ import annotations

import inspect
from dataclasses import fields

import pytest

from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    DeploymentProfileError,
    FixedTenantResolver,
    PrincipalTenantResolver,
    TenantIdentifierError,
    TenantResolver,
    VerifiedCallerIdentity,
    current_resolver,
    pk_for,
    reset_resolver_cache,
    resolver_for,
    resolver_from_environment,
    tenant_of,
)

FIXED_TENANT = "tenant-deployment"

CALLER = VerifiedCallerIdentity(
    caller_identity="arn:aws:sts::123456789012:assumed-role/Caller/session",
    tenant_id="tenant-a",
)


@pytest.fixture(autouse=True)
def _forget_the_held_resolver() -> None:
    """One process exercises both profiles; an execution environment serves one deployment."""
    reset_resolver_cache()


# --- The profile value itself (R11.15, R11.16) -------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "   ", "\t"])
def test_an_absent_profile_resolves_to_single_tenant(value: str | None) -> None:
    assert (
        DeploymentProfile.from_configuration(value) is DeploymentProfile.SINGLE_TENANT
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("single-tenant", DeploymentProfile.SINGLE_TENANT),
        ("multi-tenant", DeploymentProfile.MULTI_TENANT),
    ],
)
def test_each_accepted_literal_resolves_to_its_profile(
    value: str, expected: DeploymentProfile
) -> None:
    assert DeploymentProfile.from_configuration(value) is expected


@pytest.mark.parametrize(
    "value",
    ["Single-Tenant", "MULTI-TENANT", "single_tenant", "shared", "singletenant"],
)
def test_a_value_that_is_neither_literal_fails_loudly(value: str) -> None:
    """A near miss is a value the operator believes they declared, so it is not defaulted."""
    with pytest.raises(DeploymentProfileError) as raised:
        DeploymentProfile.from_configuration(value)
    message = str(raised.value)
    assert repr(value) in message
    assert "single-tenant" in message and "multi-tenant" in message


# --- FixedTenantResolver: the Tenant comes from no request content (R11.17) ---------------------


@pytest.mark.parametrize(
    "identity",
    [
        CALLER,
        # A different caller, a different Tenant attribute, and no attribute at all: none of the
        # three can move the Tenant of a Session under `single-tenant`.
        VerifiedCallerIdentity(caller_identity="arn:other", tenant_id="tenant-b"),
        VerifiedCallerIdentity(caller_identity="arn:other"),
        # An attribute that could not itself become a key is still merely unread.
        VerifiedCallerIdentity(caller_identity="arn:other", tenant_id="tenant#b"),
    ],
)
def test_the_fixed_resolver_returns_the_constant_whatever_the_caller(
    identity: VerifiedCallerIdentity,
) -> None:
    assert FixedTenantResolver(FIXED_TENANT).resolve(identity) == FIXED_TENANT


def test_the_fixed_resolver_refuses_a_constant_that_could_not_become_a_key() -> None:
    """Built once per execution environment, so this fails on the first request, not first write."""
    with pytest.raises(TenantIdentifierError):
        FixedTenantResolver("tenant#a")


# --- PrincipalTenantResolver: the verified principal's own Tenant -------------------------------


def test_the_principal_resolver_returns_the_verified_identity_tenant() -> None:
    assert PrincipalTenantResolver().resolve(CALLER) == "tenant-a"


def test_two_principals_of_two_tenants_resolve_apart() -> None:
    other = VerifiedCallerIdentity(caller_identity="arn:other", tenant_id="tenant-b")
    assert PrincipalTenantResolver().resolve(
        CALLER
    ) != PrincipalTenantResolver().resolve(other)


def test_an_identity_carrying_no_tenant_attribute_fails_closed() -> None:
    """No default is safe: any fallback would hand one caller another Tenant's partition."""
    with pytest.raises(TenantIdentifierError):
        PrincipalTenantResolver().resolve(
            VerifiedCallerIdentity(caller_identity="arn:no-tenant")
        )


@pytest.mark.parametrize("tenant_id", ["", "tenant#a", "tenant a", "t" * 300])
def test_a_tenant_attribute_that_could_not_become_a_key_is_refused(
    tenant_id: str,
) -> None:
    with pytest.raises(TenantIdentifierError):
        PrincipalTenantResolver().resolve(
            VerifiedCallerIdentity(caller_identity="arn:caller", tenant_id=tenant_id)
        )


# --- One call, under either profile (R11.18) ----------------------------------------------------


def test_both_resolvers_are_the_one_resolver_interface() -> None:
    for resolver in (FixedTenantResolver(FIXED_TENANT), PrincipalTenantResolver()):
        assert isinstance(resolver, TenantResolver)


def test_the_profile_selects_the_resolver_and_nothing_else() -> None:
    assert isinstance(
        resolver_for(DeploymentProfile.SINGLE_TENANT, FIXED_TENANT),
        FixedTenantResolver,
    )
    assert isinstance(
        resolver_for(DeploymentProfile.MULTI_TENANT), PrincipalTenantResolver
    )


def test_single_tenant_without_a_deployment_time_constant_is_a_configuration_error() -> (
    None
):
    with pytest.raises(DeploymentProfileError) as raised:
        resolver_for(DeploymentProfile.SINGLE_TENANT)
    assert TENANT_ID_VARIABLE in str(raised.value)


def test_multi_tenant_ignores_a_constant_it_never_reads() -> None:
    """A stack that writes both variables cannot pin a `multi-tenant` deployment to one Tenant."""
    resolver = resolver_from_environment(
        {
            DEPLOYMENT_PROFILE_VARIABLE: "multi-tenant",
            TENANT_ID_VARIABLE: FIXED_TENANT,
        }
    )
    assert resolver.resolve(CALLER) == "tenant-a"


@pytest.mark.parametrize(
    "environment, expected",
    [
        ({TENANT_ID_VARIABLE: FIXED_TENANT}, FIXED_TENANT),
        (
            {
                DEPLOYMENT_PROFILE_VARIABLE: "single-tenant",
                TENANT_ID_VARIABLE: FIXED_TENANT,
            },
            FIXED_TENANT,
        ),
        ({DEPLOYMENT_PROFILE_VARIABLE: "multi-tenant"}, "tenant-a"),
    ],
)
def test_tenant_of_is_the_same_call_under_either_profile(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], expected: str
) -> None:
    monkeypatch.delenv(DEPLOYMENT_PROFILE_VARIABLE, raising=False)
    monkeypatch.delenv(TENANT_ID_VARIABLE, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert tenant_of(CALLER) == expected


@pytest.mark.parametrize(
    "environment",
    [
        {TENANT_ID_VARIABLE: "tenant-a"},
        {DEPLOYMENT_PROFILE_VARIABLE: "multi-tenant"},
    ],
)
def test_what_the_resolved_identifier_is_used_for_does_not_vary(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    """Downstream is one code path: the principal carries it and `pk_for` addresses one partition."""
    monkeypatch.delenv(DEPLOYMENT_PROFILE_VARIABLE, raising=False)
    monkeypatch.delenv(TENANT_ID_VARIABLE, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    principal = AuthenticatedPrincipal(
        caller_identity=CALLER.caller_identity, tenant_id=tenant_of(CALLER)
    )
    assert principal.tenant_id == "tenant-a"
    assert pk_for(principal) == pk_for(
        AuthenticatedPrincipal(caller_identity="arn:other", tenant_id="tenant-a")
    )


def test_an_undeclared_profile_value_fails_the_request_rather_than_defaulting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(DEPLOYMENT_PROFILE_VARIABLE, "shared")
    monkeypatch.setenv(TENANT_ID_VARIABLE, FIXED_TENANT)
    with pytest.raises(DeploymentProfileError):
        tenant_of(CALLER)


def test_the_resolver_is_built_once_per_execution_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(TENANT_ID_VARIABLE, FIXED_TENANT)
    first = current_resolver()
    assert current_resolver() is first
    reset_resolver_cache()
    assert current_resolver() is not first


# --- No request field is an argument, under either profile --------------------------------------


def test_tenant_of_takes_the_verified_identity_and_nothing_else() -> None:
    parameters = list(inspect.signature(tenant_of, eval_str=True).parameters.values())
    assert [parameter.name for parameter in parameters] == ["verified_caller_identity"]
    assert parameters[0].annotation is VerifiedCallerIdentity
    assert parameters[0].default is inspect.Parameter.empty


@pytest.mark.parametrize(
    "resolver", [FixedTenantResolver(FIXED_TENANT), PrincipalTenantResolver()]
)
def test_neither_resolver_has_a_second_parameter(resolver: TenantResolver) -> None:
    parameters = list(
        inspect.signature(resolver.resolve, eval_str=True).parameters.values()
    )
    assert [parameter.name for parameter in parameters] == ["verified_caller_identity"]
    assert parameters[0].annotation is VerifiedCallerIdentity


def test_the_verified_identity_has_no_field_a_request_could_ride_in() -> None:
    """Two fields, both established by the authorizer: there is nowhere for a body to arrive."""
    assert [field.name for field in fields(VerifiedCallerIdentity)] == [
        "caller_identity",
        "tenant_id",
    ]
