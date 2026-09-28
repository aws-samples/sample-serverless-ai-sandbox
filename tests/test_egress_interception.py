# kiro-classification: public
"""The three interception tiers: their visibility, their injection, and every way they fail closed.

Deterministic throughout, and nothing draws inputs. Property 19 (injected credentials are absent from
the Sandbox) and Property 17 (egress decisions and the absence of an alternative route) are their own
tasks; this file establishes the mechanism those will be quantified over, along four lines:

- **Visibility is derived, so it is asserted from outside as well as at import.** A tier's rule set is
  computed from the fields of the type it is handed and the outcome type it produces, so the tests
  below recompute the containment rather than restating a list, and a tier gaining an observation
  would change both the module and these assertions together.
- **Each tier is exercised through its own form.** Tier 1 discards and re-signs, Tier 2 injects on the
  upstream leg, Tier 3 carries nothing, and a request arriving in the wrong form for its destination's
  tier is denied.
- **Every fail-closed path is driven, not argued.** An unreachable policy store, an unparsable
  authority, an unreadable `Host` header, a signer that cannot sign and a secret that cannot be read
  each produce a denial, per form.
- **The reasons are the existing closed vocabulary.** Every denial reason is asserted to be a
  `control_plane.allocation.DenialReason` member, the three circumventing classifications are asserted
  to be in the closed subset and the ordinary ones asserted to be outside it, and no outcome is
  allowed to carry a byte of the attempted destination.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from typing import Any, Final

import pytest

from control_plane.allocation import (
    CIRCUMVENTION_REASONS,
    DenialReason,
    is_circumvention,
)
from egress import (
    ENFORCEABLE_RULES,
    HANDLER_RULES,
    INJECTION,
    MAX_PATH_LENGTH,
    OUTCOME_FORMS,
    REQUEST_FORMS,
    REQUEST_OBSERVATION_FIELDS,
    RESIGNED_REQUEST_HEADERS,
    RESPONSE_OBSERVATIONS,
    RULE_OBSERVATIONS,
    TIER_OBSERVATIONS,
    CachedPolicyReader,
    Denied,
    EgressPolicy,
    EnforcementRule,
    Forwarded,
    Injection,
    InterceptionOutcome,
    InterceptionSettings,
    Interceptor,
    Observation,
    PolicyCacheSettings,
    PolicyDocumentError,
    PolicyUnavailable,
    TerminatedRequest,
    Tier,
    Tunnelled,
    TunnelledConnection,
    UpstreamCredentialUnavailable,
)

#: The design's own destination sets, with a Tier 3 set added so all three tiers are reachable, and
#: `gpu-target-inference` kept because it is the one Tier 1 entry that names no upstream host.
DOCUMENT: Final[dict[str, Any]] = {
    "policyVersion": 14,
    "destinationSets": {
        "bedrock-runtime": {
            "tier": 1,
            "alias": "bedrock.egress.internal",
            "upstreamHost": "bedrock-runtime.us-east-1.amazonaws.com",
            "signAs": "bedrock",
            "viaVpcEndpoint": True,
        },
        "gpu-target-inference": {
            "tier": 1,
            "alias": "gpu.egress.internal",
            "signAs": "execute-api",
        },
        "public-package-registries": {
            "tier": 2,
            "entries": [
                {
                    "alias": "pypi.egress.internal",
                    "upstreamHost": "pypi.org",
                    "injectHeader": "Authorization",
                    "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:p",
                    "stripResponseHeaders": ["x-echo-request-headers"],
                }
            ],
        },
        "documentation": {"tier": 3, "upstreamHost": "docs.example.com"},
    },
    "defaultAction": "deny",
}

#: What the Tier 1 double returns, and what the Tier 2 secret holds. Distinctive strings so a test can
#: assert their absence from anything the Sandbox can read.
SIGNED: Final = (
    "AWS4-HMAC-SHA256 Credential=PROXYTASKROLE/20260101/us-east-1/bedrock/aws4_request"
)
TOKEN: Final = "Bearer registry-token-96f1"

#: What the Sandbox sends: the placeholder credentials the design records as "something
#: credential-shaped is present in the Sandbox environment, and it is worthless".
SANDBOX_SIGNATURE: Final = (
    "AWS4-HMAC-SHA256 Credential=SANDBOX/20260101/us-east-1/bedrock/aws4_request"
)


@dataclass
class Source:
    """A policy source under the test's control, failing when it holds no policy."""

    policy: EgressPolicy | None

    def read(self) -> EgressPolicy:
        if self.policy is None:
            raise PolicyUnavailable("the policy store is unreachable")
        return self.policy


@dataclass
class Signer:
    """Tier 1's re-signing double. `available` off is a task role whose credentials cannot be had."""

    available: bool = True
    signed: list[tuple[str, str, str, str]] = dataclasses.field(default_factory=list)

    def authorization(
        self, *, sign_as: str, upstream_host: str, method: str, path: str
    ) -> str:
        if not self.available:
            raise UpstreamCredentialUnavailable("the task role credentials expired")
        self.signed.append((sign_as, upstream_host, method, path))
        return SIGNED


@dataclass
class Tokens:
    """Tier 2's secret double. `available` off is a Secrets Manager read that fails."""

    available: bool = True
    read: list[str] = dataclasses.field(default_factory=list)

    def token(self, secret_arn: str) -> str:
        if not self.available:
            raise UpstreamCredentialUnavailable("the secret could not be read")
        self.read.append(secret_arn)
        return TOKEN


def policy(**overrides: Any) -> EgressPolicy:
    """The document above, with top-level keys replaced."""
    return EgressPolicy.from_document(DOCUMENT | overrides)


def interceptor(
    *,
    unavailable: bool = False,
    settings: InterceptionSettings | None = None,
    signer: Signer | None = None,
    tokens: Tokens | None = None,
) -> Interceptor:
    """An interceptor reading a fresh policy on every request, so nothing here depends on a clock.

    `unavailable` is the policy store being down, which is the one condition no policy document can
    express and therefore cannot be passed in as one.
    """
    return Interceptor(
        reader=CachedPolicyReader(
            source=Source(policy=None if unavailable else policy()),
            settings=PolicyCacheSettings(cache_ttl_seconds=0.0),
        ),
        settings=settings if settings is not None else InterceptionSettings.build(),
        signer=signer if signer is not None else Signer(),
        tokens=tokens if tokens is not None else Tokens(),
    )


def request(
    *,
    server_name: str,
    host_header: str | None = None,
    method: str = "POST",
    path: str = "/model/anthropic/invoke",
    headers: dict[str, str] | None = None,
) -> TerminatedRequest:
    """A request on a terminated tier. The `Host` header defaults to the name connected to."""
    return TerminatedRequest(
        server_name=server_name,
        host_header=server_name if host_header is None else host_header,
        method=method,
        path=path,
        headers={} if headers is None else headers,
    )


def forwarded(outcome: InterceptionOutcome) -> Forwarded:
    """The outcome as a forward, failing the test rather than the type checker if it is not one."""
    assert isinstance(outcome, Forwarded), outcome
    return outcome


def denied(outcome: InterceptionOutcome) -> Denied:
    assert isinstance(outcome, Denied), outcome
    return outcome


# --- Visibility, derived and asserted from outside the module -----------------------------------


@pytest.mark.parametrize(
    "table",
    [TIER_OBSERVATIONS, ENFORCEABLE_RULES, REQUEST_FORMS, OUTCOME_FORMS, INJECTION],
)
def test_every_tier_declaration_is_total_over_the_three_tiers(
    table: dict[Tier, object],
) -> None:
    """Asserted here as well as at import, so each claim has two witnesses."""
    assert set(table) == set(Tier)


def test_only_a_tier_that_terminates_tls_sees_more_than_the_connection_target() -> None:
    """The design's Tier 3 sentence: the proxy sees only the requested host."""
    assert TIER_OBSERVATIONS[Tier.CONNECT_TUNNEL] == frozenset(
        {Observation.CONNECTION_TARGET}
    )
    assert TIER_OBSERVATIONS[Tier.SIGV4_RESIGNING] == frozenset(Observation)
    assert TIER_OBSERVATIONS[Tier.TOKEN_INJECTION] == frozenset(Observation)


def test_a_tier_enforces_exactly_the_rules_its_observations_support() -> None:
    """Recomputed rather than restated: the containment is the whole guarantee."""
    for tier, rules in ENFORCEABLE_RULES.items():
        for rule, required in RULE_OBSERVATIONS.items():
            assert (rule in rules) is (required <= TIER_OBSERVATIONS[tier]), (
                tier,
                rule,
            )


def test_the_rules_a_tunnel_cannot_enforce_are_exactly_those_needing_what_it_cannot_see() -> (
    None
):
    unavailable = (
        ENFORCEABLE_RULES[Tier.SIGV4_RESIGNING] - ENFORCEABLE_RULES[Tier.CONNECT_TUNNEL]
    )
    assert unavailable == {
        EnforcementRule.HOST_MATCHES_SERVER_NAME,
        EnforcementRule.HOST_IS_THE_RESOLVED_ALIAS,
        EnforcementRule.ECHO_PRONE_PATH_REFUSED,
        EnforcementRule.INBOUND_AUTHORIZATION_DISCARDED,
        EnforcementRule.RESPONSE_HEADERS_STRIPPED,
    }
    assert ENFORCEABLE_RULES[Tier.CONNECT_TUNNEL] == {
        EnforcementRule.PERMITTED_DESTINATION,
        EnforcementRule.MANAGEMENT_INTERFACE_REFUSED,
    }


def test_every_handler_enforces_exactly_the_rule_set_its_form_supports() -> None:
    """A handler enforcing a rule its form cannot see would fail the build; this says so too."""
    for tier in Tier:
        assert HANDLER_RULES[REQUEST_FORMS[tier]] == ENFORCEABLE_RULES[tier]


def test_every_enforcement_rule_is_enforced_by_at_least_one_tier() -> None:
    enforced = {rule for rules in ENFORCEABLE_RULES.values() for rule in rules}
    assert enforced == set(EnforcementRule)


@pytest.mark.parametrize(
    ("form", "fields"),
    [
        (
            TerminatedRequest,
            {"server_name", "host_header", "method", "path", "headers"},
        ),
        (TunnelledConnection, {"connect_target"}),
    ],
)
def test_a_request_form_carries_exactly_the_fields_its_observations_name(
    form: type, fields: set[str]
) -> None:
    """The tie between a declared visibility and the type a handler is actually handed."""
    assert {field.name for field in dataclasses.fields(form)} == fields
    declared = {
        name for names in REQUEST_OBSERVATION_FIELDS[form].values() for name in names
    }
    assert declared == fields


def test_a_tunnel_carries_no_path_no_header_and_no_handshake_name() -> None:
    """Not a convention: there is no attribute to read, which is why the rules are absent."""
    connection = TunnelledConnection(connect_target="docs.example.com")
    for absent in ("path", "headers", "host_header", "server_name", "method"):
        assert not hasattr(connection, absent), absent


def test_only_the_terminated_tiers_produce_an_outcome_that_can_rewrite_a_response() -> (
    None
):
    """Which is what gives them `RESPONSE_HEADERS` and denies it to the tunnel."""
    for tier in Tier:
        rewrites = OUTCOME_FORMS[tier] is Forwarded
        assert (RESPONSE_OBSERVATIONS <= TIER_OBSERVATIONS[tier]) is rewrites
    assert hasattr(Forwarded, "response_to_sandbox")
    assert not hasattr(Tunnelled, "response_to_sandbox")


def test_tier_three_injects_nothing_and_the_other_two_inject_something() -> None:
    assert INJECTION[Tier.CONNECT_TUNNEL] is Injection.NONE
    assert INJECTION[Tier.SIGV4_RESIGNING] is Injection.RESIGN_AS_TASK_ROLE
    assert INJECTION[Tier.TOKEN_INJECTION] is Injection.UPSTREAM_TOKEN


# --- Tier 1: SigV4 re-signing, with the inbound authorization header discarded -------------------


def test_tier_1_discards_the_inbound_authorization_header_and_re_signs() -> None:
    signer = Signer()
    outcome = forwarded(
        interceptor(signer=signer).intercept(
            request(
                server_name="bedrock.egress.internal",
                headers={"Authorization": SANDBOX_SIGNATURE},
            )
        )
    )
    assert outcome.tier is Tier.SIGV4_RESIGNING
    assert outcome.injection is Injection.RESIGN_AS_TASK_ROLE
    assert outcome.upstream_headers["Authorization"] == SIGNED
    assert SANDBOX_SIGNATURE not in outcome.upstream_headers.values()
    assert signer.signed == [
        (
            "bedrock",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "POST",
            "/model/anthropic/invoke",
        )
    ]


@pytest.mark.parametrize("header", sorted(RESIGNED_REQUEST_HEADERS))
def test_tier_1_discards_every_header_a_sigv4_signature_travels_in(header: str) -> None:
    """A header the signature covers that the Sandbox chose could pin a signature the proxy did not."""
    outcome = forwarded(
        interceptor().intercept(
            request(
                server_name="bedrock.egress.internal",
                headers={header: "chosen-by-untrusted-code"},
            )
        )
    )
    assert "chosen-by-untrusted-code" not in outcome.upstream_headers.values()


def test_tier_1_discards_the_inbound_header_whatever_case_it_was_sent_in() -> None:
    outcome = forwarded(
        interceptor().intercept(
            request(
                server_name="bedrock.egress.internal",
                headers={"AUTHORIZATION": SANDBOX_SIGNATURE, "X-Amz-DATE": "20260101"},
            )
        )
    )
    assert SANDBOX_SIGNATURE not in outcome.upstream_headers.values()
    assert "20260101" not in outcome.upstream_headers.values()


def test_tier_1_addresses_the_upstream_in_the_host_header_it_sends() -> None:
    """`aws-sigv4-proxy` forwards to the host in the `Host` header, so the rewrite is the forward."""
    outcome = forwarded(
        interceptor().intercept(
            request(
                server_name="bedrock.egress.internal",
                headers={"Host": "bedrock.egress.internal"},
            )
        )
    )
    assert outcome.upstream_headers["Host"] == "bedrock-runtime.us-east-1.amazonaws.com"
    assert outcome.upstream_host == "bedrock-runtime.us-east-1.amazonaws.com"


def test_tier_1_leaves_alone_the_headers_it_has_no_business_touching() -> None:
    outcome = forwarded(
        interceptor().intercept(
            request(
                server_name="bedrock.egress.internal",
                headers={"Content-Type": "application/json", "Accept": "text/plain"},
            )
        )
    )
    assert outcome.upstream_headers["Content-Type"] == "application/json"
    assert outcome.upstream_headers["Accept"] == "text/plain"


def test_a_tier_1_entry_naming_no_upstream_is_forwarded_under_its_alias() -> None:
    """`gpu-target-inference` names an alias and a service to sign as, and no upstream host."""
    outcome = forwarded(
        interceptor().intercept(request(server_name="gpu.egress.internal"))
    )
    assert outcome.destination_set == "gpu-target-inference"
    assert outcome.upstream_host == "gpu.egress.internal"


def test_tier_1_strips_the_header_it_injected_out_of_the_response() -> None:
    outcome = forwarded(
        interceptor().intercept(request(server_name="bedrock.egress.internal"))
    )
    assert outcome.strip_response_headers == {"authorization"}
    visible = outcome.response_to_sandbox({"Authorization": SIGNED, "Date": "today"})
    assert visible == {"Date": "today"}


# --- Tier 2: the aliased reverse proxy, injecting on the upstream leg only -----------------------


def test_tier_2_injects_the_upstream_token_on_the_upstream_leg() -> None:
    tokens = Tokens()
    outcome = forwarded(
        interceptor(tokens=tokens).intercept(
            request(server_name="pypi.egress.internal", method="GET", path="/simple")
        )
    )
    assert outcome.tier is Tier.TOKEN_INJECTION
    assert outcome.injection is Injection.UPSTREAM_TOKEN
    assert outcome.destination_set == "public-package-registries"
    assert outcome.upstream_host == "pypi.org"
    assert outcome.upstream_headers["Authorization"] == TOKEN
    assert tokens.read == ["arn:aws:secretsmanager:eu-west-1:1:secret:p"]


def test_the_token_tier_2_injected_is_absent_from_the_response_the_sandbox_reads() -> (
    None
):
    """The upstream leg is a TLS session the Sandbox has no access to; the return leg is stripped."""
    outcome = forwarded(
        interceptor().intercept(request(server_name="pypi.egress.internal", path="/"))
    )
    assert outcome.injected_header_names == {"authorization"}
    assert outcome.strip_response_headers == {
        "authorization",
        "x-echo-request-headers",
    }
    visible = outcome.response_to_sandbox(
        {
            "Authorization": TOKEN,
            "X-Echo-Request-Headers": f"authorization: {TOKEN}",
            "Content-Type": "text/html",
        }
    )
    assert visible == {"Content-Type": "text/html"}
    assert TOKEN not in "".join(visible.values())


@pytest.mark.parametrize("preset", ["Authorization", "authorization", "AUTHORIZATION"])
def test_tier_2_replaces_a_preset_injected_header_rather_than_carrying_it(
    preset: str,
) -> None:
    """A spelling that differs only in case must not reach the upstream leg beside the token."""
    outcome = forwarded(
        interceptor().intercept(
            request(
                server_name="pypi.egress.internal",
                path="/simple",
                headers={preset: "Bearer chosen-by-untrusted-code"},
            )
        )
    )
    assert list(outcome.upstream_headers.values()).count(TOKEN) == 1
    assert "Bearer chosen-by-untrusted-code" not in outcome.upstream_headers.values()


# --- Tier 3: the CONNECT tunnel, with no injection -----------------------------------------------


def test_tier_3_opens_a_tunnel_to_the_permitted_upstream_and_injects_nothing() -> None:
    outcome = interceptor().intercept(
        TunnelledConnection(connect_target="docs.example.com")
    )
    assert outcome == Tunnelled(
        destination_set="documentation", upstream_host="docs.example.com"
    )
    assert outcome.injection is Injection.NONE
    assert not hasattr(outcome, "upstream_headers")


def test_a_tunnel_needs_no_credential_seam_at_all() -> None:
    """Injection is impossible by construction, so neither seam is consulted."""
    signer = Signer(available=False)
    tokens = Tokens(available=False)
    outcome = interceptor(signer=signer, tokens=tokens).intercept(
        TunnelledConnection(connect_target="docs.example.com")
    )
    assert isinstance(outcome, Tunnelled)
    assert signer.signed == []
    assert tokens.read == []


# --- A tier is never handed an attempt of a form it cannot read ----------------------------------


def test_a_tunnel_requested_for_an_aliased_destination_is_denied() -> None:
    """It asks the proxy to permit an aliased destination while withholding the plaintext."""
    for alias in ("bedrock.egress.internal", "pypi.egress.internal"):
        outcome = denied(
            interceptor().intercept(TunnelledConnection(connect_target=alias))
        )
        assert outcome.reason is DenialReason.UNDECLARED_DESTINATION
        assert outcome.tier in {Tier.SIGV4_RESIGNING, Tier.TOKEN_INJECTION}


def test_a_terminated_request_for_a_tunnelled_destination_is_denied() -> None:
    outcome = denied(interceptor().intercept(request(server_name="docs.example.com")))
    assert outcome.reason is DenialReason.UNDECLARED_DESTINATION
    assert outcome.tier is Tier.CONNECT_TUNNEL


# --- Fail closed, per tier ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "attempt",
    [
        TunnelledConnection(connect_target="docs.example.com"),
        TerminatedRequest(
            server_name="bedrock.egress.internal",
            host_header="bedrock.egress.internal",
            method="POST",
            path="/",
            headers={},
        ),
        TerminatedRequest(
            server_name="pypi.egress.internal",
            host_header="pypi.egress.internal",
            method="GET",
            path="/simple",
            headers={},
        ),
    ],
)
def test_an_unreachable_policy_store_denies_whatever_form_the_attempt_arrived_in(
    attempt: TerminatedRequest | TunnelledConnection,
) -> None:
    """R12.8 holds per tier, because every tier reaches the policy through `decide` and nothing else."""
    outcome = denied(interceptor(unavailable=True).intercept(attempt))
    assert outcome.reason is DenialReason.CONTROLLER_UNREACHABLE
    assert outcome.tier is None


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "has space",
        "https://bedrock.egress.internal",
        "café.egress.internal",
        "[::1",
    ],
)
def test_an_authority_that_does_not_parse_denies_on_both_forms(authority: str) -> None:
    subject = interceptor()
    assert (
        denied(subject.intercept(TunnelledConnection(connect_target=authority))).reason
        is DenialReason.UNDECLARED_DESTINATION
    )
    assert (
        denied(subject.intercept(request(server_name=authority))).reason
        is DenialReason.UNDECLARED_DESTINATION
    )


def test_a_signer_that_cannot_sign_denies_rather_than_forwarding_unsigned() -> None:
    outcome = denied(
        interceptor(signer=Signer(available=False)).intercept(
            request(server_name="bedrock.egress.internal")
        )
    )
    assert outcome.reason is DenialReason.CONTROLLER_UNREACHABLE
    assert outcome.tier is Tier.SIGV4_RESIGNING
    assert not is_circumvention(outcome.reason)


def test_a_secret_that_cannot_be_read_denies_rather_than_forwarding_untokened() -> None:
    outcome = denied(
        interceptor(tokens=Tokens(available=False)).intercept(
            request(server_name="pypi.egress.internal", path="/simple")
        )
    )
    assert outcome.reason is DenialReason.CONTROLLER_UNREACHABLE
    assert outcome.tier is Tier.TOKEN_INJECTION


def test_a_destination_the_policy_does_not_name_denies_on_both_forms() -> None:
    subject = interceptor()
    assert (
        denied(
            subject.intercept(TunnelledConnection(connect_target="exfil.example"))
        ).reason
        is DenialReason.UNDECLARED_DESTINATION
    )
    assert (
        denied(subject.intercept(request(server_name="exfil.example"))).reason
        is DenialReason.UNDECLARED_DESTINATION
    )


def test_the_upstream_behind_an_alias_is_not_reachable_through_any_tier() -> None:
    """Reaching `pypi.org` directly would be the interception R12.4 rests on, gone."""
    subject = interceptor()
    assert isinstance(
        subject.intercept(TunnelledConnection(connect_target="pypi.org")), Denied
    )
    assert isinstance(subject.intercept(request(server_name="pypi.org")), Denied)


# --- Circumvention, classified where a tier can see it and nowhere else --------------------------


def test_a_host_header_disagreeing_with_the_handshake_name_is_classified_as_such() -> (
    None
):
    outcome = denied(
        interceptor().intercept(
            request(server_name="bedrock.egress.internal", host_header="exfil.example")
        )
    )
    assert outcome.reason is DenialReason.HOST_SNI_MISMATCH
    assert is_circumvention(outcome.reason)
    assert outcome.tier is Tier.SIGV4_RESIGNING


def test_a_host_header_naming_another_permitted_alias_is_alias_spoofing() -> None:
    """A permitted alias presented for a destination that is not the one behind it."""
    outcome = denied(
        interceptor().intercept(
            request(
                server_name="pypi.egress.internal",
                host_header="bedrock.egress.internal",
            )
        )
    )
    assert outcome.reason is DenialReason.ALIAS_SPOOFED
    assert is_circumvention(outcome.reason)


@pytest.mark.parametrize("literal", ["203.0.113.5", "[2001:db8::1]"])
def test_a_host_header_that_is_a_bare_address_for_an_aliased_upstream_is_classified(
    literal: str,
) -> None:
    outcome = denied(
        interceptor().intercept(
            request(server_name="pypi.egress.internal", host_header=literal)
        )
    )
    assert outcome.reason is DenialReason.IP_LITERAL_FOR_ALIASED_UPSTREAM
    assert is_circumvention(outcome.reason)


def test_a_port_on_the_host_header_that_the_handshake_did_not_use_is_a_mismatch() -> (
    None
):
    outcome = denied(
        interceptor().intercept(
            request(
                server_name="bedrock.egress.internal",
                host_header="bedrock.egress.internal:8080",
            )
        )
    )
    assert outcome.reason is DenialReason.HOST_SNI_MISMATCH


def test_an_unreadable_host_header_is_the_ordinary_denial_rather_than_a_quarantine() -> (
    None
):
    """A malformed request is not evidence that Untrusted_Code tried to get out."""
    for unreadable in ("", "has space", "café.example"):
        outcome = denied(
            interceptor().intercept(
                request(server_name="bedrock.egress.internal", host_header=unreadable)
            )
        )
        assert outcome.reason is DenialReason.UNDECLARED_DESTINATION
        assert not is_circumvention(outcome.reason)


def test_the_proxy_management_interface_is_refused_on_both_forms() -> None:
    settings = InterceptionSettings.build(
        management_authorities=["proxy-admin.egress.internal"]
    )
    subject = interceptor(settings=settings)
    for attempt in (
        TunnelledConnection(connect_target="proxy-admin.egress.internal"),
        request(server_name="proxy-admin.egress.internal"),
        request(server_name="PROXY-ADMIN.egress.internal."),
    ):
        outcome = denied(subject.intercept(attempt))
        assert outcome.reason is DenialReason.PROXY_MANAGEMENT_INTERFACE
        assert is_circumvention(outcome.reason)


def test_the_management_interface_is_classified_before_the_policy_comparison() -> None:
    """Otherwise the ordinary comparison reaches it first and reports the less specific reason."""
    settings = InterceptionSettings.build(
        management_authorities=["docs.example.com"],
    )
    outcome = denied(
        interceptor(settings=settings).intercept(
            TunnelledConnection(connect_target="docs.example.com")
        )
    )
    assert outcome.reason is DenialReason.PROXY_MANAGEMENT_INTERFACE


def test_a_tunnel_makes_none_of_the_classifications_its_visibility_cannot_support() -> (
    None
):
    """A bare address over a tunnel is the ordinary denial: the tunnel was given no name to compare."""
    outcome = denied(
        interceptor().intercept(TunnelledConnection(connect_target="203.0.113.5"))
    )
    assert outcome.reason is DenialReason.UNDECLARED_DESTINATION
    assert not is_circumvention(outcome.reason)


# --- The echo denylist and the response strip list -----------------------------------------------


def echo_settings() -> InterceptionSettings:
    return InterceptionSettings.build(
        echo_denylist={"pypi.egress.internal": ["/debug", "/-/whoami"]}
    )


@pytest.mark.parametrize(
    "path", ["/debug", "/debug/headers", "/debug/deep/er", "/-/whoami"]
)
def test_a_path_on_this_destinations_echo_denylist_is_refused(path: str) -> None:
    """The design's second mitigation for the response-echo residual."""
    outcome = denied(
        interceptor(settings=echo_settings()).intercept(
            request(server_name="pypi.egress.internal", path=path)
        )
    )
    assert outcome.reason is DenialReason.UNDECLARED_DESTINATION
    assert outcome.tier is Tier.TOKEN_INJECTION
    assert not is_circumvention(outcome.reason)


@pytest.mark.parametrize("path", ["/debugger", "/simple", "/", "/simple/requests"])
def test_a_path_that_only_resembles_a_denylisted_one_is_forwarded(path: str) -> None:
    """Segment-bounded, so an operator's listing does not reach further than they wrote."""
    outcome = interceptor(settings=echo_settings()).intercept(
        request(server_name="pypi.egress.internal", path=path)
    )
    assert isinstance(outcome, Forwarded)


def test_the_echo_denylist_applies_to_the_destination_it_was_configured_for() -> None:
    outcome = interceptor(settings=echo_settings()).intercept(
        request(server_name="bedrock.egress.internal", path="/debug")
    )
    assert isinstance(outcome, Forwarded)


@pytest.mark.parametrize(
    "path",
    [
        "simple",
        "",
        "/%64ebug",
        "/a/../debug",
        "/a//b",
        "/café",
        "/simple?name=x",
        "/simple#frag",
        "/has space",
        "/x" * MAX_PATH_LENGTH,
    ],
)
def test_a_path_this_comparison_cannot_hold_is_refused_rather_than_repaired(
    path: str,
) -> None:
    """Decoding is where a path comparison and its author come to disagree."""
    outcome = denied(
        interceptor(settings=echo_settings()).intercept(
            request(server_name="pypi.egress.internal", path=path)
        )
    )
    assert outcome.reason is DenialReason.UNDECLARED_DESTINATION


def test_a_trailing_slash_is_the_same_path_on_both_sides() -> None:
    subject = interceptor(
        settings=InterceptionSettings.build(
            echo_denylist={"pypi.egress.internal": ["/debug/"]}
        )
    )
    assert isinstance(
        subject.intercept(request(server_name="pypi.egress.internal", path="/debug")),
        Denied,
    )
    assert isinstance(
        subject.intercept(request(server_name="pypi.egress.internal", path="/debug/")),
        Denied,
    )


@pytest.mark.parametrize("authority", ["café.internal", "has space", "", ".."])
def test_a_management_authority_that_could_never_match_is_refused(
    authority: str,
) -> None:
    with pytest.raises(PolicyDocumentError, match="managementAuthorities"):
        InterceptionSettings.build(management_authorities=[authority])


def test_a_management_authority_naming_a_port_is_refused() -> None:
    with pytest.raises(PolicyDocumentError, match="names a port"):
        InterceptionSettings.build(
            management_authorities=["proxy-admin.egress.internal:9901"]
        )


@pytest.mark.parametrize("path", ["debug", "/%64ebug", "/a/../b", "/café"])
def test_a_configured_denylist_path_that_could_never_match_is_refused(
    path: str,
) -> None:
    """An entry whose author believes something is refused when nothing is."""
    with pytest.raises(PolicyDocumentError, match="echoDenylist"):
        InterceptionSettings.build(echo_denylist={"pypi.egress.internal": [path]})


def test_configured_authorities_are_normalised_by_the_one_normaliser_this_package_has() -> (
    None
):
    settings = InterceptionSettings.build(
        management_authorities=["PROXY-ADMIN.Egress.Internal."],
        echo_denylist={"PyPI.egress.internal.": ["/debug"]},
    )
    assert settings.management_authorities == {"proxy-admin.egress.internal"}
    assert settings.echo_denylist == {"pypi.egress.internal": frozenset({"/debug"})}


# --- The reason vocabulary, and what never travels outward ---------------------------------------


def test_every_reason_a_tier_returns_is_a_member_of_the_closed_set() -> None:
    """`control_plane.allocation.DenialReason` is the vocabulary; this module defines no second one."""
    settings = InterceptionSettings.build(
        management_authorities=["proxy-admin.egress.internal"],
        echo_denylist={"pypi.egress.internal": ["/debug"]},
    )
    attempts: list[TerminatedRequest | TunnelledConnection] = [
        TunnelledConnection(connect_target="exfil.example"),
        TunnelledConnection(connect_target="proxy-admin.egress.internal"),
        TunnelledConnection(connect_target="bedrock.egress.internal"),
        request(server_name="exfil.example"),
        request(server_name="docs.example.com"),
        request(server_name="pypi.egress.internal", path="/debug"),
        request(server_name="pypi.egress.internal", host_header="exfil.example"),
        request(
            server_name="pypi.egress.internal", host_header="bedrock.egress.internal"
        ),
        request(server_name="pypi.egress.internal", host_header="203.0.113.5"),
        request(server_name="bedrock.egress.internal", host_header=""),
    ]
    subject = interceptor(settings=settings)
    reasons = {denied(subject.intercept(attempt)).reason for attempt in attempts}
    assert reasons <= set(DenialReason)
    # Every classification the terminated tiers add over the policy comparison is in the closed
    # circumvention subset, and every ordinary denial is outside it.
    assert reasons & CIRCUMVENTION_REASONS == {
        DenialReason.HOST_SNI_MISMATCH,
        DenialReason.ALIAS_SPOOFED,
        DenialReason.IP_LITERAL_FOR_ALIASED_UPSTREAM,
        DenialReason.PROXY_MANAGEMENT_INTERFACE,
    }
    assert DenialReason.UNDECLARED_DESTINATION in reasons


def test_a_denial_carries_no_byte_of_the_attempted_destination() -> None:
    """The destination is chosen by Untrusted_Code; the audit record reproduces it, a reason does not."""
    marker = "exfil-marker.example"
    path_marker = "/exfil-marker-path"
    subject = interceptor(settings=echo_settings())
    attempts: list[TerminatedRequest | TunnelledConnection] = [
        TunnelledConnection(connect_target=marker),
        request(server_name=marker, path=path_marker),
        request(server_name="bedrock.egress.internal", host_header=marker),
        request(server_name="pypi.egress.internal", path=f"/debug{path_marker}"),
    ]
    for attempt in attempts:
        outcome = denied(subject.intercept(attempt))
        assert {field.name for field in dataclasses.fields(outcome)} == {
            "reason",
            "tier",
        }
        rendered = repr(outcome) + str(outcome.reason)
        assert marker not in rendered, attempt
        assert path_marker not in rendered, attempt


def test_a_denial_before_a_tier_was_chosen_names_no_tier() -> None:
    outcome = denied(
        interceptor().intercept(TunnelledConnection(connect_target="exfil.example"))
    )
    assert outcome.tier is None


def test_nothing_is_logged_at_any_level(caplog: pytest.LogCaptureFixture) -> None:
    """The audit record is task 10.5's, built where the attempt is. This module emits nothing."""
    subject = interceptor(settings=echo_settings())
    with caplog.at_level(logging.DEBUG):
        subject.intercept(request(server_name="bedrock.egress.internal"))
        subject.intercept(request(server_name="pypi.egress.internal", path="/debug"))
        subject.intercept(TunnelledConnection(connect_target="exfil.example"))
        subject.intercept(TunnelledConnection(connect_target="docs.example.com"))
    assert caplog.records == []


def test_the_same_attempt_yields_the_same_outcome() -> None:
    subject = interceptor()
    attempt = request(server_name="pypi.egress.internal", path="/simple")
    assert subject.intercept(attempt) == subject.intercept(attempt)
