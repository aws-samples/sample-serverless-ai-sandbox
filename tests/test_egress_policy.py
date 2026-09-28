# kiro-classification: public
"""The egress policy document, the decision function, and the cache TTL that bounds revocation.

Every assertion here is deterministic and nothing draws inputs. Property 17 quantifies over policy
documents and attempted destinations and is its own task; what this file establishes is the mechanism
that property will be quantified over, in four senses:

- the document in `design.md`'s `Egress policy document` section is loaded *verbatim*, so the schema
  this package implements is pinned against the design rather than against its author's memory of it;
- the two branch tables are asserted total from outside the module, so the import-time assertions are
  not the only thing standing behind the claim that no destination shape and no `defaultAction` value
  reaches a default;
- the denial reasons are asserted to be members of `control_plane.allocation.DenialReason` and to lie
  outside the circumvention subset, which is the claim that this task reused the closed vocabulary
  instead of starting a second one;
- the cache is driven by a fake clock and a source that can fail mid-flight, so revocation latency and
  the fail-closed read are read off a call count rather than waited for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

import pytest

from control_plane.allocation import (
    CIRCUMVENTION_REASONS,
    DenialReason,
)
from egress import (
    DEFAULT_ACTION_DENIALS,
    EGRESS_TLS_PORT,
    FORM_MATCH_RULES,
    MAX_POLICY_CACHE_TTL_SECONDS,
    CachedPolicyReader,
    Decision,
    DefaultAction,
    Destination,
    DestinationForm,
    EgressPolicy,
    MatchRule,
    PolicyCacheSettings,
    PolicyDocumentError,
    PolicyUnavailable,
    Tier,
    decide,
)

# The document from design.md's `Egress policy document` section, with the region placeholder and the
# elided secret ARN filled in and nothing else changed. Held as text rather than as a dict so that a
# reader can diff it against the design by eye.
DESIGN_DOCUMENT: Final = """
{
  "policyVersion": 14,
  "destinationSets": {
    "bedrock-runtime": {
      "tier": 1,
      "alias": "bedrock.egress.internal",
      "upstreamHost": "bedrock-runtime.us-east-1.amazonaws.com",
      "signAs": "bedrock",
      "viaVpcEndpoint": true
    },
    "public-package-registries": {
      "tier": 2,
      "entries": [
        { "alias": "pypi.egress.internal", "upstreamHost": "pypi.org",
          "injectHeader": "Authorization", "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:p",
          "stripResponseHeaders": ["x-echo-request-headers"] }
      ]
    },
    "gpu-target-inference": { "tier": 1, "alias": "gpu.egress.internal", "signAs": "execute-api" }
  },
  "defaultAction": "deny"
}
"""


def design_policy() -> EgressPolicy:
    """The design's own document, loaded."""
    return EgressPolicy.from_document(json.loads(DESIGN_DOCUMENT))


def document(**overrides: Any) -> dict[str, Any]:
    """A minimal valid document, with top-level keys replaced."""
    base: dict[str, Any] = {
        "policyVersion": 1,
        "destinationSets": {
            "one": {"tier": 3, "upstreamHost": "example.internal"},
        },
        "defaultAction": "deny",
    }
    base.update(overrides)
    return base


def sets(**named: Any) -> dict[str, Any]:
    """A document whose destination sets are exactly `named`."""
    return document(destinationSets=named)


@dataclass
class FixedSource:
    """A policy source under the test's control: what it returns, and whether it fails.

    `reads` is counted here as well as by the reader, so "the cache served this request" is asserted
    against the source rather than against the reader's own bookkeeping.
    """

    policy: EgressPolicy | None
    reads: int = 0

    def read(self) -> EgressPolicy:
        self.reads += 1
        if self.policy is None:
            raise PolicyUnavailable("the policy store is unreachable")
        return self.policy


@dataclass
class FakeClock:
    """A monotonic clock the test advances. Nothing here waits for a TTL to elapse."""

    now: float = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class RecordingSource:
    """A source that serves each policy in turn, so a revocation lands between two reads."""

    policies: list[EgressPolicy | None] = field(default_factory=list)
    reads: int = 0

    def read(self) -> EgressPolicy:
        index = min(self.reads, len(self.policies) - 1)
        self.reads += 1
        policy = self.policies[index]
        if policy is None:
            raise PolicyUnavailable("the policy store is unreachable")
        return policy


def reader(
    source: FixedSource | RecordingSource,
    *,
    clock: FakeClock,
    ttl: float = 30.0,
) -> CachedPolicyReader:
    return CachedPolicyReader(
        source=source, settings=PolicyCacheSettings(cache_ttl_seconds=ttl), clock=clock
    )


# --- The design's document, loaded verbatim ------------------------------------------------------


def test_the_designs_own_policy_document_loads() -> None:
    """The schema is pinned against design.md rather than against a paraphrase of it."""
    policy = design_policy()
    assert policy.policy_version == 14
    assert policy.default_action is DefaultAction.DENY
    assert [destination_set.name for destination_set in policy.destination_sets] == [
        "bedrock-runtime",
        "public-package-registries",
        "gpu-target-inference",
    ]


def test_each_destination_set_carries_the_tier_the_design_gives_it() -> None:
    policy = design_policy()
    tiers = {
        destination_set.name: destination_set.tier
        for destination_set in policy.destination_sets
    }
    assert tiers == {
        "bedrock-runtime": Tier.SIGV4_RESIGNING,
        "public-package-registries": Tier.TOKEN_INJECTION,
        "gpu-target-inference": Tier.SIGV4_RESIGNING,
    }


def test_the_inline_single_entry_form_and_the_entries_form_load_alike() -> None:
    """`bedrock-runtime` is written inline and `public-package-registries` as a list of one."""
    policy = design_policy()
    entries = {
        destination_set.name: destination_set.entries
        for destination_set in policy.destination_sets
    }
    assert len(entries["bedrock-runtime"]) == 1
    assert len(entries["public-package-registries"]) == 1
    assert entries["bedrock-runtime"][0].alias == "bedrock.egress.internal"
    assert entries["bedrock-runtime"][0].via_vpc_endpoint is True
    assert entries["public-package-registries"][0].inject_header == "Authorization"


def test_a_tier_2_strip_list_is_stored_lowercased() -> None:
    """A header name is case-insensitive, so the strip has to hold whichever case the upstream used."""
    policy = EgressPolicy.from_document(
        sets(
            registry={
                "tier": 2,
                "alias": "npm.egress.internal",
                "upstreamHost": "registry.npmjs.org",
                "injectHeader": "Authorization",
                "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:n",
                "stripResponseHeaders": ["X-Echo-Request-Headers"],
            }
        )
    )
    assert policy.destination_sets[0].entries[0].strip_response_headers == (
        "x-echo-request-headers",
    )


# --- What is permitted is the alias, not the upstream behind it --------------------------------


def test_the_alias_is_what_a_sandbox_may_address() -> None:
    policy = design_policy()
    decision = decide(policy, Destination.parse("bedrock.egress.internal"))
    assert decision.permitted
    assert decision.destination_set == "bedrock-runtime"
    assert decision.tier is Tier.SIGV4_RESIGNING


def test_the_upstream_behind_an_alias_is_not_permitted() -> None:
    """Reaching `pypi.org` directly would be the interception the credential absence rests on, gone."""
    policy = design_policy()
    for upstream in ("pypi.org", "bedrock-runtime.us-east-1.amazonaws.com"):
        decision = decide(policy, Destination.parse(upstream))
        assert not decision.permitted, upstream
        assert decision.reason is DenialReason.UNDECLARED_DESTINATION


def test_a_tier_3_entry_is_permitted_under_its_upstream_host() -> None:
    """A `CONNECT` tunnel has no alias, so the upstream host is the permitted name."""
    policy = EgressPolicy.from_document(
        sets(tunnel={"tier": 3, "upstreamHost": "docs.example.com"})
    )
    decision = decide(policy, Destination.parse("docs.example.com"))
    assert decision.permitted
    assert decision.tier is Tier.CONNECT_TUNNEL
    assert decision.entry is not None
    assert decision.entry.alias is None


# --- One normalisation, applied to both sides ---------------------------------------------------


@pytest.mark.parametrize(
    "attempted",
    [
        "bedrock.egress.internal",
        "BEDROCK.EGRESS.INTERNAL",
        "Bedrock.Egress.Internal",
        "bedrock.egress.internal.",
        "BEDROCK.egress.internal.",
        f"bedrock.egress.internal:{EGRESS_TLS_PORT}",
        f"BEDROCK.egress.internal.:{EGRESS_TLS_PORT}",
    ],
)
def test_a_case_or_trailing_dot_variant_of_a_permitted_alias_is_the_same_destination(
    attempted: str,
) -> None:
    """DNS is case-insensitive and the fully-qualified form of a name is that name."""
    assert decide(design_policy(), Destination.parse(attempted)).permitted


def test_an_entry_authored_in_a_different_case_permits_the_lowercase_attempt() -> None:
    """The loader normalises the entry through the same function, so the two sides cannot diverge."""
    policy = EgressPolicy.from_document(
        sets(tunnel={"tier": 3, "upstreamHost": "Docs.Example.COM."})
    )
    assert policy.destination_sets[0].entries[0].permitted_host == "docs.example.com"
    assert decide(policy, Destination.parse("docs.example.com")).permitted


@pytest.mark.parametrize(
    ("attempted", "form", "host"),
    [
        ("example.internal", DestinationForm.DNS_NAME, "example.internal"),
        ("example.internal.", DestinationForm.DNS_NAME, "example.internal"),
        ("xn--caf-dma.example", DestinationForm.DNS_NAME, "xn--caf-dma.example"),
        ("1.2.3.4", DestinationForm.IPV4_LITERAL, "1.2.3.4"),
        ("[::1]", DestinationForm.IPV6_LITERAL, "::1"),
        ("::1", DestinationForm.IPV6_LITERAL, "::1"),
        ("[0:0:0:0:0:0:0:1]", DestinationForm.IPV6_LITERAL, "::1"),
        ("café.example", DestinationForm.NON_ASCII_NAME, ""),
        ("", DestinationForm.UNPARSABLE, ""),
        ("has space", DestinationForm.UNPARSABLE, ""),
        ("has\x00null", DestinationForm.UNPARSABLE, ""),
        ("example.internal:", DestinationForm.UNPARSABLE, ""),
        ("example.internal:0", DestinationForm.UNPARSABLE, ""),
        ("example.internal:99999", DestinationForm.UNPARSABLE, ""),
        ("example.internal:٤٤٣", DestinationForm.UNPARSABLE, ""),
        ("[::1", DestinationForm.UNPARSABLE, ""),
        ("..", DestinationForm.UNPARSABLE, ""),
        ("https://example.internal", DestinationForm.UNPARSABLE, ""),
    ],
)
def test_every_destination_shape_normalises_to_a_form_and_a_canonical_host(
    attempted: str, form: DestinationForm, host: str
) -> None:
    """Total: parsing never raises, whatever Untrusted_Code supplied."""
    destination = Destination.parse(attempted)
    assert destination.form is form
    assert destination.host == host


def test_a_destination_that_matches_nothing_carries_no_host() -> None:
    """The only use for a host is the comparison, and an unmatched copy is a copy waiting to be logged."""
    for attempted in ("café.example", "has space", ""):
        assert Destination.parse(attempted).host == ""


def test_two_spellings_of_one_address_are_one_destination() -> None:
    policy = EgressPolicy.from_document(
        sets(tunnel={"tier": 3, "upstreamHost": "0:0:0:0:0:0:0:1"})
    )
    assert decide(policy, Destination.parse("[::1]")).permitted


def test_a_u_label_does_not_match_its_a_label_entry_and_the_denial_is_the_safe_direction() -> (
    None
):
    policy = EgressPolicy.from_document(
        sets(tunnel={"tier": 3, "upstreamHost": "xn--caf-dma.example"})
    )
    assert decide(policy, Destination.parse("xn--caf-dma.example")).permitted
    denied = decide(policy, Destination.parse("café.example"))
    assert not denied.permitted
    assert denied.reason is DenialReason.UNDECLARED_DESTINATION


def test_resolution_is_equality_rather_than_a_prefix_or_suffix_match() -> None:
    policy = design_policy()
    for near_miss in (
        "bedrock.egress.internal.example.com",
        "notbedrock.egress.internal",
        "egress.internal",
        "bedrock.egress.internal-",
    ):
        assert not decide(policy, Destination.parse(near_miss)).permitted, near_miss


# --- The port is part of the match, and 443 is the only one -------------------------------------


@pytest.mark.parametrize("port", [80, 8080, 1, 65535])
def test_a_port_other_than_443_resolves_to_no_entry(port: int) -> None:
    """The attachment's security group reaches the proxy on 443 alone."""
    decision = decide(
        design_policy(), Destination.parse(f"bedrock.egress.internal:{port}")
    )
    assert not decision.permitted
    assert decision.reason is DenialReason.UNDECLARED_DESTINATION


def test_an_entry_may_not_carry_a_port() -> None:
    with pytest.raises(PolicyDocumentError, match="names a port"):
        EgressPolicy.from_document(
            sets(tunnel={"tier": 3, "upstreamHost": "example.internal:8443"})
        )


# --- defaultAction, and the absence of a permitting value ---------------------------------------


def test_default_action_has_exactly_one_value_and_it_denies() -> None:
    """The schema's own claim: no value of `defaultAction` permits an undeclared destination."""
    assert list(DefaultAction) == [DefaultAction.DENY]
    assert set(DEFAULT_ACTION_DENIALS) == set(DefaultAction)
    assert all(
        isinstance(reason, DenialReason) for reason in DEFAULT_ACTION_DENIALS.values()
    )


@pytest.mark.parametrize(
    "action", ["allow", "permit", "ALLOW", "", "deny-unless-listed"]
)
def test_a_document_asking_for_any_other_default_action_is_refused(action: str) -> None:
    with pytest.raises(PolicyDocumentError, match="is not a value of this schema"):
        EgressPolicy.from_document(document(defaultAction=action))


def test_a_document_with_no_destination_sets_permits_nothing() -> None:
    policy = EgressPolicy.from_document(document(destinationSets={}))
    decision = decide(policy, Destination.parse("bedrock.egress.internal"))
    assert not decision.permitted
    assert decision.reason is DenialReason.UNDECLARED_DESTINATION


# --- The decision function is total -------------------------------------------------------------


def test_every_destination_form_has_a_match_rule() -> None:
    """Asserted from outside the module as well as at import, so the claim has two witnesses."""
    assert set(FORM_MATCH_RULES) == set(DestinationForm)


def test_the_forms_that_match_nothing_are_the_two_that_cannot_be_canonicalised() -> (
    None
):
    never = {
        form
        for form, rule in FORM_MATCH_RULES.items()
        if rule is MatchRule.NEVER_MATCHES
    }
    assert never == {DestinationForm.NON_ASCII_NAME, DestinationForm.UNPARSABLE}


def test_a_decision_exists_for_every_form_under_a_policy_and_under_none() -> None:
    """One decision per form, with no form left without an answer either way."""
    policy = design_policy()
    samples = {
        DestinationForm.DNS_NAME: "bedrock.egress.internal",
        DestinationForm.IPV4_LITERAL: "1.2.3.4",
        DestinationForm.IPV6_LITERAL: "[::1]",
        DestinationForm.NON_ASCII_NAME: "café.example",
        DestinationForm.UNPARSABLE: "has space",
    }
    assert set(samples) == set(DestinationForm)
    for form, attempted in samples.items():
        destination = Destination.parse(attempted)
        assert destination.form is form
        assert isinstance(decide(policy, destination), Decision)
        assert decide(None, destination).reason is DenialReason.CONTROLLER_UNREACHABLE


def test_the_decision_function_is_pure() -> None:
    """Same policy, same destination, same decision, however many times it is asked."""
    policy = design_policy()
    destination = Destination.parse("pypi.egress.internal")
    first = decide(policy, destination)
    assert first == decide(policy, destination)
    assert first == decide(design_policy(), Destination.parse("pypi.egress.internal"))


def test_a_permit_names_its_entry_and_a_denial_names_a_reason() -> None:
    permit = decide(design_policy(), Destination.parse("gpu.egress.internal"))
    assert permit.reason is None
    assert permit.entry is not None
    denial = decide(design_policy(), Destination.parse("elsewhere.example"))
    assert denial.entry is None
    assert denial.destination_set is None
    assert denial.tier is None


def test_a_decision_cannot_be_constructed_in_a_mixed_shape() -> None:
    """The invariant is checked, so a caller cannot assemble a permit with a denial reason."""
    with pytest.raises(ValueError, match="a permit names"):
        Decision(permitted=True, reason=DenialReason.UNDECLARED_DESTINATION)
    with pytest.raises(ValueError, match="a denial carries"):
        Decision(permitted=False)


# --- The reason vocabulary is the one that already exists ---------------------------------------


def test_every_reason_this_package_can_return_is_a_denial_reason_member() -> None:
    """The closed set is `control_plane.allocation.DenialReason`; this package defines no second one."""
    returned = {
        DenialReason.CONTROLLER_UNREACHABLE,
        *DEFAULT_ACTION_DENIALS.values(),
    }
    assert returned <= set(DenialReason)


def test_neither_reason_this_package_returns_quarantines_a_sandbox() -> None:
    """A mistyped hostname and a policy store outage are not evidence of attempted circumvention."""
    returned = {DenialReason.CONTROLLER_UNREACHABLE, *DEFAULT_ACTION_DENIALS.values()}
    assert not returned & CIRCUMVENTION_REASONS


# --- Refusals: a malformed document is not a permissive one -------------------------------------


def test_an_alias_permitted_by_two_destination_sets_is_refused() -> None:
    """The alias is the interception point; two sets claiming it disagree about what is injected."""
    with pytest.raises(PolicyDocumentError, match="already permitted"):
        EgressPolicy.from_document(
            sets(
                first={
                    "tier": 2,
                    "alias": "shared.egress.internal",
                    "upstreamHost": "one.example",
                    "injectHeader": "Authorization",
                    "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:a",
                },
                second={
                    "tier": 1,
                    "alias": "shared.egress.internal",
                    "signAs": "bedrock",
                },
            )
        )


@pytest.mark.parametrize(
    "destination_set",
    [
        {"tier": 3, "upstreamHost": "one.example", "injectHeader": "Authorization"},
        {"tier": 3, "upstreamHost": "one.example", "signAs": "bedrock"},
        {"tier": 3, "upstreamHost": "one.example", "stripResponseHeaders": ["x-a"]},
        {"tier": 1, "alias": "a.internal", "signAs": "bedrock", "injectHeader": "X-A"},
        {
            "tier": 2,
            "alias": "a.internal",
            "upstreamHost": "one.example",
            "injectHeader": "Authorization",
            "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:a",
            "signAs": "bedrock",
        },
    ],
)
def test_a_field_the_tier_cannot_honour_is_refused(
    destination_set: dict[str, Any],
) -> None:
    """Ignoring it would leave an operator believing a credential is applied when it is not."""
    with pytest.raises(PolicyDocumentError, match="cannot honour"):
        EgressPolicy.from_document(sets(one=destination_set))


@pytest.mark.parametrize(
    ("destination_set", "required"),
    [
        ({"tier": 1, "alias": "a.internal"}, "signAs"),
        ({"tier": 1, "signAs": "bedrock"}, "alias"),
        (
            {"tier": 2, "alias": "a.internal", "upstreamHost": "one.example"},
            "injectHeader",
        ),
        (
            {
                "tier": 2,
                "alias": "a.internal",
                "upstreamHost": "one.example",
                "injectHeader": "Authorization",
            },
            "secretArn",
        ),
        ({"tier": 3}, "upstreamHost"),
    ],
)
def test_a_tier_requires_the_fields_it_cannot_work_without(
    destination_set: dict[str, Any], required: str
) -> None:
    with pytest.raises(PolicyDocumentError, match=required):
        EgressPolicy.from_document(sets(one=destination_set))


@pytest.mark.parametrize(
    "document_body",
    [
        {
            "policyVersion": 1,
            "destinationSets": {},
            "defaultAction": "deny",
            "extra": 1,
        },
        {"policyVersion": 1, "destinationSets": {}},
        {"destinationSets": {}, "defaultAction": "deny"},
        {"policyVersion": 1, "defaultAction": "deny"},
    ],
)
def test_a_document_missing_or_carrying_a_key_this_schema_does_not_define_is_refused(
    document_body: dict[str, Any],
) -> None:
    with pytest.raises(PolicyDocumentError):
        EgressPolicy.from_document(document_body)


def test_a_misspelled_entry_key_is_refused_rather_than_ignored() -> None:
    """A misspelled `stripResponseHeaders` is a strip list that silently does not exist."""
    with pytest.raises(PolicyDocumentError, match="does not define"):
        EgressPolicy.from_document(
            sets(
                one={
                    "tier": 2,
                    "alias": "a.internal",
                    "upstreamHost": "one.example",
                    "injectHeader": "Authorization",
                    "secretArn": "arn:aws:secretsmanager:eu-west-1:1:secret:a",
                    "stripResponseHeader": ["x-echo"],
                }
            )
        )


@pytest.mark.parametrize("tier", [0, 4, -1, 99])
def test_a_tier_the_design_does_not_name_is_refused(tier: int) -> None:
    with pytest.raises(PolicyDocumentError, match="is not an interception tier"):
        EgressPolicy.from_document(
            sets(one={"tier": tier, "upstreamHost": "a.example"})
        )


def test_a_boolean_is_not_a_tier_and_is_not_a_version() -> None:
    """`True` is an `int` in Python and would otherwise pass for tier 1."""
    with pytest.raises(PolicyDocumentError, match="must be an integer"):
        EgressPolicy.from_document(sets(one={"tier": True, "alias": "a.internal"}))
    with pytest.raises(PolicyDocumentError, match="must be an integer"):
        EgressPolicy.from_document(document(policyVersion=True))


def test_a_policy_version_below_one_is_refused() -> None:
    with pytest.raises(PolicyDocumentError, match="numbered from 1"):
        EgressPolicy.from_document(document(policyVersion=0))


def test_a_destination_set_describing_its_entries_twice_is_refused() -> None:
    with pytest.raises(PolicyDocumentError, match="twice"):
        EgressPolicy.from_document(
            sets(
                one={
                    "tier": 3,
                    "upstreamHost": "a.example",
                    "entries": [{"upstreamHost": "b.example"}],
                }
            )
        )


def test_an_empty_entries_array_is_refused() -> None:
    with pytest.raises(PolicyDocumentError, match="permits nothing"):
        EgressPolicy.from_document(sets(one={"tier": 3, "entries": []}))


@pytest.mark.parametrize("host", ["café.internal", "has space", "", "..", "a" * 300])
def test_an_entry_that_could_never_match_is_refused(host: str) -> None:
    """An entry whose author believes something is permitted when nothing is."""
    with pytest.raises(PolicyDocumentError):
        EgressPolicy.from_document(sets(one={"tier": 3, "upstreamHost": host}))


def test_an_entry_declaring_a_tier_other_than_its_sets_is_refused() -> None:
    with pytest.raises(PolicyDocumentError, match="different from the destination set"):
        EgressPolicy.from_document(
            sets(
                one={
                    "tier": 3,
                    "entries": [{"tier": 1, "upstreamHost": "a.example"}],
                }
            )
        )


# --- The per-request read, and the TTL that bounds revocation -----------------------------------


def test_the_policy_is_read_once_per_ttl_rather_than_once_per_request() -> None:
    clock = FakeClock()
    source = FixedSource(policy=design_policy())
    subject = reader(source, clock=clock, ttl=30.0)
    for _ in range(5):
        assert subject.decide("bedrock.egress.internal").permitted
    assert source.reads == 1
    clock.advance(29.999)
    assert subject.decide("bedrock.egress.internal").permitted
    assert source.reads == 1
    clock.advance(0.001)
    assert subject.decide("bedrock.egress.internal").permitted
    assert source.reads == 2
    assert subject.reads == source.reads


def test_a_ttl_of_zero_reads_on_every_request() -> None:
    """Strictly safer, at the cost of a read per request. A legitimate deployment choice."""
    clock = FakeClock()
    source = FixedSource(policy=design_policy())
    subject = reader(source, clock=clock, ttl=0.0)
    for _ in range(3):
        subject.decide("bedrock.egress.internal")
    assert source.reads == 3


def test_a_revoked_destination_stops_being_permitted_within_the_ttl() -> None:
    """The design's revocation claim is a claim about this cache and no other component."""
    clock = FakeClock()
    source = RecordingSource(
        policies=[
            design_policy(),
            EgressPolicy.from_document(document(destinationSets={})),
        ]
    )
    subject = reader(source, clock=clock, ttl=30.0)
    assert subject.decide("bedrock.egress.internal").permitted
    clock.advance(MAX_POLICY_CACHE_TTL_SECONDS)
    denied = subject.decide("bedrock.egress.internal")
    assert not denied.permitted
    assert denied.reason is DenialReason.UNDECLARED_DESTINATION


def test_an_unreachable_policy_store_denies_rather_than_permits() -> None:
    clock = FakeClock()
    subject = reader(FixedSource(policy=None), clock=clock)
    decision = subject.decide("bedrock.egress.internal")
    assert not decision.permitted
    assert decision.reason is DenialReason.CONTROLLER_UNREACHABLE
    assert subject.policy() is None


def test_a_failed_read_discards_the_cached_policy_rather_than_serving_it() -> None:
    """Serving the last known policy would extend revocation for as long as the outage lasts."""
    clock = FakeClock()
    source = RecordingSource(policies=[design_policy(), None])
    subject = reader(source, clock=clock, ttl=30.0)
    assert subject.decide("bedrock.egress.internal").permitted
    clock.advance(30.0)
    denied = subject.decide("bedrock.egress.internal")
    assert denied.reason is DenialReason.CONTROLLER_UNREACHABLE
    # Still denied on the next request rather than falling back to what was cached before the outage.
    assert (
        subject.decide("bedrock.egress.internal").reason
        is DenialReason.CONTROLLER_UNREACHABLE
    )


def test_a_source_error_that_is_not_policy_unavailable_is_not_swallowed() -> None:
    """Absorbing every exception would make an adapter defect look like a policy store outage."""

    class BrokenSource:
        def read(self) -> EgressPolicy:
            raise RuntimeError("a client error the adapter failed to translate")

    subject = CachedPolicyReader(
        source=BrokenSource(), settings=PolicyCacheSettings(cache_ttl_seconds=30.0)
    )
    with pytest.raises(RuntimeError):
        subject.decide("bedrock.egress.internal")


@pytest.mark.parametrize("ttl", [-0.001, -1.0])
def test_a_negative_cache_ttl_is_refused(ttl: float) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        PolicyCacheSettings(cache_ttl_seconds=ttl)


def test_a_cache_ttl_above_the_documented_revocation_latency_is_refused() -> None:
    """A deployment configuring five minutes would be falsifying a documented property."""
    PolicyCacheSettings(cache_ttl_seconds=MAX_POLICY_CACHE_TTL_SECONDS)
    with pytest.raises(ValueError, match="must not exceed"):
        PolicyCacheSettings(cache_ttl_seconds=MAX_POLICY_CACHE_TTL_SECONDS + 0.001)
