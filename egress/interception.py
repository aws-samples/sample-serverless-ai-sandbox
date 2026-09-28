# kiro-classification: public
"""The three interception tiers: what each one sees, what each one injects, and what each denies.

The design's `Three interception tiers, chosen per destination class` section opens with the sentence
this module is built around: "Credential injection requires seeing the request in plaintext. There is
no way around that, so the design decides *where* plaintext exists rather than pretending it does not
need to." Three tiers follow from that decision, and they differ in exactly one way that matters
here — **how much of the attempt each one can see**:

- **Tier 1, SigV4 re-signing** (R12.6, R16.2, R5.11). TLS terminates legitimately at the proxy,
  because the alias *is* the proxy. The inbound `Authorization` header is discarded and the request is
  re-signed with the proxy task role.
- **Tier 2, the aliased reverse proxy** (R12.6). TLS also terminates at the alias. The upstream token
  is added on the **upstream leg only** — a TLS session the proxy originates and to which the Sandbox
  has no access (R12.4).
- **Tier 3, the `CONNECT` tunnel.** TLS is end to end. The proxy sees the requested authority and
  nothing else, and injection is impossible by construction.

## A tier cannot be asked to enforce a rule it cannot see

That is structural here rather than a review convention, and it is built as a chain in which every
link is checked at import:

1. :class:`Observation` enumerates what a proxy can observe about one attempt.
2. The **fields of the request type** a tier is handed determine which of those it holds:
   :data:`REQUEST_OBSERVATION_FIELDS` names the attribute behind each observation and is asserted
   against :func:`dataclasses.fields` in both directions, so a field added without an observation, or
   an observation claimed without a field, fails the build.
3. The **outcome type** determines whether the tier sees the response at all:
   :data:`OUTCOME_FORMS` gives the terminated tiers :class:`Forwarded`, which can rewrite response
   headers, and Tier 3 :class:`Tunnelled`, which cannot. That correspondence is asserted too.
4. :data:`TIER_OBSERVATIONS` is therefore **derived** from the types a tier works with, and
   :data:`ENFORCEABLE_RULES` is derived from it by subset containment against
   :data:`RULE_OBSERVATIONS`. A tier's rule set is not something anybody can get wrong: a rule needing
   an observation the tier lacks is absent from that tier's set as a matter of arithmetic.
5. Each handler declares the rules it enforces, and :data:`HANDLER_RULES` is asserted equal to the
   derived set. A handler enforcing a rule its form cannot see, or dropping one it can, fails the
   build.

So there is no runtime check to forget. The Tier 3 handler has no `path` attribute to read, because a
`CONNECT` tunnel does not carry one, and the echo-denylist rule is absent from its rule set because
the observation it needs is absent from its observation set.

Two things are deliberately outside :class:`Observation`. The **request body** and the **response
body** pass through Tier 1 and Tier 2 in plaintext and are invisible at Tier 3, and no rule here
examines either. That is the design's accepted residual: "the Sandbox reads the upstream response. An
upstream that reflects request headers back … would return the injected credential to the Sandbox.
Mitigation is a response-header strip list and a denylist of echo-prone paths per aliased
destination". Both mitigations are implemented — :attr:`EnforcementRule.RESPONSE_HEADERS_STRIPPED` and
:attr:`EnforcementRule.ECHO_PRONE_PATH_REFUSED` — and neither is body inspection, so the residual is
recorded here as the design records it rather than papered over with a scan that would be incomplete.

## Fail closed, per tier

:func:`~egress.decision.decide` already denies for a `None` policy (R12.8), and every tier reaches the
policy through it and through nothing else, so that property holds per tier rather than once
centrally. On top of it:

- an attempt whose authority does not parse denies, because
  :meth:`~egress.policy.Destination.parse` classifies it
  :attr:`~egress.policy.DestinationForm.UNPARSABLE` and the policy names no such destination;
- an attempt arriving in the **wrong form** for the tier its destination is served by denies. A
  `CONNECT` tunnel requested for a Tier 1 alias asks the proxy to permit an aliased destination while
  withholding the plaintext the alias exists to obtain, and no permitted destination-and-tier pair
  describes it;
- an attempt on a terminated tier whose `Host` header cannot be read denies;
- an attempt whose injected credential cannot be obtained denies. A Secrets Manager read that fails
  or a signer that cannot sign is the Egress_Controller unable to serve this attempt, and R12.8's
  answer to that is denial rather than an unsigned or untokened request going upstream;
- a terminated tier that injects nothing denies rather than relaying plaintext. No such tier exists —
  :data:`INJECTION` gives both terminated tiers an injection and gives Tier 3 none — but the branch
  is a denial so that adding one could not quietly open a plaintext relay.

## The reason vocabulary is reused, not extended

Every denial carries a :class:`~control_plane.allocation.DenialReason`. This module defines no reason
of its own, for the reason :mod:`egress.decision` gives: the set is closed because R11.12's
circumvention subset is drawn from it, and a reason invented here would be a reason the quarantine
classification has never heard of.

What the terminated tiers add over :mod:`egress.decision` is that they see enough to *classify* three
of the circumventing shapes, which the policy comparison alone cannot:

- :attr:`~control_plane.allocation.DenialReason.ALIAS_SPOOFED` — the `Host` header names a permitted
  alias other than the one the connection was made to.
- :attr:`~control_plane.allocation.DenialReason.HOST_SNI_MISMATCH` — the `Host` header disagrees with
  the name negotiated in the handshake, and the name it gives is not itself an interception point.
- :attr:`~control_plane.allocation.DenialReason.IP_LITERAL_FOR_ALIASED_UPSTREAM` — the `Host` header
  is a bare address where the destination is reachable only under its alias.

:attr:`~control_plane.allocation.DenialReason.PROXY_MANAGEMENT_INTERFACE` needs only the connection
target, so all three tiers classify it, and it is checked **before** the policy comparison: a
management authority is precisely a destination no policy declares, so the ordinary comparison would
reach it first and report the less specific reason.

None of the other three classifications is available at Tier 3, and that is the honest consequence of
its visibility rather than a gap to be filled. A tunnel carries no `Host` header to disagree with an
SNI the proxy never sees, and whether a bare address stands in for an aliased upstream is a question
about a name the tunnel was not given.

## Nothing here logs, and no attempted destination travels outward

:class:`Denied` carries a reason and, when one had been chosen, a tier. It carries no destination, no
host, no path and no header, and no denial reason is composed from caller text — the discipline
:mod:`egress.decision` documents, for the same reason: the authority and the path are chosen by
Untrusted_Code, so a copy of either inside a reason string is attacker-chosen content on its way into
a metric dimension and a log line. The module emits no log record at all, at any level.

The blocked-attempt audit record R12.3 requires does reproduce the attempted destination exactly, and
the classification that routes the circumvention subset to quarantine (R11.12) is beside it. Both are
task 10.5's, built from the request the caller still holds; what this module hands them is a reason
already in the vocabulary they use.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol, assert_never, runtime_checkable

from control_plane.allocation.quarantine import DenialReason
from egress.decision import Decision, decide
from egress.policy import (
    EGRESS_TLS_PORT,
    Destination,
    DestinationEntry,
    DestinationForm,
    EgressPolicy,
    PermittedDestination,
    PolicyDocumentError,
    Tier,
)
from egress.reader import CachedPolicyReader

__all__ = [
    "ENFORCEABLE_RULES",
    "HANDLER_RULES",
    "INJECTION",
    "MAX_PATH_LENGTH",
    "OUTCOME_FORMS",
    "REQUEST_FORMS",
    "REQUEST_OBSERVATION_FIELDS",
    "RESIGNED_REQUEST_HEADERS",
    "RESPONSE_OBSERVATIONS",
    "RULE_OBSERVATIONS",
    "TIER_OBSERVATIONS",
    "Denied",
    "EnforcementRule",
    "Forwarded",
    "Injection",
    "InterceptedRequest",
    "InterceptionOutcome",
    "InterceptionSettings",
    "Interceptor",
    "Observation",
    "TerminatedRequest",
    "Tunnelled",
    "TunnelledConnection",
    "UpstreamCredentialUnavailable",
    "UpstreamSigner",
    "UpstreamTokens",
]

#: The request headers Tier 1 discards before re-signing. The design's sentence is "the proxy discards
#: the inbound `Authorization` header and re-signs the request with its own task role"; the other
#: three are the rest of what a SigV4 signature travels in. The Sandbox holds placeholder credentials,
#: so anything it signed is worthless, and a header the signature covers that the *Sandbox* chose is a
#: header it could use to pin a signature the proxy did not compute. Discarding the set is the design's
#: sentence applied to the whole mechanism rather than to one header of it.
RESIGNED_REQUEST_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
    }
)

#: A request path longer than this is refused rather than compared. Bounded for the reason
#: `egress.policy` bounds a hostname: an over-long value gets a *defined* answer.
MAX_PATH_LENGTH: Final = 4096

_HOST_HEADER: Final = "host"

#: The characters a request path may contain. An allow-list, matching `egress.policy`'s stance on
#: hostnames: the set of things that should not appear in a path is not one anybody enumerates
#: correctly. Percent-encoding is excluded rather than decoded, so `/%64ebug` is refused rather than
#: raced against the denylist — decoding is where a path comparison and its author come to disagree.
_PATH_CHARACTERS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/+,;=:@$&'()*!"
)


class Observation(enum.StrEnum):
    """What a proxy can observe about one outbound attempt, for the purpose of enforcing something.

    Deliberately not a catalogue of everything that passes through a proxy: the request body and the
    response body are absent because no rule here examines either, and naming them would imply a check
    this design does not make. See the module docstring.
    """

    #: The authority the Sandbox asked the proxy to reach: the `CONNECT` target on a tunnel, the name
    #: negotiated in the handshake on a tier that terminates TLS. Every tier holds this one.
    CONNECTION_TARGET = "connection-target"
    #: The server name presented at the handshake, as a value distinct from whatever the request then
    #: claims. Only a tier that terminates TLS holds both halves of that comparison.
    TLS_SERVER_NAME = "tls-server-name"
    #: The request method.
    REQUEST_METHOD = "request-method"
    #: The request target path.
    REQUEST_PATH = "request-path"
    #: The request headers as the Sandbox sent them.
    REQUEST_HEADERS = "request-headers"
    #: The upstream response headers, before the Sandbox sees them.
    RESPONSE_HEADERS = "response-headers"


class EnforcementRule(enum.StrEnum):
    """One check or rewrite a tier applies, with the observations it needs in :data:`RULE_OBSERVATIONS`.

    A rule either denies the attempt or rewrites a header set, and the enum does not separate the two:
    what it exists to express is *observability*, and both kinds need the same thing — a view of the
    attempt the tier may not have.
    """

    #: Deny unless the connection target resolves to an entry in the policy (R12.2, R12.8). Every tier
    #: enforces this, through :func:`~egress.decision.decide` and nothing else.
    PERMITTED_DESTINATION = "permitted-destination"
    #: Deny an attempt on the proxy's own management authority — probing the enforcement point rather
    #: than a destination beyond it.
    MANAGEMENT_INTERFACE_REFUSED = "management-interface-refused"
    #: Deny when the `Host` header disagrees with the name negotiated at the handshake.
    HOST_MATCHES_SERVER_NAME = "host-matches-server-name"
    #: Deny when the `Host` header names an interception point other than the one connected to, or a
    #: bare address where only the alias is reachable.
    HOST_IS_THE_RESOLVED_ALIAS = "host-is-the-resolved-alias"
    #: Deny a path on this destination's echo denylist, and any path beneath it. The design's second
    #: mitigation for the response-echo residual.
    ECHO_PRONE_PATH_REFUSED = "echo-prone-path-refused"
    #: Discard the credential-bearing request headers the Sandbox sent, so nothing it chose reaches
    #: the upstream leg in their place.
    INBOUND_AUTHORIZATION_DISCARDED = "inbound-authorization-discarded"
    #: Remove the injected header names, and this destination's configured strip list, from the
    #: response before the Sandbox sees it. The design's first mitigation for the same residual.
    RESPONSE_HEADERS_STRIPPED = "response-headers-stripped"


class Injection(enum.StrEnum):
    """What a tier puts on the upstream leg. Total over :class:`~egress.policy.Tier`, Tier 3 has none."""

    #: Tier 1: re-sign with the proxy task role, having discarded what the Sandbox sent.
    RESIGN_AS_TASK_ROLE = "resign-as-task-role"
    #: Tier 2: the static upstream token, read from Secrets Manager.
    UPSTREAM_TOKEN = "upstream-token"  # nosec B105 — test fixture
    #: Tier 3: nothing, and nothing is possible.
    NONE = "none"


RULE_OBSERVATIONS: Final[Mapping[EnforcementRule, frozenset[Observation]]] = {
    EnforcementRule.PERMITTED_DESTINATION: frozenset({Observation.CONNECTION_TARGET}),
    EnforcementRule.MANAGEMENT_INTERFACE_REFUSED: frozenset(
        {Observation.CONNECTION_TARGET}
    ),
    EnforcementRule.HOST_MATCHES_SERVER_NAME: frozenset(
        {Observation.TLS_SERVER_NAME, Observation.REQUEST_HEADERS}
    ),
    EnforcementRule.HOST_IS_THE_RESOLVED_ALIAS: frozenset(
        {Observation.CONNECTION_TARGET, Observation.REQUEST_HEADERS}
    ),
    EnforcementRule.ECHO_PRONE_PATH_REFUSED: frozenset({Observation.REQUEST_PATH}),
    EnforcementRule.INBOUND_AUTHORIZATION_DISCARDED: frozenset(
        {Observation.REQUEST_HEADERS}
    ),
    EnforcementRule.RESPONSE_HEADERS_STRIPPED: frozenset(
        {Observation.RESPONSE_HEADERS}
    ),
}

if set(RULE_OBSERVATIONS) != set(
    EnforcementRule
):  # pragma: no cover - import-time invariant
    _unspecified = sorted(
        rule.value for rule in EnforcementRule if rule not in RULE_OBSERVATIONS
    )
    raise AssertionError(
        f"enforcement rules with no declared observations: {_unspecified}"
    )


@dataclass(frozen=True, slots=True)
class TerminatedRequest:
    """One request on a tier that terminates TLS at its own alias: Tier 1 or Tier 2.

    Its fields *are* what these tiers can observe of a request, tied to :class:`Observation` by
    :data:`REQUEST_OBSERVATION_FIELDS` and asserted at import. There is no body field: no rule
    examines a body, and a field nothing reads would suggest otherwise.
    """

    #: The name negotiated at the handshake — the alias the Sandbox connected to.
    server_name: str
    #: The `Host` header the request then claims. A separate field because the disagreement between
    #: the two is the whole of :attr:`EnforcementRule.HOST_MATCHES_SERVER_NAME`.
    host_header: str
    method: str
    path: str
    #: The remaining request headers as the Sandbox sent them. `Host` is `host_header`, so a `Host` in
    #: here is dropped rather than read.
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class TunnelledConnection:
    """One `CONNECT` tunnel: the authority asked for, and nothing else there is to know.

    TLS is end to end. The absence of every other field is the design's Tier 3 claim expressed as a
    type, and it is why :data:`ENFORCEABLE_RULES` gives that tier two rules rather than seven.
    """

    connect_target: str


InterceptedRequest = TerminatedRequest | TunnelledConnection


@dataclass(frozen=True, slots=True)
class Forwarded:
    """A permitted attempt on a terminated tier: what goes upstream, and what comes back.

    `upstream_headers` is the leg the Sandbox has no access to, and is where the injected credential
    is. :meth:`response_to_sandbox` is the return path, and the existence of that method on this type
    and not on :class:`Tunnelled` is what gives the terminated tiers
    :attr:`Observation.RESPONSE_HEADERS`.
    """

    tier: Tier
    destination_set: str
    upstream_host: str
    injection: Injection
    upstream_headers: Mapping[str, str]
    #: Lowercased, because a header name is case-insensitive and the strip has to hold whichever case
    #: the upstream used.
    injected_header_names: frozenset[str]
    strip_response_headers: frozenset[str]

    def response_to_sandbox(
        self, upstream_response_headers: Mapping[str, str]
    ) -> dict[str, str]:
        """The response headers the Sandbox sees: the strip list applied, case-insensitively.

        Not a mitigation for a reflecting *body* — nothing here reads a body. The module docstring
        says what that leaves accepted.
        """
        return {
            name: value
            for name, value in upstream_response_headers.items()
            if name.lower() not in self.strip_response_headers
        }


@dataclass(frozen=True, slots=True)
class Tunnelled:
    """A permitted attempt on Tier 3. No headers, because nothing was injected and nothing is seen."""

    destination_set: str
    upstream_host: str
    tier: Tier = Tier.CONNECT_TUNNEL
    injection: Injection = Injection.NONE


@dataclass(frozen=True, slots=True)
class Denied:
    """A refused attempt: a reason from the closed set, and the tier if one had been chosen.

    Carries no destination, no path and no header. `tier` is `None` when the attempt was refused
    before a destination resolved to one, which is every denial the policy comparison itself makes.
    """

    reason: DenialReason
    tier: Tier | None = None


InterceptionOutcome = Forwarded | Tunnelled | Denied


#: Which attribute of each request form carries each observation. The tie between a declared
#: visibility and the type a handler is actually given: asserted below against
#: :func:`dataclasses.fields` in both directions, so neither a new field nor a new observation can be
#: added on its own.
REQUEST_OBSERVATION_FIELDS: Final[
    Mapping[
        type[TerminatedRequest | TunnelledConnection],
        Mapping[Observation, frozenset[str]],
    ]
] = {
    TerminatedRequest: {
        Observation.CONNECTION_TARGET: frozenset({"server_name"}),
        Observation.TLS_SERVER_NAME: frozenset({"server_name"}),
        Observation.REQUEST_METHOD: frozenset({"method"}),
        Observation.REQUEST_PATH: frozenset({"path"}),
        # Two fields, because the `Host` header is held apart from the rest so that the
        # host-against-server-name comparison has two values to compare.
        Observation.REQUEST_HEADERS: frozenset({"host_header", "headers"}),
    },
    TunnelledConnection: {
        Observation.CONNECTION_TARGET: frozenset({"connect_target"}),
    },
}

#: What a tier observes of the *response* rather than of the request. Held by whichever tiers produce
#: a :class:`Forwarded`, because that is the only outcome that can rewrite a response.
RESPONSE_OBSERVATIONS: Final[frozenset[Observation]] = frozenset(
    {Observation.RESPONSE_HEADERS}
)

REQUEST_FORMS: Final[Mapping[Tier, type[TerminatedRequest | TunnelledConnection]]] = {
    Tier.SIGV4_RESIGNING: TerminatedRequest,
    Tier.TOKEN_INJECTION: TerminatedRequest,
    Tier.CONNECT_TUNNEL: TunnelledConnection,
}

OUTCOME_FORMS: Final[Mapping[Tier, type[Forwarded | Tunnelled]]] = {
    Tier.SIGV4_RESIGNING: Forwarded,
    Tier.TOKEN_INJECTION: Forwarded,
    Tier.CONNECT_TUNNEL: Tunnelled,
}

INJECTION: Final[Mapping[Tier, Injection]] = {
    Tier.SIGV4_RESIGNING: Injection.RESIGN_AS_TASK_ROLE,
    Tier.TOKEN_INJECTION: Injection.UPSTREAM_TOKEN,
    Tier.CONNECT_TUNNEL: Injection.NONE,
}

for _table, _what in (
    (REQUEST_FORMS, "request form"),
    (OUTCOME_FORMS, "outcome form"),
    (INJECTION, "injection"),
):
    if set(_table) != set(Tier):  # pragma: no cover - import-time invariant
        _undeclared = sorted(tier.name for tier in Tier if tier not in _table)
        raise AssertionError(f"tiers with no declared {_what}: {_undeclared}")

for _form, _observed in REQUEST_OBSERVATION_FIELDS.items():
    _declared = {name for names in _observed.values() for name in names}
    _actual = {field.name for field in dataclasses.fields(_form)}
    if _declared != _actual:  # pragma: no cover - import-time invariant
        raise AssertionError(
            f"{_form.__name__} carries {sorted(_actual)} but its observations name "
            f"{sorted(_declared)}; a field with no observation is a view nothing declares, and an "
            f"observation with no field is a view nothing holds"
        )

#: Derived from the types a tier works with rather than authored: the observations its request form
#: carries, plus the response observations when its outcome can rewrite a response.
TIER_OBSERVATIONS: Final[Mapping[Tier, frozenset[Observation]]] = {
    tier: frozenset(REQUEST_OBSERVATION_FIELDS[REQUEST_FORMS[tier]])
    | (RESPONSE_OBSERVATIONS if OUTCOME_FORMS[tier] is Forwarded else frozenset())
    for tier in Tier
}

#: Derived, never authored: a tier enforces exactly the rules whose required observations it holds.
#: This is the mapping that makes "a tier cannot be asked to enforce a rule it cannot see" arithmetic
#: rather than review.
ENFORCEABLE_RULES: Final[Mapping[Tier, frozenset[EnforcementRule]]] = {
    tier: frozenset(
        rule for rule, required in RULE_OBSERVATIONS.items() if required <= observations
    )
    for tier, observations in TIER_OBSERVATIONS.items()
}

_UNENFORCEABLE: Final[frozenset[EnforcementRule]] = frozenset(
    EnforcementRule
) - frozenset(rule for rules in ENFORCEABLE_RULES.values() for rule in rules)

if _UNENFORCEABLE:  # pragma: no cover - import-time invariant
    raise AssertionError(
        "enforcement rules no tier can enforce, so they are enforced nowhere: "
        f"{sorted(rule.value for rule in _UNENFORCEABLE)}"
    )


#: What the terminated-request handler enforces. Declared here and asserted against the derived set
#: below, so the handler and the arithmetic cannot drift apart.
_TERMINATED_RULES: Final[frozenset[EnforcementRule]] = frozenset(
    {
        EnforcementRule.PERMITTED_DESTINATION,
        EnforcementRule.MANAGEMENT_INTERFACE_REFUSED,
        EnforcementRule.HOST_MATCHES_SERVER_NAME,
        EnforcementRule.HOST_IS_THE_RESOLVED_ALIAS,
        EnforcementRule.ECHO_PRONE_PATH_REFUSED,
        EnforcementRule.INBOUND_AUTHORIZATION_DISCARDED,
        EnforcementRule.RESPONSE_HEADERS_STRIPPED,
    }
)

#: What the tunnel handler enforces: the two rules the connection target alone supports.
_TUNNELLED_RULES: Final[frozenset[EnforcementRule]] = frozenset(
    {
        EnforcementRule.PERMITTED_DESTINATION,
        EnforcementRule.MANAGEMENT_INTERFACE_REFUSED,
    }
)

HANDLER_RULES: Final[
    Mapping[type[TerminatedRequest | TunnelledConnection], frozenset[EnforcementRule]]
] = {
    TerminatedRequest: _TERMINATED_RULES,
    TunnelledConnection: _TUNNELLED_RULES,
}

_UNDERENFORCED: Final[tuple[str, ...]] = tuple(
    tier.name
    for tier in Tier
    if HANDLER_RULES[REQUEST_FORMS[tier]] != ENFORCEABLE_RULES[tier]
)

if _UNDERENFORCED:  # pragma: no cover - import-time invariant
    raise AssertionError(
        "tiers whose handler enforces something other than the rules their observations support: "
        f"{sorted(_UNDERENFORCED)}"
    )


class UpstreamCredentialUnavailable(Exception):
    """The credential a tier must inject could not be obtained, so the attempt is denied (R12.8).

    Raised by the two seams below and absorbed by :meth:`Interceptor.intercept`, which turns it into
    :attr:`~control_plane.allocation.DenialReason.CONTROLLER_UNREACHABLE`: from the Sandbox's side a
    proxy that cannot reach Secrets Manager and a proxy that cannot be reached at all are the same
    condition, and denial is the answer to both.

    `detail` is for an operator reading a proxy task's log. Like
    :class:`~egress.policy.PolicyDocumentError` it must carry operator-authored text only; nothing in
    this module composes it, and nothing in this module reads it.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"the upstream credential could not be obtained: {detail}")
        self.detail = detail


@runtime_checkable
class UpstreamSigner(Protocol):
    """Tier 1's re-signing, with the proxy task role and never with anything the Sandbox holds.

    A seam rather than an implementation, for the reason :class:`~egress.reader.PolicySource` gives: a
    concrete signer here would be this package asserting a credential provider and a signing library
    the deployment owns. The offline suite drives it with a double, so the tier's behaviour is
    assertable without a network and without a role.
    """

    def authorization(
        self, *, sign_as: str, upstream_host: str, method: str, path: str
    ) -> str:
        """The `Authorization` header value for the re-signed request.

        Raises:
            UpstreamCredentialUnavailable: the task role's credentials could not be obtained.
        """
        ...


@runtime_checkable
class UpstreamTokens(Protocol):
    """Tier 2's static token, read from Secrets Manager by the proxy task role.

    The Sandbox execution role carries an explicit `Deny` on reading these secrets (R12.5), which the
    Control_Plane provisions and asserts; this seam is only how the *proxy* obtains what it injects.
    """

    def token(self, secret_arn: str) -> str:
        """The token to inject, for the secret this entry names.

        Raises:
            UpstreamCredentialUnavailable: the secret could not be read.
        """
        ...


@dataclass(frozen=True, slots=True)
class InterceptionSettings:
    """The proxy configuration the tiers apply beyond the destination policy.

    The design's network-connector table lists "Response strip lists, echo denylists" as proxy
    configuration in AppConfig, reaching running Sandboxes within the policy cache TTL, and the
    management authorities are the same kind of value. They live here rather than in
    :class:`~egress.policy.EgressPolicy` because that document's schema is closed against unknown keys
    and because declaring *what* a Sandbox may reach is not the job of configuring *how* the proxy
    serves it. The per-destination response strip list is already in the document, on the entry, and is
    read from there.

    Build through :meth:`build`, which puts both sides through the one normaliser this package has.
    """

    #: Canonical hosts that are the proxy's own management interface. Never a permitted destination.
    management_authorities: frozenset[str]
    #: Canonical permitted host → the echo-prone path prefixes refused for it.
    echo_denylist: Mapping[str, frozenset[str]]

    @classmethod
    def build(
        cls,
        *,
        management_authorities: Iterable[str] = (),
        echo_denylist: Mapping[str, Iterable[str]] | None = None,
    ) -> InterceptionSettings:
        """Normalise operator-authored configuration, refusing what could never match.

        Raises:
            PolicyDocumentError: an authority does not normalise to a matchable host, or a path is not
                one this comparison can hold. Reused rather than a second exception type, because it
                is the same class of mistake in the same AppConfig configuration — a value whose
                author believes it does something and it does not.
        """
        return cls(
            management_authorities=frozenset(
                _configured_host("managementAuthorities", authority)
                for authority in management_authorities
            ),
            echo_denylist={
                _configured_host("echoDenylist", host): frozenset(
                    _configured_path(f"echoDenylist.{host}", path) for path in paths
                )
                for host, paths in (echo_denylist or {}).items()
            },
        )


class Interceptor:
    """Applies the tier the policy names to one intercepted attempt.

    Holds the policy reader, the proxy configuration and the two credential seams. Not a dataclass,
    for the reason :class:`~egress.reader.CachedPolicyReader` is not one: it composes a component with
    mutable cache state.
    """

    def __init__(
        self,
        *,
        reader: CachedPolicyReader,
        settings: InterceptionSettings,
        signer: UpstreamSigner,
        tokens: UpstreamTokens,
    ) -> None:
        self._reader = reader
        self._settings = settings
        self._signer = signer
        self._tokens = tokens

    def intercept(self, request: InterceptedRequest) -> InterceptionOutcome:
        """Permit `request` through the tier its destination is served by, or deny it.

        Total: every request yields an outcome, and every outcome that is not a forward or a tunnel is
        a denial carrying a reason from the closed set.
        """
        destination = Destination.parse(_connection_target(request))
        if (
            destination.host
            and destination.host in self._settings.management_authorities
        ):
            # Before the policy comparison, which would otherwise report the less specific reason: the
            # management interface is exactly a destination no policy declares.
            return Denied(reason=DenialReason.PROXY_MANAGEMENT_INTERFACE)
        policy = self._reader.policy()
        resolved = _resolve(decide(policy, destination))
        if isinstance(resolved, DenialReason):
            return Denied(reason=resolved)
        if not isinstance(request, REQUEST_FORMS[resolved.tier]):
            # The destination is permitted, but not in the form it arrived in: a tunnel asking for an
            # aliased destination withholds the plaintext the alias exists to obtain, and a terminated
            # request for a tunnelled one claims a TLS session that tier does not hold. No permitted
            # destination-and-tier pair describes either.
            return Denied(
                reason=DenialReason.UNDECLARED_DESTINATION, tier=resolved.tier
            )
        match request:
            case TunnelledConnection():
                return _tunnel(resolved)
            case TerminatedRequest():
                return self._terminated(request, resolved, policy)
            case _ as unhandled:  # pragma: no cover - mypy proves this unreachable
                assert_never(unhandled)

    def _terminated(
        self,
        request: TerminatedRequest,
        resolved: PermittedDestination,
        policy: EgressPolicy | None,
    ) -> InterceptionOutcome:
        """Tier 1 and Tier 2: classify the request, then inject on the upstream leg."""
        refusal = _host_refusal(request, resolved.entry, policy)
        if refusal is None:
            refusal = _path_refusal(request.path, resolved.entry, self._settings)
        if refusal is not None:
            return Denied(reason=refusal, tier=resolved.tier)
        try:
            return self._inject(request, resolved)
        except UpstreamCredentialUnavailable:
            # An unsigned or untokened request must not go upstream, and a credential the proxy cannot
            # obtain is the Egress_Controller unable to serve this attempt (R12.8). The exception's
            # own detail is not read: nothing this module returns carries free text.
            return Denied(
                reason=DenialReason.CONTROLLER_UNREACHABLE, tier=resolved.tier
            )

    def _inject(
        self, request: TerminatedRequest, resolved: PermittedDestination
    ) -> InterceptionOutcome:
        """Build the upstream leg for a permitted terminated request.

        Raises:
            UpstreamCredentialUnavailable: propagated from a seam, and denied by the caller.
        """
        entry = resolved.entry
        upstream_host = entry.upstream_host or entry.permitted_host
        injection = INJECTION[resolved.tier]
        match injection:
            case Injection.RESIGN_AS_TASK_ROLE:
                injected = {
                    "Authorization": self._signer.authorization(
                        sign_as=entry.sign_as or "",
                        upstream_host=upstream_host,
                        method=request.method,
                        path=request.path,
                    )
                }
                # Every header a SigV4 signature travels in, not only the one the Sandbox filled.
                discarded = RESIGNED_REQUEST_HEADERS
            case Injection.UPSTREAM_TOKEN:
                header = entry.inject_header or ""
                injected = {header: self._tokens.token(entry.secret_arn or "")}
                # The Sandbox's own value for the injected header is discarded as well as replaced: a
                # request that presets it must not have its value reach the upstream leg under a
                # spelling that differs only in case.
                discarded = frozenset({header.lower()})
            case Injection.NONE:
                # No terminated tier injects nothing. If one were added this denies rather than
                # relaying the Sandbox's plaintext request to an upstream unchanged.
                return Denied(
                    reason=DenialReason.UNDECLARED_DESTINATION, tier=resolved.tier
                )
            case _ as unhandled:  # pragma: no cover - mypy proves this unreachable
                assert_never(unhandled)
        injected_names = frozenset(name.lower() for name in injected)
        upstream_headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in discarded
            and name.lower() not in injected_names
            and name.lower() != _HOST_HEADER
        }
        upstream_headers["Host"] = upstream_host
        upstream_headers.update(injected)
        return Forwarded(
            tier=resolved.tier,
            destination_set=resolved.destination_set,
            upstream_host=upstream_host,
            injection=injection,
            upstream_headers=upstream_headers,
            injected_header_names=injected_names,
            strip_response_headers=injected_names
            | frozenset(entry.strip_response_headers),
        )


def _connection_target(request: InterceptedRequest) -> str:
    """The authority the Sandbox asked the proxy to reach, whichever form the attempt arrived in."""
    match request:
        case TunnelledConnection():
            return request.connect_target
        case TerminatedRequest():
            return request.server_name
        case _ as unhandled:  # pragma: no cover - mypy proves this unreachable
            assert_never(unhandled)


def _resolve(decision: Decision) -> PermittedDestination | DenialReason:
    """Re-narrow a :class:`~egress.decision.Decision` to the permit it names, or to its reason.

    :class:`~egress.decision.Decision` checks the invariant that a permit names a set, a tier and an
    entry, so the second branch is unreachable through its constructors. It denies rather than raising
    anyway: a decision shape this cannot read must not become a forward.
    """
    if (
        decision.permitted
        and decision.destination_set is not None
        and decision.tier is not None
        and decision.entry is not None
    ):
        return PermittedDestination(
            destination_set=decision.destination_set,
            tier=decision.tier,
            entry=decision.entry,
        )
    return (
        decision.reason
        if decision.reason is not None
        else DenialReason.UNDECLARED_DESTINATION
    )


def _tunnel(resolved: PermittedDestination) -> InterceptionOutcome:
    """Tier 3: the tunnel is opened to the permitted authority, with nothing added to it."""
    entry = resolved.entry
    return Tunnelled(
        destination_set=resolved.destination_set,
        upstream_host=entry.upstream_host or entry.permitted_host,
    )


def _host_refusal(
    request: TerminatedRequest, entry: DestinationEntry, policy: EgressPolicy | None
) -> DenialReason | None:
    """Classify the `Host` header against the alias the connection was made to, or accept it.

    The order runs from the most specific classification to the least, because each of the three
    mismatch reasons is a *circumvention* reason (R11.12) and an operator reading a quarantine needs
    the shape that actually occurred. A `Host` header that cannot be read at all is the ordinary
    denial: a malformed request is not evidence that Untrusted_Code tried to get out.
    """
    claimed = Destination.parse(request.host_header)
    if not claimed.host:
        return DenialReason.UNDECLARED_DESTINATION
    connected = Destination.parse(request.server_name)
    if claimed.host == connected.host and claimed.port == connected.port:
        return None
    if entry.alias is not None and claimed.form in {
        DestinationForm.IPV4_LITERAL,
        DestinationForm.IPV6_LITERAL,
    }:
        return DenialReason.IP_LITERAL_FOR_ALIASED_UPSTREAM
    if policy is not None and policy.permitted_for(claimed) is not None:
        # The name it gives is itself an interception point, which is a permitted alias presented for
        # a destination other than the one behind it.
        return DenialReason.ALIAS_SPOOFED
    return DenialReason.HOST_SNI_MISMATCH


def _path_refusal(
    path: str, entry: DestinationEntry, settings: InterceptionSettings
) -> DenialReason | None:
    """Refuse an unreadable path, and one on this destination's echo denylist.

    Both are the ordinary denial rather than a circumvention reason. Fetching a diagnostic endpoint
    that reflects request headers is how the response-echo residual is exercised, and it may well be
    deliberate — but R11.12's subset is about defeating the *destination* policy, and quarantining a
    Sandbox for one request to a path an operator listed would make that subset mean something the
    design does not say it means.
    """
    normalised = _normalised_path(path)
    if normalised is None:
        return DenialReason.UNDECLARED_DESTINATION
    denied = settings.echo_denylist.get(entry.permitted_host, frozenset())
    if any(_is_under(normalised, prefix) for prefix in denied):
        return DenialReason.UNDECLARED_DESTINATION
    return None


def _is_under(path: str, prefix: str) -> bool:
    """Whether `path` is `prefix` or lies beneath it, at a segment boundary.

    Segment-bounded rather than a bare `startswith`, so a denylisted `/debug` refuses `/debug/headers`
    without also refusing `/debugger`, which is a different resource and would be an operator's
    listing reaching further than they wrote.
    """
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _normalised_path(path: str) -> str | None:
    """A request path this comparison can hold, or `None`.

    Nothing is repaired and nothing is decoded; see :data:`_PATH_CHARACTERS`. A query string is not
    part of a path, so a `?` or a `#` here means the caller handed over a target of a shape this
    function was not given, and the answer is `None` rather than a guess at where the path ended.
    """
    if not path.startswith("/") or len(path) > MAX_PATH_LENGTH:
        return None
    if not path.isascii() or not set(path) <= _PATH_CHARACTERS:
        return None
    if ".." in path or "//" in path:
        return None
    return path if path == "/" else path.rstrip("/")


def _configured_host(where: str, value: str) -> str:
    """One operator-authored authority, normalised by the one normaliser this package has."""
    destination = Destination.parse(value)
    if destination.form in {DestinationForm.UNPARSABLE, DestinationForm.NON_ASCII_NAME}:
        raise PolicyDocumentError(
            where,
            f"{value!r} does not normalise to a host any attempt could match, so configuring it "
            f"does nothing",
        )
    if destination.port != EGRESS_TLS_PORT:
        raise PolicyDocumentError(
            where,
            f"{value!r} names a port; an attempt reaches the proxy on {EGRESS_TLS_PORT} alone, so a "
            f"port here would be compared against nothing",
        )
    return destination.host


def _configured_path(where: str, value: str) -> str:
    """One operator-authored path prefix, held to the same reading as a request path."""
    normalised = _normalised_path(value)
    if normalised is None:
        raise PolicyDocumentError(
            where,
            f"{value!r} is not a path this comparison can hold, so no request could ever match it",
        )
    return normalised
