# kiro-classification: public
"""The Egress_Controller's policy: what a Sandbox may reach, and what happens when it may not.

R12.2 restricts Sandbox outbound traffic to a configured set of permitted destinations and R12.8
requires denial rather than permission when the Egress_Controller cannot be reached. Those two
sentences are one decision function over one document, and this package is that pair:

- :mod:`egress.policy` — the document the design fixes, `defaultAction` included, and the
  normalisation both an authored alias and an attempted destination pass through.
- :mod:`egress.decision` — the pure, total decision function, with its two branch tables asserted
  total at import.
- :mod:`egress.reader` — the per-request read and the configured cache TTL that bounds how long a
  revoked destination stays permitted.

**Fail-closed lives in two places and this is the smaller one.** The design's structural answer to
R12.8 is the absence of an alternative route: an egress VPC with no internet gateway and no NAT
gateway, a security group reaching the proxy load balancer alone, a DNS Firewall that answers an
unlisted name with a block, and a load balancer with no healthy target when the fleet is down. That
half is deployment topology and belongs to the IaC_Package. What this package adds is that no *policy*
value permits an undeclared destination and no unreadable policy permits anything at all, so a
configuration mistake cannot undo what the topology arranges.

- :mod:`egress.interception` — the three interception tiers, each one's visibility derived from the
  types it works with, the injection each performs on the upstream leg, and the response-header strip
  list and echo denylist that mitigate the response-echo residual.

**What is deliberately not here.** Neither the blocked-attempt audit record nor the classification that
routes the circumvention subset to quarantine is here; the denial reasons those use are
:class:`~control_plane.allocation.DenialReason`, which this package imports rather than restates. The
named permitted-destination configurations (`bedrock-runtime`, `public-package-registries`,
`gpu-target-<name>`), the GPU delegation surface, the Family B Sandbox identity and the connector
generation blue/green each have their own task. Every one of them is data or behaviour *above* this
document, which is the point of the design's separation of the fixed pipe from the mutable policy.
"""

from egress.decision import (
    DEFAULT_ACTION_DENIALS,
    FORM_MATCH_RULES,
    Decision,
    MatchRule,
    decide,
)
from egress.interception import (
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
    Denied,
    EnforcementRule,
    Forwarded,
    Injection,
    InterceptedRequest,
    InterceptionOutcome,
    InterceptionSettings,
    Interceptor,
    Observation,
    TerminatedRequest,
    Tunnelled,
    TunnelledConnection,
    UpstreamCredentialUnavailable,
    UpstreamSigner,
    UpstreamTokens,
)
from egress.policy import (
    EGRESS_TLS_PORT,
    MAX_HOST_LENGTH,
    MAX_LABEL_LENGTH,
    DefaultAction,
    Destination,
    DestinationEntry,
    DestinationForm,
    DestinationSet,
    EgressPolicy,
    PermittedDestination,
    PolicyDocumentError,
    Tier,
)
from egress.reader import (
    MAX_POLICY_CACHE_TTL_SECONDS,
    CachedPolicyReader,
    PolicyCacheSettings,
    PolicySource,
    PolicyUnavailable,
)

__all__ = [
    "DEFAULT_ACTION_DENIALS",
    "EGRESS_TLS_PORT",
    "ENFORCEABLE_RULES",
    "FORM_MATCH_RULES",
    "HANDLER_RULES",
    "INJECTION",
    "MAX_HOST_LENGTH",
    "MAX_LABEL_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_POLICY_CACHE_TTL_SECONDS",
    "OUTCOME_FORMS",
    "REQUEST_FORMS",
    "REQUEST_OBSERVATION_FIELDS",
    "RESIGNED_REQUEST_HEADERS",
    "RESPONSE_OBSERVATIONS",
    "RULE_OBSERVATIONS",
    "TIER_OBSERVATIONS",
    "CachedPolicyReader",
    "Decision",
    "DefaultAction",
    "Denied",
    "Destination",
    "DestinationEntry",
    "DestinationForm",
    "DestinationSet",
    "EgressPolicy",
    "EnforcementRule",
    "Forwarded",
    "Injection",
    "InterceptedRequest",
    "InterceptionOutcome",
    "InterceptionSettings",
    "Interceptor",
    "MatchRule",
    "Observation",
    "PermittedDestination",
    "PolicyCacheSettings",
    "PolicyDocumentError",
    "PolicySource",
    "PolicyUnavailable",
    "TerminatedRequest",
    "Tier",
    "Tunnelled",
    "TunnelledConnection",
    "UpstreamCredentialUnavailable",
    "UpstreamSigner",
    "UpstreamTokens",
    "decide",
]
