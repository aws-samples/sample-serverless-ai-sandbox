# kiro-classification: public
"""The egress policy document, and the destination form the decision function compares against it.

The design's `Egress policy document` section fixes the shape: a `policyVersion`, a
`destinationSets` mapping whose entries carry a tier and an alias, and `defaultAction` fixed to
`deny`. R12.2 restricts Sandbox outbound traffic to a configured set of permitted destinations, and
R12.8 requires denial rather than permission when the Egress_Controller cannot be reached. This
module is the document and the destination; :mod:`egress.decision` is the function over the two, and
:mod:`egress.reader` is the per-request read with the configured cache TTL.

## `defaultAction` is an enum with one member, on purpose

The design's sentence is "the schema has no value that would permit an undeclared destination, so
R12.8's fail-closed behaviour cannot be undone by a policy edit any more than by a routing mistake".
:class:`DefaultAction` has exactly one member and :data:`egress.decision.DEFAULT_ACTION_DENIALS` maps
every member to a :class:`~control_plane.allocation.DenialReason`, asserted total at import. A future
member has to be given a *denial* reason before the build passes, so "no permitting value" is a
mechanised claim rather than a paragraph. A document whose `defaultAction` is anything other than
`deny` is refused rather than coerced: coercing would accept a document that does not mean what its
author wrote.

## One normalisation, applied to both sides

The policy is authored by an operator and the destination is chosen by Untrusted_Code, and the
comparison between them is the whole of R12.2. Any difference between how the two sides are
normalised is a bypass: a destination the comparison treats as `pypi.egress.internal` and an entry
the loader stored as `PyPI.egress.internal.` would fail to match, and the mirror image of that
mistake would match something the operator never declared. So :meth:`Destination.parse` is the only
normaliser in this package, and the loader runs entry aliases through it too. What it does:

- an ASCII-lowercased name, because DNS names are case-insensitive;
- one trailing dot removed, because the fully-qualified form of a name is that name;
- an IP literal replaced by :mod:`ipaddress`'s canonical text, so two spellings of one address are
  one string;
- an explicit port kept, defaulting to 443.

What it deliberately does **not** do is convert a U-label to an A-label. A name containing non-ASCII
characters is classified :attr:`DestinationForm.NON_ASCII_NAME` and matches nothing, so a Sandbox
asking for `café.egress.internal` against an entry spelled `xn--caf-dma.egress.internal` is denied.
That is the fail-closed direction, it keeps IDNA's own failure modes out of a request path whose
answer must be total, and it matches how the allowlist is authored on the other side of the
architecture: a Route 53 Resolver DNS Firewall rule group holds A-labels.

## The port is part of the match, and 443 is the only one

The document's schema carries no port, and the design's topology explains why: the security group on
the connector attachment "permits egress only to the load balancer on 443 and to the interface
endpoints". So an entry may not carry a port, and a destination naming a port other than 443 resolves
to no entry. Ignoring the port instead would have this function permit a destination the network
cannot carry, and — the direction that matters — permit a port no policy declared.

## What is permitted is the alias, not the upstream behind it

For a Tier 1 or Tier 2 entry the Sandbox addresses the *alias*; the upstream host is where the proxy
forwards, on a TLS session the Sandbox has no access to. Permitting the upstream host as well would
hand the Sandbox the aliased destination directly, which is the interception the design's whole
credential-absence argument (R12.4) rests on. A Tier 3 entry has no alias, because a `CONNECT` tunnel
injects nothing and TLS is end to end, so its permitted name is the upstream host itself. Hence
:attr:`DestinationEntry.permitted_host`: the alias when there is one, the upstream host when there is
not, canonical either way.

## Refusals, and why a malformed document is not a permissive one

Every refusal below raises :class:`PolicyDocumentError`, and the reader treats an unreadable document
exactly as it treats an unreachable policy store: no policy, therefore no permitted destination
(R12.8). The refusals are all cases where accepting the document would mean guessing at a
security-relevant intention:

- an unknown key, at any level, because a misspelled `stripResponseHeaders` is a strip list that
  silently does not exist;
- an alias appearing in more than one destination set, because the alias *is* the interception point
  and two sets claiming it disagree about which credential gets injected into it; resolving that by
  ordering would make an operator's choice of set name decide which secret is used;
- a field belonging to a different tier — `injectHeader` on a Tier 3 entry, `signAs` on a Tier 2 one
  — because a tier that cannot honour the field would either ignore it, leaving the operator
  believing a credential is applied, or apply it, contradicting the tier;
- an alias or upstream host that does not normalise to a matchable form, because an entry that can
  never match is an entry whose author believes something is permitted when nothing is.
"""

from __future__ import annotations

import enum
import ipaddress
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "EGRESS_TLS_PORT",
    "MAX_HOST_LENGTH",
    "MAX_LABEL_LENGTH",
    "DefaultAction",
    "Destination",
    "DestinationEntry",
    "DestinationForm",
    "DestinationSet",
    "EgressPolicy",
    "PermittedDestination",
    "PolicyDocumentError",
    "Tier",
]

#: The one port the connector attachment's security group permits to the proxy load balancer. A
#: destination naming any other port resolves to no entry; an entry may not carry a port at all.
EGRESS_TLS_PORT: Final = 443

#: DNS limits, applied so that an over-long name has a *defined* answer rather than an incidental
#: one. Both sides of the comparison pass through the same check, so a name this rejects could not
#: have reached an entry either.
MAX_HOST_LENGTH: Final = 253
MAX_LABEL_LENGTH: Final = 63

#: The characters a name may contain. An allow-list rather than a denylist of the obvious separators,
#: which is the posture `runtime.observability` takes about log fields and for the same reason: the
#: set of things that should not appear in a hostname is not one anybody can enumerate correctly.
_NAME_CHARACTERS: Final = frozenset(string.ascii_lowercase + string.digits + "-_")

_MAX_PORT_DIGITS: Final = 5
_MAX_PORT: Final = 65535


class PolicyDocumentError(Exception):
    """The policy document does not mean one thing, so it is refused rather than interpreted.

    Carries the path to the offending element, because a deployment reading this in a proxy task's
    log needs to know which entry of which destination set to fix. Every value in the message is
    operator-authored: this exception is raised over the *document*, never over a destination
    Untrusted_Code supplied.
    """

    def __init__(self, where: str, detail: str) -> None:
        super().__init__(f"egress policy document at {where}: {detail}")
        self.where = where
        self.detail = detail


class DefaultAction(enum.StrEnum):
    """What the policy does with a destination no entry names. One member, and it denies.

    An enum with a single member rather than a `bool` or a bare constant, so that
    :data:`egress.decision.DEFAULT_ACTION_DENIALS` is a mapping whose totality can be asserted and
    whose codomain is denial reasons only.
    """

    DENY = "deny"


class Tier(enum.IntEnum):
    """The interception tier a destination set is served by. The design names three and no more.

    Integer-valued because the document spells `"tier": 1`. What each tier *does* to a request is
    the interception work; here the tier only decides which fields an entry may carry.
    """

    #: SigV4 re-signing for AWS service destinations: the inbound authorization header is discarded
    #: and the request is re-signed with the proxy task role.
    SIGV4_RESIGNING = 1
    #: An aliased reverse proxy injecting a static token on the upstream leg only.
    TOKEN_INJECTION = 2
    #: A `CONNECT` tunnel. Nothing is injected and nothing is observed but the requested host.
    CONNECT_TUNNEL = 3


class DestinationForm(enum.Enum):
    """What kind of thing the attempted destination is, after normalisation.

    A closed classification, so :data:`egress.decision.FORM_MATCH_RULES` is total over it and no
    destination shape reaches the decision function without a recorded answer. The two forms that
    match nothing are named rather than collapsed into one, because "a name this comparison cannot
    canonicalise" and "not an authority at all" are different facts about the caller's input.
    """

    #: An ASCII DNS name, lowercased, with any trailing dot removed.
    DNS_NAME = "dns-name"
    #: An IPv4 literal in `ipaddress`'s canonical text.
    IPV4_LITERAL = "ipv4-literal"
    #: An IPv6 literal in `ipaddress`'s canonical text, brackets removed.
    IPV6_LITERAL = "ipv6-literal"
    #: A syntactically plausible name carrying non-ASCII characters. Not converted to an A-label, so
    #: it matches nothing; see this module's docstring.
    NON_ASCII_NAME = "non-ascii-name"
    #: Not an authority this comparison can read: an empty host, a malformed port, an unbracketed
    #: address with a port, a control byte, an over-long name.
    UNPARSABLE = "unparsable"


@dataclass(frozen=True, slots=True)
class Destination:
    """One attempted outbound destination, normalised for comparison.

    `host` is empty for every form that matches nothing, because the only use this package has for a
    host is the comparison, and a copy of unmatched caller-supplied text is a copy waiting to be
    logged. Reproducing the attempted destination *exactly* is the audit record's job (R12.3), and it
    has the caller's own bytes to do it with.
    """

    host: str
    port: int
    form: DestinationForm

    @classmethod
    def parse(cls, attempted: str) -> Destination:
        """Normalise `attempted`. Total: every string yields a destination, matchable or not.

        Never raises. The input is chosen by Untrusted_Code, so a shape this cannot read has to be an
        ordinary denial rather than an exception on a request path.
        """
        authority = _split_host_port(attempted)
        if authority is None:
            return cls(host="", port=0, form=DestinationForm.UNPARSABLE)
        host, port = authority
        canonical, form = _canonical_host(host)
        return cls(host=canonical, port=port, form=form)


@dataclass(frozen=True, slots=True)
class DestinationEntry:
    """One permitted destination: what the Sandbox may address, and what the proxy does with it.

    `permitted_host` is the canonical name the comparison uses, and it is derived rather than
    authored — the alias for Tier 1 and Tier 2, the upstream host for Tier 3.
    """

    permitted_host: str
    alias: str | None = None
    upstream_host: str | None = None
    #: Tier 1 only: the service name the proxy signs the re-signed request as.
    sign_as: str | None = None
    #: Tier 2 only: the header the proxy adds on the upstream leg, and where its value comes from.
    inject_header: str | None = None
    secret_arn: str | None = None
    #: Tier 2 only: response headers stripped before the Sandbox sees them, lowercased because a
    #: header name is case-insensitive and the strip has to hold whichever case the upstream used.
    strip_response_headers: tuple[str, ...] = ()
    #: Tier 1 only: whether the upstream leg goes over an interface VPC endpoint.
    via_vpc_endpoint: bool = False


@dataclass(frozen=True, slots=True)
class DestinationSet:
    """A named permitted-destination configuration, served by one tier (R12.6, R5.11)."""

    name: str
    tier: Tier
    entries: tuple[DestinationEntry, ...]


@dataclass(frozen=True, slots=True)
class PermittedDestination:
    """The result of resolving a destination: which set permitted it, at which tier, by which entry."""

    destination_set: str
    tier: Tier
    entry: DestinationEntry


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """A whole policy document, validated on construction.

    Resolution is a scan rather than a prebuilt index. A policy holds a handful of destination sets,
    the scan is over `permitted_host` strings, and the alternative — a mapping computed in
    `__post_init__` and stored on a frozen instance — would buy nothing measurable and would give
    this class a second representation of its own contents to keep consistent.
    """

    policy_version: int
    destination_sets: tuple[DestinationSet, ...]
    default_action: DefaultAction = DefaultAction.DENY

    def __post_init__(self) -> None:
        seen: dict[str, str] = {}
        for destination_set in self.destination_sets:
            for entry in destination_set.entries:
                owner = seen.get(entry.permitted_host)
                if owner is not None:
                    raise PolicyDocumentError(
                        f"destinationSets.{destination_set.name}",
                        f"permits a destination already permitted by {owner!r}, so the two sets "
                        f"disagree about how one interception point is served",
                    )
                seen[entry.permitted_host] = destination_set.name

    def permitted_for(self, destination: Destination) -> PermittedDestination | None:
        """The entry `destination` resolves to, or `None` when the policy names no such destination.

        Pure, and the only comparison in this package. It compares `permitted_host` for equality,
        because both sides were canonicalised by :meth:`Destination.parse`; there is no prefix,
        suffix or wildcard match, so a destination cannot resolve by resembling a permitted one.
        """
        if destination.port != EGRESS_TLS_PORT or not destination.host:
            return None
        for destination_set in self.destination_sets:
            for entry in destination_set.entries:
                if entry.permitted_host == destination.host:
                    return PermittedDestination(
                        destination_set=destination_set.name,
                        tier=destination_set.tier,
                        entry=entry,
                    )
        return None

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> EgressPolicy:
        """Load the design's JSON document shape.

        Raises:
            PolicyDocumentError: the document is not one this schema can read exactly one way.
        """
        _reject_unknown_keys(
            "", document, {"policyVersion", "destinationSets", "defaultAction"}
        )
        version = _required_int("policyVersion", document.get("policyVersion"))
        if version < 1:
            raise PolicyDocumentError(
                "policyVersion",
                f"a published policy is numbered from 1; {version} is indistinguishable from unset",
            )
        action = _required_str("defaultAction", document.get("defaultAction"))
        if action != DefaultAction.DENY.value:
            raise PolicyDocumentError(
                "defaultAction",
                f"{action!r} is not a value of this schema; the only value is "
                f"{DefaultAction.DENY.value!r}, so no edit can permit an undeclared destination",
            )
        sets = document.get("destinationSets")
        if not isinstance(sets, Mapping):
            raise PolicyDocumentError("destinationSets", "must be an object")
        return cls(
            policy_version=version,
            destination_sets=tuple(
                _destination_set(str(name), sets[name]) for name in sets
            ),
            default_action=DefaultAction.DENY,
        )


_INLINE_ENTRY_KEYS: Final = frozenset(
    {
        "alias",
        "upstreamHost",
        "signAs",
        "viaVpcEndpoint",
        "injectHeader",
        "secretArn",
        "stripResponseHeaders",
    }
)

#: Which entry fields each tier may carry. Total over :class:`Tier`, asserted below, so a tier added
#: to the model without a field policy fails the build rather than accepting every field.
_TIER_FIELDS: Final[Mapping[Tier, frozenset[str]]] = {
    Tier.SIGV4_RESIGNING: frozenset(
        {"alias", "upstreamHost", "signAs", "viaVpcEndpoint"}
    ),
    Tier.TOKEN_INJECTION: frozenset(
        {"alias", "upstreamHost", "injectHeader", "secretArn", "stripResponseHeaders"}
    ),
    Tier.CONNECT_TUNNEL: frozenset({"upstreamHost"}),
}

if set(_TIER_FIELDS) != set(Tier):  # pragma: no cover - import-time invariant
    _missing = sorted(tier.name for tier in Tier if tier not in _TIER_FIELDS)
    raise AssertionError(f"tiers with no declared entry fields: {_missing}")

#: The fields each tier *requires*. Tier 1 must name a service to sign as; Tier 2 must name a header
#: and the secret behind it, or it is Tier 3 with an alias; Tier 3 must name the upstream it tunnels
#: to, because it has no alias to be permitted under.
_TIER_REQUIRED: Final[Mapping[Tier, frozenset[str]]] = {
    Tier.SIGV4_RESIGNING: frozenset({"alias", "signAs"}),
    Tier.TOKEN_INJECTION: frozenset(
        {"alias", "upstreamHost", "injectHeader", "secretArn"}
    ),
    Tier.CONNECT_TUNNEL: frozenset({"upstreamHost"}),
}

if set(_TIER_REQUIRED) != set(Tier):  # pragma: no cover - import-time invariant
    _missing = sorted(tier.name for tier in Tier if tier not in _TIER_REQUIRED)
    raise AssertionError(f"tiers with no required entry fields: {_missing}")


def _destination_set(name: str, document: Any) -> DestinationSet:
    """One named destination set, in either the inline single-entry form or the `entries` form."""
    where = f"destinationSets.{name}"
    if not name:
        raise PolicyDocumentError(
            "destinationSets", "a destination set name may not be empty"
        )
    if not isinstance(document, Mapping):
        raise PolicyDocumentError(where, "must be an object")
    _reject_unknown_keys(where, document, _INLINE_ENTRY_KEYS | {"tier", "entries"})
    tier = _tier(where, document.get("tier"))
    inline = _INLINE_ENTRY_KEYS & set(document)
    listed = document.get("entries")
    if listed is not None and inline:
        raise PolicyDocumentError(
            where,
            f"carries both `entries` and the inline entry field(s) {sorted(inline)}, so it "
            f"describes its permitted destinations twice",
        )
    if listed is None:
        return DestinationSet(
            name=name, tier=tier, entries=(_entry(where, tier, document),)
        )
    if not isinstance(listed, Sequence) or isinstance(listed, str | bytes):
        raise PolicyDocumentError(f"{where}.entries", "must be an array")
    if not listed:
        raise PolicyDocumentError(
            f"{where}.entries",
            "is empty; a destination set that permits nothing is a set that should not be declared",
        )
    return DestinationSet(
        name=name,
        tier=tier,
        entries=tuple(
            _entry(f"{where}.entries[{index}]", tier, element)
            for index, element in enumerate(listed)
        ),
    )


def _entry(where: str, tier: Tier, document: Any) -> DestinationEntry:
    """One permitted destination, with the fields its tier admits and no others."""
    if not isinstance(document, Mapping):
        raise PolicyDocumentError(where, "must be an object")
    admitted = _TIER_FIELDS[tier]
    _reject_unknown_keys(where, document, _INLINE_ENTRY_KEYS | {"tier"})
    if "tier" in document and _tier(where, document["tier"]) is not tier:
        raise PolicyDocumentError(
            where, "declares a tier different from the destination set that contains it"
        )
    offered = set(document) - admitted - {"tier"}
    if offered:
        raise PolicyDocumentError(
            where,
            f"carries {sorted(offered)}, which tier {tier.value} cannot honour",
        )
    missing = _TIER_REQUIRED[tier] - set(document)
    if missing:
        raise PolicyDocumentError(
            where, f"tier {tier.value} requires {sorted(missing)}"
        )
    alias = _optional_host(f"{where}.alias", document.get("alias"))
    upstream = _optional_host(f"{where}.upstreamHost", document.get("upstreamHost"))
    permitted = alias if alias is not None else upstream
    if (
        permitted is None
    ):  # pragma: no cover - the required-field check reaches this first
        raise PolicyDocumentError(where, "names no destination a Sandbox could address")
    return DestinationEntry(
        permitted_host=permitted,
        alias=alias,
        upstream_host=upstream,
        sign_as=_optional_str(f"{where}.signAs", document.get("signAs")),
        inject_header=_optional_str(
            f"{where}.injectHeader", document.get("injectHeader")
        ),
        secret_arn=_optional_str(f"{where}.secretArn", document.get("secretArn")),
        strip_response_headers=_header_names(
            f"{where}.stripResponseHeaders", document.get("stripResponseHeaders")
        ),
        via_vpc_endpoint=_optional_bool(
            f"{where}.viaVpcEndpoint", document.get("viaVpcEndpoint")
        ),
    )


def _tier(where: str, value: Any) -> Tier:
    """The tier, which must be one of the three the design names."""
    number = _required_int(f"{where}.tier", value)
    try:
        return Tier(number)
    except ValueError as exc:
        raise PolicyDocumentError(
            f"{where}.tier",
            f"{number} is not an interception tier; the tiers are "
            f"{sorted(tier.value for tier in Tier)}",
        ) from exc


def _reject_unknown_keys(
    where: str, document: Mapping[str, Any], known: Iterable[str]
) -> None:
    """Refuse a key this schema does not define, wherever it appears."""
    unknown = sorted(set(document) - set(known))
    if unknown:
        raise PolicyDocumentError(
            where or "<document>",
            f"carries key(s) {unknown} this schema does not define; a misspelled field is a "
            f"field that silently does nothing",
        )


def _required_int(where: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyDocumentError(where, "must be an integer")
    return value


def _required_str(where: str, value: Any) -> str:
    if not isinstance(value, str):
        raise PolicyDocumentError(where, "must be a string")
    return value


def _optional_str(where: str, value: Any) -> str | None:
    if value is None:
        return None
    text = _required_str(where, value)
    if not text:
        raise PolicyDocumentError(where, "must not be empty")
    return text


def _optional_bool(where: str, value: Any) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise PolicyDocumentError(where, "must be true or false")
    return value


def _optional_host(where: str, value: Any) -> str | None:
    """A host authored in the document, normalised by the same function destinations pass through."""
    text = _optional_str(where, value)
    if text is None:
        return None
    destination = Destination.parse(text)
    if destination.form in {DestinationForm.UNPARSABLE, DestinationForm.NON_ASCII_NAME}:
        raise PolicyDocumentError(
            where,
            f"{text!r} does not normalise to a host any destination could match, so declaring it "
            f"permits nothing",
        )
    if destination.port != EGRESS_TLS_PORT:
        raise PolicyDocumentError(
            where,
            f"{text!r} names a port; the connector attachment reaches the proxy on "
            f"{EGRESS_TLS_PORT} alone, so a port here could never be reached",
        )
    return destination.host


def _header_names(where: str, value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise PolicyDocumentError(where, "must be an array of header names")
    names = []
    for index, element in enumerate(value):
        name = _required_str(f"{where}[{index}]", element)
        if not name or not name.isascii():
            raise PolicyDocumentError(
                f"{where}[{index}]", "must be a non-empty ASCII header name"
            )
        names.append(name.lower())
    return tuple(names)


def _split_host_port(attempted: str) -> tuple[str, int] | None:
    """Split an authority into a host and a port, or `None` when it is not an authority.

    Whitespace is not stripped and nothing is repaired: a caller-supplied string that needs tidying
    before it can be read is a string this function has no business guessing at, and guessing is how
    the two sides of the comparison come to disagree.
    """
    if attempted.startswith("["):
        closing = attempted.find("]")
        if closing < 0:
            return None
        host = attempted[1:closing]
        remainder = attempted[closing + 1 :]
        if not remainder:
            return host, EGRESS_TLS_PORT
        if not remainder.startswith(":"):
            return None
        port = _port(remainder[1:])
        return None if port is None else (host, port)
    head, separator, tail = attempted.rpartition(":")
    if not separator:
        return attempted, EGRESS_TLS_PORT
    if ":" in head:
        # Several colons and no brackets: an IPv6 literal must be bracketed to carry a port, so this
        # is the whole address rather than an address and a port.
        return attempted, EGRESS_TLS_PORT
    port = _port(tail)
    return None if port is None else (head, port)


def _port(text: str) -> int | None:
    """A port, or `None`. ASCII digits only: `str.isdigit` alone admits other numerals."""
    if not text.isascii() or not text.isdigit() or len(text) > _MAX_PORT_DIGITS:
        return None
    port = int(text)
    return port if 1 <= port <= _MAX_PORT else None


def _canonical_host(host: str) -> tuple[str, DestinationForm]:
    """Canonicalise one host, and say what kind of host it turned out to be."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        form = (
            DestinationForm.IPV4_LITERAL
            if literal.version == 4
            else DestinationForm.IPV6_LITERAL
        )
        return str(literal), form
    if not host.isascii():
        return "", DestinationForm.NON_ASCII_NAME
    name = host[:-1] if host.endswith(".") and len(host) > 1 else host
    if not _is_name(name):
        return "", DestinationForm.UNPARSABLE
    return name.lower(), DestinationForm.DNS_NAME


def _is_name(name: str) -> bool:
    """Whether `name` is a DNS name this comparison can hold, before case folding."""
    if not name or len(name) > MAX_HOST_LENGTH:
        return False
    labels = name.split(".")
    return all(
        label
        and len(label) <= MAX_LABEL_LENGTH
        and set(label.lower()) <= _NAME_CHARACTERS
        for label in labels
    )
