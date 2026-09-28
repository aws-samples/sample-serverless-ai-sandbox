# kiro-classification: public
"""The egress decision function: one policy, one attempted destination, one decision (R12.2, R12.8).

Pure and total. Every input yields a :class:`Decision`, there is no branch that falls through to a
default, and nothing here reads a clock, a network or a store — :mod:`egress.reader` owns the read,
so this function can be quantified over exhaustively without a fixture.

## Two tables, both total, both asserted at import

The repository's established way of keeping a documented branch table from silently acquiring a
default is :data:`control_plane.api.resolution.LOSER_BRANCHES`: an enum for the outcome, a mapping
declared over every member of the input enum, and an import-time assertion that the mapping is total.
Two tables here follow it.

:data:`FORM_MATCH_RULES` says, for each :class:`~egress.policy.DestinationForm`, whether a destination
of that shape is compared against the policy at all. A form added to the model without a rule fails
the build rather than defaulting into the comparison — which is the direction that would matter, since
defaulting *into* the comparison is how a shape nobody thought about acquires a way to match.

:data:`DEFAULT_ACTION_DENIALS` says what the policy's `defaultAction` does to a destination no entry
names. It is a mapping from :class:`~egress.policy.DefaultAction` to
:class:`~control_plane.allocation.DenialReason`, so its codomain is denial reasons and nothing else:
there is no value of the mapping that permits. That is the design's "the schema has no value that
would permit an undeclared destination", expressed as something the build checks.

## The reason vocabulary is reused, not extended

:class:`~control_plane.allocation.DenialReason` is the closed set, defined once in
:mod:`control_plane.allocation.quarantine` because R11.12's circumvention subset is drawn from it.
This module reaches for two of its members and defines nothing of its own:

- :attr:`~control_plane.allocation.DenialReason.UNDECLARED_DESTINATION` for the ordinary R12.2 case,
  which is what that member's own documentation says it is for;
- :attr:`~control_plane.allocation.DenialReason.CONTROLLER_UNREACHABLE` for R12.8.

Both are outside :data:`~control_plane.allocation.CIRCUMVENTION_REASONS`, so neither quarantines a
Sandbox, which is correct: a mistyped hostname and a policy store outage are not evidence that
Untrusted_Code tried to get out. Recognising the *circumventing* shapes — an alias presented for the
wrong upstream, a `Host` header disagreeing with SNI, an IP literal standing in for an aliased
upstream — is denial classification, and it is a separate task with its own audit record. This
function's job is permit-or-deny, and every denial it returns carries a reason that is already in the
vocabulary that task will refine.

## A decision carries no caller-supplied text

:class:`Decision` holds a reason from the closed set and, on a permit, the operator-authored set name,
tier and entry. It does not carry the attempted destination, and the denial reason is never composed
from caller text. A destination is chosen by Untrusted_Code, so a reason string built from it would be
attacker-chosen content travelling into a metric dimension and a log line, which is the disclosure
`runtime.observability` refuses field by field. The audit record R12.3 requires does reproduce the
attempted destination exactly — that is its purpose — and it is built where the attempt is, not here.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, assert_never

from control_plane.allocation.quarantine import DenialReason
from egress.policy import (
    DefaultAction,
    Destination,
    DestinationEntry,
    DestinationForm,
    EgressPolicy,
    PermittedDestination,
    Tier,
)

__all__ = [
    "DEFAULT_ACTION_DENIALS",
    "FORM_MATCH_RULES",
    "Decision",
    "MatchRule",
    "decide",
]


class MatchRule(enum.Enum):
    """Whether a destination of a given form is compared against the policy's permitted hosts."""

    #: Compared for equality against `permitted_host`, both sides having passed through
    #: :meth:`~egress.policy.Destination.parse`.
    COMPARE_CANONICAL_HOST = "compare-canonical-host"
    #: Matches nothing. Not an error and not a special denial: a destination this comparison cannot
    #: hold is a destination the policy does not name, which is the ordinary denial.
    NEVER_MATCHES = "never-matches"


FORM_MATCH_RULES: Final[Mapping[DestinationForm, MatchRule]] = {
    DestinationForm.DNS_NAME: MatchRule.COMPARE_CANONICAL_HOST,
    # An IP literal is compared like any other host and is therefore permitted only where an entry
    # names that same literal — which a Tier 3 entry may. It gets no special permitting treatment,
    # and a literal standing in for an aliased upstream resolves to nothing here.
    DestinationForm.IPV4_LITERAL: MatchRule.COMPARE_CANONICAL_HOST,
    DestinationForm.IPV6_LITERAL: MatchRule.COMPARE_CANONICAL_HOST,
    # Not converted to an A-label, so it cannot equal an entry; see egress.policy's docstring.
    DestinationForm.NON_ASCII_NAME: MatchRule.NEVER_MATCHES,
    DestinationForm.UNPARSABLE: MatchRule.NEVER_MATCHES,
}

if set(FORM_MATCH_RULES) != set(
    DestinationForm
):  # pragma: no cover - import-time invariant
    _unruled = sorted(
        form.value for form in DestinationForm if form not in FORM_MATCH_RULES
    )
    raise AssertionError(f"destination forms with no match rule: {_unruled}")


DEFAULT_ACTION_DENIALS: Final[Mapping[DefaultAction, DenialReason]] = {
    DefaultAction.DENY: DenialReason.UNDECLARED_DESTINATION,
}

if set(DEFAULT_ACTION_DENIALS) != set(
    DefaultAction
):  # pragma: no cover - import-time invariant
    _undecided = sorted(
        action.value for action in DefaultAction if action not in DEFAULT_ACTION_DENIALS
    )
    raise AssertionError(f"default actions with no denial reason: {_undecided}")


@dataclass(frozen=True, slots=True)
class Decision:
    """Permit or deny, and the operator-authored context behind it. Never caller-supplied text.

    The two shapes are mutually exclusive and the invariant is checked rather than trusted: a permit
    names the entry that permitted it and carries no reason, a denial carries a reason and names no
    entry. Construct through :meth:`permit` and :meth:`deny`.
    """

    permitted: bool
    reason: DenialReason | None = None
    destination_set: str | None = None
    tier: Tier | None = None
    entry: DestinationEntry | None = None

    def __post_init__(self) -> None:
        named = (self.destination_set, self.tier, self.entry)
        if self.permitted:
            if self.reason is not None or any(part is None for part in named):
                raise ValueError(
                    "a permit names the destination set, tier and entry that permitted it, "
                    "and carries no denial reason"
                )
        elif self.reason is None or any(part is not None for part in named):
            raise ValueError(
                "a denial carries a reason from the closed set and names no permitted entry"
            )

    @classmethod
    def permit(cls, permitted: PermittedDestination) -> Decision:
        """The destination resolved to an entry in the policy's permitted sets."""
        return cls(
            permitted=True,
            destination_set=permitted.destination_set,
            tier=permitted.tier,
            entry=permitted.entry,
        )

    @classmethod
    def deny(cls, reason: DenialReason) -> Decision:
        """The destination is not permitted, for a reason drawn from the closed set."""
        return cls(permitted=False, reason=reason)


def decide(policy: EgressPolicy | None, destination: Destination) -> Decision:
    """Permit `destination` exactly when `policy` names it, and deny otherwise.

    `policy` is `None` when no policy could be read — an unreachable policy store, or a document that
    could not be loaded. R12.8's answer is denial, and it is the *first* branch here rather than a
    fallback at the end, because "no policy" is the state in which the largest number of ways to get
    it wrong exist: a stale document, a partially parsed one, or an empty one treated as permissive.
    There is no policy value that reaches the comparison, so none of those is expressible.

    Every other denial is the `defaultAction`'s, which is why the reason comes out of
    :data:`DEFAULT_ACTION_DENIALS` rather than being spelled at each `return`.
    """
    if policy is None:
        return Decision.deny(DenialReason.CONTROLLER_UNREACHABLE)
    rule = FORM_MATCH_RULES[destination.form]
    match rule:
        case MatchRule.NEVER_MATCHES:
            return Decision.deny(DEFAULT_ACTION_DENIALS[policy.default_action])
        case MatchRule.COMPARE_CANONICAL_HOST:
            permitted = policy.permitted_for(destination)
            if permitted is None:
                return Decision.deny(DEFAULT_ACTION_DENIALS[policy.default_action])
            return Decision.permit(permitted)
        case _ as unhandled:  # pragma: no cover - mypy proves this unreachable
            assert_never(unhandled)
