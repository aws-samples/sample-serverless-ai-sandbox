# kiro-classification: public
"""The closed circumvention reason subset, and the two triggers that quarantine a Sandbox.

R11.12 makes a Sandbox unavailable for further allocation when an egress denial *attributable to
attempted circumvention* is recorded against it. R11.13 does the same when a Session failure is
recorded. Both write `eligibility = quarantined` onto the Sandbox's claim item, and both record a
reason; this module is where the vocabulary of that reason lives.

**Why the circumvention subset is closed.** "Attributable to attempted circumvention" reads like a
judgement, and a judgement is not something a Lambda can make. So it is a classification instead:
:class:`DenialReason` enumerates every reason the Egress_Controller records for a denial, and
:data:`CIRCUMVENTION_REASONS` is the named subset of those that quarantine. A reason can therefore be
*matched* rather than only read, following :class:`runtime.restore.RestoreCause`. The values are
kebab-case for the same reason as that enum: a reason travels into a stored attribute, a metric
dimension and a log line, and one spelling across all three is what lets an operator grep.

**Why it is a subset rather than the whole set.** The ordinary denial — a plain request to a
destination nobody declared, which is the case R12.2 and R12.3 are about — is a mistyped hostname or
a package registry an operator forgot to permit. Quarantining for it would make the rule worthless,
because the first team that lost a Sandbox to a typo would turn it off, and then R11.12 protects
nothing. :data:`NON_CIRCUMVENTION_REASONS` is derived rather than listed, so a reason added to
:class:`DenialReason` is non-circumventing until somebody puts it in the subset deliberately. That is
the safe default: a new reason cannot start quarantining Sandboxes because it was added.

**Why the two triggers stay distinguishable.** They are different facts about a Sandbox. A
circumvention quarantine says Untrusted_Code tried to get out; a session-failure quarantine says the
Session did not work. An operator investigating a quarantine rate needs to know which, and a single
"quarantined" marker with no cause would send them to the wrong place. The distinction survives in
the stored data with no second attribute, because the two vocabularies are disjoint: every
circumvention reason is a :class:`DenialReason` value and :data:`SESSION_FAILURE_REASON` is not one,
so :meth:`Quarantine.from_recorded_reason` recovers the trigger from the `quarantineReason` attribute
alone. The offline suite asserts the disjointness rather than trusting it, because it is the whole
basis of that recovery.

Emitting the `SandboxQuarantined` metric the design names is Requirement 14's observability work and
not this module's; what this module fixes is the reason value that metric will carry.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Final

__all__ = [
    "CIRCUMVENTION_REASONS",
    "NON_CIRCUMVENTION_REASONS",
    "SESSION_FAILURE_REASON",
    "DenialIsNotCircumvention",
    "DenialReason",
    "Quarantine",
    "QuarantineReasonUnrecognised",
    "QuarantineTrigger",
    "is_circumvention",
]


class DenialReason(enum.StrEnum):
    """Why the Egress_Controller denied an outbound connection. Closed, so it can be matched.

    Membership in this enum says nothing about quarantine. :data:`CIRCUMVENTION_REASONS` is the
    subset that quarantines, and a member absent from that subset quarantines nothing.
    """

    #: The ordinary case (R12.2, R12.3): the destination is not in the permitted set. A mistyped
    #: hostname and an unlisted package registry both land here, which is why it quarantines
    #: nothing.
    UNDECLARED_DESTINATION = "undeclared-destination"
    #: The Egress_Controller could not be reached, so the Sandbox denied rather than permitted
    #: (R12.8). Fail-closed is working, and the Sandbox did nothing wrong.
    CONTROLLER_UNREACHABLE = "controller-unreachable"
    #: A permitted alias presented for a destination that is not the aliased upstream.
    ALIAS_SPOOFED = "alias-spoofed"
    #: The `Host` header disagrees with the name negotiated in the TLS handshake, which is a request
    #: shaped to pass one check and reach a different destination.
    HOST_SNI_MISMATCH = "host-sni-mismatch"
    #: A bare IP literal addressing an upstream that is reachable only under its alias, which is
    #: name-based policy evaded by not using a name.
    IP_LITERAL_FOR_ALIASED_UPSTREAM = "ip-literal-for-aliased-upstream"
    #: An attempt to reach the proxy's own management interface — probing the enforcement point
    #: itself rather than a destination beyond it.
    PROXY_MANAGEMENT_INTERFACE = "proxy-management-interface"
    #: Denials from one Sandbox above the configured threshold within the configured window. The
    #: only member that is a rate rather than a single request, which is what catches enumeration
    #: performed entirely out of otherwise-ordinary denials.
    DENIAL_RATE_EXCEEDED = "denial-rate-exceeded"


#: The closed circumvention subset (R11.12). Every member describes a request shaped to defeat the
#: permitted-destination policy rather than one that merely fell outside it. Adding a member here is
#: a deliberate decision that a Sandbox showing this behaviour must never serve another Session.
CIRCUMVENTION_REASONS: Final[frozenset[DenialReason]] = frozenset(
    {
        DenialReason.ALIAS_SPOOFED,
        DenialReason.HOST_SNI_MISMATCH,
        DenialReason.IP_LITERAL_FOR_ALIASED_UPSTREAM,
        DenialReason.PROXY_MANAGEMENT_INTERFACE,
        DenialReason.DENIAL_RATE_EXCEEDED,
    }
)

#: Derived, never listed. A reason added to :class:`DenialReason` lands here by default, so no new
#: denial reason starts quarantining Sandboxes merely by existing.
NON_CIRCUMVENTION_REASONS: Final[frozenset[DenialReason]] = (
    frozenset(DenialReason) - CIRCUMVENTION_REASONS
)

#: The reason recorded when R11.13's trigger fires. Deliberately not a :class:`DenialReason` member:
#: the disjointness of the two vocabularies is what lets the stored reason identify its own trigger.
SESSION_FAILURE_REASON: Final = "session-failed"


class QuarantineTrigger(enum.StrEnum):
    """Which rule made a Sandbox ineligible. Recovered from the recorded reason, not stored twice."""

    #: R11.12: an egress denial in the closed circumvention subset.
    EGRESS_CIRCUMVENTION = "egress-circumvention"
    #: R11.13: a Session failure recorded against the Sandbox.
    SESSION_FAILURE = "session-failure"


class DenialIsNotCircumvention(Exception):
    """A denial reason outside the closed subset was offered as grounds for quarantine.

    A programming error rather than an operational condition: R11.12 quarantines for the subset and
    for nothing else, so a caller reaching here has skipped :func:`is_circumvention`. Refusing is
    what keeps the subset closed at runtime as well as in the enum.
    """

    def __init__(self, reason: DenialReason) -> None:
        super().__init__(
            f"denial reason {reason.value!r} is not in the closed circumvention subset, "
            f"so it quarantines nothing (R11.12)"
        )
        self.reason = reason


class QuarantineReasonUnrecognised(Exception):
    """A stored `quarantineReason` belongs to neither vocabulary, so its trigger is unknown."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"quarantine reason {reason!r} is neither a circumvention reason nor "
            f"{SESSION_FAILURE_REASON!r}"
        )
        self.reason = reason


def is_circumvention(reason: DenialReason) -> bool:
    """Whether this denial reason is attributable to attempted circumvention (R11.12)."""
    return reason in CIRCUMVENTION_REASONS


@dataclass(frozen=True, slots=True)
class Quarantine:
    """One quarantine decision: the reason to record, and the trigger it came from.

    The two fields are not independent. Construct through the two classmethods and the trigger
    follows from the reason; :meth:`from_recorded_reason` inverts that mapping over what the claim
    item stores, which is why an operator reading a claim item can tell R11.12's quarantine from
    R11.13's without a second attribute existing.
    """

    reason: str
    trigger: QuarantineTrigger

    @classmethod
    def for_denial(cls, reason: DenialReason) -> Quarantine:
        """The R11.12 quarantine for a denial in the closed circumvention subset.

        Raises:
            DenialIsNotCircumvention: `reason` is outside the subset.
        """
        if not is_circumvention(reason):
            raise DenialIsNotCircumvention(reason)
        return cls(reason=reason.value, trigger=QuarantineTrigger.EGRESS_CIRCUMVENTION)

    @classmethod
    def for_session_failure(cls) -> Quarantine:
        """The R11.13 quarantine, written in the same step that records the terminal state."""
        return cls(
            reason=SESSION_FAILURE_REASON, trigger=QuarantineTrigger.SESSION_FAILURE
        )

    @classmethod
    def from_recorded_reason(cls, reason: str) -> Quarantine:
        """Recover a quarantine, trigger included, from the `quarantineReason` a claim item stores.

        Raises:
            QuarantineReasonUnrecognised: the stored reason is in neither vocabulary.
        """
        if reason == SESSION_FAILURE_REASON:
            return cls.for_session_failure()
        try:
            denial = DenialReason(reason)
        except ValueError as exc:
            raise QuarantineReasonUnrecognised(reason) from exc
        if not is_circumvention(denial):
            # A non-circumventing denial reason should never have reached a claim item, so reading
            # one back means something wrote a quarantine R11.12 does not authorise.
            raise QuarantineReasonUnrecognised(reason)
        return cls.for_denial(denial)
