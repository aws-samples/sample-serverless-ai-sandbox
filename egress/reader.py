# kiro-classification: public
"""The per-request policy read, and the configured cache TTL that bounds revocation (R12.2, R12.8).

The design puts the policy in AppConfig and reads it "per request with a 30 s cache", and the network
connector constraint section is where that number earns its keep: the connector is fixed for the life
of a running MicroVM, so revoking a destination for a Sandbox that is already running is a policy-data
change and nothing else. The TTL is therefore the *revocation latency* of the whole architecture —
"removing a destination takes effect within 30 s" is a claim about this cache and no other component.

## Which is why the TTL has a ceiling but no default

`cache_ttl_seconds` is required with no class-level default, following
:class:`~control_plane.api.creation_wait.CreationWaitSettings`: it is a deployment value, and a
literal here would be a second source for a number the deployment owns. But it is refused above
:data:`MAX_POLICY_CACHE_TTL_SECONDS`, because a deployment configuring five minutes would not be
choosing a different trade-off, it would be falsifying a documented security property. Zero is
allowed and means no caching at all — strictly safer, at the cost of a policy read on every request.

## An expired entry is not a fallback

When the read fails, the cached policy is *discarded* and the decision is
:attr:`~control_plane.allocation.DenialReason.CONTROLLER_UNREACHABLE`. Serving the last known policy
would be the obvious availability move and it is the wrong one twice over: it extends revocation past
the bound above for exactly as long as the outage lasts, which is unbounded, and it makes a policy
store outage indistinguishable from a working one right up until the moment an operator needs a
revocation to have landed. R12.8 already settles the direction — unreachable denies — and the design
accepts the consequence in as many words: "an Egress_Controller outage is a total egress outage for
every running Sandbox", with proxy-fleet availability as the answer rather than stale policy.

## The clock is monotonic and injected

`time.monotonic`, for the reason :class:`~control_plane.api.creation_wait.PollingCreationWait` gives:
this measures an elapsed interval, and a wall clock that steps backwards would extend the TTL. Both
the clock and the source are injected, so the offline suite drives expiry, a mid-flight revocation and
an outage without waiting for anything or reaching a network.

## What travels outward

:meth:`CachedPolicyReader.decide` is where a caller-supplied destination enters: it is parsed to a
:class:`~egress.policy.Destination` immediately, and what comes back is a
:class:`~egress.decision.Decision` carrying a closed-vocabulary reason. Nothing here logs, and no
attempted destination is retained — the audit record R12.3 requires is built by the interception path
that holds the request, from the request.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from egress.decision import Decision, decide
from egress.policy import Destination, EgressPolicy

__all__ = [
    "MAX_POLICY_CACHE_TTL_SECONDS",
    "CachedPolicyReader",
    "PolicyCacheSettings",
    "PolicySource",
    "PolicyUnavailable",
]

#: The ceiling the design's revocation claim fixes: a destination removed from the policy stops being
#: permitted within this many seconds. A configured TTL above it is refused, not clamped, because a
#: deployment that asked for slower revocation should learn that it cannot have it.
MAX_POLICY_CACHE_TTL_SECONDS: Final = 30.0


class PolicyUnavailable(Exception):
    """No policy could be read. Denial follows (R12.8).

    The seam's whole contract for failure, and the only exception
    :meth:`CachedPolicyReader.policy` absorbs. A source adapter that lets a client error escape
    instead is a defect and is not caught here: absorbing every exception would turn a bug in the
    adapter into a silent total egress outage that looked exactly like a policy store being down.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"the egress policy could not be read: {detail}")
        self.detail = detail


@runtime_checkable
class PolicySource(Protocol):
    """Where the policy document comes from. One method, because that is the whole dependency.

    The deployed implementation reads AppConfig and calls
    :meth:`~egress.policy.EgressPolicy.from_document`. A concrete class here would be this package
    asserting a client library and a configuration profile it has no standing to assert, which is the
    stance `runtime.ports` takes about the endpoint URL shape.
    """

    def read(self) -> EgressPolicy:
        """The current policy.

        Raises:
            PolicyUnavailable: the policy store could not be reached, or its document was refused.
        """
        ...


@dataclass(frozen=True, slots=True)
class PolicyCacheSettings:
    """The deployment-configured cache TTL. Required, bounded above, and zero means no caching."""

    cache_ttl_seconds: float

    def __post_init__(self) -> None:
        if self.cache_ttl_seconds < 0:
            raise ValueError(
                f"cache_ttl_seconds must not be negative: {self.cache_ttl_seconds}"
            )
        if self.cache_ttl_seconds > MAX_POLICY_CACHE_TTL_SECONDS:
            raise ValueError(
                f"cache_ttl_seconds must not exceed {MAX_POLICY_CACHE_TTL_SECONDS} seconds, "
                f"which is the revocation latency the design documents: "
                f"{self.cache_ttl_seconds}"
            )


class CachedPolicyReader:
    """Reads the policy per request, at most once per TTL, and decides against what it read.

    Not a dataclass: it holds mutable cache state, and a frozen wrapper around a mutable cache would
    misdescribe itself.
    """

    def __init__(
        self,
        *,
        source: PolicySource,
        settings: PolicyCacheSettings,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._settings = settings
        self._clock = clock
        self._cached: EgressPolicy | None = None
        self._read_at: float | None = None
        self._reads = 0

    @property
    def reads(self) -> int:
        """How many times the source has been read.

        Readable so that "the cache is working" and "the cache is being bypassed" are observable from
        inside the process, the same reason `runtime.observability` exposes its dropped count.
        """
        return self._reads

    def policy(self) -> EgressPolicy | None:
        """The current policy, or `None` when none could be read.

        `None` rather than a raise, because an unreachable policy store is an ordinary denial on a
        request path (R12.8), not an exceptional condition for the caller to handle.
        """
        if self._cached is not None and self._read_at is not None:
            elapsed = self._clock() - self._read_at
            if elapsed < self._settings.cache_ttl_seconds:
                return self._cached
        return self._refresh()

    def decide(self, attempted: str) -> Decision:
        """The decision for one attempted destination: read the policy, then apply it.

        `attempted` is the authority Untrusted_Code asked for. It is normalised immediately and is not
        retained.
        """
        return decide(self.policy(), Destination.parse(attempted))

    def _refresh(self) -> EgressPolicy | None:
        """Read through, dropping whatever was cached first, so a failure cannot serve stale policy."""
        self._cached = None
        self._read_at = None
        self._reads += 1
        try:
            policy = self._source.read()
        except PolicyUnavailable:
            return None
        self._cached = policy
        self._read_at = self._clock()
        return policy
