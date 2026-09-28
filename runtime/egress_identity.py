# kiro-classification: public
"""The `/resume` hook's body: refresh the Family B egress identity before serving again (R7.10).

R7.10 asks for the Session credentials to be refreshed before `/resume` returns 200, and the design
names which credentials: the Family B egress identity, the one the Sandbox presents to the
Egress_Controller. The client's Family A credential is untouched — different family, different
lifetime, different issuer, and nothing inside the MicroVM has any business refreshing it.

`runtime.hooks` owns the ordering and it is the load-bearing half of the requirement: the refresh
runs *before* the readiness gate reopens, so no protocol request can be served against a stale
egress identity. A failure here therefore leaves the gate `SUSPENDED`, which is a Sandbox that has
not resumed rather than a Sandbox serving traffic it cannot get out of.

## What this hook genuinely owns, and what it does not

The private key already exists. `runtime.session_values` generated it inside `/run`, from the
operating system's CSPRNG, because R7.12 requires every per-Session value to be born in the hook
rather than captured at image build time. This hook does not mint a new key, and that is deliberate
rather than an omission: the key is the Sandbox's identity for its whole Session, and a `/resume`
that replaced it would invalidate the certificate the Egress_Controller is currently willing to
accept, in the one hook whose job is to make sure that certificate is usable.

So what is refreshed is the *certificate over* that key, and building one is not this task's:

- A certificate signing request is an X.509 structure. Producing one means an asymmetric signature
  over a DER encoding with a public key derived from the private key, none of which the standard
  library offers and none of which is worth hand-rolling. No cryptography library is pinned, and
  pinning one is a dependency decision belonging to the task that needs it.
- The exchange with the signing endpoint, the certificate lifetime clamped to the Session
  remainder, and the egress generation the Control_Plane tracks are the Egress_Controller's and the
  orchestrator's concerns, reached from inside the MicroVM over the connector.

Both of those live behind `EgressIdentitySource`, which is the seam the **Family B egress identity
task** implements. What is implemented here is everything around it, and it is not nothing:

1. **Refusing to refresh what does not exist.** A `/resume` arriving before any `/run` has no
   per-Session key, so there is no identity to refresh and there is no honest 200 to return. The
   readiness gate would refuse the transition a moment later, but the refusal has to be here as
   well: the hook calls this *first*, so a body that shrugged would have already told the caller
   the refresh succeeded by the time the gate spoke.
2. **Bounding the exchange.** The signing endpoint is reached over the network. An unbounded wait
   is a `/resume` that never returns, and a Sandbox stuck mid-resume is neither serving nor
   collectable.
3. **Replacing atomically.** The new identity is published only after the exchange succeeds, so a
   failed refresh leaves the previous one in place. That matters because the previous certificate
   may still be valid — a refresh that failed early is not the same event as a certificate that has
   expired — and discarding it would turn a recoverable failure into an unrecoverable one.
4. **Making the refresh observable.** `refresh_count` and `identity` are readable, so "the identity
   in effect is the one this resume produced" is assertable rather than inferred from the absence of
   an exception.

## The private key crosses one in-process call and no wire

`EgressIdentitySource.refresh` takes the key material. That is a call within the MicroVM to code
packaged in the same image, so the design's premise — the Runtime generates the keypair inside the
MicroVM and never transmits the private key — is not weakened by it. It does place an obligation on
the implementation of that seam, and the obligation is stated here because this is where a reader
looking at the signature will ask: **the implementation signs with the key and sends the signature
and the public key; it never sends the key.** A seam that transmitted it would break the one
property the whole Family B design rests on, and no check on this side of the call could detect it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

__all__ = [
    "DEFAULT_EGRESS_REFRESH_DEADLINE_SECONDS",
    "EgressIdentity",
    "EgressIdentityManager",
    "EgressIdentitySource",
    "EgressRefreshFailure",
]

#: How long the signing exchange may take. Short, because `/resume` is on the latency path the
#: design measures (R10.10) and because a signing endpoint that has not answered in ten seconds is
#: not about to: the correct outcome is a failed resume the orchestrator can observe and retry,
#: not a hook that keeps waiting.
DEFAULT_EGRESS_REFRESH_DEADLINE_SECONDS: Final = 10.0


class EgressRefreshFailure(Exception):
    """The Family B egress identity could not be refreshed.

    One type rather than a closed cause set, unlike `runtime.restore.RestoreCause`. The difference
    is what the requirement asks for: R13.7 asks a restoration failure to be *identified*, because
    the Control_Plane records the reason against the Session and an operator reads it there. R7.10
    asks only that the refresh happen before 200, so the reason here is a sentence for whoever
    reads the non-200 and not a value anything matches on.
    """


@dataclass(frozen=True, slots=True)
class EgressIdentity:
    """The Family B identity in effect: the certificate over this Sandbox's own key, and its expiry.

    The private key is deliberately absent. This object is the *public* half — it is what would be
    presented to the Egress_Controller — and keeping the key out of it means the identity can be
    reported, logged and compared without a value that must never leave the MicroVM travelling with
    it. `runtime.session_values` holds the key, and its `repr` withholds it for the same reason.

    Frozen, so that the identity a request was authorised against cannot be edited underneath it.
    """

    certificate: bytes
    not_after_epoch_seconds: int

    def __post_init__(self) -> None:
        """Refuse an identity that could not authenticate anything.

        An empty certificate and a non-positive expiry are both shapes a stub seam produces by
        accident, and either would let `/resume` return 200 carrying an identity that fails at the
        proxy instead of at the hook that installed it.
        """
        if not self.certificate:
            raise ValueError(
                "an egress identity carries the certificate issued over this Sandbox's key"
            )
        if self.not_after_epoch_seconds <= 0:
            raise ValueError(
                f"an egress identity expires at a point in time: "
                f"{self.not_after_epoch_seconds}"
            )


@runtime_checkable
class EgressIdentitySource(Protocol):
    """Produces a refreshed Family B identity for this Sandbox's own key.

    The whole of the Family B exchange, behind one method: build the certificate signing request
    over `private_key`, present it to the Egress_Controller's signing endpoint, and return the
    identity that came back. See the module docstring for the obligation this signature carries and
    for why the CSR is not built on this side of it.
    """

    async def refresh(self, private_key: bytes) -> EgressIdentity:
        """Return a refreshed identity over `private_key`, or raise."""
        ...


class EgressIdentityManager:
    """The Family B identity of one Sandbox_Runtime, and the refresh `/resume` performs.

    One per runtime process. A second manager would be a second identity for one Sandbox, and the
    Egress_Controller would then accept traffic authenticated with whichever of them happened to be
    reached — which is the sort of ambiguity that is discovered from a proxy log rather than a test.
    """

    def __init__(
        self,
        source: EgressIdentitySource,
        *,
        deadline_seconds: float = DEFAULT_EGRESS_REFRESH_DEADLINE_SECONDS,
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError(
                f"an egress refresh deadline is a positive number of seconds: "
                f"{deadline_seconds}"
            )
        self._source = source
        self._deadline_seconds = deadline_seconds
        self._identity: EgressIdentity | None = None
        self._refresh_count = 0

    @property
    def identity(self) -> EgressIdentity | None:
        """The identity in effect, or None before any refresh has succeeded."""
        return self._identity

    @property
    def refresh_count(self) -> int:
        """How many refreshes have succeeded. One per `/resume` that returned 200."""
        return self._refresh_count

    async def refresh(self, *, private_key: bytes) -> EgressIdentity:
        """Refresh the identity over `private_key`, replacing the previous one on success.

        Raises:
            EgressRefreshFailure: no refreshed identity was obtained. The previous identity, if
                there was one, is left in place.
        """
        if not private_key:
            raise EgressRefreshFailure(
                "this Sandbox has no per-Session egress private key, so there is no Family B "
                "identity to refresh; the key is generated inside the /run hook (R7.12), which "
                "means a /resume before /run cannot refresh anything"
            )
        try:
            async with asyncio.timeout(self._deadline_seconds):
                refreshed = await self._source.refresh(private_key)
        except TimeoutError as exc:
            raise EgressRefreshFailure(
                f"refreshing the Family B egress identity did not complete within "
                f"{self._deadline_seconds:g}s"
            ) from exc
        except EgressRefreshFailure:
            # Already the reported vocabulary. Re-wrapping would nest one reason inside another.
            raise
        except Exception as exc:
            # A seam implementation may raise anything.
            # `/resume` must not return 200 on a failure this module did not recognise, and the
            # hook turns an exception into a non-200 whatever its type. Translating rather than
            # propagating keeps the failure vocabulary of this hook one type wide, so a caller
            # catching it catches every way the refresh can fail.
            raise EgressRefreshFailure(
                f"refreshing the Family B egress identity failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        self._identity = refreshed
        self._refresh_count += 1
        return refreshed
