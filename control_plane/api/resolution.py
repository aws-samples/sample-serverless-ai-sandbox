# kiro-classification: public
"""`ResolveSession`: get-or-create by Affinity_Key, as one conditional transaction (R6.15).

`POST /sessions/resolve`, `AWS_IAM` like every route, which is the whole of R6.22: an Affinity_Key
names a Session and confers no access, so the gateway rejects an unsigned request before any code
here runs and the per-request credentials the handler holds cannot address another Tenant's
partition at all. Nothing in this module compares a Tenant identifier, because there is no code path
on which two could differ.

This is the reconnect path a multi-turn agent takes on every turn, so it is the highest-frequency
operation in the system. **The Session_Orchestrator is not in the resolution path.** That is a
deliberate exclusion: resolution provisions nothing, so it depends on conditional writes and reads
and on nothing else. The orchestrator appears only on the create branch, reached through
:meth:`~control_plane.api.creation.CreationOperations.create`, because provisioning must be
governed.

## The two actions, and why exactly one happens

R6.15 admits exactly one of two outcomes: return the credential of the Session already bound to the
key, or create a Session, bind the key, and return that Session's credential. Which one happened is
reported on the response as :data:`RESOLUTION_FIELD`, taking :class:`ResolutionOutcome`'s two
values, because a caller that cannot tell a resolve from a create cannot report that one Sandbox
served every turn.

The order of operations is fixed by R6.18: **the binding is established by a conditional write that
fails when one already exists, never by a read followed by an unconditional write.** So a resolution
*starts* by attempting the claim. It does not look first. The read of an existing binding happens
only after a claim has already lost, which is the one moment at which the existence of that binding
is a fact rather than an observation that could be stale by the time it is acted on.

## The atomic claim

One :meth:`BindingStore.claim_binding` — a single `TransactWriteItems` carrying two `Put` items, the
Session row and the binding, where the binding carries `attribute_not_exists(pk)`:

```
TransactWriteItems:
  Put  pk=T#<tenant>  sk=S#<newSessionId>   { lifecycleState: PENDING, affinityKeyDigest: <d>, … }
  Put  pk=T#<tenant>  sk=K#<d>              { sessionId: <newSessionId>, expiresAt: <deadline> }
       Condition: attribute_not_exists(pk)
```

A transaction rather than two conditional writes, and the reason is what the loser does *not* leave
behind. Two concurrent requests carrying one Tenant and one Affinity_Key both attempt this; the
store serialises them and exactly one commits. The loser commits **neither** item, so there is no
orphan Session row for a Reaper to find and no row a later reader could mistake for a live Session.
Combined with two orderings already required elsewhere — `StartExecution` happens only after a
committed claim, and `provision` happens only inside a started execution — exactly one Session and
exactly one Sandbox result (R6.17). The exactly-once guarantee is a composition of existing
orderings rather than a new mechanism.

The row written by the winning transaction is built by the same
:meth:`~control_plane.api.creation.CreationOperations.create` that `POST /sessions` uses, with the
transaction substituted for the plain `Put` through :data:`~control_plane.api.creation
.SessionRowWriter`. There is deliberately no second place that builds a Session row or starts an
execution: R6.11 is a claim about *every* Sandbox, and a second creation path would be a second
place to get its ordering wrong.

## The binding record, and where its keys come from

The partition key is `pk_for(principal)` — the same sole producer that produces every other Tenant
partition key — and the caller-supplied Affinity_Key can only ever become a **sort** key. That
asymmetry is what discharges R6.16 and R11.11 with no additional check: the inline session policy's
`dynamodb:LeadingKeys` condition already confines every request to the caller's own partition, so a
binding in another Tenant's partition is not merely not-found, it is unaddressable by the
credentials in hand. Two Tenants presenting the byte-identical Affinity_Key therefore resolve to
different Sessions and neither can name the other's.

The sort key is `K#<base64url(sha256(affinityKey))>`, produced by
:func:`~control_plane.state.keys.affinity_key_digest`. The raw key is never persisted. Three reasons,
all of them structural rather than stylistic: an Affinity_Key is caller-supplied and may collide with
the sort-key delimiter convention, which the digest's alphabet cannot; the digest is fixed length, so
a binding item's size is bounded whatever the caller sends; and a thread or conversation identifier
is not a secret but is also not something this system needs to keep. Errors naming the Affinity_Key
are raised by the client or the tool interface (R9.13, R20.9), each of which already holds the raw
value.

**No length limit is imposed on the Affinity_Key.** That is the digest doing its job: length reaches
neither a key nor an attribute, so a cap would refuse a caller for no benefit. What *is* refused is a
key with no byte representation at all — the empty string, and a string carrying unpaired surrogates,
which `json` will decode but which no UTF-8 encoding accepts. Neither can be hashed, so neither can
name a binding, and :class:`InvalidAffinityKey` says so as a `400` rather than surfacing a
`UnicodeEncodeError` as a `500`.

## The loser's path, one branch per lifecycle state

R6.19 requires the loser to resolve the existing binding rather than fail. On a lost claim the
handler reads the binding, reads the Session it names, and branches on that Session's lifecycle
state. The table is :data:`LOSER_BRANCHES` and it is total over
:class:`~control_plane.state.records.LifecycleState`, asserted at import, so a state added later
fails the build rather than falling into a default:

| State of the bound Session | Action |
| --- | --- |
| `RUNNING` | Mint a fresh credential and return it (R6.19, R6.23) |
| `SUSPENDED` | Mint a fresh credential, return it, **leave the Session suspended** (R6.20) |
| `PENDING`, `ORCHESTRATING`, `PROVISIONING`, `STARTING` | Wait on the winner's row, then mint (R6.19) |
| `SUSPENDING`, `RESUMING`, `CONTINUING` | Same wait; transient and resolving to `RUNNING` or terminal |
| `TERMINATED`, `FAILED` | Treat the binding as absent and create (R6.21) |
| Row absent entirely | Treat the binding as absent and create; the stale-binding self-heal (R13.8) |

**The waiting case reuses the creation wait verbatim.** That is why the wait was designed as a
function of a Session row rather than of a request: the loser hands it the winner's row and waits on
the same interval and the same budget the winner is waiting on. A loser therefore experiences
get-or-create as slightly slower than the winner and never as a failure — and if the budget expires
it receives the asynchronous response shape, a Session identifier with no credential, which the
Client_SDK and the Agent_Tool_Interface already treat as "not yet published" (R9.16). Never a `504`,
which would carry no Session identifier and so lose a Session the caller is now paying for.

**The suspended case returns a credential and does nothing else.** No resume call, and this is a cost
decision rather than an omission. The first request the caller delivers to the Sandbox endpoint
triggers auto-resume in the provider (R10.5), so resuming from here would pay for compute the caller
may never use — on a reconnect that turns out to be the agent's last turn that is the entire
idle-cost objective given away for nothing. It would also insert a Control_Plane dependency into a
path that has none.

**The terminal case replaces the binding rather than deleting and re-creating it**, and the
replacement is itself conditional on the binding still naming the Session just found terminal
(:meth:`BindingStore.replace_binding`). Without that condition, three concurrent requests finding
one terminal binding would each delete-then-create and produce three Sessions. With it, one commits
and the others fail the condition and re-enter the loser's path, where they now find a live Session.
The conditional replacement is what keeps R6.17's exactly-one guarantee true across the terminal case
as well as the fresh one, which is why there is no `DeleteItem` anywhere in this module.

Re-entering is literally a loop, bounded by :data:`MAX_CLAIM_ATTEMPTS`. See its docstring for why the
bound is small and why exceeding it is an error rather than a further retry.

## Freshly minted on every resolution

R6.23 requires resolution to mint a new credential rather than return one issued previously, and it
reads as being in tension with R6.13, which requires *creation* to return a credential read from the
State_Store. The two branches are therefore separated explicitly, and the separation is visible in
what each branch touches:

- **Create branch.** Returns the credential the orchestration published seconds ago as part of
  provisioning this Session (R6.12, R6.13). It reads the published attribute and mints nothing.
- **Resolve branch.** Calls :meth:`~control_plane.credentials.ConnectionIssuer.issue`, the sole
  issuer, producing a credential minted now with a fresh expiry clamped to the Session remainder. It
  never reads the published attribute.

That includes the waiting case. The published credential there is a **readiness signal** — it is how
the loser learns that `/run` returned 200 and the Sandbox is reachable — and the credential the
loser then returns is minted, not the one it read. Returning the published one would hand a Session
reconnected on turn fifty a credential minted at turn one, which either has expired or should have,
and it is what the design's own separation of the two branches exists to prevent.

## Survival across continuation

R6.24 needs no code here. The binding names the **Session identifier** and nothing else: no Sandbox
handle, no generation, no credential, no lifecycle state. A continuation past the duration ceiling
replaces the handle and increments `generation` while the Session identifier stays fixed, so the
binding requires no update and none is performed. The next resolution mints against the current
generation and the caller reaches the replacement Sandbox. This is a property of the key structure
rather than of a code path that maintains it, which is exactly why a binding that cached a
descriptor would have been wrong.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from http import HTTPStatus
from typing import Any, Final, Protocol

from control_plane.api.connection import ConnectionUnavailable
from control_plane.api.creation import (
    CreatedSession,
    CreationOperations,
    SessionRowWriter,
)
from control_plane.api.errors import ControlPlaneError, error_response
from control_plane.api.handlers import (
    NotImplementedOperations,
    OperationRequest,
    OperationResult,
)
from control_plane.api.lookup import SessionLookup
from control_plane.credentials import ConnectionIssuer, ConnectionNotIssuable
from control_plane.state.keys import (
    ItemShapeError,
    affinity_key_digest,
    binding_sort_key,
    session_sort_key,
)
from control_plane.state.records import (
    AffinityKeyBindingRecord,
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = [
    "AFFINITY_KEY_FIELD",
    "DEFAULT_BINDING_MAX_AGE_SECONDS",
    "INVALID_AFFINITY_KEY_ERROR_CODE",
    "LOSER_BRANCHES",
    "MAX_CLAIM_ATTEMPTS",
    "RESOLUTION_FIELD",
    "UNSETTLED_ERROR_CODE",
    "BindingConditionFailed",
    "BindingSettings",
    "BindingStore",
    "InvalidAffinityKey",
    "LoserBranch",
    "ResolutionDidNotSettle",
    "ResolutionOperations",
    "ResolutionOutcome",
    "binding_for",
    "digest_of_requested_affinity_key",
    "resolution_payload",
]

#: The `ResolveSession` body field naming the Affinity_Key. camelCase, matching every other request
#: field in this component, and the only field this operation reads: no duration, no port set and
#: certainly no Tenant, because a caller who could name one would have named their way out of the
#: confinement that makes cross-tenant resolution impossible.
AFFINITY_KEY_FIELD: Final = "affinityKey"

#: The response field naming which of R6.15's two actions happened.
RESOLUTION_FIELD: Final = "resolution"

#: The `error` code of a body that carries no Affinity_Key this operation can hash.
INVALID_AFFINITY_KEY_ERROR_CODE: Final = "InvalidAffinityKey"

#: The `error` code of a resolution that neither claimed nor resolved inside its attempt bound.
UNSETTLED_ERROR_CODE: Final = "ResolutionDidNotSettle"

#: How many times one resolution attempts a claim before giving up.
#:
#: Four, and the number is small on purpose. The ordinary paths take one attempt (the claim commits,
#: or it loses to a live Session) or two (the claim loses to a terminal binding, and the conditional
#: replacement commits). A third and fourth are spent only on a genuine race: a binding deleted
#: between a failed claim and the read of it, or a Session that reached a terminal state during the
#: wait. Each iteration is at most one transaction and two reads, so a loop that has consumed four
#: has not hit a slow store, it has hit contention that is not converging — and continuing to retry
#: would hold a request open behind a condition that keeps flipping. Failing with
#: :class:`ResolutionDidNotSettle` is bounded and visible; retrying forever is neither.
MAX_CLAIM_ATTEMPTS: Final = 4

#: The configured ceiling on how long a binding may live, before the Session deadline clamps it.
#: 28,800 seconds is the Session duration ceiling, so this default clamps nothing on its own and the
#: Session's own deadline is what bounds every binding — which is R13.8's requirement stated as the
#: safe default. A deployment that wants bindings reclaimed sooner than their Sessions lowers it.
DEFAULT_BINDING_MAX_AGE_SECONDS: Final = 28_800

_MILLISECONDS_PER_SECOND: Final = 1000


class ResolutionOutcome(str, Enum):
    """Which of R6.15's two actions this resolution performed.

    Reported on the response so the caller can tell them apart, which the Agent_Tool_Interface maps
    onto its `reconnected` flag. A `str` enum so the value serialises as the design's literal, and
    two members rather than three because R6.15 admits exactly two outcomes — a resolution that
    waited on a winner still `resolved`, since it created nothing.
    """

    CREATED = "created"
    RESOLVED = "resolved"


class InvalidAffinityKey(ControlPlaneError):
    """The body carries no Affinity_Key that can name a binding.

    A `400` naming the field and not the value. The empty string and a string carrying unpaired
    surrogates are the two cases: neither has a UTF-8 encoding, so neither can be hashed, so neither
    can name a binding. Refused here rather than allowed to surface as a `UnicodeEncodeError`, which
    would reach the gateway as a `500` for what is a caller's mistake.

    The message echoes no part of the key. An Affinity_Key is not a credential, but it is also not
    something a response needs to repeat back to the party that just sent it.
    """

    def __init__(self, reason: str) -> None:
        message = f"{AFFINITY_KEY_FIELD} {reason}"
        super().__init__(
            error_response(
                HTTPStatus.BAD_REQUEST, INVALID_AFFINITY_KEY_ERROR_CODE, message
            ),
            message,
        )
        self.reason = reason


class ResolutionDidNotSettle(ControlPlaneError):
    """Neither a claim nor a resolution settled inside :data:`MAX_CLAIM_ATTEMPTS`.

    `503` with a retry-able meaning: nothing is wrong with the request, and the caller repeating it
    is the correct response. Not a `500`, because no invariant was violated — every attempt either
    committed nothing or lost a condition, which is the mechanism working. Not a silent further
    retry either: contention that has not converged in four attempts is a thing an operator should
    see as a metric rather than as latency.

    No Session row and no binding is left behind by a resolution that ends here, because every write
    on this path is a transaction that commits both items or neither.
    """

    def __init__(self, attempts: int) -> None:
        message = (
            f"the Affinity_Key binding neither claimed nor resolved in {attempts} "
            f"attempts; retry the request"
        )
        super().__init__(
            error_response(
                HTTPStatus.SERVICE_UNAVAILABLE, UNSETTLED_ERROR_CODE, message
            ),
            message,
        )
        self.attempts = attempts


class BindingConditionFailed(Exception):
    """A conditional write on the binding item found a state the condition excluded.

    This is `TransactionCanceledException` with a `ConditionalCheckFailed` **on the binding item**,
    at this seam. It says only that the condition did not hold; what that means, and what happens
    next, is decided by :class:`ResolutionOperations` and by nothing in the store.

    A store implementation must raise it for the binding item's condition alone. A cancellation
    attributable to any other reason — the Session `Put`, a capacity rejection, a transaction
    conflict — is not this, and absorbing one into it would turn an infrastructure failure into a
    silent "somebody else won the race" and produce a resolution of a Session that does not exist.
    """


class BindingStore(Protocol):
    """The two transactions and one read a resolution performs on binding items.

    Every method's contract is stated as the condition expression it carries, because the conditions
    *are* the guarantees: an implementation that dropped one would still satisfy the signatures and
    would break R6.17, so they are written down here rather than left to each implementation to
    remember. This is the posture :class:`~control_plane.allocation.ledger.ClaimItemStore` takes for
    the same reason.

    A structural type, so the offline suite drives the whole of resolution — both transactions, every
    row of the loser's branch table, and concurrent claims serialised as the store serialises them —
    against an in-memory store keyed as DynamoDB is, with no deployed resource and no network.

    Reached with the per-request tenant-confined credentials of
    :mod:`control_plane.state.access`, whose action set includes `TransactWriteItems` for exactly
    this reason. `dynamodb:LeadingKeys` applies to a transaction the same way it applies to a single
    write, and both items of both transactions below sit in the caller's own partition, so a
    transaction that touched another Tenant's partition would be refused by IAM rather than by a
    check here.
    """

    def claim_binding(
        self,
        *,
        session_item: Mapping[str, Any],
        binding_item: Mapping[str, Any],
    ) -> None:
        """`TransactWriteItems` the Session row and the binding, the binding conditional on absence.

        `ConditionExpression: attribute_not_exists(pk)` on the binding item, and none on the Session
        row. One transaction, so a losing caller commits **neither** item and leaves no orphan
        Session row (R6.17, R6.18).

        Raises:
            BindingConditionFailed: a binding already exists for this Affinity_Key.
        """
        ...

    def replace_binding(
        self,
        *,
        session_item: Mapping[str, Any],
        binding_item: Mapping[str, Any],
        expected_session_id: str,
    ) -> None:
        """Same transaction, with the binding conditional on it still naming the expected Session.

        `ConditionExpression: sessionId = :expected` on the binding item (R6.21). A replacement
        rather than a delete followed by a create, so that concurrent requests finding one terminal
        binding produce one Session rather than one each.

        Raises:
            BindingConditionFailed: the binding no longer names `expected_session_id`, because
                another request replaced it first or it was deleted outright.
        """
        ...

    def read_binding(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        """Return the binding item at this key, or `None` when there is none.

        Strongly consistent. An eventually consistent read here could miss the binding a claim just
        lost to and send the loser back to claim again, which would spend the attempt bound on a
        replica lag rather than on contention.
        """
        ...


@dataclass(frozen=True, slots=True)
class BindingSettings:
    """The one deployment-configured number a binding's expiry depends on.

    A field with a stated default rather than a required one, because unlike
    :class:`~control_plane.api.creation.CreationSettings` this value has a *safe* default that is not
    a guess about a deployment: clamping to the Session deadline alone is exactly what R13.8
    requires, and the ceiling only ever shortens that.
    """

    max_age_seconds: int = DEFAULT_BINDING_MAX_AGE_SECONDS

    def __post_init__(self) -> None:
        # One condition rather than two, so a misconfigured deployment fails as the
        # misconfiguration it is — a `ValueError` naming the field — rather than as a `TypeError`
        # for the string half and a `ValueError` for the non-positive half of the same mistake.
        # `bool` is excluded explicitly: it is a subclass of `int`, so `True` would otherwise
        # configure a one-second binding ceiling.
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or self.max_age_seconds <= 0
        ):
            raise ValueError(
                f"max_age_seconds must be a positive integer number of seconds, "
                f"got {self.max_age_seconds!r}"
            )


def digest_of_requested_affinity_key(body: Mapping[str, Any]) -> str:
    """Return the digest of the Affinity_Key this body names.

    The one place a caller-supplied value enters this operation, and it leaves as a fixed-length,
    delimiter-free digest. Nothing downstream of here has the raw key, which is what makes "the raw
    Affinity_Key is never persisted" a property of the code's shape rather than of a reviewer
    noticing.

    Raises:
        InvalidAffinityKey: the field is absent, is not a string, is empty, or carries unpaired
            surrogates and therefore has no UTF-8 encoding to hash.
    """
    value = body.get(AFFINITY_KEY_FIELD)
    if value is None:
        raise InvalidAffinityKey("is required")
    if not isinstance(value, str):
        raise InvalidAffinityKey(
            f"must be a string, got a value of type {type(value).__name__}"
        )
    try:
        return affinity_key_digest(value)
    except UnicodeEncodeError as exc:
        # `json` decodes an escaped lone surrogate into a `str` that no UTF-8 encoder accepts, so
        # this is reachable from the wire rather than only from a caller inside the process.
        raise InvalidAffinityKey(
            "must be text with a UTF-8 encoding; it carries an unpaired surrogate"
        ) from exc
    except ItemShapeError as exc:
        raise InvalidAffinityKey("must not be empty") from exc


def binding_for(
    record: SessionRecord, digest: str, settings: BindingSettings
) -> AffinityKeyBindingRecord:
    """Build the binding item for a Session row, expiring no later than that Session (R13.8).

    `expiresAt = min(sessionDeadline, boundAt + configuredMaxAge)`, so a Session whose deadline is
    pushed out cannot extend a binding indefinitely and R13.8's "no later than the configured
    deadline" holds by construction rather than by an update path that could be skipped.

    **The expiry is in epoch seconds while `boundAt` is in epoch milliseconds.** The mismatch is
    not an oversight: DynamoDB expires an item only on a top-level number holding epoch *seconds*, so
    writing milliseconds would place every expiry tens of thousands of years out and make cleanup
    layer 3 silently inert — a failure that no test of the write itself would catch. `boundAt` is in
    milliseconds because it is this system's own timestamp unit, shared with every other recorded
    time, and it is read by nothing outside this repository.

    The partition key is taken from the Session row, which took it from
    :func:`~control_plane.tenancy.pk_for`. It is not rebuilt here, so the binding and the Session it
    names cannot end up in different partitions.
    """
    bound_at = record.created_at
    deadline_ms = bound_at + record.max_duration_seconds * _MILLISECONDS_PER_SECOND
    ceiling_ms = bound_at + settings.max_age_seconds * _MILLISECONDS_PER_SECOND
    return AffinityKeyBindingRecord(
        pk=record.pk,
        affinity_key_digest=digest,
        session_id=record.session_id,
        bound_at=bound_at,
        # Floored, so the clamp can only ever move the expiry earlier than the Session deadline.
        expires_at=min(deadline_ms, ceiling_ms) // _MILLISECONDS_PER_SECOND,
    )


def resolution_payload(
    record: SessionRecord,
    connection: ConnectionDescriptor | None,
    outcome: ResolutionOutcome,
) -> dict[str, Any]:
    """The `ResolveSession` response body.

    The design's connection descriptor response plus :data:`RESOLUTION_FIELD`. `connection` is
    omitted rather than sent as null when none is available, because the Client_SDK and the
    Agent_Tool_Interface both read an absent `connection` as "not yet published" and poll
    `GetSession`; a null would be a third state each would have to learn (R9.16).

    `generation` is present for the same reason it is on `RefreshConnection`: it tells a caller which
    Sandbox behind a continuing Session it is now talking to, and it is the one field that changes
    across a continuation while the Session identifier does not (R6.24).
    """
    payload: dict[str, Any] = {
        "sessionId": record.session_id,
        "generation": record.generation,
        "lifecycleState": record.lifecycle_state.value,
        RESOLUTION_FIELD: outcome.value,
    }
    if connection is not None:
        payload["connection"] = connection.to_map()
    return payload


class LoserBranch(Enum):
    """What the loser does about the Session state it found.

    An enum rather than three predicates, so :data:`LOSER_BRANCHES` is a total mapping the import
    check below can verify against :class:`~control_plane.state.records.LifecycleState`. A state
    added to the lifecycle model without a decision recorded here fails the build, which is what
    keeps the design's branch table from silently acquiring a default.

    Public rather than private because the table *is* the design's documented behaviour, and a
    coverage claim over it should be assertable from outside this module without reaching into it.
    """

    #: A Sandbox exists and is reachable now: mint a fresh credential and return (R6.19, R6.20).
    RETURN_CREDENTIAL = "return-credential"
    #: Provisioning is in flight: wait on the winner's row, then mint (R6.19).
    WAIT_FOR_THE_WINNER = "wait-for-the-winner"
    #: The bound Session will never serve a request: treat the binding as absent (R6.21).
    TREAT_AS_ABSENT = "treat-as-absent"


LOSER_BRANCHES: Final[Mapping[LifecycleState, LoserBranch]] = {
    LifecycleState.RUNNING: LoserBranch.RETURN_CREDENTIAL,
    # R6.20: a credential, and the Session stays suspended. The first request the caller delivers to
    # the endpoint is what resumes it, so no resume is issued from here.
    LifecycleState.SUSPENDED: LoserBranch.RETURN_CREDENTIAL,
    LifecycleState.PENDING: LoserBranch.WAIT_FOR_THE_WINNER,
    LifecycleState.ORCHESTRATING: LoserBranch.WAIT_FOR_THE_WINNER,
    LifecycleState.PROVISIONING: LoserBranch.WAIT_FOR_THE_WINNER,
    LifecycleState.STARTING: LoserBranch.WAIT_FOR_THE_WINNER,
    # Transient: each resolves to RUNNING or to a terminal state, and the wait is what distinguishes
    # them. SUSPENDING in particular must not be treated as SUSPENDED — its Sandbox is mid-flush.
    LifecycleState.SUSPENDING: LoserBranch.WAIT_FOR_THE_WINNER,
    LifecycleState.RESUMING: LoserBranch.WAIT_FOR_THE_WINNER,
    LifecycleState.CONTINUING: LoserBranch.WAIT_FOR_THE_WINNER,
    # R6.21. TERMINATING is here rather than under the wait: it is not terminal, but it is one-way,
    # so waiting on it would spend a budget arriving at a Session that cannot serve the caller.
    LifecycleState.TERMINATING: LoserBranch.TREAT_AS_ABSENT,
    LifecycleState.TERMINATED: LoserBranch.TREAT_AS_ABSENT,
    LifecycleState.FAILED: LoserBranch.TREAT_AS_ABSENT,
}

if set(LOSER_BRANCHES) != set(
    LifecycleState
):  # pragma: no cover - import-time invariant
    missing = sorted(
        state.value for state in LifecycleState if state not in LOSER_BRANCHES
    )
    raise AssertionError(f"lifecycle states with no resolution branch: {missing}")


@dataclass(frozen=True, slots=True)
class _Recreate:
    """The loser found no Session that will serve this caller, so this resolution creates one.

    `over` names the Session the binding was found to hold, which becomes the replacement's
    condition (R6.21). `None` means the binding itself was gone, so the next attempt is a plain
    claim conditional on absence.
    """

    over: str | None


@dataclass(frozen=True, slots=True)
class ResolutionOperations(NotImplementedOperations):
    """The operation this task implements: `ResolveSession`, and no other.

    Inherits the remaining seven seams so the routes those tasks own keep answering `501` naming the
    task that fills them, which is the shape
    :class:`~control_plane.api.connection.ConnectionOperations` established. `CreateSession` is
    reached through :attr:`creation` rather than inherited, because the create branch needs the
    creation's *outcome* and not its response shape.

    Every collaborator is injected. There is no provider on this class and no mint: the credential a
    resolution returns comes from :class:`~control_plane.credentials.ConnectionIssuer`, the sole
    issuer, which takes the Session record and nothing else — so nothing here can widen a
    credential's port set or stretch its expiry.
    """

    creation: CreationOperations
    bindings: BindingStore
    lookup: SessionLookup
    issuer: ConnectionIssuer = field(default_factory=ConnectionIssuer)
    settings: BindingSettings = field(default_factory=BindingSettings)

    def resolve_session(self, request: OperationRequest) -> OperationResult:
        """Get-or-create by Affinity_Key: exactly one of resolve or create (R6.15).

        The first thing this does is attempt the claim, not read the binding (R6.18). The loop is
        the design's "re-enter the loser's path", made explicit and bounded.

        Raises:
            InvalidAffinityKey: the body names no hashable Affinity_Key.
            ResolutionDidNotSettle: contention did not converge inside the attempt bound.
            ConnectionUnavailable: the bound Session is the caller's own and live, but admits no
                credential — see :meth:`_mint_for`.
        """
        digest = digest_of_requested_affinity_key(request.body)
        recreate = _Recreate(over=None)
        for _ in range(MAX_CLAIM_ATTEMPTS):
            settled = self._attempt(request, digest=digest, recreate=recreate)
            if isinstance(settled, OperationResult):
                return settled
            recreate = settled
        raise ResolutionDidNotSettle(MAX_CLAIM_ATTEMPTS)

    # -- one attempt: claim, or lose and resolve --------------------------------------------

    def _attempt(
        self,
        request: OperationRequest,
        *,
        digest: str,
        recreate: _Recreate,
    ) -> OperationResult | _Recreate:
        """Attempt the claim; on a lost condition, resolve what is already bound.

        Nothing is read before the write. The claim either commits — in which case this resolution
        created the Session, bound the key and provisioned exactly one Sandbox — or its condition
        failed, which is the only circumstance under which the existing binding is worth reading.
        """
        try:
            created = self.creation.create(
                request.principal,
                request.body,
                write=self._claim(digest=digest, over=recreate.over),
                affinity_key_digest=digest,
            )
        except BindingConditionFailed:
            # Neither item committed, so there is no Session row and no execution to undo.
            return self._resolve_bound(request.principal, digest)
        return self._created(created)

    def _claim(self, *, digest: str, over: str | None) -> SessionRowWriter:
        """Return the writer that commits the Session row and the binding as one transaction.

        A closure over the digest and the condition, handed to
        :meth:`~control_plane.api.creation.CreationOperations.create` in place of the plain
        conditional `Put`. It receives the finished item, so it cannot alter what R6.6 requires to
        be written — only how, and under which condition, that item is committed.
        """

        def write(session_item: Mapping[str, Any]) -> None:
            # Parsed rather than picked apart: the binding's partition key, Session identifier and
            # deadline all come off the row that is about to be written, so the two items cannot
            # disagree about which Session in which partition this binding names.
            record = SessionRecord.from_item(session_item)
            binding_item = binding_for(record, digest, self.settings).to_item()
            if over is None:
                self.bindings.claim_binding(
                    session_item=session_item, binding_item=binding_item
                )
            else:
                self.bindings.replace_binding(
                    session_item=session_item,
                    binding_item=binding_item,
                    expected_session_id=over,
                )

        return write

    def _created(self, created: CreatedSession) -> OperationResult:
        """Render the create branch: the credential the orchestration published, never a mint.

        R6.13 requires a creation to return the credential read from the State_Store, and this is
        the branch that does. It is the one path through this module that does not reach the issuer.
        """
        status = (
            HTTPStatus.CREATED
            if created.connection is not None
            else HTTPStatus.ACCEPTED
        )
        return OperationResult(
            payload=resolution_payload(
                created.record, created.connection, ResolutionOutcome.CREATED
            ),
            status=status,
        )

    # -- the loser's path ---------------------------------------------------------------------

    def _resolve_bound(
        self, principal: AuthenticatedPrincipal, digest: str
    ) -> OperationResult | _Recreate:
        """Read the binding and the Session it names, and take that state's branch (R6.19).

        Both reads are issued at `pk_for(principal)`, so a binding recorded in another Tenant's
        partition is not something this code sees and declines to follow — it is something these
        credentials cannot address (R6.16, R11.11). No Tenant identifier is compared anywhere below.
        """
        partition_key = pk_for(principal)
        item = self.bindings.read_binding(
            partition_key=partition_key, sort_key=binding_sort_key(digest)
        )
        if item is None:
            # The binding lost a race and then vanished: deleted by cleanup, or replaced and
            # expired, between the failed condition and this read. Nothing to resolve and nothing to
            # replace, so the next attempt is a plain claim.
            return _Recreate(over=None)
        binding = AffinityKeyBindingRecord.from_item(item)

        bound = self._read_session(partition_key, binding.session_id)
        if bound is None:
            # R13.8's stale-binding self-heal. Correctness does not wait on a TTL: a binding naming
            # a Session that no longer exists is treated as absent the moment it is read, which is
            # what makes a best-effort 48-hour expiry acceptable.
            return _Recreate(over=binding.session_id)

        branch = LOSER_BRANCHES[bound.lifecycle_state]
        if branch is LoserBranch.TREAT_AS_ABSENT:
            return _Recreate(over=binding.session_id)
        if branch is LoserBranch.RETURN_CREDENTIAL:
            return self._resolved(bound)
        return self._wait_then_resolve(partition_key, bound)

    def _wait_then_resolve(
        self, partition_key: str, bound: SessionRecord
    ) -> OperationResult | _Recreate:
        """Wait on the winner's row, then mint against the row as it then stands (R6.19).

        The wait is :attr:`CreationOperations.wait` used verbatim — the same poll, the same interval
        and the same budget the winner is itself waiting on, which is why it was designed as a
        function of a Session row rather than of a request. Jitter matters here rather than
        decoratively: the loser polls the *same row* as the winner, so two unjittered waiters would
        poll in lockstep by construction.

        The published credential is the **readiness signal** and not the answer. Once it appears the
        row is re-read and a fresh credential is minted against it (R6.23), because the row now
        carries the Sandbox handle that the pre-publication read did not.
        """
        if self.creation.wait.await_connection(bound) is None:
            # The budget expired. The asynchronous response shape — a Session identifier with no
            # credential — which the SDK and the tool interface already read as "not yet published"
            # (R9.16). Never a `504`: that would carry no identifier and lose the Session.
            return OperationResult(
                payload=resolution_payload(bound, None, ResolutionOutcome.RESOLVED),
                status=HTTPStatus.ACCEPTED,
            )
        published = self._read_session(partition_key, bound.session_id)
        if published is None or LOSER_BRANCHES[published.lifecycle_state] is (
            LoserBranch.TREAT_AS_ABSENT
        ):
            # It reached a terminal state while this request waited. Re-enter with a replacement
            # conditional on that Session, which is the same treatment R6.21 gives a binding found
            # terminal on the first read.
            return _Recreate(over=bound.session_id)
        return self._resolved(published)

    def _resolved(self, record: SessionRecord) -> OperationResult:
        """Render the resolve branch: a freshly minted credential for the bound Session.

        Nothing here writes. A resolution of a `SUSPENDED` Session in particular returns a credential
        and leaves the Session suspended (R6.20), and the way that is guaranteed is that this method
        has nothing to write with — there is no store on this path and no provider call.
        """
        return OperationResult(
            payload=resolution_payload(
                record, self._mint_for(record), ResolutionOutcome.RESOLVED
            )
        )

    def _mint_for(self, record: SessionRecord) -> ConnectionDescriptor:
        """Mint a fresh credential through the sole issuer (R6.23).

        The record is the only argument, so this cannot widen the port set or stretch the expiry of
        what it receives; both are derived by the issuer from stored Session state.

        A Session the issuer refuses is reported as
        :class:`~control_plane.api.connection.ConnectionUnavailable`, a `409` naming the reason,
        reusing `RefreshConnection`'s answer to the same condition rather than inventing a second
        one. It is reachable only for a Session that is live by its lifecycle state and yet admits no
        credential — in practice one whose maximum duration elapsed before the Reaper terminated it.
        Creating a new Session instead would replace a binding that names a *non-terminal* Session,
        which is not what R6.21 licenses.
        """
        try:
            return self.issuer.issue(record)
        except ConnectionNotIssuable as exc:
            raise ConnectionUnavailable(exc.reason) from exc

    def _read_session(
        self, partition_key: str, session_id: str
    ) -> SessionRecord | None:
        """Read one Session row in the caller's own partition, or report that there is none.

        `None` rather than :class:`~control_plane.api.errors.SessionNotFound`, and the difference is
        the point: on this path an absent row is the stale-binding self-heal (R13.8) rather than an
        answer to the caller, who named no Session identifier at all. A row that is present but
        malformed is *not* absorbed — an item in the caller's own partition with the wrong shape is a
        defect in this system, and reporting it as a stale binding would hide a bug by quietly
        provisioning a second Sandbox.
        """
        item = self.lookup.read_session(
            partition_key=partition_key, sort_key=session_sort_key(session_id)
        )
        return None if item is None else SessionRecord.from_item(item)
