# kiro-classification: public
"""The Sandbox claim ledger: one conditional write is the whole of tenant-level exclusivity.

R11.1 requires a distinct Sandbox per Session and forbids allocating one Sandbox to more than one
Session. R11.10 sharpens it into the non-reuse rule: a Sandbox that has executed Untrusted_Code is
allocated to no subsequent Session. Both are enforced here, and the mechanism is deliberately not a
read followed by a decision.

**Why a conditional write and not a check.** A read-then-write is two operations, and between them
a second caller can read the same absence and reach the same conclusion. No amount of care at the
call site closes that window, because the window is in the store rather than in the code. So the
ledger writes the claim item at `H#<providerName>#<sandboxId>` / `CLAIM` under
`attribute_not_exists(pk)` and lets the store arbitrate: at most one write succeeds, and the loser is
told it lost. Exclusivity is therefore a property of one operation, and :meth:`SandboxClaimLedger.
claim` has no code path that could conclude "no claim exists" and be wrong by the time it acts.

The partition key names a provider and a Sandbox rather than a Tenant, and that is the point. The
uniqueness R11.10 requires holds across Sessions and therefore across Tenants, which no
Tenant-partitioned item can express: two Tenants claiming one Sandbox identifier must collide, and
items in two different Tenant partitions never do. This is the one key shape outside a Tenant
partition, which is why :func:`~control_plane.state.keys.claim_partition_key` builds it and
:func:`~control_plane.tenancy.partition.pk_for` — the sole producer of a *Tenant* partition key —
is not involved. The claim's `tenantId` is a recorded attribute, not a key component.

**What the loser receives, and why the ledger terminates for it.** A caller that lost the race is
holding a Sandbox it provisioned and will now never use. Left alone it runs until the provider's own
maximum duration expires, and it is billable for every second of that. Raising
:class:`SandboxAlreadyClaimed` and trusting the caller to clean up would make the leak depend on
every call site remembering, which is the same class of mistake the conditional write exists to
remove. So the ledger terminates the duplicate itself, *before* the exception is raised, and reports
the outcome on :attr:`SandboxAlreadyClaimed.termination`. Termination is attempted exactly once and
its failure does not replace the exception the caller needs to see; a failed termination is recorded
on the exception instead, and the Reaper is the backstop that finds the Sandbox by its tags. That is
the second reason R11.7's tags are a precondition of a claim rather than metadata: a duplicate whose
termination failed is reachable only through
:meth:`~control_plane.providers.base.ComputeProvider.discover`, and `discover` matches on tags.

**Eligibility is three-valued and one-way.** :class:`~control_plane.state.records.Eligibility`
distinguishes a Sandbox that has never executed anything from one that has, because a future
pre-warmed pool may hold only the former and the distinction has to survive in the ledger for that
to be checkable. `never-run → used` at the moment `/run` is invoked; either state → `quarantined`;
no edge back. Each transition is its own conditional update, so an out-of-order call fails at the
store rather than silently moving a Sandbox backwards.

**Eligibility for allocation is not eligibility on the claim.** :func:`is_allocatable` answers the
allocation question, and it answers `False` for *any* existing claim regardless of its
`eligibility` value. That is R11.10: a claimed Sandbox has been allocated once, so it is never
allocated again, whether it ran, whether it was quarantined, whether it merely was claimed and the
Session died before `/run`. The quarantine markers are belt-and-braces given that — they exist
because R11.12 and R11.13 are stated as allocation rules and because a pool would need them to be
real — and treating them as the allocation gate would be a weaker rule than the one that already
holds.

**What this module does not do.** It does not provision. Allocation observes a Sandbox that already
exists, and `provision` lives behind the Compute_Provider seam under a lint rule that keeps every
initiation of it inside a started Session_Orchestrator execution. It does not mint credentials;
`control_plane/credentials.py` is the sole issuer, also under a lint rule. It writes no TTL
attribute: the claim item is the only record that a billable Sandbox was ever allocated to a
Session, so letting expiry reach it would delete the evidence of the very leak the Reaper uses it to
find.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from control_plane.allocation.quarantine import (
    DenialReason,
    Quarantine,
)
from control_plane.allocation.tags import require_attribution
from control_plane.providers.base import SandboxHandle, SandboxState, SandboxStatus
from control_plane.state.keys import claim_partition_key
from control_plane.state.records import Eligibility, SandboxClaimRecord

__all__ = [
    "ELIGIBILITY_ATTRIBUTE",
    "QUARANTINE_REASON_ATTRIBUTE",
    "ClaimConditionFailed",
    "ClaimItemStore",
    "DuplicateTermination",
    "SandboxAlreadyClaimed",
    "SandboxClaimLedger",
    "SandboxNotClaimed",
    "SandboxTerminator",
    "claim_key_for",
    "is_allocatable",
]

#: The attribute the eligibility transitions write. Named here so the ledger and a store
#: implementation's condition expression cannot disagree about which attribute they guard.
ELIGIBILITY_ATTRIBUTE: Final = "eligibility"

#: The attribute carrying the quarantine reason, and therefore its trigger. Guarded by
#: `attribute_not_exists` on every quarantine, which is what makes the first reason the one that
#: survives.
QUARANTINE_REASON_ATTRIBUTE: Final = "quarantineReason"


def claim_key_for(handle: SandboxHandle) -> str:
    """Return the claim item's partition key for a Sandbox, from its handle alone.

    A handle already carries the provider name and the Sandbox identifier, so the key is derived
    rather than passed alongside it. A caller cannot supply a key that names a different Sandbox
    from the one it is about to claim, because it does not supply a key.
    """
    return claim_partition_key(handle.provider_name, handle.sandbox_id)


def is_allocatable(claim: SandboxClaimRecord | None) -> bool:
    """Whether a Sandbox with this claim state may be allocated to a Session (R11.1, R11.10).

    `True` only for `None`. An existing claim — of any eligibility — means this Sandbox has already
    been allocated once, and R11.10 admits no second allocation. Written as a function over the
    claim rather than as a method on the ledger so the rule is stated in one expression that a
    property test can quantify over without a store.
    """
    return claim is None


class ClaimConditionFailed(Exception):
    """A conditional write on a claim item found the store in a state the condition excluded.

    This is DynamoDB's `ConditionalCheckFailedException` at this seam, and it is raised by a
    :class:`ClaimItemStore` implementation rather than by the ledger. Keeping it distinct from
    :class:`SandboxAlreadyClaimed` matters: this one says only that a condition did not hold, and
    the ledger is what decides which requirement that failure means and what has to happen to a
    Sandbox as a result.
    """


@dataclass(frozen=True, slots=True)
class DuplicateTermination:
    """What became of the Sandbox a losing caller provisioned and will never use.

    Carried on :class:`SandboxAlreadyClaimed` so the loser learns both facts at once: it did not get
    the claim, and this is what happened to its Sandbox. `terminated` false with `failure` set is
    the case an operator has to be able to see — the Sandbox is still billable and the Reaper is now
    the thing that will find it, by the tags R11.7 requires.
    """

    handle: SandboxHandle
    terminated: bool
    state: SandboxState | None = None
    failure: str | None = None

    @property
    def leaked(self) -> bool:
        """Whether a billable Sandbox outlived the failed claim and needs the Reaper."""
        return not self.terminated


class SandboxAlreadyClaimed(Exception):
    """This Sandbox is already claimed by a Session, so it is allocated to no other (R11.1, R11.10).

    Raised only after the duplicate has been dealt with, so a caller catching it never has an
    obligation it could forget. :attr:`termination` says what happened; :attr:`claimed_by_session_id`
    names the Session that holds the claim, which is safe to report here because both Sessions are
    the ledger's own callers inside one orchestration and no part of this reaches an API response.
    """

    def __init__(
        self,
        *,
        partition_key: str,
        attempted_session_id: str,
        claimed_by_session_id: str,
        termination: DuplicateTermination,
    ) -> None:
        super().__init__(
            f"Sandbox at {partition_key!r} is already claimed by Session "
            f"{claimed_by_session_id!r}, so it is not allocated to {attempted_session_id!r} "
            f"(R11.1, R11.10); the duplicate was "
            f"{'terminated' if termination.terminated else 'NOT terminated'}"
        )
        self.partition_key = partition_key
        self.attempted_session_id = attempted_session_id
        self.claimed_by_session_id = claimed_by_session_id
        self.termination = termination


class SandboxNotClaimed(Exception):
    """An eligibility transition named a Sandbox that holds no claim.

    A programming error rather than an operational condition. Marking a Sandbox used, or
    quarantining it, presupposes that it was allocated to a Session; if no claim exists there is no
    allocation to constrain and nothing the transition could protect. Refusing is what stops a
    quarantine from creating a claim item for a Sandbox no Session ever held.
    """

    def __init__(self, partition_key: str) -> None:
        super().__init__(f"no claim item exists at {partition_key!r}")
        self.partition_key = partition_key


class SandboxTerminator(Protocol):
    """The one provider operation the ledger performs: terminating a duplicate.

    Narrowed to a single method on purpose. The ledger is handed the ability to stop a Sandbox and
    nothing else — it cannot provision, cannot suspend, cannot mint a credential — so the blast
    radius of the claim path is visible in this type.
    :class:`~control_plane.providers.base.ComputeProvider` satisfies it structurally, which is why
    no adapter exists.
    """

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Terminate a Sandbox. Idempotent on an already terminal Sandbox."""
        ...


class ClaimItemStore(Protocol):
    """The three writes and one read the ledger performs on claim items.

    A structural type, so the offline suite drives the whole ledger against an in-memory store keyed
    as DynamoDB is, with no deployed resource and no network. Every method's contract is stated as
    the condition expression it carries, because the conditions *are* the guarantees: an
    implementation that dropped one would still satisfy the signatures and would break exclusivity,
    so the conditions are written down here rather than left to the implementation to remember.

    Reached with the orchestrator's own role rather than a per-request tenant-confined credential.
    The claim item lives outside every Tenant partition, so a `dynamodb:LeadingKeys` condition
    cannot address it; a claim is never read or written on behalf of a caller, and nothing it holds
    is returned to one.
    """

    def put_claim_if_absent(self, item: Mapping[str, Any]) -> None:
        """`Put` the claim item under `ConditionExpression: attribute_not_exists(pk)`.

        Raises:
            ClaimConditionFailed: an item already exists at this key. This is the only
                arbitration of exclusivity in the system; an implementation that writes
                unconditionally makes R11.1 and R11.10 unenforceable.
        """
        ...

    def read_claim(self, *, partition_key: str) -> Mapping[str, Any] | None:
        """Return the stored claim item, or `None` when none exists."""
        ...

    def mark_claim_used(self, *, partition_key: str) -> None:
        """`SET eligibility = used`, conditional on the claim existing and being `never-run`.

        `ConditionExpression: attribute_exists(pk) AND eligibility = :never_run`. The condition is
        what makes the transition one-way: a second call, or a call against a quarantined claim,
        fails rather than overwriting the recorded state.

        Raises:
            ClaimConditionFailed: no claim exists, or its eligibility is not `never-run`.
        """
        ...

    def quarantine_claim(self, *, partition_key: str, reason: str) -> None:
        """`SET eligibility = quarantined, quarantineReason = :reason`, first writer only.

        `ConditionExpression: attribute_exists(pk) AND attribute_not_exists(quarantineReason)`. The
        second half is deliberate and is explained on
        :meth:`SandboxClaimLedger.quarantine_for_session_failure`: the earliest reason is the
        diagnostic one and a later quarantine must not overwrite it.

        Raises:
            ClaimConditionFailed: no claim exists, or the claim is already quarantined.
        """
        ...


@dataclass(frozen=True, slots=True)
class SandboxClaimLedger:
    """The claim ledger: allocate a Sandbox to a Session once, and record what it did afterwards.

    Both collaborators are injected and both are structural types, so the whole of allocation is
    exercised offline. The terminator is held for exactly one purpose — the duplicate a lost race
    leaves behind — and the ledger reaches for it on no other path.
    """

    store: ClaimItemStore
    terminator: SandboxTerminator

    def read(self, handle: SandboxHandle) -> SandboxClaimRecord | None:
        """Return the claim recorded against this Sandbox, or `None` when it holds none."""
        item = self.store.read_claim(partition_key=claim_key_for(handle))
        return None if item is None else SandboxClaimRecord.from_item(item)

    def is_allocatable(self, handle: SandboxHandle) -> bool:
        """Whether this Sandbox may be allocated to a Session (R11.1, R11.10).

        A convenience over :func:`is_allocatable` and *not* a precondition of :meth:`claim`. Asking
        first is advisory only: the answer can be stale by the time it is acted on, which is exactly
        why the claim is a conditional write. Nothing in this module calls it before claiming.
        """
        return is_allocatable(self.read(handle))

    def claim(
        self,
        *,
        handle: SandboxHandle,
        session_id: str,
        tenant_id: str,
        tags: Mapping[str, str],
        claimed_at: int,
    ) -> SandboxClaimRecord:
        """Allocate this Sandbox to this Session, or refuse and terminate the duplicate.

        `tags` are the tags the Sandbox was provisioned with. They are checked against `tenant_id`
        and `session_id` before the write, so a Sandbox cannot become the recorded Sandbox of a
        Session unless its own tags agree with the claim: the provider side and the State_Store side
        are two independent records of the same attribution, and a claim is the moment they must
        match (R11.7). A disagreement is refused here, where nothing has been attributed yet and
        there is therefore nothing to reconcile.

        Returns:
            The claim as written, with `eligibility = never-run`.

        Raises:
            SandboxNotAttributable: the tags do not attribute the Sandbox to this Tenant and this
                Session.
            SandboxAlreadyClaimed: another Session holds the claim. The Sandbox behind `handle` has
                been terminated, or the failure to terminate it is recorded on the exception.
        """
        require_attribution(tags, tenant_id=tenant_id, session_id=session_id)
        record = SandboxClaimRecord(
            pk=claim_key_for(handle),
            session_id=session_id,
            tenant_id=tenant_id,
            claimed_at=claimed_at,
            eligibility=Eligibility.NEVER_RUN,
        )
        try:
            self.store.put_claim_if_absent(record.to_item())
        except ClaimConditionFailed as failure:
            raise self._lost_the_race(
                handle=handle, attempted_session_id=session_id
            ) from failure
        return record

    def mark_used(self, handle: SandboxHandle) -> None:
        """Record that Untrusted_Code has executed in this Sandbox (`never-run → used`).

        Called at the moment `/run` is invoked, which is the one-way transition the design's pool
        constraint names. It changes nothing about allocation — the Sandbox was already
        unallocatable the instant its claim existed — and exists so that a future pool can tell a
        never-executed Sandbox from a used one without inventing a second record.

        Raises:
            SandboxNotClaimed: this Sandbox holds no claim, so nothing executed in an allocated
                Sandbox.
            ClaimConditionFailed: the claim is no longer `never-run`. A repeat call and a call
                against a quarantined claim both land here rather than moving the claim backwards.
        """
        partition_key = claim_key_for(handle)
        try:
            self.store.mark_claim_used(partition_key=partition_key)
        except ClaimConditionFailed:
            # Distinguish "no claim at all" from "a claim in the wrong state". The read happens only
            # on this already-exceptional path, so the ordinary transition stays one write.
            if self.store.read_claim(partition_key=partition_key) is None:
                raise SandboxNotClaimed(partition_key) from None
            raise

    def quarantine_for_denial(
        self, handle: SandboxHandle, reason: DenialReason
    ) -> Quarantine:
        """Quarantine after an egress denial attributable to attempted circumvention (R11.12).

        Raises:
            DenialIsNotCircumvention: `reason` is outside the closed circumvention subset. The
                ordinary undeclared-destination denial quarantines nothing, and refusing here is
                what keeps the subset closed at runtime as well as in the enum.
            SandboxNotClaimed: this Sandbox holds no claim.
        """
        return self._record(handle, Quarantine.for_denial(reason))

    def quarantine_for_session_failure(self, handle: SandboxHandle) -> Quarantine:
        """Quarantine on a recorded Session failure (R11.13).

        Written by the orchestrator in the same step that writes `FAILED` to the Session row, so any
        Session recorded `FAILED` has a quarantined claim item and the pair can be asserted directly.

        Raises:
            SandboxNotClaimed: this Sandbox holds no claim.
        """
        return self._record(handle, Quarantine.for_session_failure())

    def quarantine_of(self, handle: SandboxHandle) -> Quarantine | None:
        """Return the quarantine recorded against this Sandbox, trigger included, or `None`.

        The trigger is recovered from the stored reason rather than read from a second attribute:
        the two vocabularies are disjoint, so the reason identifies which of R11.12 and R11.13
        fired. That is what keeps the two triggers distinguishable after the fact without the
        ledger storing the same fact twice and risking the two copies disagreeing.
        """
        claim = self.read(handle)
        if claim is None or claim.eligibility is not Eligibility.QUARANTINED:
            return None
        if claim.quarantine_reason is None:  # pragma: no cover - the record forbids it
            raise SandboxNotClaimed(claim.pk)
        return Quarantine.from_recorded_reason(claim.quarantine_reason)

    def _record(self, handle: SandboxHandle, quarantine: Quarantine) -> Quarantine:
        """Apply a quarantine, letting the first recorded reason stand.

        The first reason wins, and that is a decision rather than an accident of the condition
        expression. A Session whose Untrusted_Code attempted circumvention very often also fails, so
        R11.13's trigger tends to arrive second; if a later quarantine overwrote the reason, the
        security-relevant fact would be replaced by `session-failed` in precisely the cases an
        operator most needs to see it. The Sandbox is equally unallocatable either way, so nothing is
        lost by keeping the earlier reason and the more informative record is kept.
        """
        partition_key = claim_key_for(handle)
        try:
            self.store.quarantine_claim(
                partition_key=partition_key, reason=quarantine.reason
            )
        except ClaimConditionFailed:
            item = self.store.read_claim(partition_key=partition_key)
            if item is None:
                raise SandboxNotClaimed(partition_key) from None
            existing = SandboxClaimRecord.from_item(item)
            if existing.quarantine_reason is None:
                raise
            return Quarantine.from_recorded_reason(existing.quarantine_reason)
        return quarantine

    def _lost_the_race(
        self, *, handle: SandboxHandle, attempted_session_id: str
    ) -> SandboxAlreadyClaimed:
        """Terminate the duplicate, then build the exception describing both facts.

        Ordered deliberately: the Sandbox is dealt with before the caller is told anything, so there
        is no window in which a caller has the exception and the duplicate is still running because
        somebody's `except` block had not reached its cleanup yet.
        """
        partition_key = claim_key_for(handle)
        termination = self._terminate_duplicate(handle)
        item = self.store.read_claim(partition_key=partition_key)
        winner = (
            SandboxClaimRecord.from_item(item).session_id
            if item is not None
            # The claim was deleted between the failed write and this read. Nothing to name, and
            # inventing a Session identifier would be worse than saying so.
            else "<unknown>"
        )
        return SandboxAlreadyClaimed(
            partition_key=partition_key,
            attempted_session_id=attempted_session_id,
            claimed_by_session_id=winner,
            termination=termination,
        )

    def _terminate_duplicate(self, handle: SandboxHandle) -> DuplicateTermination:
        """Stop the Sandbox nobody will use, exactly once, and report what happened.

        Every exception is caught, and that is the unusual choice worth defending. The caller's
        problem is that it lost the claim; replacing that with a provider error would hide the
        requirement being enforced behind a transport failure, and retrying here would hold a
        request open on the one path where the answer is already known. So the failure is recorded
        on the exception and the Sandbox becomes the Reaper's, which is reachable because R11.7 put
        the Tenant and Session tags on it.
        """
        try:
            status = self.terminator.terminate(handle)
        except Exception as error:  # noqa: BLE001 - the loser's error must not mask R11.1
            return DuplicateTermination(
                handle=handle,
                terminated=False,
                failure=f"{type(error).__name__}: {error}",
            )
        terminal = status.state in (SandboxState.TERMINATING, SandboxState.TERMINATED)
        return DuplicateTermination(
            handle=handle,
            terminated=terminal,
            state=status.state,
            failure=None
            if terminal
            else f"terminate returned state {status.state.value}, which is not terminal",
        )
