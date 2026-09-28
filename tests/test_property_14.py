# kiro-classification: public
"""Property 14: Sandbox allocation is exclusive and attributed.

Two words carry R11.1 and R11.7, and this property is one claim about both because the second is
the reason the first is recoverable. *Exclusive*: a Sandbox is claimed by at most one Session, ever,
and the Session that lost does not walk away holding a billable duplicate. *Attributed*: every
Sandbox that becomes the recorded Sandbox of a Session carries the owning Tenant identifier as a tag
together with its Session identifier — which is what lets the Reaper reach the duplicate whose
termination failed, since `discover` matches on tags and on nothing else.

`test_allocation_claim_ledger.py` pins the mechanism example by example. What is generalised here is
the *domain*: how many Sessions compete for one Sandbox, in what order they arrive, which Tenants
they belong to, what shape their identifiers take, whether the Sandbox they present was tagged by
the sole producer or by something else, and what the provider does when asked to stop the duplicate.

## Competing claims, modelled as a drawn schedule rather than as a race

No thread is started and no clock is read. The schedule *is* the interleaving: a drawn permutation
of the batch's claim attempts and quarantine events, executed one at a time against one shared
:class:`~tests.test_allocation_claim_ledger.FakeClaimStore`. That is a faithful model rather than a
convenient one, because the arbitration under test is a single conditional write — `Put` under
`attribute_not_exists(pk)` — and a store serialises those whatever the callers were doing. Every
distinguishable outcome of a real race is therefore some drawn order of atomic attempts, and a
threaded version would add scheduler noise without adding a reachable state. The losers' Sandboxes
exist before any claim is attempted, so each loser is a caller that has already provisioned and is
holding something billable, which is the situation the termination exists for.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| the number of Sandboxes in the batch, and the contention degree on each (1 to 3) | a Sandbox claimed once, and one claimed by up to three Sessions |
| a mixture of Tenants across the competing attempts | a Sandbox reused across Tenants and a Sandbox reused within one Tenant, both as failures the property would catch |
| a permutation of every claim attempt and quarantine event | that the winner is whichever attempt arrives first, rather than the one this file expects |
| one Sandbox identifier under two provider names | that the claim key names a provider, so two backends' Sandboxes do not collide |
| Tenant and Session identifiers carrying `:`, `=`, `,`, the key separator, non-ASCII text, an astral-plane character, and 300 characters | that the attribution survives values a flattened `tenant:session` or `k=v,k=v` tag encoding would confuse |
| the tag defect on each attempt: absent keys, an empty value, padded values, swapped values, a map naming another Tenant or another Session, and an `extra` tag trying to override the pair | that no path allocates a Sandbox this Tenant and Session cannot be read back off |
| what `terminate` does to the duplicate: terminated, terminating, still running, or raising | both the terminated case and the leaked case, where the tags are the only remaining handle on it |
| a quarantine event on a claimed Sandbox, an unclaimed one, a second one after the first, and one carrying a reason outside the closed circumvention subset | R11.1 and R11.7 where R11.12 reaches them: a quarantine writes no second claim and rewrites no attribution |

Session identifiers are unique per attempt, because a batch of Session creations is a batch of
*new* Sessions; that is what makes "no Sandbox handle appears on more than one Session record"
assertable in both directions rather than only one. Tenant identifiers are deliberately not unique,
because the mixture is the point.

## What is asserted, at every step of every schedule

- **Exactly one claim commits per Sandbox** (R11.1). Counted over the schedule: at most one attempt
  on a given claim key returns, and exactly one does whenever any attempt on it was attributable.
- **Every loser is refused by name, and the winner is untouched.** The refusal carries the claim
  key, the attempting Session and the Session that holds the claim, and the whole store is
  byte-identical afterwards — so a loser cannot overwrite, append or renumber.
- **The duplicate is terminated inside the failing call, exactly once.** Asserted from the
  provider's log rather than from the exception's own account, and asserted to be one call whatever
  the drawn provider behaviour was. When the drawn behaviour leaves the Sandbox running or raises,
  the refusal still reaches the caller, the leak is reported on it, and the leaked Sandbox's tags
  still read back as this Tenant and this Session — which is the operational half of R11.7 stated
  where it matters.
- **Nothing untagged is ever allocated** (R11.7). Every attempt whose tags do not attribute the
  Sandbox to exactly the claiming Tenant and Session is refused with nothing written and nothing
  terminated, and every claim item that exists at the end names the Tenant and Session the tags on
  its Sandbox name, recovered through :func:`~control_plane.allocation.attribution_of` rather than
  compared field by field.
- **A quarantine changes neither the count of claims nor the attribution on one.**

The expectation for each step is derived from a local restatement of R11.7,
:func:`attributes_correctly`, rather than from `require_attribution`; a property that asked the code
under test what it should do would pass against any code.
:func:`test_the_attribution_restatement_agrees_with_the_implementation` checks the restatement
against the implementation over a stated table, which is where the two are allowed to meet.

## Where the boundary against Properties 13 and 39 runs

Property 39 (task 6.15) owns R11.10, R11.12 and R11.13: reallocation across time, the eligibility
transitions, and the quarantine triggers as *allocation* rules. So nothing here reads
`eligibility`, calls `mark_used`, or asserts that a quarantined Sandbox is unallocatable. What is
asserted about a quarantine is only what R11.1 and R11.7 reach: it creates no second claim, deletes
none, and leaves the recorded Tenant and Session exactly as they were. The closed circumvention
subset appears in the same narrow sense — a reason outside it is refused and writes nothing, so a
denial cannot invent a claim — with the subset's composition and its two triggers left to 39.

Property 13 (task 6.17) owns R11.2 and R11.3: Tenant partition confinement, and the identity of
responses across Tenants. Nothing here asserts anything about a Tenant partition key or about what
a caller can read. Where two Tenants meet in this file they meet on one *claim* key, which sits
outside every Tenant partition precisely so that the collision R11.1 needs can happen at all.

## Non-vacuity

:func:`test_every_bucket_is_reachable_and_the_property_holds_on_each` runs the same checker over an
enumerated case for every bucket the generator can produce, and asserts all of them are reached, so
no arm of the checker is dead.
:func:`test_the_assertions_discriminate_three_plausible_wrong_allocations` asserts that three wrong
implementations disagree with what the ledger does on cases this property draws: an unconditional
write, a refusal that leaves the duplicate running, and a claim that trusts the tags it is handed.
:func:`test_identifier_pairs_that_collide_under_a_naive_encoding_stay_distinct` pins the pair the
identifier pool exists for.

## Budget

200 examples. Each one runs up to nine claim attempts and three quarantine events against an
in-memory dict with a stub terminator: no thread, no subprocess, no filesystem, no network and no
wall-clock read, so the whole property runs in well under a second. Above the design's floor of 100
because the drawn dimensions multiply — contention degree crossed with eleven tag defects crossed
with four provider behaviours — and a hundred examples would leave several defects unvisited on a
given run.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Final

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.allocation import (
    CIRCUMVENTION_REASONS,
    NON_CIRCUMVENTION_REASONS,
    SESSION_TAG_KEY,
    TENANT_TAG_KEY,
    DenialIsNotCircumvention,
    DenialReason,
    SandboxAlreadyClaimed,
    SandboxClaimLedger,
    SandboxNotAttributable,
    SandboxNotClaimed,
    attribution_of,
    claim_key_for,
    sandbox_tags,
)
from control_plane.providers.base import (
    SandboxHandle,
    SandboxState,
    SandboxStatus,
)
from control_plane.state.keys import CLAIM_SORT_KEY, SEPARATOR
from control_plane.state.records import Eligibility
from tests.test_allocation_claim_ledger import FakeClaimStore

#: Epoch milliseconds. Every claim timestamp is this plus the step's position, so ordering is
#: arithmetic over the drawn schedule and no clock is read.
NOW_MS: Final = 1_700_000_000_000

#: The two provider names the batch draws over. Two are enough for the claim that one Sandbox
#: identifier under two backends is two Sandboxes, and a third would add no reachable state.
PROVIDER_POOL: Final = ("lambda-microvms", "local-firecracker")

#: Sandbox identifiers. Separator-free and non-empty, because they are key components; the awkward
#: values belong on the Tenant and Session axes, which are attributes rather than key components.
SANDBOX_ID_POOL: Final = ("sbx-1", "sbx-2", "sbx-pooled")

#: Identifiers worth drawing by name, every one of them a value a naive tag encoding mangles: the
#: two halves of a `tenant:session` collision, text spelled like a `k=v` pair and like a tag key,
#: the State_Store key separator, non-ASCII text, an astral-plane character, and 300 characters. No
#: member is empty or carries edge whitespace — those are drawn on the defect axis instead, because
#: the sole tag producer refuses to build a map from them at all.
IDENTIFIER_POOL: Final = (
    "tenant-a",
    "tenant-b",
    "a",
    "a:b",
    "b:c",
    "c",
    f"{TENANT_TAG_KEY}=forged",
    f"{SESSION_TAG_KEY}=forged,{TENANT_TAG_KEY}=forged",
    f"S{SEPARATOR}01JLOOKSLIKEASESSIONROWKEY",
    "会話-9f3",
    "\U0001f600",
    "x" * 300,
)

#: Below this length an identifier occurs inside ordinary item content by coincidence, so the
#: "longer than a short string" bucket is claimed only well above it.
LONG_IDENTIFIER_LENGTH: Final = 256


class Defect(enum.StrEnum):
    """What is wrong with the tags on the Sandbox an attempt presents, if anything.

    Every member other than :attr:`NONE` describes a Sandbox tagged by something that is not
    :func:`~control_plane.allocation.sandbox_tags`, which is the case the claim-time guard exists
    for: the provider side and the State_Store side are two independent records of one attribution,
    and a claim is the moment they must agree.
    """

    #: Tags built by the sole producer, agreeing with the claim.
    NONE = "none"
    #: The Session tag names a different Session.
    OTHER_SESSION = "the Session tag names another Session"
    #: The Tenant tag names a different Tenant.
    OTHER_TENANT = "the Tenant tag names another Tenant"
    #: The Tenant tag is absent.
    MISSING_TENANT = "the Tenant tag is absent"
    #: The Session tag is absent.
    MISSING_SESSION = "the Session tag is absent"
    #: No tags at all — the Sandbox the Reaper could never find.
    NO_TAGS = "there are no tags at all"
    #: The Tenant tag is present and empty.
    EMPTY_TENANT = "the Tenant tag is empty"
    #: The Session tag carries trailing whitespace, so it matches under one provider's filter and
    #: not another's.
    PADDED_SESSION = "the Session tag carries edge whitespace"
    #: The two values are in each other's keys.
    SWAPPED = "the two tag values are swapped"
    #: The claim itself names an empty Tenant, so the malformed side is the ledger's caller.
    CLAIM_TENANT_EMPTY = "the claim names an empty Tenant"
    #: An `extra` operator tag attempts to override an attribution key, so the sole producer refuses
    #: before any claim is attempted.
    EXTRA_OVERRIDES = "an extra tag overrides the attribution pair"


class Termination(enum.StrEnum):
    """What the provider does when the ledger asks it to stop a duplicate."""

    TERMINATED = "terminated"
    TERMINATING = "terminating"
    STILL_RUNNING = "still-running"
    RAISES = "raises"

    @property
    def is_terminal(self) -> bool:
        """Whether this outcome means the duplicate stopped being billable."""
        return self in (Termination.TERMINATED, Termination.TERMINATING)


_TERMINAL_STATES: Final = {
    Termination.TERMINATED: SandboxState.TERMINATED,
    Termination.TERMINATING: SandboxState.TERMINATING,
    Termination.STILL_RUNNING: SandboxState.RUNNING,
}


@dataclass
class DrawnTerminator:
    """The one provider operation the ledger performs, with the drawn outcome.

    Local rather than imported: the deterministic suite's terminator keys its log on the Sandbox
    identifier alone, and this property draws one identifier under two provider names. Recording the
    pair is what lets "the duplicate was terminated" name a Sandbox rather than a string two
    backends share. Consolidating the two into the harness is a later change.
    """

    behaviour: Termination
    log: list[tuple[str, str]] = field(default_factory=list)

    def terminate(self, target: SandboxHandle) -> SandboxStatus:
        """Record the call, then behave as drawn."""
        self.log.append((target.provider_name, target.sandbox_id))
        if self.behaviour is Termination.RAISES:
            raise TimeoutError("provider did not answer")
        return SandboxStatus(
            handle=target,
            state=_TERMINAL_STATES[self.behaviour],
            memory_bytes=0,
            # No clock: a started_at nobody asserts on would be the only wall-clock read here.
            started_at=None,
            state_reason=None,
        )


@dataclass(frozen=True, slots=True)
class ClaimStep:
    """One Session's attempt to claim one Sandbox, with the tags that Sandbox carries."""

    provider: str
    sandbox_id: str
    tenant_id: str
    session_id: str
    defect: Defect = Defect.NONE
    operator_tag: bool = False

    @property
    def handle(self) -> SandboxHandle:
        return SandboxHandle(
            provider_name=self.provider, sandbox_id=self.sandbox_id, opaque={}
        )

    @property
    def claimed_tenant_id(self) -> str:
        """The Tenant the claim names, which the defect axis is allowed to break."""
        return "" if self.defect is Defect.CLAIM_TENANT_EMPTY else self.tenant_id

    def build_tags(self) -> dict[str, str]:
        """The tags the Sandbox carries, from the sole producer where a defect permits it.

        Raises:
            SandboxNotAttributable: the defect is one the sole producer refuses to build at all,
                which is :attr:`Defect.EXTRA_OVERRIDES`.
        """
        extra = {"costCentre": "cc-7"} if self.operator_tag else None
        if self.defect is Defect.EXTRA_OVERRIDES:
            return sandbox_tags(
                tenant_id=self.tenant_id,
                session_id=self.session_id,
                extra={TENANT_TAG_KEY: "forged"},
            )
        if self.defect in (Defect.NONE, Defect.CLAIM_TENANT_EMPTY):
            return sandbox_tags(
                tenant_id=self.tenant_id, session_id=self.session_id, extra=extra
            )
        # Every remaining defect is a Sandbox tagged by something other than the producer, so the
        # map is spelled out rather than built.
        forged = {
            Defect.OTHER_SESSION: {
                TENANT_TAG_KEY: self.tenant_id,
                SESSION_TAG_KEY: f"{self.session_id}-other",
            },
            Defect.OTHER_TENANT: {
                TENANT_TAG_KEY: f"{self.tenant_id}-other",
                SESSION_TAG_KEY: self.session_id,
            },
            Defect.MISSING_TENANT: {SESSION_TAG_KEY: self.session_id},
            Defect.MISSING_SESSION: {TENANT_TAG_KEY: self.tenant_id},
            Defect.NO_TAGS: {},
            Defect.EMPTY_TENANT: {
                TENANT_TAG_KEY: "",
                SESSION_TAG_KEY: self.session_id,
            },
            Defect.PADDED_SESSION: {
                TENANT_TAG_KEY: self.tenant_id,
                SESSION_TAG_KEY: f"{self.session_id} ",
            },
            Defect.SWAPPED: {
                TENANT_TAG_KEY: self.session_id,
                SESSION_TAG_KEY: self.tenant_id,
            },
        }[self.defect]
        return dict(forged)


@dataclass(frozen=True, slots=True)
class QuarantineStep:
    """One quarantine event against one Sandbox: a denial reason, or a recorded Session failure."""

    provider: str
    sandbox_id: str
    reason: DenialReason | None = None

    @property
    def handle(self) -> SandboxHandle:
        return SandboxHandle(
            provider_name=self.provider, sandbox_id=self.sandbox_id, opaque={}
        )


Step = ClaimStep | QuarantineStep


@dataclass(frozen=True, slots=True)
class AllocationCase:
    """One batch of Session creations, one arrival order, and one provider behaviour."""

    schedule: tuple[Step, ...]
    termination: Termination = Termination.TERMINATED

    def buckets(self) -> frozenset[str]:
        """The buckets this case occupies before a single step has run."""
        claims = [step for step in self.schedule if isinstance(step, ClaimStep)]
        sandboxes = {(step.provider, step.sandbox_id) for step in claims}
        buckets = {
            "batch: one Sandbox" if len(sandboxes) == 1 else "batch: several Sandboxes"
        }
        buckets.add(f"contention: {_contention_of(claims)}")
        identifiers = {step.tenant_id for step in claims} | {
            step.session_id for step in claims
        }
        by_id: dict[str, set[str]] = {}
        for provider, sandbox_id in sandboxes:
            by_id.setdefault(sandbox_id, set()).add(provider)
        if any(len(providers) > 1 for providers in by_id.values()):
            buckets.add("providers: one Sandbox identifier under two providers")
        if any(SEPARATOR in value for value in identifiers):
            buckets.add("identifier: carries the key separator")
        if any(not value.isascii() for value in identifiers):
            buckets.add("identifier: not ASCII")
        if any(len(value) > LONG_IDENTIFIER_LENGTH for value in identifiers):
            buckets.add("identifier: longer than a short string")
        return frozenset(buckets)


def _contention_of(claims: list[ClaimStep]) -> str:
    """Describe the competition for a Sandbox in this batch: none, one Tenant's, or several."""
    tenants_per_sandbox: dict[tuple[str, str], list[str]] = {}
    for step in claims:
        tenants_per_sandbox.setdefault((step.provider, step.sandbox_id), []).append(
            step.claimed_tenant_id
        )
    contended = [
        tenants for tenants in tenants_per_sandbox.values() if len(tenants) > 1
    ]
    if not contended:
        return "no competing attempt"
    if any(len(set(tenants)) > 1 for tenants in contended):
        return "competing attempts across Tenants"
    return "competing attempts within one Tenant"


#: Every bucket the generator can land in. A generator that quietly stopped producing one would be
#: caught by the enumerated-case test rather than silently narrowing the domain claimed above.
BUCKETS: Final = frozenset(
    {
        "batch: one Sandbox",
        "batch: several Sandboxes",
        "contention: no competing attempt",
        "contention: competing attempts within one Tenant",
        "contention: competing attempts across Tenants",
        "providers: one Sandbox identifier under two providers",
        "identifier: carries the key separator",
        "identifier: not ASCII",
        "identifier: longer than a short string",
        "claim: committed",
        "claim: an operator tag rode alongside the attribution pair",
        "claim: refused because the Sandbox is already claimed",
        "claim: refused after the Sandbox was quarantined",
        "termination: the duplicate stopped being billable",
        "termination: the duplicate leaked and stays tagged for the Reaper",
        "quarantine: a circumvention denial",
        "quarantine: a recorded Session failure",
        "quarantine: a second reason arrives after the first",
        "quarantine: refused, the Sandbox holds no claim",
        "quarantine: refused, the denial is outside the closed subset",
        *(
            f"tags: refused, {defect.value}"
            for defect in Defect
            if defect is not Defect.NONE
        ),
    }
)


# --- R11.7, restated ------------------------------------------------------------------------------


def attributes_correctly(
    tags: Mapping[str, str], *, tenant_id: str, session_id: str
) -> bool:
    """Whether these tags attribute their Sandbox to exactly this Tenant and this Session.

    A restatement of R11.7 over a tag map, deliberately not a call into
    :func:`~control_plane.allocation.require_attribution`: the expectation a property checks must
    not be produced by the code the property is checking.

    Both halves are required of both keys. A value must be present, non-empty and free of edge
    whitespace — a tag that matches under one provider's filter and not another's is unusable to a
    Reaper sweep — and it must equal the identifier the claim names, on both sides, so a claim whose
    own Tenant is empty is as unattributable as a Sandbox whose tag is.
    """
    for key, claimed in ((TENANT_TAG_KEY, tenant_id), (SESSION_TAG_KEY, session_id)):
        tagged = tags.get(key)
        if not isinstance(tagged, str) or tagged != claimed:
            return False
        if not claimed or claimed.strip() != claimed:
            return False
    return True


# --- One step of one schedule ---------------------------------------------------------------------


@dataclass
class Batch:
    """The mutable state one schedule accumulates: the store, the provider, and what is known."""

    store: FakeClaimStore
    terminator: DrawnTerminator
    ledger: SandboxClaimLedger
    winners: dict[str, ClaimStep] = field(default_factory=dict)
    quarantined: set[str] = field(default_factory=set)
    commits: dict[str, int] = field(default_factory=dict)
    attributable: set[str] = field(default_factory=set)

    @classmethod
    def for_case(cls, case: AllocationCase) -> Batch:
        store = FakeClaimStore()
        terminator = DrawnTerminator(behaviour=case.termination)
        return cls(
            store=store,
            terminator=terminator,
            ledger=SandboxClaimLedger(store=store, terminator=terminator),
        )

    def snapshot(self) -> dict[tuple[str, str], dict[str, object]]:
        """The whole store, copied deeply enough that a later write cannot alter the copy."""
        return {key: dict(item) for key, item in self.store.items.items()}


def run_claim(batch: Batch, step: ClaimStep, claimed_at: int) -> set[str]:
    """Run one claim attempt, assert the whole of R11.1 and R11.7 of it, and name its buckets."""
    partition_key = claim_key_for(step.handle)
    before = batch.snapshot()
    terminations_before = len(batch.terminator.log)

    if step.defect is Defect.EXTRA_OVERRIDES:
        # The sole producer refuses to build the map at all, so no Sandbox is ever tagged this way
        # and no claim is attempted. A producer that silently ignored the override would hand back a
        # map naming a Tenant that is not paying for the Sandbox.
        with pytest.raises(SandboxNotAttributable):
            step.build_tags()
        assert batch.store.items == before
        assert len(batch.terminator.log) == terminations_before
        return {f"tags: refused, {step.defect.value}"}

    tags = step.build_tags()
    claimed_tenant = step.claimed_tenant_id
    if not attributes_correctly(
        tags, tenant_id=claimed_tenant, session_id=step.session_id
    ):
        # R11.7: an unattributable Sandbox never becomes the recorded Sandbox of a Session, and the
        # refusal happens before the store is reached, so no path allocates an untagged one.
        with pytest.raises(SandboxNotAttributable):
            batch.ledger.claim(
                handle=step.handle,
                session_id=step.session_id,
                tenant_id=claimed_tenant,
                tags=tags,
                claimed_at=claimed_at,
            )
        assert batch.store.items == before
        assert len(batch.terminator.log) == terminations_before
        return {f"tags: refused, {step.defect.value}"}

    batch.attributable.add(partition_key)
    if partition_key not in batch.winners:
        record = batch.ledger.claim(
            handle=step.handle,
            session_id=step.session_id,
            tenant_id=claimed_tenant,
            tags=tags,
            claimed_at=claimed_at,
        )
        assert record.pk == partition_key
        assert record.sort_key == CLAIM_SORT_KEY
        assert record.session_id == step.session_id
        assert record.tenant_id == claimed_tenant
        assert record.claimed_at == claimed_at
        assert record.eligibility is Eligibility.NEVER_RUN
        # Exactly one item appeared, at the claim key, and nothing was terminated: the Sandbox a
        # winning caller provisioned is the Sandbox it keeps.
        assert set(batch.store.items) - set(before) == {(partition_key, CLAIM_SORT_KEY)}
        assert len(batch.terminator.log) == terminations_before
        batch.winners[partition_key] = step
        batch.commits[partition_key] = batch.commits.get(partition_key, 0) + 1
        if step.operator_tag:
            return {"claim: an operator tag rode alongside the attribution pair"}
        return {"claim: committed"}

    # R11.1: this Sandbox is already claimed, so it is allocated to no second Session.
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        batch.ledger.claim(
            handle=step.handle,
            session_id=step.session_id,
            tenant_id=claimed_tenant,
            tags=tags,
            claimed_at=claimed_at,
        )
    failure = raised.value
    assert failure.partition_key == partition_key
    assert failure.attempted_session_id == step.session_id
    assert failure.claimed_by_session_id == batch.winners[partition_key].session_id
    # The winner's claim survives the loser byte for byte: not overwritten, not appended to, not
    # renumbered, and its recorded Tenant is still the winner's.
    assert batch.store.items == before

    # The duplicate was stopped inside the failing call, exactly once, whatever the provider did.
    assert batch.terminator.log[terminations_before:] == [
        (step.provider, step.sandbox_id)
    ]
    termination = failure.termination
    assert termination.handle == step.handle
    assert termination.terminated is batch.terminator.behaviour.is_terminal
    assert termination.leaked is not batch.terminator.behaviour.is_terminal
    buckets = {"termination: the duplicate stopped being billable"}
    if termination.leaked:
        # A leaked duplicate is reachable only through `discover`, which matches on tags. This is
        # why R11.7 is a precondition of a claim rather than metadata about one.
        assert termination.failure is not None
        assert attribution_of(tags) == (claimed_tenant, step.session_id)
        buckets = {"termination: the duplicate leaked and stays tagged for the Reaper"}
    if partition_key in batch.quarantined:
        return buckets | {"claim: refused after the Sandbox was quarantined"}
    return buckets | {"claim: refused because the Sandbox is already claimed"}


def run_quarantine(batch: Batch, step: QuarantineStep) -> str:
    """Run one quarantine event and assert what R11.1 and R11.7 reach of it."""
    partition_key = claim_key_for(step.handle)
    before = batch.snapshot()
    terminations_before = len(batch.terminator.log)
    claim_before = before.get((partition_key, CLAIM_SORT_KEY))
    bucket = ""

    if step.reason is not None and step.reason not in CIRCUMVENTION_REASONS:
        # The closed subset, at the only point R11.1 and R11.7 reach it: a denial outside it cannot
        # write anything, so it can neither invent a claim nor disturb one.
        with pytest.raises(DenialIsNotCircumvention):
            batch.ledger.quarantine_for_denial(step.handle, step.reason)
        bucket = "quarantine: refused, the denial is outside the closed subset"
    elif claim_before is None:
        with pytest.raises(SandboxNotClaimed):
            _apply_quarantine(batch, step)
        bucket = "quarantine: refused, the Sandbox holds no claim"
    else:
        _apply_quarantine(batch, step)
        # R11.1's reach: a quarantine writes no second claim and deletes none, so the count of
        # allocations this Sandbox has ever had does not move.
        assert set(batch.store.items) == set(before)
        # R11.7's reach: the attribution recorded against the claim is not rewritten by a
        # quarantine, so the Sandbox stays attributable to the Session that was allocated it.
        after = batch.store.claim_at(partition_key)
        assert after.session_id == claim_before["sessionId"]
        assert after.tenant_id == claim_before["tenantId"]
        if partition_key in batch.quarantined:
            bucket = "quarantine: a second reason arrives after the first"
        elif step.reason is None:
            bucket = "quarantine: a recorded Session failure"
        else:
            bucket = "quarantine: a circumvention denial"
        batch.quarantined.add(partition_key)

    if bucket.startswith("quarantine: refused"):
        assert batch.store.items == before
    # A quarantine is a marker, not a lifecycle operation: nothing is terminated on this path.
    assert len(batch.terminator.log) == terminations_before
    return bucket


def _apply_quarantine(batch: Batch, step: QuarantineStep) -> None:
    """Route the event to its trigger, which is the reason's presence and nothing else."""
    if step.reason is None:
        batch.ledger.quarantine_for_session_failure(step.handle)
    else:
        batch.ledger.quarantine_for_denial(step.handle, step.reason)


def check_case(case: AllocationCase) -> frozenset[str]:
    """Run the drawn schedule against one store, asserting every step, and return its buckets."""
    batch = Batch.for_case(case)
    buckets = set(case.buckets())

    for position, step in enumerate(case.schedule):
        if isinstance(step, ClaimStep):
            buckets |= run_claim(batch, step, claimed_at=NOW_MS + position)
        else:
            buckets.add(run_quarantine(batch, step))

    # R11.1: exactly one claim committed on every Sandbox any attributable attempt named, and no
    # Sandbox holds a claim that no attempt committed.
    assert set(batch.commits) == batch.attributable
    assert all(count == 1 for count in batch.commits.values())
    assert set(batch.store.items) == {
        (partition_key, CLAIM_SORT_KEY) for partition_key in batch.winners
    }

    # The allocated Sandboxes are pairwise distinct and so are the Sessions holding them: one
    # Sandbox never appears on two Session records, and no Session ended up with two Sandboxes.
    sessions = [step.session_id for step in batch.winners.values()]
    assert len(sessions) == len(set(sessions))

    # R11.7: every claim that exists names the Tenant and the Session the tags on its own Sandbox
    # name, recovered from the tag map rather than compared field by field.
    for partition_key, winner in batch.winners.items():
        stored = batch.store.claim_at(partition_key)
        assert (stored.tenant_id, stored.session_id) == attribution_of(
            winner.build_tags()
        )
        assert stored.tenant_id == winner.claimed_tenant_id
        assert stored.session_id == winner.session_id
    return frozenset(buckets)


# --- The generator --------------------------------------------------------------------------------


@st.composite
def session_batch(drawn: st.DrawFn) -> AllocationCase:
    """A batch of Session creations competing over a drawn pool of Sandboxes.

    The batch size is the drawn contention degrees summed, and the mixture of Tenants is drawn per
    attempt, so a Sandbox reused across Tenants and a Sandbox reused within one Tenant are both
    reachable failures. Session identifiers carry the attempt's index, because two Session
    creations are two Sessions however awkward the identifiers they draw.
    """
    sandboxes = drawn(
        st.lists(
            st.tuples(st.sampled_from(PROVIDER_POOL), st.sampled_from(SANDBOX_ID_POOL)),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    steps: list[Step] = []
    for index, (provider, sandbox_id) in enumerate(sandboxes):
        degree = drawn(st.integers(min_value=1, max_value=3))
        for attempt in range(degree):
            suffix = drawn(st.sampled_from(IDENTIFIER_POOL))
            steps.append(
                ClaimStep(
                    provider=provider,
                    sandbox_id=sandbox_id,
                    tenant_id=drawn(st.sampled_from(IDENTIFIER_POOL)),
                    session_id=f"{index}{attempt}-{suffix}",
                    defect=drawn(
                        # Weighted towards well-formed tags, so contention is reached rather than
                        # every attempt being refused before it competes.
                        st.one_of(
                            st.just(Defect.NONE),
                            st.just(Defect.NONE),
                            st.sampled_from(tuple(Defect)),
                        )
                    ),
                    operator_tag=drawn(st.booleans()),
                )
            )
    quarantines = drawn(
        st.lists(
            st.tuples(
                st.sampled_from(sandboxes),
                st.one_of(st.none(), st.sampled_from(tuple(DenialReason))),
            ),
            max_size=3,
        )
    )
    steps.extend(
        QuarantineStep(provider=provider, sandbox_id=sandbox_id, reason=reason)
        for (provider, sandbox_id), reason in quarantines
    )
    return AllocationCase(
        # The permutation *is* the interleaving: competing claims and quarantine events arrive in a
        # drawn order against one store, which is every distinguishable outcome a real race has.
        schedule=tuple(drawn(st.permutations(steps))),
        termination=drawn(st.sampled_from(tuple(Termination))),
    )


# Feature: aws-serverless-agent-sandbox, Property 14: For all batches of Session creations, the
# allocated Sandbox identifiers are pairwise distinct, no Sandbox handle appears on more than one
# Session record, and every provisioned Sandbox carries the owning Tenant identifier as a tag
# together with its Session identifier.
@given(case=session_batch())
@settings(max_examples=200)
def test_sandbox_allocation_is_exclusive_and_attributed(case: AllocationCase) -> None:
    """**Validates: Requirements 11.1, 11.7**"""
    for bucket in check_case(case):
        event(bucket)


# --- Non-vacuity, all deterministic ---------------------------------------------------------------


def test_the_attribution_restatement_agrees_with_the_implementation() -> None:
    """The expectation this property derives is checked against the guard it stands in for.

    Stated over a table rather than over drawn values, because this is the one place the
    restatement and the implementation are allowed to meet: everywhere else the restatement is what
    says whether a claim should have been refused.
    """
    tenant, session = "tenant-a", "01JSESSIONAAAAAAAAAAAAAAAA"
    table: tuple[tuple[Mapping[str, str], str, str], ...] = (
        ({TENANT_TAG_KEY: tenant, SESSION_TAG_KEY: session}, tenant, session),
        ({TENANT_TAG_KEY: tenant, SESSION_TAG_KEY: "other"}, tenant, session),
        ({TENANT_TAG_KEY: "other", SESSION_TAG_KEY: session}, tenant, session),
        ({SESSION_TAG_KEY: session}, tenant, session),
        ({TENANT_TAG_KEY: tenant}, tenant, session),
        ({}, tenant, session),
        ({TENANT_TAG_KEY: "", SESSION_TAG_KEY: session}, "", session),
        ({TENANT_TAG_KEY: tenant, SESSION_TAG_KEY: f"{session} "}, tenant, session),
        (
            {TENANT_TAG_KEY: tenant, SESSION_TAG_KEY: f"{session} "},
            tenant,
            f"{session} ",
        ),
        ({TENANT_TAG_KEY: session, SESSION_TAG_KEY: tenant}, tenant, session),
        ({TENANT_TAG_KEY: "a:b", SESSION_TAG_KEY: "c"}, "a:b", "c"),
    )
    for tags, tenant_id, session_id in table:
        restated = attributes_correctly(
            tags, tenant_id=tenant_id, session_id=session_id
        )
        store = FakeClaimStore()
        ledger = SandboxClaimLedger(
            store=store, terminator=DrawnTerminator(behaviour=Termination.TERMINATED)
        )
        claim = ClaimStep(
            provider=PROVIDER_POOL[0],
            sandbox_id=SANDBOX_ID_POOL[0],
            tenant_id=tenant_id,
            session_id=session_id,
        )
        if restated:
            ledger.claim(
                handle=claim.handle,
                session_id=session_id,
                tenant_id=tenant_id,
                tags=tags,
                claimed_at=NOW_MS,
            )
            assert len(store.items) == 1
        else:
            with pytest.raises(SandboxNotAttributable):
                ledger.claim(
                    handle=claim.handle,
                    session_id=session_id,
                    tenant_id=tenant_id,
                    tags=tags,
                    claimed_at=NOW_MS,
                )
            assert store.items == {}


def test_identifier_pairs_that_collide_under_a_naive_encoding_stay_distinct() -> None:
    """Two Sessions whose attribution a flattened tag encoding would confuse stay distinguishable.

    `("a:b", "c")` and `("a", "b:c")` are different Tenant and Session pairs that a system joining
    the two values into one string renders identically. Each is claimed against its own Sandbox and
    read back exactly, and each Sandbox's tags refuse the other pair's claim — so the attribution
    survives values a naive encoding loses.
    """
    collide = (("a:b", "c"), ("a", "b:c"))
    assert len({f"{tenant}:{session}" for tenant, session in collide}) == 1

    store = FakeClaimStore()
    ledger = SandboxClaimLedger(
        store=store, terminator=DrawnTerminator(behaviour=Termination.TERMINATED)
    )
    for index, (tenant_id, session_id) in enumerate(collide):
        step = ClaimStep(
            provider=PROVIDER_POOL[0],
            sandbox_id=SANDBOX_ID_POOL[index],
            tenant_id=tenant_id,
            session_id=session_id,
        )
        record = ledger.claim(
            handle=step.handle,
            session_id=session_id,
            tenant_id=tenant_id,
            tags=step.build_tags(),
            claimed_at=NOW_MS,
        )
        stored = store.claim_at(record.pk)
        assert (stored.tenant_id, stored.session_id) == (tenant_id, session_id)

    # Neither Sandbox's tags will attribute it to the other pair, which is the claim a flattened
    # encoding could not make.
    swapped = ClaimStep(
        provider=PROVIDER_POOL[0],
        sandbox_id=SANDBOX_ID_POOL[2],
        tenant_id=collide[0][0],
        session_id=collide[0][1],
    )
    with pytest.raises(SandboxNotAttributable):
        ledger.claim(
            handle=swapped.handle,
            session_id=collide[1][1],
            tenant_id=collide[1][0],
            tags=swapped.build_tags(),
            claimed_at=NOW_MS,
        )
    assert len(store.items) == 2


#: The case every enumerated one below varies from: one Sandbox, one Session, well-formed tags.
BASE_STEP: Final = ClaimStep(
    provider=PROVIDER_POOL[0],
    sandbox_id=SANDBOX_ID_POOL[0],
    tenant_id="tenant-a",
    session_id="00-a",
)

#: A second Session competing for the same Sandbox within one Tenant, and a third from another.
SAME_TENANT_RIVAL: Final = replace(BASE_STEP, session_id="01-b")
OTHER_TENANT_RIVAL: Final = replace(BASE_STEP, session_id="02-c", tenant_id="tenant-b")

#: One case per bucket, stated rather than drawn, so every arm of the checker runs whatever the
#: generator happens to produce on a given run.
ENUMERATED_CASES: Final = (
    AllocationCase(schedule=(BASE_STEP,)),
    AllocationCase(schedule=(replace(BASE_STEP, operator_tag=True),)),
    # Contention within one Tenant, and across two, at degree three.
    AllocationCase(schedule=(BASE_STEP, SAME_TENANT_RIVAL)),
    AllocationCase(schedule=(BASE_STEP, SAME_TENANT_RIVAL, OTHER_TENANT_RIVAL)),
    # Every provider behaviour on a loser's duplicate.
    *(
        AllocationCase(schedule=(BASE_STEP, SAME_TENANT_RIVAL), termination=behaviour)
        for behaviour in Termination
    ),
    # Several Sandboxes, including one identifier under two provider names.
    AllocationCase(
        schedule=(
            BASE_STEP,
            replace(BASE_STEP, sandbox_id=SANDBOX_ID_POOL[1], session_id="10-a"),
            replace(BASE_STEP, provider=PROVIDER_POOL[1], session_id="20-a"),
        )
    ),
    # Every tag defect, each against a Sandbox no other attempt names.
    *(
        AllocationCase(schedule=(replace(BASE_STEP, defect=defect),))
        for defect in Defect
    ),
    # The awkward identifier shapes, one case each.
    AllocationCase(
        schedule=(replace(BASE_STEP, tenant_id=f"S{SEPARATOR}looks-like-a-row-key"),)
    ),
    AllocationCase(schedule=(replace(BASE_STEP, session_id="03-会話"),)),
    AllocationCase(schedule=(replace(BASE_STEP, tenant_id="x" * 300),)),
    # Quarantine: each trigger alone on a claimed Sandbox, then both in one schedule, then one on
    # an unclaimed Sandbox, and one carrying a reason outside the closed subset.
    AllocationCase(
        schedule=(
            BASE_STEP,
            QuarantineStep(
                provider=BASE_STEP.provider, sandbox_id=BASE_STEP.sandbox_id
            ),
        )
    ),
    AllocationCase(
        schedule=(
            BASE_STEP,
            QuarantineStep(
                provider=BASE_STEP.provider,
                sandbox_id=BASE_STEP.sandbox_id,
                reason=DenialReason.HOST_SNI_MISMATCH,
            ),
            QuarantineStep(
                provider=BASE_STEP.provider, sandbox_id=BASE_STEP.sandbox_id
            ),
            SAME_TENANT_RIVAL,
        )
    ),
    AllocationCase(
        schedule=(
            QuarantineStep(
                provider=BASE_STEP.provider, sandbox_id=BASE_STEP.sandbox_id
            ),
            BASE_STEP,
            QuarantineStep(
                provider=BASE_STEP.provider,
                sandbox_id=BASE_STEP.sandbox_id,
                reason=min(NON_CIRCUMVENTION_REASONS),
            ),
        )
    ),
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain this property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    for case in ENUMERATED_CASES:
        covered |= check_case(case)
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"


def test_the_assertions_discriminate_three_plausible_wrong_allocations() -> None:
    """Each wrong rule disagrees with what the ledger does on a case this property draws.

    Without this, "the outcome matched what I derived" could hold of an implementation that got the
    same thing wrong in both places.
    """
    store = FakeClaimStore()
    terminator = DrawnTerminator(behaviour=Termination.TERMINATED)
    ledger = SandboxClaimLedger(store=store, terminator=terminator)

    winner = BASE_STEP
    ledger.claim(
        handle=winner.handle,
        session_id=winner.session_id,
        tenant_id=winner.tenant_id,
        tags=winner.build_tags(),
        claimed_at=NOW_MS,
    )
    loser = SAME_TENANT_RIVAL
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger.claim(
            handle=loser.handle,
            session_id=loser.session_id,
            tenant_id=loser.tenant_id,
            tags=loser.build_tags(),
            claimed_at=NOW_MS + 1,
        )

    # 1. An unconditional write would leave the second Session holding the claim. One claim exists
    #    and it is still the first Session's.
    assert len(store.items) == 1
    assert store.claim_at(claim_key_for(winner.handle)).session_id == winner.session_id

    # 2. A refusal that left the duplicate running would report the same exception. The provider was
    #    asked to stop it, once, before the caller learned anything.
    assert terminator.log == [(loser.provider, loser.sandbox_id)]
    assert raised.value.termination.terminated is True

    # 3. A claim that trusted the tags it was handed would write an item naming a Session no tag
    #    mentions. Nothing is written, and the store still holds one claim.
    forged = replace(
        BASE_STEP,
        sandbox_id=SANDBOX_ID_POOL[1],
        session_id="04-d",
        defect=Defect.OTHER_SESSION,
    )
    with pytest.raises(SandboxNotAttributable):
        ledger.claim(
            handle=forged.handle,
            session_id=forged.session_id,
            tenant_id=forged.tenant_id,
            tags=forged.build_tags(),
            claimed_at=NOW_MS + 2,
        )
    assert len(store.items) == 1
