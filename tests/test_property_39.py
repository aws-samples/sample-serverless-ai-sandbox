# kiro-classification: public
"""Property 39: A Sandbox that has executed anything is never allocated again.

R11.10 is a claim about *time*, not about a moment. "Allocated to no subsequent Session" cannot be
observed by looking at one allocation attempt, because the word doing the work is *subsequent*: the
Sandbox has to be watched across a claim, an execution, a suspend, a resume, a termination, a
quarantine and the disappearance of the Session that held it, and refused at every one of those
points. R11.12 and R11.13 are the same shape — an egress denial in the closed circumvention subset,
or a recorded Session failure, makes a Sandbox unavailable *for any further Session* — so all three
are one property over histories rather than three properties over calls.

So what is drawn here is a **history**: a pool of Sandboxes, a sequence of events against them, and
a drawn interleaving of that sequence. After every single event, every Sandbox that holds a claim is
offered to a brand-new, perfectly attributable Session, and must be refused. That is the whole of
R11.10 stated as an experiment rather than as an inspection.

## Concurrency as a drawn schedule, not as threads

No thread is started, no clock is read and no `time.sleep` appears. The interleaving *is* a drawn
permutation of the history's events, executed one at a time against one shared
:class:`~tests.test_allocation_claim_ledger.FakeClaimStore`. This is faithful rather than merely
convenient, for the reason `test_property_14.py` gives about its own schedule: every operation the
ledger performs on a claim item is a single conditional write, and a store serialises those whatever
the callers were doing. Every distinguishable outcome of a real race is therefore some drawn order
of atomic steps. The permutation also reaches the *out-of-order* arrivals that a per-Sandbox
lifecycle order would never produce — an execution recorded before the claim, a quarantine before
the Sandbox was ever allocated — which are exactly the arms of the transition model that a
happy-path generator leaves dead.

## Where the boundary against Property 14 runs

Property 14 owns R11.1 and R11.7: exclusivity within one batch, and the attribution tags. It states
explicitly that it never reads `eligibility`, never calls `mark_used`, and never asserts that a
quarantined Sandbox is unallocatable, leaving R11.10, R11.12 and R11.13 here. So this file takes the
other side of that line and does not restate its half:

- The tag-defect axis is Property 14's. Every claim attempted here carries tags built by the sole
  producer and agreeing with the claim, because the interesting question is whether a *well-formed*
  Session is refused a Sandbox that has been used — a claim refused for bad tags would prove nothing
  about non-reuse. :class:`~control_plane.allocation.SandboxNotAttributable` is never expected here.
- The duplicate-termination behaviour axis is Property 14's. The terminator here always succeeds;
  what is asserted about it is only that a refused reallocation stopped the duplicate exactly once,
  because a non-reuse rule that leaked a billable Sandbox on every refusal would be unusable.
- Contention *within one batch* is Property 14's. Contention here is contention *across time*: the
  second Session arrives after the first has run, suspended, resumed, terminated or been
  quarantined.

What this file adds is the eligibility model itself, the two quarantine triggers as allocation
rules, and reallocation attempted at every point in a history.

## The eligibility model, restated locally and asserted total

:data:`TRANSITION_TABLE` restates the rules over the four states the model admits — no claim, plus
the three :class:`~control_plane.state.records.Eligibility` values — crossed with the four
transitions the ledger performs. It is a stated table with no default branch and no fallback, and
:func:`test_the_transition_restatement_is_total_over_the_eligibility_model` asserts its keys are
exactly that cross product. A fourth eligibility value added to the model later therefore fails the
build rather than falling quietly into a default and being assumed benign.

Two claims are then made *of the table itself*, before any implementation is involved:

- **It is one-way.** :func:`test_the_transitions_are_one_way` asserts that allocatability is
  monotone non-increasing along every edge, that nothing re-enters `never-run` once it has left, and
  that `quarantined` is absorbing. There is no edge back, so no history can walk a Sandbox back to
  allocatable.
- **It agrees with the ledger.**
  :func:`test_the_transition_restatement_agrees_with_the_implementation` drives the real ledger
  through all sixteen entries. That is the one place the restatement and the code under test are
  allowed to meet, following the pattern `test_property_14.py` uses for `attributes_correctly`: a
  property whose expectations were produced by the code it checks would pass against any code.

The closed circumvention subset is restated the same way, as
:data:`CIRCUMVENTING_REASONS_RESTATED` — literal reason strings, not
:data:`~control_plane.allocation.CIRCUMVENTION_REASONS` — and reconciled against the implementation
in :func:`test_the_circumvention_restatement_agrees_with_the_implementation`. A reason moved into or
out of the subset therefore breaks a test that names it, rather than silently changing what this
property asserts.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| one to three Sandboxes, drawn from two provider names crossed with two Sandbox identifiers | histories over a pool, and one Sandbox identifier present under both providers |
| zero to two claim attempts per Sandbox | the never-claimed arms of the table, the ordinary allocation, and reallocation as a drawn event rather than only as a probe |
| suspend, resume, terminate, and the Session record being gone | that no lifecycle event touches the claim ledger, so none of them restores allocatability |
| an execution event per Sandbox, at a drawn position | `never-run → used`, a repeat execution, and an execution against a Sandbox that holds no claim |
| a quarantine event carrying either a drawn `DenialReason` or nothing at all | both triggers: R11.12's closed subset, a reason outside it, and R11.13's recorded Session failure |
| a permutation of the whole event list | out-of-order arrival, second triggers after the first, and reallocation attempted before and after every other kind of event |

## What is asserted

After **every** event, for **every** Sandbox holding a claim:

- a brand-new attributable Session is refused with
  :class:`~control_plane.allocation.SandboxAlreadyClaimed`, whatever the Sandbox has been through;
- the refusal names the Session that holds the claim, and that Session identifier is the one first
  written — immutable across the whole history;
- the store is byte-identical afterwards, so a refused reallocation cannot overwrite, append or
  renumber;
- the duplicate the losing caller was holding was terminated exactly once inside the failing call.

And per event, the outcome is the one :data:`TRANSITION_TABLE` predicts: the committed state, or the
named refusal with the store unchanged. A denial reason outside the closed subset is refused and
writes nothing — including the eligibility it would have overwritten — at every state, and a
Sandbox already quarantined keeps its first reason.

## Non-vacuity

:func:`test_every_bucket_is_reachable_and_the_property_holds_on_each` runs the same checker over
stated cases covering every bucket, including all sixteen transition arms, and asserts every one is
reached. :func:`test_the_assertions_discriminate_four_plausible_wrong_non_reuse_rules` asserts that
four wrong implementations disagree with the ledger on cases this property draws: allocation gated
on eligibility rather than on the claim's existence, a quarantine that clears on resume, a repeat
execution that moves the claim backwards, and non-reuse keyed on the Sandbox identifier alone.
:func:`test_two_providers_sharing_one_sandbox_identifier_are_two_sandboxes` pins the last of those
from the other side.

## Budget

200 examples, above the design's floor of 100 because the drawn dimensions multiply: three
Sandboxes, seven event kinds and seven denial reasons under a permutation leave several transition
arms unvisited at a hundred. Each example runs at most twenty-one events and, after each, up to
three reallocation probes, all against an in-memory dict with a stub terminator — no thread, no
subprocess, no filesystem, no network and no wall-clock read.
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
    SESSION_FAILURE_REASON,
    ClaimConditionFailed,
    DenialIsNotCircumvention,
    DenialReason,
    Quarantine,
    QuarantineTrigger,
    SandboxAlreadyClaimed,
    SandboxClaimLedger,
    SandboxNotClaimed,
    claim_key_for,
    is_allocatable,
    is_circumvention,
    sandbox_tags,
)
from control_plane.providers.base import SandboxHandle, SandboxState, SandboxStatus
from control_plane.state.keys import CLAIM_SORT_KEY
from control_plane.state.records import Eligibility, SandboxClaimRecord
from tests.test_allocation_claim_ledger import FakeClaimStore

#: Epoch milliseconds. Every timestamp is this plus the step's position in the history, so ordering
#: is arithmetic over the drawn schedule and no clock is read.
NOW_MS: Final = 1_700_000_000_000

#: The Tenant every Session in a history belongs to. One Tenant, deliberately: R11.10 forbids reuse
#: across Sessions, and the sharpest case is two Sessions of the *same* Tenant, where an
#: implementation that only checked Tenants would allow it. Cross-Tenant reuse is Property 14's.
TENANT: Final = "tenant-a"

#: Two provider names, so one Sandbox identifier can be present under both.
PROVIDER_POOL: Final = ("lambda-microvms", "local-firecracker")

#: One identifier unique to a provider and one deliberately shared between them.
PRIVATE_SANDBOX_ID: Final = "sbx-1"
SHARED_SANDBOX_ID: Final = "sbx-shared"

#: A Sandbox in this model is the pair that names it, because the claim key names a provider. A bare
#: identifier is not a Sandbox: two backends may both call something `sbx-shared`.
Sandbox = tuple[str, str]

#: The pool a history draws from: both identifiers under both provider names.
SANDBOX_POOL: Final[tuple[Sandbox, ...]] = tuple(
    (provider, sandbox_id)
    for provider in PROVIDER_POOL
    for sandbox_id in (PRIVATE_SANDBOX_ID, SHARED_SANDBOX_ID)
)

#: Session identifier suffixes. Short and separator-free: the awkward identifier shapes are Property
#: 14's axis, and repeating them here would draw a wider domain to assert a narrower claim.
SESSION_SUFFIXES: Final = ("a", "b")


def handle_for(sandbox: Sandbox) -> SandboxHandle:
    """The provider handle for a Sandbox, from the pair that names it."""
    provider, sandbox_id = sandbox
    return SandboxHandle(provider_name=provider, sandbox_id=sandbox_id, opaque={})


# --- The rules, restated locally ------------------------------------------------------------------
#
# Everything below this line is a restatement of R11.10, R11.12 and R11.13 that does not call the
# code under test. Two dedicated tests reconcile each restatement with the implementation; every
# other assertion in this file derives its expectation from here.


#: R11.12's closed circumvention subset, spelled as the reason strings an operator would grep for
#: rather than imported from :data:`~control_plane.allocation.CIRCUMVENTION_REASONS`. Moving a reason
#: into or out of the subset breaks a test that names it.
CIRCUMVENTING_REASONS_RESTATED: Final[frozenset[str]] = frozenset(
    {
        "alias-spoofed",
        "host-sni-mismatch",
        "ip-literal-for-aliased-upstream",
        "proxy-management-interface",
        "denial-rate-exceeded",
    }
)


def quarantines(reason: DenialReason | None) -> bool:
    """Whether this quarantine trigger reaches the claim item at all (R11.12, R11.13).

    `None` is R11.13's trigger — a recorded Session failure, which always quarantines. A
    :class:`~control_plane.allocation.DenialReason` is R11.12's, and quarantines only inside the
    closed subset restated above: the ordinary undeclared-destination denial is a typo, and
    quarantining for it would make the rule the first thing an operator turned off.
    """
    return reason is None or reason.value in CIRCUMVENTING_REASONS_RESTATED


def expected_reason(reason: DenialReason | None) -> str:
    """The reason a quarantine records, which is what makes its trigger recoverable later."""
    return SESSION_FAILURE_REASON if reason is None else reason.value


def expected_trigger(reason: DenialReason | None) -> QuarantineTrigger:
    """Which of R11.12 and R11.13 a quarantine came from."""
    return (
        QuarantineTrigger.SESSION_FAILURE
        if reason is None
        else QuarantineTrigger.EGRESS_CIRCUMVENTION
    )


def allocatable(eligibility: Eligibility | None) -> bool:
    """Whether a Sandbox in this claim state may be allocated to a Session (R11.10).

    `None` means no claim item exists, and it is the *only* allocatable state. Every eligibility
    value — including `never-run`, the Sandbox that was claimed and whose Session died before it ran
    anything — means this Sandbox has already been allocated once, and R11.10 admits no second
    allocation. Stated over the eligibility model rather than over the claim record so a history can
    predict the answer without reading the store.
    """
    return eligibility is None


class Transition(enum.StrEnum):
    """The four operations that can move a claim item's eligibility, or fail trying."""

    #: A Session attempts to be allocated this Sandbox.
    CLAIM = "a claim"
    #: `/run` is invoked, so Untrusted_Code executes in this Sandbox.
    RUN = "an execution"
    #: R11.12: an egress denial inside the closed circumvention subset.
    QUARANTINE_CIRCUMVENTION = "a circumvention quarantine"
    #: R11.13: a Session failure recorded against the Sandbox.
    QUARANTINE_SESSION_FAILURE = "a session-failure quarantine"


#: Every state a Sandbox's claim can be in: no claim at all, plus each eligibility value. Derived
#: from the enum rather than listed, so the totality assertion below has something to compare
#: against that grows when the model does.
CLAIM_STATES: Final[tuple[Eligibility | None, ...]] = (None, *Eligibility)


@dataclass(frozen=True, slots=True)
class Outcome:
    """What a transition does: the state afterwards, and the refusal if it did not commit.

    `eligibility` is the state *after* the transition, which for a refusal is the state before it —
    a refused transition changes nothing, and saying so in the same field is what lets the one-way
    assertion below quantify over every edge without special-casing failures.
    """

    eligibility: Eligibility | None
    refusal: type[Exception] | None = None

    @property
    def committed(self) -> bool:
        return self.refusal is None


def _quarantine_row(
    source: Eligibility | None,
) -> Outcome:
    """The outcome of either quarantine trigger from one source state.

    Both triggers behave identically on the claim item — that is the point of R11.12 and R11.13
    being one marker — so the row is written once rather than twice, and which trigger fired is
    recovered from the recorded reason instead.
    """
    if source is None:
        return Outcome(eligibility=None, refusal=SandboxNotClaimed)
    # Already quarantined is not a refusal: the ledger lets the first recorded reason stand and
    # hands back the quarantine that is already there, because the Sandbox is equally unallocatable
    # either way and the earlier reason is the more informative one.
    return Outcome(eligibility=Eligibility.QUARANTINED)


#: The whole eligibility model, stated with no default branch. Sixteen entries: four states crossed
#: with four transitions. :func:`test_the_transition_restatement_is_total_over_the_eligibility_model`
#: asserts the keys are exactly that cross product, so a fifth state fails the build here rather
#: than falling into a fallback and being assumed harmless.
TRANSITION_TABLE: Final[Mapping[tuple[Eligibility | None, Transition], Outcome]] = {
    # No claim: allocation is the one thing that succeeds. Everything else presupposes an allocation
    # that never happened, and creating a claim item for it would record a Session that never held
    # this Sandbox.
    (None, Transition.CLAIM): Outcome(eligibility=Eligibility.NEVER_RUN),
    (None, Transition.RUN): Outcome(eligibility=None, refusal=SandboxNotClaimed),
    (None, Transition.QUARANTINE_CIRCUMVENTION): _quarantine_row(None),
    (None, Transition.QUARANTINE_SESSION_FAILURE): _quarantine_row(None),
    # Claimed and never run: R11.10 already forbids a second allocation, before anything executed.
    (Eligibility.NEVER_RUN, Transition.CLAIM): Outcome(
        eligibility=Eligibility.NEVER_RUN, refusal=SandboxAlreadyClaimed
    ),
    (Eligibility.NEVER_RUN, Transition.RUN): Outcome(eligibility=Eligibility.USED),
    (
        Eligibility.NEVER_RUN,
        Transition.QUARANTINE_CIRCUMVENTION,
    ): _quarantine_row(Eligibility.NEVER_RUN),
    (
        Eligibility.NEVER_RUN,
        Transition.QUARANTINE_SESSION_FAILURE,
    ): _quarantine_row(Eligibility.NEVER_RUN),
    # Used: the state R11.10 is named for. A repeat execution fails the store's condition rather
    # than moving the claim backwards.
    (Eligibility.USED, Transition.CLAIM): Outcome(
        eligibility=Eligibility.USED, refusal=SandboxAlreadyClaimed
    ),
    (Eligibility.USED, Transition.RUN): Outcome(
        eligibility=Eligibility.USED, refusal=ClaimConditionFailed
    ),
    (
        Eligibility.USED,
        Transition.QUARANTINE_CIRCUMVENTION,
    ): _quarantine_row(Eligibility.USED),
    (
        Eligibility.USED,
        Transition.QUARANTINE_SESSION_FAILURE,
    ): _quarantine_row(Eligibility.USED),
    # Quarantined is absorbing. A further quarantine keeps the first reason; an execution against it
    # fails, which is what stops a quarantined Sandbox being walked back to `used`.
    (Eligibility.QUARANTINED, Transition.CLAIM): Outcome(
        eligibility=Eligibility.QUARANTINED, refusal=SandboxAlreadyClaimed
    ),
    (Eligibility.QUARANTINED, Transition.RUN): Outcome(
        eligibility=Eligibility.QUARANTINED, refusal=ClaimConditionFailed
    ),
    (
        Eligibility.QUARANTINED,
        Transition.QUARANTINE_CIRCUMVENTION,
    ): _quarantine_row(Eligibility.QUARANTINED),
    (
        Eligibility.QUARANTINED,
        Transition.QUARANTINE_SESSION_FAILURE,
    ): _quarantine_row(Eligibility.QUARANTINED),
}


def transition_bucket(source: Eligibility | None, transition: Transition) -> str:
    """The bucket name for one arm of the table, so coverage of all sixteen is observable."""
    state = "no claim" if source is None else source.value
    return f"transition: {state} + {transition.value}"


# --- The history model ----------------------------------------------------------------------------


class EventKind(enum.StrEnum):
    """One thing that happens to a Sandbox in a history.

    Four of the seven perform no ledger operation at all, and that is what they are here to
    establish: R11.10 holds across a Sandbox's whole lifecycle because nothing in that lifecycle
    deletes or relaxes its claim. A suspend, a resume, a termination and the disappearance of the
    Session record all leave the claim item exactly as it was, so none of them can restore
    allocatability — and the reallocation probe after each one is what says so.
    """

    #: A Session attempts to be allocated this Sandbox.
    CLAIM = "a claim attempt"
    #: `/run` is invoked. The one transition R11.10 is named for.
    RUN = "an execution"
    #: The Session is suspended. No ledger operation.
    SUSPEND = "a suspend"
    #: The Session is resumed from a snapshot. No ledger operation.
    RESUME = "a resume"
    #: The Session is terminated. No ledger operation: the claim item carries no TTL, because it is
    #: the only record that a billable Sandbox was ever allocated.
    TERMINATE = "a terminate"
    #: The Session record is gone — expired, deleted, or never durably written. No ledger operation,
    #: and the sharpest of the four: an implementation that inferred allocatability from the absence
    #: of a live Session would hand this Sandbox to a second Session here.
    SESSION_FORGOTTEN = "the Session that held it is gone"
    #: A quarantine, carrying either a denial reason (R11.12) or nothing, meaning a recorded Session
    #: failure (R11.13).
    QUARANTINE = "a quarantine"


#: The events that touch no claim item. Named so the assertion "the store is byte-identical" is
#: driven by membership rather than by repeating the list at the call site.
INERT_KINDS: Final = frozenset(
    {
        EventKind.SUSPEND,
        EventKind.RESUME,
        EventKind.TERMINATE,
        EventKind.SESSION_FORGOTTEN,
    }
)


@dataclass(frozen=True, slots=True)
class Event:
    """One event in a history: what happened, and to which Sandbox."""

    kind: EventKind
    sandbox: Sandbox
    #: The Session attempting the claim. Present only on :attr:`EventKind.CLAIM`.
    session_id: str = ""
    #: The denial reason on a quarantine. `None` means R11.13's recorded Session failure.
    reason: DenialReason | None = None

    @property
    def handle(self) -> SandboxHandle:
        return handle_for(self.sandbox)


@dataclass(frozen=True, slots=True)
class History:
    """One pool of Sandboxes and one drawn interleaving of the events against them."""

    pool: tuple[Sandbox, ...]
    events: tuple[Event, ...]

    def buckets(self) -> frozenset[str]:
        """The buckets this history occupies before a single event has run."""
        buckets = {
            "pool: one Sandbox" if len(self.pool) == 1 else "pool: several Sandboxes"
        }
        by_identifier: dict[str, set[str]] = {}
        for provider, sandbox_id in self.pool:
            by_identifier.setdefault(sandbox_id, set()).add(provider)
        if any(len(providers) > 1 for providers in by_identifier.values()):
            buckets.add("pool: one Sandbox identifier under two providers")
        return frozenset(buckets)


@dataclass
class ClaimModel:
    """What this history believes about one Sandbox, independently of the store.

    The eligibility is predicted from :data:`TRANSITION_TABLE` and never read back from the ledger
    to decide what should happen next, so a ledger that drifted from the model would be caught
    rather than followed.
    """

    eligibility: Eligibility | None = None
    #: The Session that won the claim. Written once; the immutability claim is that it never changes.
    session_id: str | None = None
    quarantine_reason: str | None = None
    quarantine_trigger: QuarantineTrigger | None = None
    #: How many claims have ever committed on this Sandbox. Asserted to be at most one, always.
    commits: int = 0
    ran: bool = False
    suspended: bool = False
    resumed: bool = False
    session_ended: bool = False
    session_forgotten: bool = False

    def history_buckets(self) -> set[str]:
        """Everything this Sandbox has been through, as the reallocation probe's buckets."""
        buckets = {"reallocation refused: after the claim"}
        if self.ran:
            buckets.add("reallocation refused: after an execution")
        if self.suspended:
            buckets.add("reallocation refused: after a suspend")
        if self.resumed:
            buckets.add("reallocation refused: after a resume")
        if self.session_ended:
            buckets.add("reallocation refused: after a terminate")
        if self.quarantine_reason is not None:
            buckets.add("reallocation refused: after a quarantine")
        if self.session_forgotten:
            buckets.add("reallocation refused: after the Session that held it is gone")
        if self.session_ended and not self.ran:
            buckets.add(
                "non-reuse: the Session ended without the Sandbox ever running anything"
            )
        return buckets


@dataclass
class PairLoggingTerminator:
    """Records every termination as the pair that names the Sandbox, and always succeeds.

    The pair rather than the identifier, because this file draws one identifier under two provider
    names: a log keyed on `sandbox_id` alone could not tell "the duplicate was terminated" from
    "some Sandbox called that was terminated". Always succeeding is deliberate — the provider's
    failure modes are Property 14's axis, and drawing them here would widen the domain without
    reaching a state R11.10 distinguishes.
    """

    log: list[Sandbox] = field(default_factory=list)

    def terminate(self, target: SandboxHandle) -> SandboxStatus:
        self.log.append((target.provider_name, target.sandbox_id))
        return SandboxStatus(
            handle=target,
            state=SandboxState.TERMINATED,
            memory_bytes=0,
            # No clock: a `started_at` nobody asserts on would be the only wall-clock read here.
            started_at=None,
            state_reason=None,
        )


@dataclass
class Run:
    """The mutable state one history accumulates: the store, the provider, and the model."""

    store: FakeClaimStore
    terminator: PairLoggingTerminator
    ledger: SandboxClaimLedger
    models: dict[Sandbox, ClaimModel]
    #: Every Session identifier that has ever won a claim, so no two Sandboxes share one.
    winners: dict[Sandbox, str] = field(default_factory=dict)

    @classmethod
    def for_history(cls, history: History) -> Run:
        store = FakeClaimStore()
        terminator = PairLoggingTerminator()
        return cls(
            store=store,
            terminator=terminator,
            ledger=SandboxClaimLedger(store=store, terminator=terminator),
            models={sandbox: ClaimModel() for sandbox in history.pool},
        )

    def snapshot(self) -> dict[tuple[str, str], dict[str, object]]:
        """The whole store, copied deeply enough that a later write cannot alter the copy."""
        return {key: dict(item) for key, item in self.store.items.items()}

    def stored(self, sandbox: Sandbox) -> SandboxClaimRecord | None:
        """The claim recorded against a Sandbox, read straight from the store."""
        item = self.store.items.get(
            (claim_key_for(handle_for(sandbox)), CLAIM_SORT_KEY)
        )
        return None if item is None else SandboxClaimRecord.from_item(item)


def _assert_store_unchanged(
    run: Run, before: dict[tuple[str, str], dict[str, object]]
) -> None:
    """The store is byte-identical: nothing overwritten, appended or renumbered."""
    assert run.store.items == before


def _tags_for(session_id: str) -> dict[str, str]:
    """Tags from the sole producer, agreeing with the claim.

    Always well-formed. A claim refused because its tags were wrong would say nothing about R11.10,
    and the defect axis belongs to Property 14.
    """
    return sandbox_tags(tenant_id=TENANT, session_id=session_id)


def _attempt_claim(run: Run, sandbox: Sandbox, session_id: str, at: int) -> None:
    """Offer a Sandbox to a Session, with correct tags and this Tenant."""
    run.ledger.claim(
        handle=handle_for(sandbox),
        session_id=session_id,
        tenant_id=TENANT,
        tags=_tags_for(session_id),
        claimed_at=at,
    )


# --- One event, and the reallocation probe that follows every one ---------------------------------


def run_claim(run: Run, event_: Event, at: int) -> set[str]:
    """Run one claim attempt and assert the outcome the table predicts."""
    model = run.models[event_.sandbox]
    outcome = TRANSITION_TABLE[(model.eligibility, Transition.CLAIM)]
    buckets = {transition_bucket(model.eligibility, Transition.CLAIM)}
    before = run.snapshot()
    terminations_before = len(run.terminator.log)
    partition_key = claim_key_for(event_.handle)

    if outcome.committed:
        _attempt_claim(run, event_.sandbox, event_.session_id, at)
        record = run.stored(event_.sandbox)
        assert record is not None
        assert record.session_id == event_.session_id
        assert record.tenant_id == TENANT
        assert record.claimed_at == at
        assert record.eligibility is Eligibility.NEVER_RUN
        assert record.quarantine_reason is None
        # Exactly one item appeared, and nothing was terminated: a winning caller keeps its Sandbox.
        assert set(run.store.items) - set(before) == {(partition_key, CLAIM_SORT_KEY)}
        assert len(run.terminator.log) == terminations_before
        model.eligibility = Eligibility.NEVER_RUN
        model.session_id = event_.session_id
        model.commits += 1
        run.winners[event_.sandbox] = event_.session_id
        return buckets | {"claim: committed"}

    assert outcome.refusal is SandboxAlreadyClaimed
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        _attempt_claim(run, event_.sandbox, event_.session_id, at)
    failure = raised.value
    assert failure.partition_key == partition_key
    assert failure.attempted_session_id == event_.session_id
    # R11.10's immutability half: the recorded Session is the one first written, whatever has
    # happened to the Sandbox since.
    assert failure.claimed_by_session_id == model.session_id
    _assert_store_unchanged(run, before)
    # The duplicate the loser was holding is stopped inside the failing call, exactly once.
    assert run.terminator.log[terminations_before:] == [event_.sandbox]
    assert failure.termination.terminated is True
    return buckets | {"claim: refused, the Sandbox is already claimed"}


def run_execution(run: Run, event_: Event) -> set[str]:
    """Run one execution and assert the outcome the table predicts."""
    model = run.models[event_.sandbox]
    outcome = TRANSITION_TABLE[(model.eligibility, Transition.RUN)]
    buckets = {transition_bucket(model.eligibility, Transition.RUN)}
    before = run.snapshot()
    terminations_before = len(run.terminator.log)

    if outcome.committed:
        run.ledger.mark_used(event_.handle)
        record = run.stored(event_.sandbox)
        assert record is not None
        assert record.eligibility is Eligibility.USED
        # The execution records what the Sandbox did; it does not touch what the claim says about
        # who holds it.
        assert record.session_id == model.session_id
        assert set(run.store.items) == set(before)
        model.eligibility = Eligibility.USED
        model.ran = True
        buckets.add("execution: recorded, never-run became used")
    else:
        assert outcome.refusal is not None
        with pytest.raises(outcome.refusal):
            run.ledger.mark_used(event_.handle)
        _assert_store_unchanged(run, before)
        if outcome.refusal is SandboxNotClaimed:
            buckets.add("execution: refused, the Sandbox holds no claim")
        else:
            buckets.add("execution: refused, the claim is no longer never-run")

    assert len(run.terminator.log) == terminations_before
    assert model.eligibility is outcome.eligibility
    return buckets


def run_quarantine(run: Run, event_: Event) -> set[str]:
    """Run one quarantine event and assert the outcome the restatement predicts.

    Two restatements meet here. :func:`quarantines` says whether the trigger reaches the store at
    all, which is R11.12's closed subset and R11.13's unconditional one; the table then says what
    the transition does once it gets there.
    """
    model = run.models[event_.sandbox]
    before = run.snapshot()
    terminations_before = len(run.terminator.log)
    buckets: set[str] = set()

    if not quarantines(event_.reason):
        # R11.12, stated as the negative it needs: a reason outside the closed subset writes
        # nothing, at any state, so a mistyped hostname cannot cost a Sandbox and cannot invent a
        # claim for one that holds none.
        assert event_.reason is not None
        with pytest.raises(DenialIsNotCircumvention) as refused:
            run.ledger.quarantine_for_denial(event_.handle, event_.reason)
        assert refused.value.reason is event_.reason
        _assert_store_unchanged(run, before)
        record = run.stored(event_.sandbox)
        assert (None if record is None else record.eligibility) is model.eligibility
        assert len(run.terminator.log) == terminations_before
        return {"quarantine: refused, the denial is outside the closed subset"}

    transition = (
        Transition.QUARANTINE_SESSION_FAILURE
        if event_.reason is None
        else Transition.QUARANTINE_CIRCUMVENTION
    )
    outcome = TRANSITION_TABLE[(model.eligibility, transition)]
    buckets.add(transition_bucket(model.eligibility, transition))
    already_quarantined = model.eligibility is Eligibility.QUARANTINED

    if not outcome.committed:
        assert outcome.refusal is SandboxNotClaimed
        with pytest.raises(SandboxNotClaimed):
            _apply_quarantine(run, event_)
        _assert_store_unchanged(run, before)
        assert len(run.terminator.log) == terminations_before
        return buckets | {"quarantine: refused, the Sandbox holds no claim"}

    recorded = _apply_quarantine(run, event_)
    record = run.stored(event_.sandbox)
    assert record is not None
    assert record.eligibility is Eligibility.QUARANTINED
    assert set(run.store.items) == set(before)
    # A quarantine records what happened to the Sandbox; it never rewrites who held it.
    assert record.session_id == model.session_id

    if already_quarantined:
        # The first reason stands, and the ledger hands back the quarantine already recorded. The
        # earlier reason is the security-relevant one in the case that matters — a Session whose
        # code attempted circumvention very often also fails — so it is not overwritten.
        assert recorded.reason == model.quarantine_reason
        assert recorded.trigger is model.quarantine_trigger
        assert record.quarantine_reason == model.quarantine_reason
        buckets.add("quarantine: a second trigger arrives, the first reason stands")
    else:
        assert recorded.reason == expected_reason(event_.reason)
        assert recorded.trigger is expected_trigger(event_.reason)
        assert record.quarantine_reason == expected_reason(event_.reason)
        model.eligibility = Eligibility.QUARANTINED
        model.quarantine_reason = recorded.reason
        model.quarantine_trigger = recorded.trigger
        buckets.add(
            "quarantine: a recorded Session failure"
            if event_.reason is None
            else "quarantine: a circumvention denial"
        )

    # The trigger is recoverable from the stored reason alone, with no second attribute.
    recovered = run.ledger.quarantine_of(event_.handle)
    assert recovered is not None
    assert recovered.trigger is model.quarantine_trigger
    assert recovered.reason == model.quarantine_reason
    assert len(run.terminator.log) == terminations_before
    return buckets


def _apply_quarantine(run: Run, event_: Event) -> Quarantine:
    """Route the event to its trigger, which is the reason's presence and nothing else."""
    if event_.reason is None:
        return run.ledger.quarantine_for_session_failure(event_.handle)
    return run.ledger.quarantine_for_denial(event_.handle, event_.reason)


def run_inert(run: Run, event_: Event) -> set[str]:
    """Run a lifecycle event that performs no ledger operation, and assert it performed none.

    This is the load-bearing half of R11.10 across time. A suspend, a resume, a termination and the
    loss of the Session record are the four moments at which a Sandbox looks free, and the claim
    item is unchanged through all of them — so the reallocation probe that follows is refused for the
    same reason it was refused a moment after the claim.
    """
    model = run.models[event_.sandbox]
    before = run.snapshot()
    terminations_before = len(run.terminator.log)

    if event_.kind is EventKind.SUSPEND:
        model.suspended = True
    elif event_.kind is EventKind.RESUME:
        model.resumed = True
    elif event_.kind is EventKind.TERMINATE:
        model.session_ended = True
    else:
        model.session_forgotten = True
        model.session_ended = True

    _assert_store_unchanged(run, before)
    assert len(run.terminator.log) == terminations_before
    return {f"lifecycle: {event_.kind.value}"}


def probe_reallocation(run: Run, at: int, probe: int) -> set[str]:
    """Offer every claimed Sandbox to a brand-new Session, and require every offer to be refused.

    Run after **every** event, which is what makes this a claim about time. The probing Session is
    new, belongs to the same Tenant, and carries tags the sole producer built — so nothing about it
    is refusable except the one thing R11.10 says: this Sandbox has been allocated before.
    """
    buckets: set[str] = set()
    for index, (sandbox, model) in enumerate(sorted(run.models.items())):
        if allocatable(model.eligibility):
            continue
        before = run.snapshot()
        terminations_before = len(run.terminator.log)
        probing_session = f"probe-{probe}-{index}"
        with pytest.raises(SandboxAlreadyClaimed) as raised:
            _attempt_claim(run, sandbox, probing_session, at)
        failure = raised.value
        assert failure.attempted_session_id == probing_session
        assert failure.claimed_by_session_id == model.session_id
        assert failure.termination.terminated is True
        _assert_store_unchanged(run, before)
        assert run.terminator.log[terminations_before:] == [sandbox]
        # The ledger's own answer to the allocation question agrees with the restatement.
        assert run.ledger.is_allocatable(handle_for(sandbox)) is False
        buckets |= model.history_buckets()
    return buckets


def check_history(history: History) -> frozenset[str]:
    """Run one drawn interleaving, asserting every event and probing after each, and name buckets."""
    run = Run.for_history(history)
    buckets = set(history.buckets())

    for position, event_ in enumerate(history.events):
        at = NOW_MS + position
        if event_.kind is EventKind.CLAIM:
            buckets |= run_claim(run, event_, at)
        elif event_.kind is EventKind.RUN:
            buckets |= run_execution(run, event_)
        elif event_.kind is EventKind.QUARANTINE:
            buckets |= run_quarantine(run, event_)
        else:
            assert event_.kind in INERT_KINDS
            buckets |= run_inert(run, event_)
        buckets |= probe_reallocation(run, at, position)

    # R11.10 over the whole history: at most one claim ever committed on each Sandbox, and the
    # Session it named is the Session recorded at the end.
    for sandbox, model in run.models.items():
        record = run.stored(sandbox)
        assert model.commits <= 1
        if model.eligibility is None:
            assert record is None
            continue
        assert record is not None
        assert record.session_id == model.session_id
        assert record.eligibility is model.eligibility
        assert record.quarantine_reason == model.quarantine_reason
        # The allocation question, asked of the record rather than of the model.
        assert is_allocatable(record) is False
        assert allocatable(model.eligibility) is False
        # A Sandbox that executed anything ends used or quarantined, never back at never-run.
        if model.ran:
            assert record.eligibility in (Eligibility.USED, Eligibility.QUARANTINED)

    # No Session holds two Sandboxes, and no Sandbox appears on two Session records.
    sessions = list(run.winners.values())
    assert len(sessions) == len(set(sessions))
    assert set(run.store.items) == {
        (claim_key_for(handle_for(sandbox)), CLAIM_SORT_KEY) for sandbox in run.winners
    }

    # Non-reuse is keyed on the Sandbox, not on an identifier two backends share: same identifier
    # under two provider names means two claim keys and two independent claims.
    keys = {sandbox: claim_key_for(handle_for(sandbox)) for sandbox in history.pool}
    assert len(set(keys.values())) == len(history.pool)
    return frozenset(buckets)


# --- The generator --------------------------------------------------------------------------------


#: The denial reasons inside the closed subset, derived from this file's *restatement* rather than
#: from the implementation. Generation may lean on the restatement freely — it is the expectations
#: that must not be produced by the code under test — and deriving it here keeps the generator from
#: quietly following a subset the implementation changed.
CIRCUMVENTING_DENIALS: Final[tuple[DenialReason, ...]] = tuple(
    reason for reason in DenialReason if reason.value in CIRCUMVENTING_REASONS_RESTATED
)


def quarantine_triggers() -> st.SearchStrategy[DenialReason | None]:
    """Either quarantine trigger, weighted so both reach a Sandbox that has already run.

    `None` is R11.13's. A :class:`~control_plane.allocation.DenialReason` is R11.12's, and the
    circumvention subset is drawn a second time on its own so the `used + a circumvention quarantine`
    arm is reached by generation: it needs a claim, then an execution, then a circumventing denial,
    in that order out of a drawn permutation, and an unweighted draw leaves it unvisited at this
    example count. Every reason outside the subset is still drawn, because the property is stated
    over *all* denial reasons.
    """
    return st.one_of(
        st.none(),
        st.sampled_from(CIRCUMVENTING_DENIALS),
        st.sampled_from(tuple(DenialReason)),
    )


@st.composite
def sandbox_histories(drawn: st.DrawFn) -> History:
    """A pool of Sandboxes, a lifecycle drawn per Sandbox, and one interleaving of the whole lot.

    Events are built per Sandbox and then permuted together, so both the natural order and every
    out-of-order arrival are reachable: an execution before the claim, a quarantine against a
    Sandbox nothing has allocated, a reallocation between a suspend and a resume. Session
    identifiers carry the Sandbox's index, because a batch of Session creations is a batch of *new*
    Sessions.
    """
    pool = drawn(
        st.lists(st.sampled_from(SANDBOX_POOL), min_size=1, max_size=3, unique=True)
    )
    events: list[Event] = []
    for index, sandbox in enumerate(pool):
        # Zero claim attempts reaches the never-claimed arms of the table; two reaches reallocation
        # as a drawn event rather than only as the probe.
        attempts = drawn(st.integers(min_value=0, max_value=2))
        for attempt in range(attempts):
            suffix = drawn(st.sampled_from(SESSION_SUFFIXES))
            events.append(
                Event(
                    kind=EventKind.CLAIM,
                    sandbox=sandbox,
                    session_id=f"{index}{attempt}-{suffix}",
                )
            )
        for kind in drawn(
            st.lists(
                st.sampled_from(
                    (
                        EventKind.RUN,
                        EventKind.RUN,
                        EventKind.SUSPEND,
                        EventKind.RESUME,
                        EventKind.TERMINATE,
                        EventKind.SESSION_FORGOTTEN,
                    )
                ),
                max_size=3,
            )
        ):
            events.append(Event(kind=kind, sandbox=sandbox))
        for reason in drawn(st.lists(quarantine_triggers(), max_size=2)):
            events.append(
                Event(kind=EventKind.QUARANTINE, sandbox=sandbox, reason=reason)
            )
    return History(
        pool=tuple(pool),
        # The permutation *is* the interleaving: one store, one step at a time, in a drawn order.
        events=tuple(drawn(st.permutations(events))),
    )


# Feature: aws-serverless-agent-sandbox, Property 39: For all sequences of Session creations,
# terminations and failures, no Sandbox identifier appears on more than one Session record over the
# whole sequence, each Sandbox claim record's Session identifier is immutable once written, a
# further claim of an already-claimed Sandbox identifier fails and the duplicate is terminated
# rather than adopted; and for all egress denial reasons and for all Session failure modes, the
# Sandbox's eligibility becomes quarantined exactly when the denial reason is in the closed
# circumvention set or a Session failure was recorded, and never for a denial reason outside that
# set.
@given(history=sandbox_histories())
@settings(max_examples=200)
def test_a_sandbox_that_has_executed_anything_is_never_allocated_again(
    history: History,
) -> None:
    """**Validates: Requirements 11.10, 11.12, 11.13**"""
    for bucket in check_history(history):
        event(bucket)


# --- The restatements, reconciled with the implementation -----------------------------------------


def test_the_transition_restatement_is_total_over_the_eligibility_model() -> None:
    """The table covers every state the model admits, with no default branch behind it.

    Stated as an equality rather than as a containment, in both directions. A fourth eligibility
    value added to :class:`~control_plane.state.records.Eligibility` grows the cross product and
    fails here, which is the point: a new state must be classified deliberately rather than
    inheriting whatever a fallback happened to do. An entry for a state that no longer exists fails
    just as loudly.
    """
    expected = {
        (state, transition) for state in CLAIM_STATES for transition in Transition
    }
    assert set(TRANSITION_TABLE) == expected
    assert len(CLAIM_STATES) == len(Eligibility) + 1
    assert len(TRANSITION_TABLE) == len(CLAIM_STATES) * len(Transition)


def test_the_transitions_are_one_way() -> None:
    """Nothing returns a Sandbox to allocatable, and nothing walks its eligibility backwards."""
    for (source, transition), outcome in TRANSITION_TABLE.items():
        # R11.10: allocatability is monotone non-increasing along every edge. Once a claim exists
        # the Sandbox is unallocatable, and no transition removes the claim.
        assert allocatable(outcome.eligibility) <= allocatable(source), (
            f"{transition} restored allocatability from {source}"
        )
        if source is not None:
            # A claim, once written, is never unwritten.
            assert outcome.eligibility is not None
        if source in (Eligibility.USED, Eligibility.QUARANTINED):
            # No edge back to never-run: a used Sandbox never looks freshly created again.
            assert outcome.eligibility is not Eligibility.NEVER_RUN
        if source is Eligibility.USED:
            assert outcome.eligibility in (Eligibility.USED, Eligibility.QUARANTINED)
        if source is Eligibility.QUARANTINED:
            # Quarantined is absorbing, which is R11.12 and R11.13 as allocation rules.
            assert outcome.eligibility is Eligibility.QUARANTINED

    # The only allocatable state is the one with no claim, and exactly one transition leaves it.
    assert [state for state in CLAIM_STATES if allocatable(state)] == [None]
    leaving = [
        transition
        for transition in Transition
        if TRANSITION_TABLE[(None, transition)].committed
    ]
    assert leaving == [Transition.CLAIM]


def test_the_transition_restatement_agrees_with_the_implementation() -> None:
    """Every one of the sixteen arms is driven against the real ledger and compared.

    This is the one place the restatement and the code under test are allowed to meet. Everywhere
    else the restatement is what says whether an operation should have succeeded, because a property
    that asked the implementation what it should do would pass against any implementation.
    """
    sandbox = SANDBOX_POOL[0]
    for (source, transition), outcome in sorted(
        TRANSITION_TABLE.items(), key=lambda item: (str(item[0][0]), item[0][1])
    ):
        run = _ledger_in_state(source, sandbox)
        before = run.snapshot()
        handle = handle_for(sandbox)

        if outcome.committed:
            _apply_transition(run, sandbox, transition)
        else:
            assert outcome.refusal is not None
            with pytest.raises(outcome.refusal):
                _apply_transition(run, sandbox, transition)
            assert run.store.items == before, (
                f"{transition} from {source} was refused but wrote to the store"
            )

        record = run.stored(sandbox)
        actual = None if record is None else record.eligibility
        assert actual is outcome.eligibility, (
            f"{transition} from {source}: the ledger reached {actual}, "
            f"the restatement predicted {outcome.eligibility}"
        )
        # And the allocation question the restatement answers is the one the ledger answers.
        assert run.ledger.is_allocatable(handle) is allocatable(outcome.eligibility)
        assert is_allocatable(record) is allocatable(outcome.eligibility)


def _apply_transition(run: Run, sandbox: Sandbox, transition: Transition) -> None:
    """Perform one transition against the real ledger, dispatched on the table's own key.

    Total over :class:`Transition` with no `else` fallback, so a fifth transition added to the model
    fails here rather than being silently routed to the last branch.
    """
    handle = handle_for(sandbox)
    if transition is Transition.CLAIM:
        _attempt_claim(run, sandbox, "later-session", NOW_MS + 1)
    elif transition is Transition.RUN:
        run.ledger.mark_used(handle)
    elif transition is Transition.QUARANTINE_CIRCUMVENTION:
        run.ledger.quarantine_for_denial(handle, DenialReason.HOST_SNI_MISMATCH)
    elif transition is Transition.QUARANTINE_SESSION_FAILURE:
        run.ledger.quarantine_for_session_failure(handle)
    else:  # pragma: no cover - unreachable while the table's totality assertion holds
        raise AssertionError(f"no ledger operation for {transition!r}")


def _ledger_in_state(source: Eligibility | None, sandbox: Sandbox) -> Run:
    """A fresh ledger whose claim on `sandbox` is in `source`, built through the ledger itself."""
    history = History(pool=(sandbox,), events=())
    run = Run.for_history(history)
    if source is None:
        return run
    _attempt_claim(run, sandbox, "first-session", NOW_MS)
    run.models[sandbox].eligibility = Eligibility.NEVER_RUN
    run.models[sandbox].session_id = "first-session"
    if source is Eligibility.USED:
        run.ledger.mark_used(handle_for(sandbox))
    elif source is Eligibility.QUARANTINED:
        run.ledger.quarantine_for_session_failure(handle_for(sandbox))
    return run


def test_the_circumvention_restatement_agrees_with_the_implementation() -> None:
    """The closed subset this file restates is the subset the implementation enforces (R11.12)."""
    assert {reason.value for reason in CIRCUMVENTION_REASONS} == (
        CIRCUMVENTING_REASONS_RESTATED
    )
    assert {reason.value for reason in NON_CIRCUMVENTION_REASONS} == (
        {reason.value for reason in DenialReason} - CIRCUMVENTING_REASONS_RESTATED
    )
    for reason in DenialReason:
        assert is_circumvention(reason) is quarantines(reason)
    # The subset is a strict, non-empty subset: an empty one would quarantine nothing and a total
    # one would quarantine on every typo, and both would make R11.12 useless in opposite directions.
    assert CIRCUMVENTING_REASONS_RESTATED
    assert NON_CIRCUMVENTION_REASONS
    # R11.13's reason is in neither vocabulary, which is what keeps the two triggers recoverable
    # from the stored reason with no second attribute.
    assert SESSION_FAILURE_REASON not in {reason.value for reason in DenialReason}
    assert quarantines(None) is True


# --- Non-vacuity, all deterministic ---------------------------------------------------------------


#: The Sandbox every stated case below uses, and its shared-identifier sibling on the other provider.
FIRST: Final[Sandbox] = (PROVIDER_POOL[0], SHARED_SANDBOX_ID)
SIBLING: Final[Sandbox] = (PROVIDER_POOL[1], SHARED_SANDBOX_ID)
SEPARATE: Final[Sandbox] = (PROVIDER_POOL[0], PRIVATE_SANDBOX_ID)

CLAIM_FIRST: Final = Event(kind=EventKind.CLAIM, sandbox=FIRST, session_id="00-a")
CLAIM_SECOND: Final = replace(CLAIM_FIRST, session_id="01-b")
RUN_FIRST: Final = Event(kind=EventKind.RUN, sandbox=FIRST)
FAILURE_QUARANTINE: Final = Event(kind=EventKind.QUARANTINE, sandbox=FIRST)
CIRCUMVENTION_QUARANTINE: Final = Event(
    kind=EventKind.QUARANTINE, sandbox=FIRST, reason=DenialReason.ALIAS_SPOOFED
)
ORDINARY_DENIAL: Final = Event(
    kind=EventKind.QUARANTINE,
    sandbox=FIRST,
    reason=DenialReason.UNDECLARED_DESTINATION,
)

#: One case per bucket, stated rather than drawn, so every arm of the checker runs whatever the
#: generator happens to produce on a given run.
ENUMERATED_HISTORIES: Final = (
    # A Sandbox claimed, run, and offered to a second Session — the property in one line.
    History(pool=(FIRST,), events=(CLAIM_FIRST, RUN_FIRST, CLAIM_SECOND)),
    # The whole lifecycle, with a reallocation attempted after every step by the probe.
    History(
        pool=(FIRST,),
        events=(
            CLAIM_FIRST,
            RUN_FIRST,
            Event(kind=EventKind.SUSPEND, sandbox=FIRST),
            Event(kind=EventKind.RESUME, sandbox=FIRST),
            Event(kind=EventKind.TERMINATE, sandbox=FIRST),
            Event(kind=EventKind.SESSION_FORGOTTEN, sandbox=FIRST),
            CLAIM_SECOND,
        ),
    ),
    # A Session that ended without the Sandbox ever running anything: still never allocated again.
    History(
        pool=(FIRST,),
        events=(
            CLAIM_FIRST,
            Event(kind=EventKind.TERMINATE, sandbox=FIRST),
            CLAIM_SECOND,
        ),
    ),
    # A repeat execution, which fails the store's condition rather than moving the claim backwards.
    History(pool=(FIRST,), events=(CLAIM_FIRST, RUN_FIRST, RUN_FIRST)),
    # Both quarantine triggers, each alone on a used Sandbox, then a reallocation attempt.
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, RUN_FIRST, CIRCUMVENTION_QUARANTINE, CLAIM_SECOND),
    ),
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, RUN_FIRST, FAILURE_QUARANTINE, CLAIM_SECOND),
    ),
    # A quarantine before anything ran, then an execution against the quarantined claim.
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, CIRCUMVENTION_QUARANTINE, RUN_FIRST, CLAIM_SECOND),
    ),
    # The second trigger arrives after the first: the earlier reason stands.
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, CIRCUMVENTION_QUARANTINE, FAILURE_QUARANTINE),
    ),
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, FAILURE_QUARANTINE, CIRCUMVENTION_QUARANTINE),
    ),
    # A denial reason outside the closed subset, against a claim in each state it could meet.
    History(pool=(FIRST,), events=(ORDINARY_DENIAL,)),
    History(pool=(FIRST,), events=(CLAIM_FIRST, ORDINARY_DENIAL)),
    History(pool=(FIRST,), events=(CLAIM_FIRST, RUN_FIRST, ORDINARY_DENIAL)),
    History(
        pool=(FIRST,),
        events=(CLAIM_FIRST, FAILURE_QUARANTINE, ORDINARY_DENIAL),
    ),
    # Out-of-order arrivals: an execution and both quarantines against a Sandbox holding no claim.
    History(pool=(FIRST,), events=(RUN_FIRST,)),
    History(pool=(FIRST,), events=(CIRCUMVENTION_QUARANTINE,)),
    History(pool=(FIRST,), events=(FAILURE_QUARANTINE,)),
    # One identifier under two providers, each with its own history, plus a third Sandbox.
    History(
        pool=(FIRST, SIBLING, SEPARATE),
        events=(
            CLAIM_FIRST,
            RUN_FIRST,
            Event(kind=EventKind.CLAIM, sandbox=SIBLING, session_id="10-a"),
            Event(kind=EventKind.CLAIM, sandbox=SEPARATE, session_id="20-a"),
            CLAIM_SECOND,
        ),
    ),
)


#: Every bucket the checker can emit. A generator that quietly stopped producing one would be caught
#: here rather than silently narrowing the domain this property claims.
BUCKETS: Final = frozenset(
    {
        "pool: one Sandbox",
        "pool: several Sandboxes",
        "pool: one Sandbox identifier under two providers",
        "claim: committed",
        "claim: refused, the Sandbox is already claimed",
        "execution: recorded, never-run became used",
        "execution: refused, the Sandbox holds no claim",
        "execution: refused, the claim is no longer never-run",
        "quarantine: a circumvention denial",
        "quarantine: a recorded Session failure",
        "quarantine: a second trigger arrives, the first reason stands",
        "quarantine: refused, the Sandbox holds no claim",
        "quarantine: refused, the denial is outside the closed subset",
        "reallocation refused: after the claim",
        "reallocation refused: after an execution",
        "reallocation refused: after a suspend",
        "reallocation refused: after a resume",
        "reallocation refused: after a terminate",
        "reallocation refused: after a quarantine",
        "reallocation refused: after the Session that held it is gone",
        "non-reuse: the Session ended without the Sandbox ever running anything",
        *(f"lifecycle: {kind.value}" for kind in INERT_KINDS),
        *(
            transition_bucket(state, transition)
            for state in CLAIM_STATES
            for transition in Transition
        ),
    }
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain this property claims to cover is one no arm of which is dead.

    The sixteen transition buckets are in :data:`BUCKETS`, so this also asserts that every arm of
    the eligibility model is reached by running a history rather than only by the table's own
    totality assertion.
    """
    covered: set[str] = set()
    for history in ENUMERATED_HISTORIES:
        covered |= check_history(history)
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"


def test_two_providers_sharing_one_sandbox_identifier_are_two_sandboxes() -> None:
    """Non-reuse is keyed on the Sandbox, not on a string two backends happen to share.

    Both providers call something `sbx-shared`. Running and quarantining one must leave the other
    allocatable, and claiming the other must not be refused — otherwise the rule would be keyed on
    an identifier whose uniqueness no provider guarantees across backends.
    """
    run = Run.for_history(History(pool=(FIRST, SIBLING), events=()))
    assert claim_key_for(handle_for(FIRST)) != claim_key_for(handle_for(SIBLING))

    _attempt_claim(run, FIRST, "session-first", NOW_MS)
    run.ledger.mark_used(handle_for(FIRST))
    run.ledger.quarantine_for_session_failure(handle_for(FIRST))

    # The sibling is untouched: still allocatable, and the claim succeeds.
    assert run.ledger.is_allocatable(handle_for(SIBLING)) is True
    assert run.ledger.read(handle_for(SIBLING)) is None
    _attempt_claim(run, SIBLING, "session-sibling", NOW_MS + 1)

    first = run.stored(FIRST)
    sibling = run.stored(SIBLING)
    assert first is not None
    assert sibling is not None
    assert first.eligibility is Eligibility.QUARANTINED
    assert sibling.eligibility is Eligibility.NEVER_RUN
    assert first.session_id == "session-first"
    assert sibling.session_id == "session-sibling"
    # And neither is allocatable now, for the same reason.
    for sandbox in (FIRST, SIBLING):
        with pytest.raises(SandboxAlreadyClaimed):
            _attempt_claim(run, sandbox, "session-third", NOW_MS + 2)


def test_the_assertions_discriminate_four_plausible_wrong_non_reuse_rules() -> None:
    """Each wrong rule disagrees with the ledger on a case this property draws.

    Without this, "the outcome matched what I derived" could hold of an implementation that got the
    same thing wrong in both places.
    """
    run = Run.for_history(History(pool=(FIRST, SIBLING), events=()))
    handle = handle_for(FIRST)
    _attempt_claim(run, FIRST, "session-first", NOW_MS)

    # 1. Allocation gated on eligibility rather than on the claim's existence would allocate a
    #    `never-run` Sandbox to a second Session. It does not: the gate is the claim.
    record = run.stored(FIRST)
    assert record is not None
    assert record.eligibility is Eligibility.NEVER_RUN
    assert is_allocatable(record) is False
    with pytest.raises(SandboxAlreadyClaimed):
        _attempt_claim(run, FIRST, "session-second", NOW_MS + 1)

    # 2. A quarantine that cleared on resume would restore allocatability. There is no resume
    #    operation on the ledger at all, so the claim item cannot be relaxed by one: the store is
    #    byte-identical across everything except the transitions the table names.
    run.ledger.mark_used(handle)
    run.ledger.quarantine_for_denial(handle, DenialReason.PROXY_MANAGEMENT_INTERFACE)
    quarantined = run.snapshot()
    assert not [
        name
        for name in dir(run.ledger)
        if name in ("resume", "release", "unquarantine", "clear", "delete")
    ]
    assert run.store.items == quarantined
    assert run.ledger.is_allocatable(handle) is False

    # 3. A repeat execution that moved the claim backwards would overwrite `quarantined` with
    #    `used`. The store's condition refuses it and the recorded reason survives.
    with pytest.raises(ClaimConditionFailed):
        run.ledger.mark_used(handle)
    assert run.store.items == quarantined
    after = run.stored(FIRST)
    assert after is not None
    assert after.eligibility is Eligibility.QUARANTINED
    assert after.quarantine_reason == DenialReason.PROXY_MANAGEMENT_INTERFACE.value

    # 4. Non-reuse keyed on the Sandbox identifier alone would refuse the sibling on the other
    #    provider, which shares the identifier and is a different Sandbox.
    assert FIRST[1] == SIBLING[1]
    _attempt_claim(run, SIBLING, "session-sibling", NOW_MS + 2)
    sibling = run.stored(SIBLING)
    assert sibling is not None
    assert sibling.session_id == "session-sibling"
