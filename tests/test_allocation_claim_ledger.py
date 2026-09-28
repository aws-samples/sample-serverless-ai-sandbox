# kiro-classification: public
"""The claim ledger: one Sandbox, one Session, ever — and what happens to the loser.

Every assertion here is deterministic and nothing draws inputs. Property 39 (exclusivity), Property
14 (non-reuse) and Property 13 (Tenant partition confinement) are tasks 6.15, 6.16 and 6.17 and
belong to their own files; what this file establishes is the mechanism those properties will be
quantified over, in four structural senses:

- :class:`FakeClaimStore` models the conditional write faithfully, so `test_the_second_claim_on_one_
  sandbox_is_refused` is refused *by the store* rather than by a comparison the ledger performs. A
  fake that wrote unconditionally would make every exclusivity assertion in this file and in 6.15
  vacuous, so `test_the_fake_store_actually_enforces_its_conditions` pins the fake itself.
- The duplicate-termination assertions read the provider's call log and its surviving Sandbox set,
  so "the loser's Sandbox is terminated" is checked from the provider's side rather than from the
  exception's.
- The quarantine assertions recover the trigger from the stored attribute alone, which is the form
  the distinguishability claim actually has to hold in.
- `test_no_module_outside_...` runs the two lint rules over the tree, carrying into CI the claims
  that allocation neither provisions nor mints credentials.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from ci.lint_rules import orchestrated_provisioning as provisioning_rule
from ci.lint_rules import sole_credential_issuer as issuer_rule
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
    SandboxNotAttributable,
    SandboxNotClaimed,
    claim_key_for,
    is_allocatable,
    sandbox_tags,
)
from control_plane.allocation.ledger import (
    ELIGIBILITY_ATTRIBUTE,
    QUARANTINE_REASON_ATTRIBUTE,
)
from control_plane.providers.base import (
    SandboxHandle,
    SandboxState,
    SandboxStatus,
)
from control_plane.state.keys import CLAIM_SORT_KEY, claim_partition_key
from control_plane.state.records import Eligibility, SandboxClaimRecord
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TTL_ATTRIBUTE,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
SESSION_A = "01JCLAIMAAAAAAAAAAAAAAAAAA"
SESSION_B = "01JCLAIMBBBBBBBBBBBBBBBBBB"
PROVIDER = "lambda-microvms"

#: Epoch milliseconds, fixed so every timestamp expectation is arithmetic rather than a comparison
#: against the wall clock.
NOW_MS = 1_700_000_000_000


def handle(sandbox_id: str = "sbx-1", provider: str = PROVIDER) -> SandboxHandle:
    return SandboxHandle(provider_name=provider, sandbox_id=sandbox_id, opaque={})


def tags_for(session_id: str = SESSION_A, tenant_id: str = TENANT) -> dict[str, str]:
    return sandbox_tags(tenant_id=tenant_id, session_id=session_id)


@dataclass
class FakeClaimStore:
    """An in-memory claim store keyed exactly as DynamoDB is: partition key, then sort key.

    Faithful in the one respect the whole of R11.1 rests on: `put_claim_if_absent` raises when an
    item already occupies the key, so a second claim fails *here* rather than in the ledger. The two
    eligibility updates carry their conditions too, which is what makes the transitions one-way
    against this fake and not only against a deployment.

    No network and no deployed resource. `log` records the order of operations so a test can assert
    that a read happened only on the exceptional path.
    """

    items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)

    def put_claim_if_absent(self, item: Mapping[str, Any]) -> None:
        key = (item[PARTITION_KEY_ATTRIBUTE], item[SORT_KEY_ATTRIBUTE])
        self.log.append("put_claim_if_absent")
        if key in self.items:
            # ConditionExpression: attribute_not_exists(pk)
            raise ClaimConditionFailed(f"a claim already exists at {key}")
        self.items[key] = dict(item)

    def read_claim(self, *, partition_key: str) -> Mapping[str, Any] | None:
        self.log.append("read_claim")
        return self.items.get((partition_key, CLAIM_SORT_KEY))

    def mark_claim_used(self, *, partition_key: str) -> None:
        self.log.append("mark_claim_used")
        item = self.items.get((partition_key, CLAIM_SORT_KEY))
        # ConditionExpression: attribute_exists(pk) AND eligibility = :never_run
        if item is None or item[ELIGIBILITY_ATTRIBUTE] != Eligibility.NEVER_RUN.value:
            raise ClaimConditionFailed(f"claim at {partition_key} is not never-run")
        item[ELIGIBILITY_ATTRIBUTE] = Eligibility.USED.value

    def quarantine_claim(self, *, partition_key: str, reason: str) -> None:
        self.log.append("quarantine_claim")
        item = self.items.get((partition_key, CLAIM_SORT_KEY))
        # ConditionExpression: attribute_exists(pk) AND attribute_not_exists(quarantineReason)
        if item is None or QUARANTINE_REASON_ATTRIBUTE in item:
            raise ClaimConditionFailed(f"claim at {partition_key} cannot be quarantined")
        item[ELIGIBILITY_ATTRIBUTE] = Eligibility.QUARANTINED.value
        item[QUARANTINE_REASON_ATTRIBUTE] = reason

    def claim_at(self, partition_key: str) -> SandboxClaimRecord:
        return SandboxClaimRecord.from_item(self.items[(partition_key, CLAIM_SORT_KEY)])


@dataclass
class RecordingTerminator:
    """A provider that records every termination and reports the Sandbox terminal afterwards.

    `live` starts as the set of Sandboxes in existence, so a test asks the provider what survives
    rather than trusting the exception's own account of what it did.
    """

    live: set[str] = field(default_factory=set)
    log: list[str] = field(default_factory=list)
    state: SandboxState = SandboxState.TERMINATED

    def terminate(self, target: SandboxHandle) -> SandboxStatus:
        self.log.append(target.sandbox_id)
        self.live.discard(target.sandbox_id)
        return SandboxStatus(
            handle=target,
            state=self.state,
            memory_bytes=0,
            started_at=datetime.fromtimestamp(NOW_MS / 1000, tz=UTC),
            state_reason=None,
        )


@dataclass
class FailingTerminator:
    """A provider whose `terminate` raises, so the leak path is exercised rather than assumed."""

    log: list[str] = field(default_factory=list)

    def terminate(self, target: SandboxHandle) -> SandboxStatus:
        self.log.append(target.sandbox_id)
        raise TimeoutError("provider did not answer")


def ledger(
    store: FakeClaimStore | None = None,
    terminator: RecordingTerminator | FailingTerminator | None = None,
) -> SandboxClaimLedger:
    return SandboxClaimLedger(
        store=store if store is not None else FakeClaimStore(),
        terminator=terminator if terminator is not None else RecordingTerminator(),
    )


# --------------------------------------------------------------------------------------
# The fake itself, before anything is asserted through it.
# --------------------------------------------------------------------------------------


def test_the_fake_store_actually_enforces_its_conditions() -> None:
    # Every exclusivity assertion below is only as good as this. A fake that overwrote would make
    # them all pass while proving nothing, so the fake's conditions are pinned first.
    store = FakeClaimStore()
    item = SandboxClaimRecord(
        pk=claim_key_for(handle()),
        session_id=SESSION_A,
        tenant_id=TENANT,
        claimed_at=NOW_MS,
    ).to_item()
    store.put_claim_if_absent(item)
    with pytest.raises(ClaimConditionFailed):
        store.put_claim_if_absent(item)
    with pytest.raises(ClaimConditionFailed):
        store.mark_claim_used(partition_key="H#lambda-microvms#absent")
    with pytest.raises(ClaimConditionFailed):
        store.quarantine_claim(partition_key="H#lambda-microvms#absent", reason="x")


# --------------------------------------------------------------------------------------
# Exclusivity: the conditional write, and what the loser receives (R11.1, R11.10).
# --------------------------------------------------------------------------------------


def test_a_claim_records_the_session_the_tenant_and_never_run_eligibility() -> None:
    store = FakeClaimStore()
    record = ledger(store).claim(
        handle=handle(),
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    assert record.pk == claim_partition_key(PROVIDER, "sbx-1")
    assert record.sort_key == CLAIM_SORT_KEY
    assert record.session_id == SESSION_A
    assert record.tenant_id == TENANT
    assert record.claimed_at == NOW_MS
    assert record.eligibility is Eligibility.NEVER_RUN
    assert record.quarantine_reason is None
    assert store.claim_at(record.pk) == record


def test_the_claim_is_one_conditional_write_and_reads_nothing_first() -> None:
    # A read-then-write would leave a window between the two in which a second caller reaches the
    # same conclusion. The absence of a read before the write is the shape of that guarantee.
    store = FakeClaimStore()
    ledger(store).claim(
        handle=handle(),
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    assert store.log == ["put_claim_if_absent"]


def test_the_second_claim_on_one_sandbox_is_refused() -> None:
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger(store).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    assert raised.value.attempted_session_id == SESSION_B
    assert raised.value.claimed_by_session_id == SESSION_A
    assert raised.value.partition_key == claim_key_for(subject)


def test_the_winning_claim_is_untouched_by_the_loser() -> None:
    # The loser must not overwrite, must not append, and must not renumber. One claim, still the
    # first Session's, still `never-run`.
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    with pytest.raises(SandboxAlreadyClaimed):
        ledger(store).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    assert len(store.items) == 1
    surviving = store.claim_at(claim_key_for(subject))
    assert surviving.session_id == SESSION_A
    assert surviving.claimed_at == NOW_MS
    assert surviving.eligibility is Eligibility.NEVER_RUN


def test_a_claim_refused_across_tenants_too() -> None:
    # The claim key names a provider and a Sandbox, not a Tenant, so uniqueness holds across Tenant
    # partitions. Two Tenants claiming one Sandbox identifier must collide; items in two Tenant
    # partitions never would, which is why this key shape sits outside them.
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A, TENANT),
        claimed_at=NOW_MS,
    )
    with pytest.raises(SandboxAlreadyClaimed):
        ledger(store).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=OTHER_TENANT,
            tags=tags_for(SESSION_B, OTHER_TENANT),
            claimed_at=NOW_MS + 1,
        )
    assert store.claim_at(claim_key_for(subject)).tenant_id == TENANT


def test_the_claim_key_is_not_a_tenant_partition_key() -> None:
    tenant_partition = pk_for(
        AuthenticatedPrincipal(
            caller_identity=f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}",
            tenant_id=TENANT,
        )
    )
    key = claim_key_for(handle())
    assert not key.startswith(tenant_partition)
    assert TENANT not in key
    # Derived from the handle alone, so a caller cannot present a key naming a different Sandbox
    # from the one it is claiming.
    assert key == claim_partition_key(PROVIDER, "sbx-1")


def test_distinct_sandboxes_claim_independently() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    for index, session in enumerate((SESSION_A, SESSION_B)):
        book.claim(
            handle=handle(f"sbx-{index}"),
            session_id=session,
            tenant_id=TENANT,
            tags=tags_for(session),
            claimed_at=NOW_MS + index,
        )
    assert len(store.items) == 2
    assert {record["sessionId"] for record in store.items.values()} == {
        SESSION_A,
        SESSION_B,
    }


def test_one_sandbox_id_under_two_providers_is_two_claims() -> None:
    # The provider name is part of the key because a Sandbox identifier is only unique within its
    # own backend; sharing a key across providers would refuse a legitimate claim.
    store = FakeClaimStore()
    book = ledger(store)
    for index, provider in enumerate((PROVIDER, "local-firecracker")):
        book.claim(
            handle=handle("sbx-same", provider=provider),
            session_id=f"{SESSION_A[:-1]}{index}",
            tenant_id=TENANT,
            tags=tags_for(f"{SESSION_A[:-1]}{index}"),
            claimed_at=NOW_MS,
        )
    assert len(store.items) == 2


# --------------------------------------------------------------------------------------
# Duplicate termination: the loser's Sandbox does not outlive the failed claim.
# --------------------------------------------------------------------------------------


def test_the_losers_sandbox_is_terminated_before_the_exception_is_raised() -> None:
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    provider = RecordingTerminator(live={"sbx-1"})
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger(store, provider).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    # Asked of the provider, not of the exception: the Sandbox is gone by the time the caller is
    # told anything, so no `except` block has an obligation it could forget.
    assert provider.log == ["sbx-1"]
    assert provider.live == set()
    termination = raised.value.termination
    assert termination.terminated is True
    assert termination.leaked is False
    assert termination.state is SandboxState.TERMINATED
    assert termination.failure is None
    assert termination.handle is subject


def test_the_duplicate_is_terminated_exactly_once() -> None:
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    provider = RecordingTerminator(live={"sbx-1"})
    with pytest.raises(SandboxAlreadyClaimed):
        ledger(store, provider).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    assert len(provider.log) == 1


def test_a_failed_termination_is_reported_rather_than_masking_the_refusal() -> None:
    # The caller's problem is that it lost the claim. A provider error replacing that would hide the
    # requirement being enforced behind a transport failure, so the leak is recorded instead.
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    provider = FailingTerminator()
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger(store, provider).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    assert provider.log == ["sbx-1"]
    termination = raised.value.termination
    assert termination.terminated is False
    assert termination.leaked is True
    assert termination.failure is not None
    assert "TimeoutError" in termination.failure
    # Still the refusal the caller has to act on, not a TimeoutError.
    assert raised.value.claimed_by_session_id == SESSION_A


def test_a_non_terminal_termination_result_counts_as_a_leak() -> None:
    # `terminate` returning RUNNING means the Sandbox is still billable. Reporting it as terminated
    # because the call did not raise would be the leak this field exists to make visible.
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    provider = RecordingTerminator(live={"sbx-1"}, state=SandboxState.RUNNING)
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger(store, provider).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    termination = raised.value.termination
    assert termination.terminated is False
    assert termination.leaked is True
    assert termination.state is SandboxState.RUNNING
    assert termination.failure is not None and "RUNNING" in termination.failure


def test_a_terminating_state_is_accepted_as_terminal() -> None:
    store = FakeClaimStore()
    subject = handle()
    ledger(store).claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(SESSION_A),
        claimed_at=NOW_MS,
    )
    provider = RecordingTerminator(live={"sbx-1"}, state=SandboxState.TERMINATING)
    with pytest.raises(SandboxAlreadyClaimed) as raised:
        ledger(store, provider).claim(
            handle=subject,
            session_id=SESSION_B,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS + 1,
        )
    assert raised.value.termination.terminated is True


def test_nothing_is_terminated_when_the_claim_succeeds() -> None:
    provider = RecordingTerminator(live={"sbx-1"})
    ledger(FakeClaimStore(), provider).claim(
        handle=handle(),
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    assert provider.log == []
    assert provider.live == {"sbx-1"}


# --------------------------------------------------------------------------------------
# Allocation eligibility (R11.10).
# --------------------------------------------------------------------------------------


def test_an_unclaimed_sandbox_is_allocatable_and_a_claimed_one_never_is() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    assert book.is_allocatable(subject) is True
    assert is_allocatable(None) is True
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    assert book.is_allocatable(subject) is False


def test_no_eligibility_value_makes_a_claimed_sandbox_allocatable_again() -> None:
    # R11.10 is about the claim existing, not about what the claim says. Quantified over every
    # eligibility value so a fourth one added later cannot quietly reopen allocation.
    for eligibility in Eligibility:
        quarantined = eligibility is Eligibility.QUARANTINED
        claim = SandboxClaimRecord(
            pk=claim_key_for(handle()),
            session_id=SESSION_A,
            tenant_id=TENANT,
            claimed_at=NOW_MS,
            eligibility=eligibility,
            quarantine_reason=SESSION_FAILURE_REASON if quarantined else None,
        )
        assert is_allocatable(claim) is False, eligibility


def test_marking_used_is_one_way() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    book.mark_used(subject)
    assert store.claim_at(claim_key_for(subject)).eligibility is Eligibility.USED
    # No second transition, and no edge back to never-run.
    with pytest.raises(ClaimConditionFailed):
        book.mark_used(subject)
    assert store.claim_at(claim_key_for(subject)).eligibility is Eligibility.USED


def test_marking_an_unclaimed_sandbox_used_is_refused_by_name() -> None:
    with pytest.raises(SandboxNotClaimed) as raised:
        ledger().mark_used(handle())
    assert raised.value.partition_key == claim_key_for(handle())


def test_marking_used_does_not_read_before_it_writes() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    store.log.clear()
    book.mark_used(subject)
    assert store.log == ["mark_claim_used"]


# --------------------------------------------------------------------------------------
# The closed circumvention subset, and the two quarantine triggers (R11.12, R11.13).
# --------------------------------------------------------------------------------------


def test_the_circumvention_subset_is_closed_and_proper() -> None:
    assert CIRCUMVENTION_REASONS < frozenset(DenialReason)
    assert NON_CIRCUMVENTION_REASONS == frozenset(DenialReason) - CIRCUMVENTION_REASONS
    assert CIRCUMVENTION_REASONS & NON_CIRCUMVENTION_REASONS == frozenset()
    assert CIRCUMVENTION_REASONS | NON_CIRCUMVENTION_REASONS == frozenset(DenialReason)
    # Derived rather than listed, so a reason added to the enum is non-circumventing until somebody
    # puts it in the subset deliberately.
    assert NON_CIRCUMVENTION_REASONS


def test_the_ordinary_undeclared_destination_denial_quarantines_nothing() -> None:
    # The rule would be worthless if a mistyped hostname cost a Sandbox: operators would disable it
    # and R11.12 would then protect nothing.
    assert DenialReason.UNDECLARED_DESTINATION in NON_CIRCUMVENTION_REASONS
    assert DenialReason.CONTROLLER_UNREACHABLE in NON_CIRCUMVENTION_REASONS


def test_every_denial_reason_is_kebab_case() -> None:
    # A reason travels into a stored attribute, a metric dimension and a log line. One spelling
    # across all three is what lets an operator grep, following `runtime.restore.RestoreCause`.
    for reason in DenialReason:
        assert reason.value == reason.value.lower()
        assert reason.value.replace("-", "").isalnum()
        assert "_" not in reason.value


def test_the_two_quarantine_vocabularies_are_disjoint() -> None:
    # This is the whole basis of recovering a trigger from the stored reason, so it is asserted
    # rather than trusted.
    assert SESSION_FAILURE_REASON not in {reason.value for reason in DenialReason}


def test_a_circumvention_denial_quarantines_and_names_its_trigger() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    recorded = book.quarantine_for_denial(subject, DenialReason.HOST_SNI_MISMATCH)
    assert recorded.trigger is QuarantineTrigger.EGRESS_CIRCUMVENTION
    claim = store.claim_at(claim_key_for(subject))
    assert claim.eligibility is Eligibility.QUARANTINED
    assert claim.quarantine_reason == DenialReason.HOST_SNI_MISMATCH.value
    assert book.quarantine_of(subject) == recorded


def test_every_circumvention_reason_quarantines() -> None:
    for index, reason in enumerate(sorted(CIRCUMVENTION_REASONS)):
        store = FakeClaimStore()
        book = ledger(store)
        subject = handle(f"sbx-{index}")
        book.claim(
            handle=subject,
            session_id=SESSION_A,
            tenant_id=TENANT,
            tags=tags_for(),
            claimed_at=NOW_MS,
        )
        recorded = book.quarantine_for_denial(subject, reason)
        assert recorded.reason == reason.value
        assert recorded.trigger is QuarantineTrigger.EGRESS_CIRCUMVENTION
        assert store.claim_at(claim_key_for(subject)).eligibility is (
            Eligibility.QUARANTINED
        )


def test_a_non_circumvention_denial_is_refused_and_writes_nothing() -> None:
    for reason in sorted(NON_CIRCUMVENTION_REASONS):
        store = FakeClaimStore()
        book = ledger(store)
        subject = handle()
        book.claim(
            handle=subject,
            session_id=SESSION_A,
            tenant_id=TENANT,
            tags=tags_for(),
            claimed_at=NOW_MS,
        )
        with pytest.raises(DenialIsNotCircumvention):
            book.quarantine_for_denial(subject, reason)
        # Refused before the store is touched, so a caller that skipped the classification cannot
        # quarantine by accident.
        assert store.claim_at(claim_key_for(subject)).eligibility is (
            Eligibility.NEVER_RUN
        )
        assert book.quarantine_of(subject) is None


def test_a_recorded_session_failure_quarantines_under_its_own_trigger() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    recorded = book.quarantine_for_session_failure(subject)
    assert recorded.trigger is QuarantineTrigger.SESSION_FAILURE
    assert recorded.reason == SESSION_FAILURE_REASON
    claim = store.claim_at(claim_key_for(subject))
    assert claim.eligibility is Eligibility.QUARANTINED
    assert claim.quarantine_reason == SESSION_FAILURE_REASON


def test_the_two_triggers_stay_distinguishable_from_the_stored_reason_alone() -> None:
    # One attribute, two triggers, recovered rather than stored twice — so the two copies cannot
    # drift apart. An operator reading a claim item can tell R11.12's quarantine from R11.13's.
    store = FakeClaimStore()
    book = ledger(store)
    circumvented, failed = handle("sbx-circ"), handle("sbx-fail")
    for subject, session in ((circumvented, SESSION_A), (failed, SESSION_B)):
        book.claim(
            handle=subject,
            session_id=session,
            tenant_id=TENANT,
            tags=tags_for(session),
            claimed_at=NOW_MS,
        )
    book.quarantine_for_denial(circumvented, DenialReason.ALIAS_SPOOFED)
    book.quarantine_for_session_failure(failed)

    for subject, trigger in (
        (circumvented, QuarantineTrigger.EGRESS_CIRCUMVENTION),
        (failed, QuarantineTrigger.SESSION_FAILURE),
    ):
        stored = store.claim_at(claim_key_for(subject))
        assert stored.quarantine_reason is not None
        # Recovered from the attribute a deployment stores, not from anything held in memory.
        assert Quarantine.from_recorded_reason(stored.quarantine_reason).trigger is (
            trigger
        )
        recovered = book.quarantine_of(subject)
        assert recovered is not None and recovered.trigger is trigger


def test_the_first_quarantine_reason_survives_a_later_one() -> None:
    # A Session whose code attempted circumvention very often also fails, so R11.13's trigger tends
    # to arrive second. Overwriting would replace the security-relevant fact with `session-failed`
    # in exactly the cases an operator most needs to see it.
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    book.quarantine_for_denial(subject, DenialReason.PROXY_MANAGEMENT_INTERFACE)
    returned = book.quarantine_for_session_failure(subject)
    # The later call reports what actually stands rather than what it asked for.
    assert returned.reason == DenialReason.PROXY_MANAGEMENT_INTERFACE.value
    assert returned.trigger is QuarantineTrigger.EGRESS_CIRCUMVENTION
    stored = store.claim_at(claim_key_for(subject))
    assert stored.quarantine_reason == DenialReason.PROXY_MANAGEMENT_INTERFACE.value


def test_quarantine_survives_a_used_sandbox_and_blocks_marking_used_after() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    book.mark_used(subject)
    book.quarantine_for_session_failure(subject)
    assert store.claim_at(claim_key_for(subject)).eligibility is Eligibility.QUARANTINED
    # No edge back out of quarantine, in either direction.
    with pytest.raises(ClaimConditionFailed):
        book.mark_used(subject)


def test_quarantining_an_unclaimed_sandbox_is_refused_by_name() -> None:
    book = ledger()
    with pytest.raises(SandboxNotClaimed):
        book.quarantine_for_session_failure(handle())
    with pytest.raises(SandboxNotClaimed):
        book.quarantine_for_denial(handle(), DenialReason.ALIAS_SPOOFED)
    assert book.quarantine_of(handle()) is None


def test_an_unquarantined_claim_reports_no_quarantine() -> None:
    store = FakeClaimStore()
    book = ledger(store)
    subject = handle()
    book.claim(
        handle=subject,
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    assert book.quarantine_of(subject) is None
    book.mark_used(subject)
    assert book.quarantine_of(subject) is None


# --------------------------------------------------------------------------------------
# The Tenant and Session tags every Sandbox carries (R11.7).
# --------------------------------------------------------------------------------------


def test_a_claim_is_refused_when_the_tags_name_a_different_session() -> None:
    # Two independent records name the Tenant and Session of a Sandbox: the tags on the provider
    # side and the claim item on the State_Store side. A claim is the moment they must agree.
    store = FakeClaimStore()
    with pytest.raises(SandboxNotAttributable):
        ledger(store).claim(
            handle=handle(),
            session_id=SESSION_A,
            tenant_id=TENANT,
            tags=tags_for(SESSION_B),
            claimed_at=NOW_MS,
        )
    assert store.items == {}
    assert store.log == []


def test_a_claim_is_refused_when_the_tags_name_a_different_tenant() -> None:
    store = FakeClaimStore()
    with pytest.raises(SandboxNotAttributable):
        ledger(store).claim(
            handle=handle(),
            session_id=SESSION_A,
            tenant_id=TENANT,
            tags=tags_for(SESSION_A, OTHER_TENANT),
            claimed_at=NOW_MS,
        )
    assert store.items == {}


def test_a_claim_is_refused_when_either_attribution_tag_is_absent() -> None:
    full = tags_for()
    for omitted in tuple(full):
        partial = {key: value for key, value in full.items() if key != omitted}
        store = FakeClaimStore()
        with pytest.raises(SandboxNotAttributable):
            ledger(store).claim(
                handle=handle(),
                session_id=SESSION_A,
                tenant_id=TENANT,
                tags=partial,
                claimed_at=NOW_MS,
            )
        assert store.items == {}


def test_an_untagged_sandbox_can_never_be_claimed() -> None:
    # An untagged Sandbox is unreachable by `discover`, which is the Reaper's only way to find a
    # Sandbox whose handle was never recorded. Refusing the claim keeps it from becoming the
    # recorded Sandbox of a Session.
    store = FakeClaimStore()
    with pytest.raises(SandboxNotAttributable):
        ledger(store).claim(
            handle=handle(),
            session_id=SESSION_A,
            tenant_id=TENANT,
            tags={},
            claimed_at=NOW_MS,
        )
    assert store.items == {}


def test_operator_tags_ride_alongside_the_attribution_pair() -> None:
    tags = sandbox_tags(
        tenant_id=TENANT, session_id=SESSION_A, extra={"costCentre": "cc-7"}
    )
    store = FakeClaimStore()
    ledger(store).claim(
        handle=handle(),
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags,
        claimed_at=NOW_MS,
    )
    assert tags["costCentre"] == "cc-7"
    assert len(store.items) == 1


def test_an_extra_tag_may_not_override_the_attribution_pair() -> None:
    for key in tags_for():
        with pytest.raises(SandboxNotAttributable):
            sandbox_tags(tenant_id=TENANT, session_id=SESSION_A, extra={key: "forged"})


# --------------------------------------------------------------------------------------
# The claim item carries no TTL, and allocation neither provisions nor mints.
# --------------------------------------------------------------------------------------


def test_a_written_claim_item_carries_no_expiry_attribute() -> None:
    # The claim is the only record that a billable Sandbox was ever allocated to a Session. TTL
    # expiry reaching it would delete the evidence of the leak the Reaper uses it to find.
    store = FakeClaimStore()
    ledger(store).claim(
        handle=handle(),
        session_id=SESSION_A,
        tenant_id=TENANT,
        tags=tags_for(),
        claimed_at=NOW_MS,
    )
    for item in store.items.values():
        assert TTL_ATTRIBUTE not in item
    # And the record type itself never names it, so no conditional write could add one.
    assert TTL_ATTRIBUTE not in inspect.getsource(SandboxClaimRecord.to_item)


def test_no_module_outside_the_provider_seam_provisions() -> None:
    # Allocation is not provisioning: it observes a Sandbox that already exists and records the
    # fact. Carried into CI here as well as in the creation suite.
    assert provisioning_rule.check_repository() == ()


def test_no_module_outside_the_sole_issuer_mints_a_credential() -> None:
    assert issuer_rule.check_repository() == ()
