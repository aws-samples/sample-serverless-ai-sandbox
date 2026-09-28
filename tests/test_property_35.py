# kiro-classification: public
"""Property 35: get-or-create resolves or creates, exactly one, within the Tenant.

Six requirements meet on one code path here, and the property is phrased as a single claim about
one resolution because they are not separable: `ResolveSession` performs exactly one of two actions
(R6.15), it addresses nothing outside the calling Tenant's partition while doing so (R6.16, R11.11),
it leaves a suspended Session suspended (R6.20), it replaces a terminal binding rather than deleting
it (R6.21), and the credential it returns on a resolve is minted now rather than read (R6.23).
`test_control_plane_resolution.py` pins sixty-four examples underneath this. What is generalised is
the *domain*: the Affinity_Key, the prior state of the binding and of the Session it names, the
lifecycle state that selects the loser's branch, the order in which two Tenants presenting one key
arrive, and the length of the request sequence.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| Affinity_Keys carrying the sort-key delimiter, non-ASCII, astral-plane characters and 8 KiB of text | that the digest, not a validation rule, is what makes a caller-supplied key safe as a sort key |
| the lifecycle state of an already-bound Session, across the whole enum | every row of `LOSER_BRANCHES` by generation rather than by `parametrize` |
| whether the bound Session's row exists at all | R13.8's stale-binding self-heal, reached without waiting on any expiry |
| whether the binding's `expiresAt` has already passed | that resolution's correctness does not depend on a TTL having fired |
| what the winner's orchestration publishes, and whether it publishes inside the budget | the three sub-branches under `WAIT_FOR_THE_WINNER`, including the one that goes terminal mid-wait |
| request sequences of one to four resolutions over one key | that the invariants hold at *every* point rather than only after the first request |
| a schedule interleaving two Tenants presenting the byte-identical key | R11.11, over addresses rather than over an absent comparison |

The lifecycle state is drawn from `LifecycleState` in full rather than from the three branch groups,
so a state whose branch changed would be drawn into a group whose expectation no longer holds. The
expectation itself is restated here as three frozensets — :data:`RETURNED_STATES`,
:data:`WAITED_STATES` and :data:`RECREATED_STATES` — rather than read out of `LOSER_BRANCHES`, and
:func:`test_the_three_branch_groups_agree_with_the_implementations_table` asserts the two agree. A
property that read the table it is checking would pass against any table.

## What is asserted, at every step of every sequence

- **Exactly one action** (R6.15). The response names `created` or `resolved`, and it is the one the
  prior state licenses. A `resolved` step adds no Session row and starts no execution; a `created`
  step adds exactly one row and exactly one execution named for it.
- **Exactly one binding, and one Session row it names** (R6.15, R6.17). One binding item per
  `(Tenant, digest)` at every point, and every Session row in the partition other than the one the
  binding names is in a state that licensed its replacement. Nothing is ever deleted: the set of
  item keys only grows, which is R6.21's "replaced, never deleted-then-created" stated as an
  invariant over addresses.
- **Confinement** (R6.16, R11.11). Every key of every read and every write in the step carries
  `pk_for(principal)` for the calling Tenant. Asserted over `keys_touched` rather than over the
  absence of a Tenant comparison, because the absence of a check is not evidence.
- **A suspended Session stays suspended** (R6.20). The whole store is compared before and after: a
  resolution that returned a credential for a live or suspended Session wrote *nothing at all*,
  which is stronger than "no resume was called" and is the reason the design gives — that branch has
  nothing to write with.
- **Freshly minted** (R6.23). On every resolve outcome carrying a credential, the returned
  credential differs from the one stored on the Session row and carries the mint's own token. The
  drawn cases arrange for the row to carry a *distinguishable* published credential in every one of
  those cases, so the inequality is a real comparison rather than one against `None`.
- **The create branch reads instead** (R6.13). Stated here as the other half of the separation: a
  `created` step returns exactly the published credential. Without it, "always minted" could be
  satisfied by an implementation that minted on both branches.

## Why the store double is imported rather than rewritten

`FakeStore` in `test_control_plane_resolution.py` implements all three binding seams over one dict
keyed as DynamoDB is, commits both items of a transaction or neither, and records every key of every
read and write in `keys_touched`. That last part is what makes the confinement half of this property
assertable at all, and a second copy of it here would be a second thing to keep faithful. The same
goes for `operations()`, which injects a fixed clock, the `RecordingMint` the sole-issuer lint rule
allows, and the shared session-identifier counter. Nothing in this file defines a store, a mint or a
provider.

Two helpers *are* local: :func:`seat_session` and :func:`seat_binding`, because the deterministic
module's `seated_session` hardcodes its digest and this property draws one. Property 36 will want
the same two, and :func:`affinity_key` as well; duplicating them into that file is preferred over
either file editing the other, and consolidating the three into the harness is a later change.

## Non-vacuity

:func:`test_every_bucket_is_reachable_and_the_property_holds_on_each` runs the same checker over an
enumerated case for every bucket the generator can produce and asserts that all of them are reached
and that all four outcome shapes are driven, so no arm of the checker is dead.
:func:`test_the_assertions_discriminate_three_plausible_wrong_resolutions` asserts that three wrong
implementations disagree with what the code does on cases this property draws: returning the
published credential on a resolve, treating a suspended Session as one to resume, and treating an
expired-but-present binding as absent.

## Budget

200 examples. Each one runs up to four resolutions against an in-memory dict with an injected clock,
an injected mint and a stub orchestration: no subprocess, no filesystem, no network and no
wall-clock wait, so the whole property runs in a couple of seconds. The design's floor of 100 would
leave several of the twelve lifecycle buckets unvisited on a given run, since the branch groups are
drawn uniformly over a twelve-member enum crossed with four prior shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from http import HTTPStatus
from typing import Any, Final

from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.api.creation import EXECUTION_NAME_PREFIX
from control_plane.api.handlers import OperationRequest
from control_plane.api.resolution import (
    AFFINITY_KEY_FIELD,
    LOSER_BRANCHES,
    RESOLUTION_FIELD,
    LoserBranch,
    ResolutionOutcome,
)
from control_plane.api.routes import Operation
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.keys import (
    BINDING_PREFIX,
    SEPARATOR,
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
from control_plane.tenancy import pk_for
from tests.test_connection_credentials import FAKE_TOKEN
from tests.test_control_plane_resolution import (
    NOW_MS,
    OTHER_TENANT,
    PUBLISHED,
    SANDBOX_HANDLE,
    SETTINGS,
    TENANT,
    FakeStore,
    RecordingStarter,
    operations,
    principal,
)

# --- The branch table, restated ------------------------------------------------------------------

#: A Sandbox exists and is reachable now, so a credential is minted and returned (R6.19, R6.20).
RETURNED_STATES: Final = frozenset({LifecycleState.RUNNING, LifecycleState.SUSPENDED})

#: Provisioning or a transition is in flight, so the loser waits on the winner's row (R6.19).
WAITED_STATES: Final = frozenset(
    {
        LifecycleState.PENDING,
        LifecycleState.ORCHESTRATING,
        LifecycleState.PROVISIONING,
        LifecycleState.STARTING,
        LifecycleState.SUSPENDING,
        LifecycleState.RESUMING,
        LifecycleState.CONTINUING,
    }
)

#: The bound Session will never serve this caller, so the binding is treated as absent (R6.21).
RECREATED_STATES: Final = frozenset(
    {
        LifecycleState.TERMINATING,
        LifecycleState.TERMINATED,
        LifecycleState.FAILED,
    }
)

# --- Fixtures the drawn cases are built from ------------------------------------------------------

#: The Session an earlier turn left in each Tenant's partition. Distinct per Tenant, so "two Tenants
#: presenting one Affinity_Key resolve to different Sessions" is a comparison of two known values.
MY_EARLIER_SESSION: Final = "01JMYEARLIERTURNAAAAAAAAAA"
THEIR_EARLIER_SESSION: Final = "01JTHEIRSEARLIERTURNAAAAAA"

#: The Session identifier a stale binding names: no row has ever existed at it (R13.8).
VANISHED_SESSION: Final = "01JVANISHEDNOROWEVERAAAAAA"

#: An hour, in the two units the binding record uses.
ONE_HOUR_MS: Final = 3_600_000
SESSION_DURATION_SECONDS: Final = 3600

#: The length of every Affinity_Key digest, taken from one rather than restated, so the claim being
#: asserted is "the same length whatever the caller sent" rather than a number this file believes.
DIGEST_LENGTH: Final = len(affinity_key_digest("a"))

#: Below this, a drawn key is short enough to occur inside ordinary item content by coincidence, so
#: "the raw key appears nowhere" is asserted only at or above it.
UNAMBIGUOUS_KEY_LENGTH: Final = 8

#: Affinity_Keys worth drawing by name. Every one of them is a key a caller's agent framework could
#: plausibly supply, and each would break a system that used the raw value as a sort key: the
#: delimiter at either end and doubled, a key spelled exactly like a Session row key, a key spelled
#: exactly like a *binding* key, non-ASCII text, an astral-plane character, and 8 KiB of it.
AFFINITY_KEY_POOL: Final = (
    "a",
    "thread-9f3",
    "thread#9f3",
    "#",
    "##a##",
    f"{SEPARATOR}trailing{SEPARATOR}",
    f"S{SEPARATOR}01JLOOKSLIKEASESSIONROWKEY",
    f"{BINDING_PREFIX}{SEPARATOR}looks-like-a-binding",
    "会話-9f3",
    "\U0001f600\U0001f600",
    "conversation/2026-06-22T10:15:00Z#turn=41",
    "x" * 8192,
    "会" * 4096,
)

#: What the winner's orchestration is drawn to publish. `RUNNING` and `SUSPENDED` reach the mint;
#: `FAILED` and `TERMINATED` are the Session that died while a loser waited on it.
PUBLISHED_STATES: Final = (
    LifecycleState.RUNNING,
    LifecycleState.SUSPENDED,
    LifecycleState.FAILED,
    LifecycleState.TERMINATED,
)

# The prior shapes of the binding, named so the buckets and the seating read the same way.
PRIOR_ABSENT: Final = "absent"
PRIOR_BOUND: Final = "bound"
PRIOR_ROW_MISSING: Final = "bound-with-no-session-row"

#: Every bucket the generator can land in. The enumerated-case test asserts each is reached, so a
#: generator that quietly stopped producing one would be caught rather than silently narrow the
#: domain this property claims to cover.
BUCKETS: Final = frozenset(
    {
        "prior: no binding",
        "prior: a binding whose Session row is absent",
        "prior: a binding whose expiry has passed",
        *(f"prior: a binding to a {state.value} Session" for state in LifecycleState),
        "other Tenant: nothing bound",
        "other Tenant: a live Session on the identical key",
        "schedule: one Tenant",
        "schedule: two Tenants interleaved",
        "key: carries the sort-key delimiter",
        "key: not ASCII",
        "key: longer than a kilobyte",
        "step: claimed an unbound key",
        "step: replaced a binding whose Session row is absent",
        "step: replaced a terminal binding",
        f"step: returned a {LifecycleState.RUNNING.value} Session",
        f"step: returned a {LifecycleState.SUSPENDED.value} Session",
        "step: waited and the budget expired",
        f"step: waited and the winner reached {LifecycleState.RUNNING.value}",
        f"step: waited and the winner reached {LifecycleState.SUSPENDED.value}",
        "step: waited and the winner went terminal",
    }
)


# --- The wait double ------------------------------------------------------------------------------


@dataclass
class DrawnWait:
    """The creation wait, standing in for the winner's orchestration publishing a credential.

    One instance serves the whole case, so the winner and every loser experience the same wait, and
    it is handed the record rather than a fixed Session identifier because a sequence of resolutions
    waits on more than one row. It publishes what an orchestration publishes — the credential *and*
    a settled lifecycle state *and* the Sandbox handle, since a credential is published only after
    `/run` has returned 200 — and `publishes=False` is the budget-expired case.
    """

    store: FakeStore
    publishes: bool
    reaches: LifecycleState
    calls: list[str] = field(default_factory=list)

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        self.calls.append(record.session_id)
        if not self.publishes:
            return None
        row = self.store.items[(record.pk, record.sort_key)]
        row["lifecycleState"] = self.reaches.value
        row["connection"] = PUBLISHED.to_map()
        row["connectionPublishedAt"] = NOW_MS
        if not self.reaches.is_terminal:
            row["sandboxHandle"] = dict(SANDBOX_HANDLE)
        return PUBLISHED


# --- Seating a prior state ------------------------------------------------------------------------


def seat_session(
    store: FakeStore,
    *,
    tenant_id: str,
    digest: str,
    session_id: str,
    state: LifecycleState,
) -> SessionRecord:
    """Seat a Session row from an earlier turn, carrying the drawn digest.

    A Session that has not provisioned yet carries neither a Sandbox handle nor a published
    credential, and one that has carries both — so a `RUNNING` row can be minted against and a
    `PENDING` row cannot, which is what the wait exists to bridge.
    """
    provisioned = state not in WAITED_STATES
    return store.place_session(
        SessionRecord(
            pk=pk_for(principal(tenant_id)),
            session_id=session_id,
            tenant_id=tenant_id,
            provider_name=LocalFirecrackerProvider.name,
            lifecycle_state=state,
            created_at=NOW_MS,
            updated_at=NOW_MS,
            max_duration_seconds=SESSION_DURATION_SECONDS,
            idle_seconds=300,
            suspended_seconds=600,
            auto_resume=True,
            memory_bytes=SETTINGS.memory_bytes,
            execution_role_arn=SETTINGS.execution_role_arn,
            reap_shard=3,
            reap_deadline=NOW_MS + SESSION_DURATION_SECONDS * 1000,
            artifact_retention_days=SETTINGS.artifact_retention_days,
            generation=1,
            sandbox_handle=dict(SANDBOX_HANDLE) if provisioned else None,
            connection=PUBLISHED if provisioned else None,
            affinity_key_digest=digest,
        )
    )


def seat_binding(
    store: FakeStore,
    *,
    tenant_id: str,
    digest: str,
    session_id: str,
    expired: bool,
) -> None:
    """Seat the binding naming that Session, optionally with an expiry already in the past.

    An expired item DynamoDB has not yet reclaimed is still an item, and resolution reads it as one.
    That is the point of drawing this dimension: correctness must not depend on a TTL having fired.
    """
    store.place_binding(
        AffinityKeyBindingRecord(
            pk=pk_for(principal(tenant_id)),
            affinity_key_digest=digest,
            session_id=session_id,
            bound_at=NOW_MS,
            expires_at=(NOW_MS + (-ONE_HOUR_MS if expired else ONE_HOUR_MS)) // 1000,
        )
    )


# --- One drawn case -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolutionCase:
    """One Affinity_Key, one prior state per Tenant, one wait behaviour and one arrival schedule."""

    affinity_key: str
    prior: str
    prior_state: LifecycleState
    binding_expired: bool
    other_prior: str
    schedule: tuple[str, ...]
    wait_publishes: bool
    wait_reaches: LifecycleState

    @property
    def digest(self) -> str:
        """The sort-key component the raw key becomes, and the only form of it that is stored."""
        return affinity_key_digest(self.affinity_key)

    def buckets(self) -> frozenset[str]:
        """The buckets this case occupies, before any step has run."""
        found = {
            PRIOR_ABSENT: "prior: no binding",
            PRIOR_ROW_MISSING: "prior: a binding whose Session row is absent",
            PRIOR_BOUND: f"prior: a binding to a {self.prior_state.value} Session",
        }[self.prior]
        buckets = {found}
        if self.prior != PRIOR_ABSENT and self.binding_expired:
            buckets.add("prior: a binding whose expiry has passed")
        buckets.add(
            "other Tenant: a live Session on the identical key"
            if self.other_prior == PRIOR_BOUND
            else "other Tenant: nothing bound"
        )
        buckets.add(
            "schedule: two Tenants interleaved"
            if OTHER_TENANT in self.schedule
            else "schedule: one Tenant"
        )
        if SEPARATOR in self.affinity_key:
            buckets.add("key: carries the sort-key delimiter")
        if not self.affinity_key.isascii():
            buckets.add("key: not ASCII")
        if len(self.affinity_key) > 1024:
            buckets.add("key: longer than a kilobyte")
        return frozenset(buckets)


@st.composite
def affinity_key(drawn: st.DrawFn) -> str:
    """A caller-supplied Affinity_Key with a UTF-8 encoding.

    The named pool is mixed with uniform draws over the whole of UTF-8, because a uniform draw alone
    would essentially never produce a key spelled like a Session row key and the pool alone would
    never produce a codepoint nobody thought to name. The empty string and unpaired surrogates are
    excluded: they have no encoding to hash, so they are a `400` rather than a resolution, and
    `test_control_plane_resolution.py` pins both.
    """
    return drawn(
        st.one_of(
            st.sampled_from(AFFINITY_KEY_POOL),
            st.text(alphabet=st.characters(codec="utf-8"), min_size=1, max_size=64),
        )
    )


@st.composite
def resolution_case(drawn: st.DrawFn) -> ResolutionCase:
    """One prior state, one wait behaviour, and a schedule that always includes the caller."""
    tail = drawn(st.lists(st.sampled_from((TENANT, OTHER_TENANT)), max_size=3))
    at = drawn(st.integers(min_value=0, max_value=len(tail)))
    return ResolutionCase(
        affinity_key=drawn(affinity_key()),
        prior=drawn(
            st.sampled_from((PRIOR_ABSENT, PRIOR_BOUND, PRIOR_BOUND, PRIOR_ROW_MISSING))
        ),
        # The whole enum, so every row of the branch table is reached by generation.
        prior_state=drawn(st.sampled_from(tuple(LifecycleState))),
        binding_expired=drawn(st.booleans()),
        other_prior=drawn(st.sampled_from((PRIOR_ABSENT, PRIOR_BOUND))),
        schedule=(*tail[:at], TENANT, *tail[at:]),
        wait_publishes=drawn(st.booleans()),
        wait_reaches=drawn(st.sampled_from(PUBLISHED_STATES)),
    )


# --- What one step must do ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Expectation:
    """What the store state at the start of a step obliges that step to do.

    Derived from the item at the binding's key and the row it names, by a restatement of the branch
    table rather than by a second call into the code under test.
    """

    outcome: ResolutionOutcome
    session_id: str | None
    connection: bool
    replaces: str | None
    waited_on: str | None
    bucket: str


def expectation_for(store: FakeStore, pk: str, case: ResolutionCase) -> Expectation:
    """The one action this resolution may take, read off the prior state (R6.15)."""
    binding_item = store.items.get((pk, binding_sort_key(case.digest)))
    if binding_item is None:
        return Expectation(
            outcome=ResolutionOutcome.CREATED,
            session_id=None,
            connection=case.wait_publishes,
            replaces=None,
            waited_on=None,
            bucket="step: claimed an unbound key",
        )
    bound = str(binding_item["sessionId"])
    row = store.items.get((pk, session_sort_key(bound)))
    if row is None:
        # R13.8: a binding naming a Session that no longer exists is absent the moment it is read.
        return Expectation(
            outcome=ResolutionOutcome.CREATED,
            session_id=None,
            connection=case.wait_publishes,
            replaces=bound,
            waited_on=None,
            bucket="step: replaced a binding whose Session row is absent",
        )
    state = LifecycleState(row["lifecycleState"])
    if state in RECREATED_STATES:
        return Expectation(
            outcome=ResolutionOutcome.CREATED,
            session_id=None,
            connection=case.wait_publishes,
            replaces=bound,
            waited_on=None,
            bucket="step: replaced a terminal binding",
        )
    if state in RETURNED_STATES:
        return Expectation(
            outcome=ResolutionOutcome.RESOLVED,
            session_id=bound,
            connection=True,
            replaces=None,
            waited_on=None,
            bucket=f"step: returned a {state.value} Session",
        )
    if not case.wait_publishes:
        # R9.16: a Session identifier with no credential, never a `504`.
        return Expectation(
            outcome=ResolutionOutcome.RESOLVED,
            session_id=bound,
            connection=False,
            replaces=None,
            waited_on=bound,
            bucket="step: waited and the budget expired",
        )
    if case.wait_reaches in RECREATED_STATES:
        return Expectation(
            outcome=ResolutionOutcome.CREATED,
            session_id=None,
            connection=True,
            replaces=bound,
            waited_on=bound,
            bucket="step: waited and the winner went terminal",
        )
    return Expectation(
        outcome=ResolutionOutcome.RESOLVED,
        session_id=bound,
        connection=True,
        replaces=None,
        waited_on=bound,
        bucket=f"step: waited and the winner reached {case.wait_reaches.value}",
    )


def session_rows(store: FakeStore, pk: str, digest: str) -> list[SessionRecord]:
    """Every Session row in this partition carrying this Affinity_Key digest."""
    return [
        record
        for key, item in store.items.items()
        if key[0] == pk
        and key[1].startswith(f"S{SEPARATOR}")
        and (record := SessionRecord.from_item(item)).affinity_key_digest == digest
    ]


def binding_keys(store: FakeStore) -> set[tuple[str, str]]:
    """Every binding item's key, across every partition."""
    return {
        key for key in store.items if key[1].startswith(f"{BINDING_PREFIX}{SEPARATOR}")
    }


def one_step(
    store: FakeStore,
    starter: RecordingStarter,
    wait: DrawnWait,
    case: ResolutionCase,
    tenant_id: str,
) -> str:
    """Run one resolution and assert the whole property of it. Returns the bucket it occupied."""
    caller = principal(tenant_id)
    pk = pk_for(caller)
    expectation = expectation_for(store, pk, case)
    before = {key: dict(item) for key, item in store.items.items()}
    executions_before = set(starter.executions)
    waits_before = len(wait.calls)
    store.keys_touched.clear()
    log_from = len(store.log)

    result = operations(store, starter=starter, wait=wait).resolve_session(
        OperationRequest(
            operation=Operation.RESOLVE_SESSION,
            principal=caller,
            body={AFFINITY_KEY_FIELD: case.affinity_key},
        )
    )
    step_log = store.log[log_from:]
    connection: dict[str, Any] | None = result.payload.get("connection")

    # R6.15: exactly one of the two actions, and the response names which one happened.
    assert result.payload[RESOLUTION_FIELD] == expectation.outcome.value

    # R6.16, R11.11: every key this resolution read or wrote is in the caller's own partition.
    assert store.keys_touched
    assert {partition for partition, _ in store.keys_touched} == {pk}

    # R6.18: the claim is attempted first. Nothing is read before it, and no unconditional write
    # exists on this path at all.
    assert step_log[0] == "claim_binding"
    assert "put_new_session" not in step_log

    # R6.21: nothing is ever deleted. A binding is replaced at the key it already occupies, so the
    # set of addresses this table holds only grows.
    assert set(before) <= set(store.items)

    # R6.15, R6.17: exactly one binding for this (Tenant, Affinity_Key), naming the drawn digest,
    # and no binding anywhere but the two partitions this case's two Tenants own. Asserted at every
    # step rather than only at the end, because "exactly one" is a claim about every point.
    binding_key = (pk, binding_sort_key(case.digest))
    assert binding_key in store.items
    assert binding_keys(store) <= {
        (pk_for(principal(TENANT)), binding_sort_key(case.digest)),
        (pk_for(principal(OTHER_TENANT)), binding_sort_key(case.digest)),
    }
    binding = AffinityKeyBindingRecord.from_item(store.items[binding_key])
    assert binding.pk == pk
    assert binding.affinity_key_digest == case.digest
    assert binding.sort_key == binding_sort_key(case.digest)
    # The digest is delimiter-free and fixed length whatever the caller sent, which is why the raw
    # key needs no length cap and why it cannot forge a different key shape.
    assert SEPARATOR not in binding.affinity_key_digest
    assert len(binding.affinity_key_digest) == DIGEST_LENGTH
    if len(case.affinity_key) >= UNAMBIGUOUS_KEY_LENGTH:
        # Short keys are substrings of ordinary item content, so this is asserted over keys long
        # enough for their presence to mean something. The raw key is never persisted.
        assert case.affinity_key not in repr(store.items[binding_key])

    # R6.17: one Session row is bound, and every other row for this key is one whose state licensed
    # its replacement.
    rows = {
        record.session_id: record for record in session_rows(store, pk, case.digest)
    }
    assert binding.session_id in rows or expectation.replaces == binding.session_id
    for session_id, record in rows.items():
        if session_id != binding.session_id:
            assert record.lifecycle_state in RECREATED_STATES

    if expectation.outcome is ResolutionOutcome.RESOLVED:
        assert result.payload["sessionId"] == expectation.session_id
        assert binding.session_id == expectation.session_id
        # No Session was created: no new item, and no execution started.
        assert set(store.items) == set(before)
        assert set(starter.executions) == executions_before
        assert "replace_binding" not in step_log
        if expectation.waited_on is None:
            # R6.20 in its strongest form. A resolution that returned a credential for a live or
            # suspended Session wrote nothing at all: no resume, no state change, no touched
            # timestamp. The branch has nothing to write with, and this is that stated as a fact
            # about the table rather than as a fact about the code.
            assert store.items == before
            row_key = (pk, session_sort_key(expectation.session_id or ""))
            assert (
                store.items[row_key]["lifecycleState"]
                == (result.payload["lifecycleState"])
            )
    else:
        created = str(result.payload["sessionId"])
        assert created != expectation.replaces
        assert binding.session_id == created
        assert (pk, session_sort_key(created)) in store.items
        # Exactly one execution, and it is the created Session's (R6.11, R6.17).
        assert set(starter.executions) - executions_before == {
            f"{EXECUTION_NAME_PREFIX}{created}"
        }
        if expectation.replaces is None:
            assert step_log.count("claim_binding") == 1
            assert "replace_binding" not in step_log
        else:
            # R6.21: one conditional replacement, and the replaced row survives it untouched.
            assert step_log.count("replace_binding") == 1
            replaced_key = (pk, session_sort_key(expectation.replaces))
            if replaced_key in before and expectation.waited_on is None:
                assert store.items[replaced_key] == before[replaced_key]

    if expectation.waited_on is not None:
        assert wait.calls[waits_before] == expectation.waited_on

    if expectation.connection:
        assert connection is not None
        if expectation.outcome is ResolutionOutcome.RESOLVED:
            # R6.23: minted now, and never the credential the orchestration published.
            row_key = (pk, session_sort_key(expectation.session_id or ""))
            stored = store.items[row_key].get("connection")
            assert stored == PUBLISHED.to_map()
            assert connection != stored
            assert connection["authHeaderValue"] == FAKE_TOKEN
            assert connection["authHeaderValue"] != PUBLISHED.auth_header_value
            assert result.status == HTTPStatus.OK
        else:
            # R6.13, the other half of the separation: a creation returns what was published.
            assert connection == PUBLISHED.to_map()
            assert result.status == HTTPStatus.CREATED
    else:
        assert connection is None
        assert result.status == HTTPStatus.ACCEPTED

    return expectation.bucket


def check_two_tenants(store: FakeStore, case: ResolutionCase) -> None:
    """R11.11: one digest, two partitions, and neither Tenant can name the other's Session."""
    mine = pk_for(principal(TENANT))
    theirs = pk_for(principal(OTHER_TENANT))
    sort_key = binding_sort_key(case.digest)

    # One binding per Tenant for this key, and no binding anywhere else.
    assert binding_keys(store) <= {(mine, sort_key), (theirs, sort_key)}

    bindings = {
        record.pk: record
        for record in store.bindings()
        if record.affinity_key_digest == case.digest
    }
    if mine in bindings and theirs in bindings:
        assert bindings[mine].session_id != bindings[theirs].session_id
        # Not merely not-found: the Session each binding names has no row in the other's partition,
        # which is the address-level statement of "and to no Session of another Tenant".
        assert (theirs, session_sort_key(bindings[mine].session_id)) not in store.items
        assert (mine, session_sort_key(bindings[theirs].session_id)) not in store.items


def check_case(case: ResolutionCase) -> frozenset[str]:
    """Seat the drawn prior state, run the schedule, and return every bucket that was occupied."""
    store = FakeStore()
    starter = RecordingStarter()
    wait = DrawnWait(
        store=store, publishes=case.wait_publishes, reaches=case.wait_reaches
    )

    if case.prior != PRIOR_ABSENT:
        if case.prior == PRIOR_BOUND:
            seat_session(
                store,
                tenant_id=TENANT,
                digest=case.digest,
                session_id=MY_EARLIER_SESSION,
                state=case.prior_state,
            )
        seat_binding(
            store,
            tenant_id=TENANT,
            digest=case.digest,
            session_id=(
                MY_EARLIER_SESSION if case.prior == PRIOR_BOUND else VANISHED_SESSION
            ),
            expired=case.binding_expired,
        )
    if case.other_prior == PRIOR_BOUND:
        seat_session(
            store,
            tenant_id=OTHER_TENANT,
            digest=case.digest,
            session_id=THEIR_EARLIER_SESSION,
            state=LifecycleState.RUNNING,
        )
        seat_binding(
            store,
            tenant_id=OTHER_TENANT,
            digest=case.digest,
            session_id=THEIR_EARLIER_SESSION,
            expired=case.binding_expired,
        )

    buckets = set(case.buckets())
    for tenant_id in case.schedule:
        buckets.add(one_step(store, starter, wait, case, tenant_id))
    check_two_tenants(store, case)
    return frozenset(buckets)


# Feature: aws-serverless-agent-sandbox, Property 35: For all Tenants, for all Affinity_Keys, and
# for all prior states of the binding and of the Session it names, a resolution performs exactly
# one of returning the bound Session's credential or creating and binding a new Session: a live
# bound Session is returned and no Session is created; a suspended bound Session is returned with a
# credential and remains suspended with no resume call issued; a bound Session in a terminal state,
# or a binding whose Session record is absent, produces exactly one newly created Session bound to
# the same digest; the returned credential is always newly minted and never equal to the credential
# stored on the Session record; and every State_Store key read or written during the resolution
# carries a partition key derived solely from the caller's authenticated Tenant, so two Tenants
# presenting the byte-identical Affinity_Key resolve to different Sessions and neither can name the
# other's.
@given(case=resolution_case())
@settings(max_examples=200)
def test_get_or_create_resolves_or_creates_exactly_one_within_the_tenant(
    case: ResolutionCase,
) -> None:
    """**Validates: Requirements 6.15, 6.16, 6.20, 6.21, 6.23, 11.11**"""
    for bucket in check_case(case):
        event(bucket)


# --- Non-vacuity, both deterministic --------------------------------------------------------------


def test_the_three_branch_groups_agree_with_the_implementations_table() -> None:
    """The restatement above is checked against `LOSER_BRANCHES` rather than read out of it."""
    expected = {
        LoserBranch.RETURN_CREDENTIAL: RETURNED_STATES,
        LoserBranch.WAIT_FOR_THE_WINNER: WAITED_STATES,
        LoserBranch.TREAT_AS_ABSENT: RECREATED_STATES,
    }
    for branch, states in expected.items():
        assert {
            state for state, row in LOSER_BRANCHES.items() if row is branch
        } == states
    assert RETURNED_STATES | WAITED_STATES | RECREATED_STATES == set(LifecycleState)
    assert not RETURNED_STATES & WAITED_STATES
    assert not RETURNED_STATES & RECREATED_STATES
    assert not WAITED_STATES & RECREATED_STATES


#: The case every enumerated one below varies from: an unbound key, one Tenant, one request, and an
#: orchestration that publishes a running Session.
BASE_CASE: Final = ResolutionCase(
    affinity_key="thread-9f3",
    prior=PRIOR_ABSENT,
    prior_state=LifecycleState.RUNNING,
    binding_expired=False,
    other_prior=PRIOR_ABSENT,
    schedule=(TENANT,),
    wait_publishes=True,
    wait_reaches=LifecycleState.RUNNING,
)

#: One case per bucket, stated rather than drawn, so every arm of the checker runs whatever the
#: generator happens to produce on a given run.
ENUMERATED_CASES: Final = (
    BASE_CASE,
    replace(BASE_CASE, prior=PRIOR_ROW_MISSING),
    replace(BASE_CASE, prior=PRIOR_ROW_MISSING, binding_expired=True),
    # One per lifecycle state, which reaches every row of the branch table.
    *(
        replace(BASE_CASE, prior=PRIOR_BOUND, prior_state=state)
        for state in LifecycleState
    ),
    # The wait's three outcomes over a bound Session that has not provisioned yet.
    replace(
        BASE_CASE,
        prior=PRIOR_BOUND,
        prior_state=LifecycleState.PENDING,
        wait_publishes=False,
    ),
    replace(
        BASE_CASE,
        prior=PRIOR_BOUND,
        prior_state=LifecycleState.PROVISIONING,
        wait_reaches=LifecycleState.SUSPENDED,
    ),
    replace(
        BASE_CASE,
        prior=PRIOR_BOUND,
        prior_state=LifecycleState.PROVISIONING,
        wait_reaches=LifecycleState.FAILED,
    ),
    # Two Tenants presenting the identical key, and a sequence long enough that a later request
    # resolves what an earlier one created.
    replace(
        BASE_CASE,
        other_prior=PRIOR_BOUND,
        schedule=(OTHER_TENANT, TENANT, TENANT, OTHER_TENANT),
    ),
    # The keys a system storing the raw value would have broken on.
    replace(BASE_CASE, affinity_key="thread#9f3"),
    replace(BASE_CASE, affinity_key="会話-9f3"),
    replace(BASE_CASE, affinity_key="x" * 8192),
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain this property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    for case in ENUMERATED_CASES:
        covered |= check_case(case)
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"


def test_the_assertions_discriminate_three_plausible_wrong_resolutions() -> None:
    """Each wrong rule disagrees with what a resolution does on a case this property draws.

    Without this, "the outcome matched what I derived" could hold of an implementation that got the
    same thing wrong in both places.
    """
    digest = affinity_key_digest(BASE_CASE.affinity_key)
    pk = pk_for(principal(TENANT))

    # 1. A resolve that returned the published credential rather than minting one (R6.23).
    store = FakeStore()
    seat_session(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        state=LifecycleState.RUNNING,
    )
    seat_binding(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        expired=False,
    )
    resolved = operations(store).resolve_session(
        OperationRequest(
            operation=Operation.RESOLVE_SESSION,
            principal=principal(TENANT),
            body={AFFINITY_KEY_FIELD: BASE_CASE.affinity_key},
        )
    )
    assert resolved.payload["connection"] != PUBLISHED.to_map()
    assert store.items[(pk, session_sort_key(MY_EARLIER_SESSION))]["connection"] == (
        PUBLISHED.to_map()
    )

    # 2. A suspended Session treated as one to resume (R6.20). The recorded state does not move,
    #    and the whole partition is byte-identical afterwards.
    store = FakeStore()
    seat_session(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        state=LifecycleState.SUSPENDED,
    )
    seat_binding(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        expired=False,
    )
    before = {key: dict(item) for key, item in store.items.items()}
    suspended = operations(store).resolve_session(
        OperationRequest(
            operation=Operation.RESOLVE_SESSION,
            principal=principal(TENANT),
            body={AFFINITY_KEY_FIELD: BASE_CASE.affinity_key},
        )
    )
    assert suspended.payload["lifecycleState"] == LifecycleState.SUSPENDED.value
    assert suspended.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    assert store.items == before

    # 3. An expired-but-present binding treated as absent. It resolves to the Session it names, and
    #    a resolution that had honoured the expiry would have created a second one.
    store = FakeStore()
    seat_session(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        state=LifecycleState.RUNNING,
    )
    seat_binding(
        store,
        tenant_id=TENANT,
        digest=digest,
        session_id=MY_EARLIER_SESSION,
        expired=True,
    )
    stale = operations(store).resolve_session(
        OperationRequest(
            operation=Operation.RESOLVE_SESSION,
            principal=principal(TENANT),
            body={AFFINITY_KEY_FIELD: BASE_CASE.affinity_key},
        )
    )
    assert stale.payload["sessionId"] == MY_EARLIER_SESSION
    assert stale.payload[RESOLUTION_FIELD] == ResolutionOutcome.RESOLVED.value
    assert len(store.sessions()) == 1
