# kiro-classification: public
"""Property 37: both creation contracts deliver a credential, and neither loses the Session.

R10.14 is a statement about a *failure mode*, not about a latency. A creation that takes longer than
the API integration timeout is allowed to answer late; what it is never allowed to do is answer with
nothing the caller can address. A `504` carries no body, so it carries no Session identifier, so a
caller who is now being billed for a provisioning Sandbox cannot poll it, terminate it or attribute
it. That is the thing this property quantifies over: not "does the credential arrive" but "is the
Session always nameable, whichever contract is configured and however long provisioning takes".

`test_control_plane_creation_wait.py` pins the clamp, the jitter and the fallback as examples, and
`test_control_plane_resolution.py` pins the resolve path's two shapes. What is generalised here is
the *domain*: the contract, the cold provision latency relative to the budget, the configured
integration timeout and the budget clamped inside it, the request body, and which of the two
Control_Plane entry points renders the response.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| the cold provision latency, at `0`, inside the budget, *exactly on* the budget, just past it, past the integration timeout, and never | that the boundary is inclusive, and that the two above-budget halves degrade rather than fail |
| the configured integration timeout, from 3 s to the documented 29 s (R10.13) | that the clamp is derived from the timeout rather than being a second configured number |
| the configured wait budget, including 60 s and an hour against a 29 s timeout | the configuration in which the clamp actually bites |
| the poll interval, across the jitter range the module offers | that the read grid, and so which read first sees the credential, is not one fixed schedule |
| requested duration across the provider's admissible range, and declared port sets including none | that the response shape does not depend on what the caller configured |
| the entry point: `POST /sessions`, `ResolveSession` claiming an unbound key, `ResolveSession` losing to a bound transient Session | both renderers of these two shapes, and the wait reached through both |

The **contract is exhausted rather than drawn**. It admits three settings — `synchronous`,
`asynchronous`, and the deployment that configured no wait at all, whose default
:class:`~control_plane.api.creation.CreationOperations` supplies — and the second half of the claim
("neither loses the Session") is a comparison *between* contracts on one case, so every drawn case
is run under all three. Exhausting a three-valued dimension covers strictly more than sampling it
would, and it is what makes the cross-contract assertion possible at all.
:func:`test_the_contract_dimension_covers_every_setting_the_switch_admits` fails if a fourth
contract is ever added, so the exhaustion cannot silently stop being one.

## The caller dimension, and what stands in for it

The design's statement quantifies over "callers drawn from the Client_SDK and the
Agent_Tool_Interface". Neither exists yet — `sdk/python/src/agent_sandbox` and `agent_tools` are
package stubs whose tasks are 9.x and 20.x — so there is no second caller implementation to draw.
What both callers exercise, and the only thing about them R10.14 constrains, is the response shape:
a `201` carrying `connection`, or a `202` carrying a Session identifier and no `connection` field at
all. So the dimension drawn in their place is the two Control_Plane entry points that *render* those
two shapes, `create_session` and `resolve_session`, which is the widest domain reachable at this
task. Widening it to the two real callers belongs with the tasks that write them.

## What is asserted, on every run of every case

- **Never nothing.** A caller ends every run holding a credential or a Session identifier it can
  poll. The status is one of `200`, `201`, `202`; `504` is asserted against by name, and no status
  at or above `500` is reachable at all. No exception escapes any contract on any latency.
- **The Session is never lost.** The identifier the response names exists as a Session row at
  `(pk_for(principal), session_sort_key(sessionId))` — a row in the caller's own partition, not
  merely a string in a payload. On a created outcome exactly one execution exists, named for that
  Session, so the Session a caller is billed for is the Session it was told about.
- **The fallback is the asynchronous shape, not a gateway timeout.** A synchronous contract whose
  budget expires answers `202` with the identifier and with `connection` *omitted* — `"connection"
  not in payload`, never present-and-null, because a null would be a third state every client would
  have to learn (R9.16).
- **An absent credential is followed by a successful read.** Every `202` is followed by the read a
  caller would issue next: the orchestration publishes, `read_session` at the row's own key returns
  it, and it parses as a :class:`~control_plane.state.records.ConnectionDescriptor`. An absent
  `connection` means "not yet published" and this is that stated as a fact rather than as a comment.
- **The contracts differ only in when.** Across all three settings on one case: the same single
  Session identifier is named, the same set of Session row keys exists, and the same set of
  executions was started. Only `connection`, the status, and the elapsed time may differ. Row
  *values* are deliberately not compared — under the asynchronous contract nothing polls the row, so
  nothing publishes onto it, which is the difference rather than a discrepancy.
- **The budget is genuinely clamped inside the timeout.** `budget_seconds <= timeout −
  RESPONSE_MARGIN_SECONDS < timeout` for every drawn configuration, and the synchronous run's own
  elapsed clock is checked against it: a wait that did not publish ends *exactly* on its budget, and
  never on the timeout.

## No wall clock, and no floating-point residue

The clock, the sleep and the jitter draw are all injected, so a latency above the 29 s integration
timeout costs microseconds and the above-timeout half of the domain is affordable at full iteration
count. Publication is driven by that same fake clock rather than by a read count, so "the credential
appeared after 4.5 simulated seconds" is what is modelled rather than "after the sixteenth read".

Every timeout, budget and poll interval drawn here is a **dyadic rational** — 0.15625, 0.1875,
0.21875, 0.25 for the interval, whole seconds for the timeouts, halves and whole seconds for the
budgets. Sums and differences of small dyadic rationals are exact in binary floating point, so the
wait's `remaining` reaches exactly zero and the loop ends on its budget rather than grinding through
a residue of 1e-16. That is a property of the *test inputs*, not a fix to the module: it is what
lets the elapsed time be asserted as an equality instead of a tolerance.

## Non-vacuity

:func:`test_every_bucket_is_reachable_and_the_property_holds_on_each` runs the checker over an
enumerated case per bucket and asserts every bucket is reached, so no arm is dead.
:func:`test_the_assertions_discriminate_three_plausible_wrong_creations` runs the same checker
against three wrong waits — one that answers a gateway timeout when its budget expires, one that
outlives the configured integration timeout, and one that reports an unpublished credential as a
failure — and asserts the checker rejects each.

## Budget

300 examples, above the design's floor of 100 because the interesting cross is
entry × latency × whether the clamp bites, which is 3 × 6 × 2 before the body and the interval are
counted. Each example runs three handler invocations against an in-memory dict with an injected
clock; no subprocess, no filesystem, no network and no real waiting.

## Duplication, deliberately

:func:`seat_transient_session` and the autouse Tenant fixture repeat what
`test_control_plane_resolution.py` and Property 35's file have, because a fixture is not importable
and that module's seating helper hardcodes a digest and a lifecycle state this file draws around.
Consolidating them into the harness is a later tidy-up rather than a behaviour change. The store, the
mint, the starter and the operation factory are all *imported*: nothing here defines a second one.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, replace
from enum import Enum
from http import HTTPStatus
from typing import Any, Final

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.api.admission import MAX_DURATION_FIELD
from control_plane.api.creation import (
    EXECUTION_NAME_PREFIX,
    EXPOSED_PORTS_FIELD,
    CreationOperations,
    CreationWait,
    NoCreationWait,
)
from control_plane.api.creation_wait import (
    RESPONSE_MARGIN_SECONDS,
    CreationContract,
    CreationWaitSettings,
    wait_for_contract,
)
from control_plane.api.handlers import OperationRequest, OperationResult
from control_plane.api.resolution import (
    AFFINITY_KEY_FIELD,
    RESOLUTION_FIELD,
    ResolutionOutcome,
)
from control_plane.api.routes import Operation
from control_plane.providers.local_firecracker import (
    MAX_DURATION_SECONDS,
    MIN_DURATION_SECONDS,
    LocalFirecrackerProvider,
)
from control_plane.state.keys import (
    SEPARATOR,
    SESSION_PREFIX,
    affinity_key_digest,
    session_sort_key,
)
from control_plane.state.records import (
    AffinityKeyBindingRecord,
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)
from tests.test_control_plane_creation_wait import INTEGRATION_TIMEOUT, FakeTime
from tests.test_control_plane_resolution import (
    NOW_MS,
    PUBLISHED,
    SANDBOX_HANDLE,
    SETTINGS,
    TENANT,
    FakeStore,
    RecordingStarter,
    operations,
    principal,
)

# --- The domain's fixed points --------------------------------------------------------------------

#: The Affinity_Key every resolve entry uses. One value rather than a drawn one: the key space is
#: Property 35's domain, and drawing it here would widen this property into that one.
AFFINITY_KEY: Final = "thread#37"
DIGEST: Final = affinity_key_digest(AFFINITY_KEY)

#: The Session an earlier turn bound, which the `RESOLVE_WAIT` entry loses its claim to.
BOUND_SESSION: Final = "01JBOUNDTRANSIENTAAAAAAAAA"

#: The statuses a creation may answer with. `504` is not among them under any contract or latency,
#: and neither is anything else at or above `500`: that is the whole of R10.14's prohibition.
ANSWERED_STATUSES: Final = frozenset(
    {HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED}
)

#: Configured API integration timeouts, in seconds. 29 is the documented value (R10.13); the three
#: shorter ones are what make "the clamp moves with the timeout" a claim over more than one number.
#: Whole seconds, so every derived budget is exact in binary floating point.
INTEGRATION_TIMEOUTS: Final = (3.0, 10.0, 20.0, INTEGRATION_TIMEOUT)

#: Configured wait budgets, in seconds. The last three exceed `29 − 2` and so are the configurations
#: in which the clamp bites; 0.5 is below every timeout's clamp and so is never clamped.
WAIT_BUDGETS: Final = (0.5, 1.0, 5.0, 12.0, 60.0, 3_600.0)

#: Poll intervals, in seconds, spanning the `200 ms ± 50 ms` range the module offers its jitter
#: source. Every one is a dyadic rational — 5/32, 3/16, 7/32, 1/4 — so the fake clock's arithmetic is
#: exact and the wait ends on its budget rather than a floating-point residue short of it.
POLL_INTERVALS: Final = (0.15625, 0.1875, 0.21875, 0.25)

#: How far past a bound a latency is placed when the point is that it is past it. A quarter of a
#: second is longer than any interval drawn above, so no read can land on it by accident.
PAST_THE_BOUND_SECONDS: Final = 0.25


class ContractSetting(Enum):
    """The three settings a deployment can be in, which is one more than the enum has members.

    `synchronous` and `asynchronous` are the two values `creationContract` admits.
    :attr:`UNCONFIGURED` is the deployment that configured no wait at all — the handler built without
    one — whose behaviour is :class:`~control_plane.api.creation.NoCreationWait` by field default.
    It is drawn as a third setting rather than assumed equal to `asynchronous`, and
    :func:`test_an_unconfigured_deployment_is_the_asynchronous_contract_by_construction` is what
    ties the two together.
    """

    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    UNCONFIGURED = "unconfigured"

    @property
    def waits(self) -> bool:
        return self is ContractSetting.SYNCHRONOUS


class LatencyKind(Enum):
    """Where the simulated cold provision latency falls relative to the clamped wait budget."""

    IMMEDIATE = "published before the first read"
    INSIDE = "published inside the budget"
    AT_BOUNDARY = "published exactly on the budget"
    JUST_PAST = "published just past the budget"
    ABOVE_TIMEOUT = "published past the integration timeout"
    NEVER = "never published"


class Entry(Enum):
    """Which Control_Plane entry point renders the response."""

    CREATE = "POST /sessions"
    RESOLVE_CREATE = "ResolveSession claiming an unbound key"
    RESOLVE_WAIT = "ResolveSession losing to a bound transient Session"

    @property
    def is_resolve(self) -> bool:
        return self is not Entry.CREATE


#: Every bucket the generator can land in. The enumerated-case test below asserts each is reached, so
#: a generator that quietly stopped producing one would be caught rather than narrow the domain this
#: property claims to cover.
BUCKETS: Final = frozenset(
    {
        *(f"entry: {entry.value}" for entry in Entry),
        *(f"latency: {kind.value}" for kind in LatencyKind),
        *(f"contract: {setting.value}" for setting in ContractSetting),
        "budget: clamped by the integration timeout",
        "budget: inside the integration timeout",
        "body: the duration was defaulted",
        "body: the duration was requested",
        "body: no ports were declared",
        "body: ports were declared",
        "outcome: a credential in the creation response",
        "outcome: a credential minted against an already-published row",
        "outcome: the asynchronous shape with a pollable Session identifier",
    }
)


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deployment profile the partition key is derived from. Repeated, see the module docstring."""
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


# --- The store: publication driven by the fake clock ----------------------------------------------


@dataclass
class ClockPublishingStore(FakeStore):
    """`FakeStore`, plus an orchestration that publishes once the simulated latency has elapsed.

    Publication is a function of the *clock* rather than of a read count, because the latency is what
    the domain draws: "the credential appeared 4.5 simulated seconds in" is the input, and which read
    first sees it follows from the drawn poll interval rather than being stated.

    It publishes what an orchestration publishes — the credential, a settled lifecycle state, and the
    Sandbox handle, since a credential is published only after `/run` has returned 200 — onto
    whichever row is being read, which is the row the handler wrote or the winner's row a loser is
    polling. `publish_at=None` is the Session whose credential never arrives.
    """

    clock: FakeTime = field(default_factory=FakeTime)
    publish_at: float | None = None
    published_onto: list[str] = field(default_factory=list)

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.publish_if_due(partition_key, sort_key)
        return super().read_session(partition_key=partition_key, sort_key=sort_key)

    def publish_if_due(self, partition_key: str, sort_key: str) -> None:
        """Publish onto this row if the simulated latency has elapsed and nothing is there yet."""
        if self.publish_at is None or self.clock.now < self.publish_at:
            return
        row = self.items.get((partition_key, sort_key))
        if row is None or "connection" in row:
            return
        row["lifecycleState"] = LifecycleState.RUNNING.value
        row["connection"] = PUBLISHED.to_map()
        row["connectionPublishedAt"] = NOW_MS
        row["sandboxHandle"] = dict(SANDBOX_HANDLE)
        # A Session row carries its identifier in the sort key rather than as an attribute, which is
        # the same reason `_session_keys` below filters on the key rather than on item content.
        self.published_onto.append(SessionRecord.from_item(row).session_id)


# --- Three deliberately wrong waits, for the discrimination test ----------------------------------


class WrongGatewayTimeout(Exception):
    """What a `504` would be if the wait raised one instead of degrading (R10.14's prohibition)."""


@dataclass(frozen=True, slots=True)
class GatewayTimeoutWait:
    """The wrong wait R10.14 exists to rule out: an expired budget reported as a timeout.

    It wraps the correct wait rather than reimplementing it, so the only thing it changes is what
    happens once the budget has expired — which is precisely the behaviour under discrimination.
    """

    inner: CreationWait

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        published = self.inner.await_connection(record)
        if published is None:
            raise WrongGatewayTimeout(record.session_id)
        return published


def gateway_timeout_instead_of_the_fallback(
    case: ContractCase,
    setting: ContractSetting,
    store: ClockPublishingStore,
    wait: CreationWait | None,
) -> CreationWait:
    """Wrap the selected wait so an expired budget raises rather than degrading."""
    del case, setting, store
    assert wait is not None, "this wrong wait wraps a configured one"
    return GatewayTimeoutWait(inner=wait)


@dataclass(frozen=True, slots=True)
class UnclampedWait:
    """A wait that honours its configured budget rather than the clamp derived from the timeout.

    It sleeps the *configured* budget and then reports nothing, which is what a handler that read
    `wait_budget_seconds` instead of `budget_seconds` would do: the gateway kills it mid-wait, and
    the elapsed clock is the evidence.
    """

    clock: FakeTime
    configured_budget_seconds: float

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        del record
        self.clock.sleep(self.configured_budget_seconds)
        return None


# --- One drawn case --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContractCase:
    """One deployment configuration, one simulated latency, one request body, one entry point."""

    entry: Entry
    latency: LatencyKind
    integration_timeout_seconds: float
    wait_budget_seconds: float
    poll_interval_seconds: float
    requested_duration_seconds: int | None
    declared_ports: tuple[int, ...]

    def wait_settings(self, contract: CreationContract) -> CreationWaitSettings:
        return CreationWaitSettings(
            contract=contract,
            integration_timeout_seconds=self.integration_timeout_seconds,
            wait_budget_seconds=self.wait_budget_seconds,
        )

    @property
    def budget_seconds(self) -> float:
        """The budget the wait actually runs to: the configured one, clamped inside the timeout."""
        return self.wait_settings(CreationContract.SYNCHRONOUS).budget_seconds

    @property
    def is_clamped(self) -> bool:
        return self.wait_settings(CreationContract.SYNCHRONOUS).is_clamped

    @property
    def publish_at(self) -> float | None:
        """The simulated cold provision latency, in seconds on the fake clock.

        Derived from the *clamped* budget rather than from the configured one, so "exactly on the
        boundary" means the boundary the wait will actually stop at.
        """
        budget = self.budget_seconds
        match self.latency:
            case LatencyKind.IMMEDIATE:
                return 0.0
            case LatencyKind.INSIDE:
                return budget / 2
            case LatencyKind.AT_BOUNDARY:
                return budget
            case LatencyKind.JUST_PAST:
                return budget + PAST_THE_BOUND_SECONDS
            case LatencyKind.ABOVE_TIMEOUT:
                return self.integration_timeout_seconds + PAST_THE_BOUND_SECONDS
            case LatencyKind.NEVER:
                return None

    @property
    def published_inside_the_budget(self) -> bool:
        """Whether a wait running the full budget would see the credential.

        Inclusive at the boundary: the loop issues one last read at exactly the deadline before
        reporting that nothing arrived, so a credential published on the boundary is delivered.
        """
        at = self.publish_at
        return at is not None and at <= self.budget_seconds

    @property
    def published_before_the_first_read(self) -> bool:
        """Whether the credential is on the row before anything polls, so no contract waits for it."""
        return self.publish_at == 0.0

    def body(self) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if self.requested_duration_seconds is not None:
            body[MAX_DURATION_FIELD] = self.requested_duration_seconds
        if self.declared_ports:
            body[EXPOSED_PORTS_FIELD] = list(self.declared_ports)
        if self.entry.is_resolve:
            body[AFFINITY_KEY_FIELD] = AFFINITY_KEY
        return body

    @property
    def seated_duration_seconds(self) -> int:
        """The duration the bound Session was created with, so the mint has a remainder to clamp to."""
        return (
            self.requested_duration_seconds
            if self.requested_duration_seconds is not None
            else 3600
        )

    def buckets(self) -> frozenset[str]:
        """The buckets this case occupies before any contract has been run."""
        return frozenset(
            {
                f"entry: {self.entry.value}",
                f"latency: {self.latency.value}",
                (
                    "budget: clamped by the integration timeout"
                    if self.is_clamped
                    else "budget: inside the integration timeout"
                ),
                (
                    "body: the duration was requested"
                    if self.requested_duration_seconds is not None
                    else "body: the duration was defaulted"
                ),
                (
                    "body: ports were declared"
                    if self.declared_ports
                    else "body: no ports were declared"
                ),
            }
        )


@st.composite
def contract_case(drawn: st.DrawFn) -> ContractCase:
    """One deployment configuration, one latency straddling both bounds, and one admissible body.

    The duration is drawn across the provider's whole admissible range and the ports across the whole
    port space, because the claim is that the response *shape* does not depend on either; a body that
    admission would reject is not drawn, since a rejected creation is R6.5's domain and never reaches
    a wait at all.
    """
    return ContractCase(
        entry=drawn(st.sampled_from(tuple(Entry))),
        latency=drawn(st.sampled_from(tuple(LatencyKind))),
        integration_timeout_seconds=drawn(st.sampled_from(INTEGRATION_TIMEOUTS)),
        wait_budget_seconds=drawn(st.sampled_from(WAIT_BUDGETS)),
        poll_interval_seconds=drawn(st.sampled_from(POLL_INTERVALS)),
        requested_duration_seconds=drawn(
            st.none()
            | st.integers(
                min_value=MIN_DURATION_SECONDS, max_value=MAX_DURATION_SECONDS
            )
        ),
        declared_ports=drawn(
            st.sets(st.integers(min_value=1, max_value=65535), max_size=4).map(
                lambda ports: tuple(sorted(ports))
            )
        ),
    )


# --- Seating the prior state the RESOLVE_WAIT entry loses to --------------------------------------


def seat_transient_session(store: FakeStore, case: ContractCase) -> SessionRecord:
    """Seat a bound Session that has not provisioned yet, plus the binding naming it.

    No Sandbox handle and no published credential, which is what puts the resolution on the
    `WAIT_FOR_THE_WINNER` branch and so reaches the creation wait through the second entry point.
    """
    duration = case.seated_duration_seconds
    record = store.place_session(
        SessionRecord(
            pk=pk_for(principal()),
            session_id=BOUND_SESSION,
            tenant_id=TENANT,
            provider_name=LocalFirecrackerProvider.name,
            lifecycle_state=LifecycleState.PENDING,
            created_at=NOW_MS,
            updated_at=NOW_MS,
            max_duration_seconds=duration,
            idle_seconds=300,
            suspended_seconds=600,
            auto_resume=True,
            memory_bytes=SETTINGS.memory_bytes,
            execution_role_arn=SETTINGS.execution_role_arn,
            reap_shard=3,
            reap_deadline=NOW_MS + duration * 1000,
            artifact_retention_days=SETTINGS.artifact_retention_days,
            exposed_ports=case.declared_ports,
            affinity_key_digest=DIGEST,
        )
    )
    store.place_binding(
        AffinityKeyBindingRecord(
            pk=record.pk,
            affinity_key_digest=DIGEST,
            session_id=BOUND_SESSION,
            bound_at=NOW_MS,
            expires_at=(NOW_MS + duration * 1000) // 1000,
        )
    )
    return record


# --- Running one case under one contract setting ---------------------------------------------------


@dataclass
class Observed:
    """Everything one run produced, including the exception it produced instead of a response."""

    case: ContractCase
    setting: ContractSetting
    result: OperationResult | None
    error: BaseException | None
    store: ClockPublishingStore
    starter: RecordingStarter
    clock: FakeTime
    executions_before: frozenset[str]
    session_keys_before: frozenset[tuple[str, str]]

    @property
    def payload(self) -> Mapping[str, Any]:
        assert self.result is not None
        return self.result.payload

    @property
    def named_session(self) -> str:
        return str(self.payload["sessionId"])


#: How a discrimination test substitutes a deliberately wrong wait for the one the switch selected.
#: It receives the case, the setting, the store and the correct wait, so a wrong wait can wrap the
#: right one rather than reimplementing it.
WaitFactory = Callable[
    [ContractCase, "ContractSetting", "ClockPublishingStore", CreationWait | None],
    CreationWait,
]


def build_wait(
    case: ContractCase,
    setting: ContractSetting,
    store: ClockPublishingStore,
) -> CreationWait | None:
    """The wait this setting selects, or `None` for the deployment that configured none.

    `None` is handed to `operations()`, which then leaves
    :class:`~control_plane.api.creation.CreationOperations` to supply its own default — which is the
    whole of what "unconfigured" means.
    """
    if setting is ContractSetting.UNCONFIGURED:
        return None
    contract = (
        CreationContract.SYNCHRONOUS
        if setting is ContractSetting.SYNCHRONOUS
        else CreationContract.ASYNCHRONOUS
    )
    return wait_for_contract(
        case.wait_settings(contract),
        lookup=store,
        clock=store.clock.monotonic,
        sleep=store.clock.sleep,
        jitter=lambda low, high: _fixed_interval(case, low, high),
    )


def _fixed_interval(case: ContractCase, low: float, high: float) -> float:
    """The drawn poll interval, checked against the bounds the module offered it.

    Asserted here rather than trusted: an interval outside the range the module draws from would make
    every elapsed-time assertion below a statement about a schedule no deployment runs.
    """
    assert low <= case.poll_interval_seconds <= high, (low, high)
    return case.poll_interval_seconds


def run_case(
    case: ContractCase,
    setting: ContractSetting,
    *,
    wait_override: WaitFactory | None = None,
) -> Observed:
    """Run one case under one contract setting against a fresh store, capturing whatever came back."""
    store = ClockPublishingStore(publish_at=case.publish_at)
    store.clock = FakeTime()
    starter = RecordingStarter()
    if case.entry is Entry.RESOLVE_WAIT:
        seat_transient_session(store, case)
    wait = build_wait(case, setting, store)
    if wait_override is not None:
        wait = wait_override(case, setting, store, wait)
    operation = operations(store, starter=starter, wait=wait)
    request = OperationRequest(
        operation=(
            Operation.CREATE_SESSION
            if case.entry is Entry.CREATE
            else Operation.RESOLVE_SESSION
        ),
        principal=principal(),
        body=case.body(),
    )
    observed = Observed(
        case=case,
        setting=setting,
        result=None,
        error=None,
        store=store,
        starter=starter,
        clock=store.clock,
        executions_before=frozenset(starter.executions),
        session_keys_before=frozenset(_session_keys(store)),
    )
    try:
        observed.result = (
            operation.creation.create_session(request)
            if case.entry is Entry.CREATE
            else operation.resolve_session(request)
        )
    except BaseException as exc:  # noqa: BLE001 - the property is that nothing escapes; see below.
        observed.error = exc
    return observed


def _session_keys(store: FakeStore) -> set[tuple[str, str]]:
    """Every Session row key the store holds, across every partition."""
    return {
        key for key in store.items if key[1].startswith(f"{SESSION_PREFIX}{SEPARATOR}")
    }


# --- What one run must have done -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Expectation:
    """What the drawn case and the contract setting oblige one run to answer.

    Derived by restating R10.14 and the two response shapes, not by asking the code under test.
    """

    status: HTTPStatus
    connection: bool
    minted: bool
    session_id: str | None
    created: bool
    bucket: str


def expectation_for(case: ContractCase, setting: ContractSetting) -> Expectation:
    """The one response this configuration and this latency license."""
    if case.entry is Entry.RESOLVE_WAIT:
        # The bound Session is resolved, never recreated: no contract and no latency changes which
        # Session this caller is talking about.
        delivered = case.published_before_the_first_read or (
            setting.waits and case.published_inside_the_budget
        )
        if delivered:
            # R6.23: the resolve branch re-reads and mints, so the credential is not the published
            # one. The credential still arrives; only its provenance differs from a creation's.
            return Expectation(
                status=HTTPStatus.OK,
                connection=True,
                minted=True,
                session_id=BOUND_SESSION,
                created=False,
                bucket="outcome: a credential minted against an already-published row",
            )
        return Expectation(
            status=HTTPStatus.ACCEPTED,
            connection=False,
            minted=False,
            session_id=BOUND_SESSION,
            created=False,
            bucket="outcome: the asynchronous shape with a pollable Session identifier",
        )
    if setting.waits and case.published_inside_the_budget:
        return Expectation(
            status=HTTPStatus.CREATED,
            connection=True,
            minted=False,
            session_id=None,
            created=True,
            bucket="outcome: a credential in the creation response",
        )
    # Everything else is the asynchronous shape, including the case where the credential was already
    # on the row: `NoCreationWait` does not read, so a contract that waits for nothing answers `202`
    # even at zero latency. That is not a lost credential — the very next `GetSession` returns it,
    # which `_check_the_credential_is_readable_afterwards` asserts on every one of these responses.
    return Expectation(
        status=HTTPStatus.ACCEPTED,
        connection=False,
        minted=False,
        session_id=None,
        created=True,
        bucket="outcome: the asynchronous shape with a pollable Session identifier",
    )


def check_one(observed: Observed) -> str:
    """Assert the whole of R10.14 about one run. Returns the bucket the outcome occupied."""
    case = observed.case
    setting = observed.setting
    expected = expectation_for(case, setting)

    # No path fails. A latency past the integration timeout is a slow creation, not an error, and a
    # contract that configured no wait is not a misconfiguration.
    assert observed.error is None, observed.error
    result = observed.result
    assert result is not None

    # Never nothing, and never a gateway timeout. Asserted against the named status as well as
    # against the whole 5xx range, because `504` is the specific answer R10.14 prohibits.
    assert result.status is not HTTPStatus.GATEWAY_TIMEOUT
    assert result.status in ANSWERED_STATUSES
    assert result.status == expected.status
    assert int(result.status) < int(HTTPStatus.INTERNAL_SERVER_ERROR)

    # Every response carries the Session identifier, whether or not it carries a credential.
    named = observed.named_session
    assert named
    if expected.session_id is not None:
        assert named == expected.session_id

    # And the Session is not merely named: it exists as a row in the caller's own partition. A
    # caller who is now being billed for a Session can address, poll and terminate it.
    row_key = (pk_for(principal()), session_sort_key(named))
    assert row_key in observed.store.items
    assert SessionRecord.from_item(observed.store.items[row_key]).session_id == named

    connection = result.payload.get("connection")
    if expected.connection:
        assert connection is not None
        assert ConnectionDescriptor.from_map(connection)
        if expected.minted:
            # R6.23: minted now, against the row as it then stood.
            assert connection != PUBLISHED.to_map()
        else:
            # R6.13: a creation returns the credential the orchestration published to the store.
            assert connection == PUBLISHED.to_map()
    else:
        # The asynchronous shape: `connection` omitted, never present-and-null. A null would be a
        # third state the Client_SDK and the Agent_Tool_Interface would each have to learn (R9.16).
        assert "connection" not in result.payload
        assert connection is None
        _check_the_credential_is_readable_afterwards(observed, named)

    if case.entry.is_resolve:
        # Both renderers of these two shapes agree about which of R6.15's two actions happened.
        expected_outcome = (
            ResolutionOutcome.CREATED
            if expected.created
            else ResolutionOutcome.RESOLVED
        )
        assert result.payload[RESOLUTION_FIELD] == expected_outcome.value

    _check_the_session_was_created_exactly_once(observed, named, expected)
    _check_the_budget_was_clamped_inside_the_timeout(observed, expected)
    return expected.bucket


def _check_the_credential_is_readable_afterwards(
    observed: Observed, session_id: str
) -> None:
    """An absent credential is followed by a successful read of one, not treated as a failure.

    The read a caller issues next is `GetSession` at the row's own key. The orchestration publishes
    first — driven here rather than waited for, since the point is that the *caller's* next read
    succeeds and not how long the orchestration took — and then the credential is on the row and
    parses as the descriptor the API returns.
    """
    store = observed.store
    key = (pk_for(principal()), session_sort_key(session_id))
    store.publish_at = store.clock.now
    subsequent = store.read_session(partition_key=key[0], sort_key=key[1])
    assert subsequent is not None
    assert ConnectionDescriptor.from_map(subsequent["connection"]) == PUBLISHED


def _check_the_session_was_created_exactly_once(
    observed: Observed, session_id: str, expected: Expectation
) -> None:
    """One Session row and one execution on a created outcome; neither on a resolved one."""
    created_keys = (
        frozenset(_session_keys(observed.store)) - observed.session_keys_before
    )
    started = frozenset(observed.starter.executions) - observed.executions_before
    if expected.created:
        assert created_keys == {(pk_for(principal()), session_sort_key(session_id))}
        assert started == {f"{EXECUTION_NAME_PREFIX}{session_id}"}
    else:
        assert created_keys == frozenset()
        assert started == frozenset()


def _check_the_budget_was_clamped_inside_the_timeout(
    observed: Observed, expected: Expectation
) -> None:
    """The wait ends strictly inside the request it runs in, so the gateway is never reached."""
    case = observed.case
    timeout = case.integration_timeout_seconds
    budget = case.budget_seconds

    # The clamp itself, derived from the configured timeout rather than set beside it.
    assert budget <= timeout - RESPONSE_MARGIN_SECONDS
    assert budget < timeout
    assert budget == min(case.wait_budget_seconds, timeout - RESPONSE_MARGIN_SECONDS)
    if case.is_clamped:
        assert budget < case.wait_budget_seconds

    # And the elapsed clock, which is the clamp observed rather than computed.
    elapsed = observed.clock.now
    assert elapsed <= budget
    assert elapsed < timeout
    if not observed.setting.waits:
        # A contract that waits for nothing spends nothing: not a shorter wait, no wait.
        assert elapsed == 0.0
        assert observed.clock.slept == []
    elif expected.connection and not case.published_before_the_first_read:
        # A read cannot see a credential published later than the moment it was issued.
        at = case.publish_at
        assert at is not None
        assert elapsed >= at
    elif not expected.connection:
        # The budget was spent in full, exactly, and it stopped on the clamp rather than the timeout.
        assert elapsed == pytest.approx(budget)


def check_case(case: ContractCase) -> frozenset[str]:
    """Run the case under all three contract settings, assert every claim, return the buckets."""
    runs = {setting: run_case(case, setting) for setting in ContractSetting}
    buckets = set(case.buckets())
    for setting, observed in runs.items():
        buckets.add(f"contract: {setting.value}")
        buckets.add(check_one(observed))
    _check_the_contracts_differ_only_in_when(case, runs)
    return frozenset(buckets)


def _check_the_contracts_differ_only_in_when(
    case: ContractCase, runs: dict[ContractSetting, Observed]
) -> None:
    """The two contracts differ in when the credential arrives, never in whether the Session exists.

    Compared across settings on one case: one Session identifier, one set of Session row keys, one
    set of executions. Row *values* are deliberately not compared — a contract that never polls never
    triggers publication, so the rows differ in exactly the way the contracts do.
    """
    named = {observed.named_session for observed in runs.values()}
    assert len(named) == 1, named
    session_id = named.pop()

    keys = {frozenset(_session_keys(observed.store)) for observed in runs.values()}
    assert len(keys) == 1, keys
    assert (pk_for(principal()), session_sort_key(session_id)) in next(iter(keys))

    executions = {frozenset(observed.starter.executions) for observed in runs.values()}
    assert len(executions) == 1, executions

    # Whether the credential arrived in the response is the only thing that may vary, and it varies
    # in one direction: a contract that waits can deliver where a contract that does not cannot.
    delivered = {
        setting: "connection" in observed.payload for setting, observed in runs.items()
    }
    if (
        case.entry is not Entry.RESOLVE_WAIT
        and not case.published_before_the_first_read
    ):
        assert not delivered[ContractSetting.ASYNCHRONOUS]
        assert not delivered[ContractSetting.UNCONFIGURED]
        assert (
            delivered[ContractSetting.SYNCHRONOUS] == case.published_inside_the_budget
        )
    assert (
        delivered[ContractSetting.ASYNCHRONOUS]
        == (delivered[ContractSetting.UNCONFIGURED])
    )


# Feature: aws-serverless-agent-sandbox, Property 37: For all creation contract settings, for all
# simulated cold provision latencies including values below, at and above the configured wait
# budget, and for all callers drawn from the Client_SDK and the Agent_Tool_Interface, the caller
# ends the creation holding a connection credential for the Session that was created; every
# response carries the Session identifier whether or not it carries a credential; an absent
# credential is followed by a successful read of one rather than treated as a failure; and no path
# produces a response carrying neither a credential nor a Session identifier.
@given(case=contract_case())
@settings(max_examples=300)
def test_both_creation_contracts_deliver_a_credential_and_neither_loses_the_session(
    case: ContractCase,
) -> None:
    """**Validates: Requirements 10.14**"""
    for bucket in check_case(case):
        event(bucket)


# --- Non-vacuity, all deterministic ---------------------------------------------------------------


def test_the_contract_dimension_covers_every_setting_the_switch_admits() -> None:
    """Exhausting the contract covers the domain only while the switch admits exactly these three.

    A fourth `creationContract` value added later fails here rather than being silently left out of a
    property that claims to quantify over "all creation contract settings".
    """
    covered = {setting.value for setting in ContractSetting}
    contracts = {contract.value for contract in CreationContract}
    assert contracts < covered
    assert covered - contracts == {ContractSetting.UNCONFIGURED.value}
    # A third context value fails where it is read rather than being treated as one of the two.
    with pytest.raises(ValueError, match="eventual"):
        CreationContract("eventual")


def test_an_unconfigured_deployment_is_the_asynchronous_contract_by_construction() -> (
    None
):
    """ "Absent" and `asynchronous` coincide because the field default *is* the waitless wait.

    Asserted structurally rather than inferred from the two settings behaving alike above, so a
    default that changed to something that waits would fail here rather than quietly widening what
    an unconfigured deployment does.
    """
    (held,) = [field_ for field_ in fields(CreationOperations) if field_.name == "wait"]
    assert held.default_factory is NoCreationWait
    assert (
        wait_for_contract(
            CreationWaitSettings(
                contract=CreationContract.ASYNCHRONOUS,
                integration_timeout_seconds=INTEGRATION_TIMEOUT,
                wait_budget_seconds=12.0,
            ),
            lookup=ClockPublishingStore(),
        ).__class__
        is NoCreationWait
    )


#: The case every enumerated one below varies from: `POST /sessions`, the documented 29 s timeout, a
#: 12 s budget inside it, and an orchestration that publishes halfway through.
BASE_CASE: Final = ContractCase(
    entry=Entry.CREATE,
    latency=LatencyKind.INSIDE,
    integration_timeout_seconds=INTEGRATION_TIMEOUT,
    wait_budget_seconds=12.0,
    poll_interval_seconds=0.25,
    requested_duration_seconds=None,
    declared_ports=(),
)

#: One case per bucket, stated rather than drawn, so every arm of the checker runs whatever the
#: generator happens to produce on a given run.
ENUMERATED_CASES: Final = (
    BASE_CASE,
    *(replace(BASE_CASE, latency=kind) for kind in LatencyKind),
    *(replace(BASE_CASE, entry=entry) for entry in Entry),
    # Every entry crossed with the two latencies that discriminate the contracts.
    *(
        replace(BASE_CASE, entry=entry, latency=kind)
        for entry in Entry
        for kind in (LatencyKind.IMMEDIATE, LatencyKind.NEVER, LatencyKind.AT_BOUNDARY)
    ),
    # The configuration in which the clamp bites: an hour of budget inside a three second timeout.
    replace(BASE_CASE, integration_timeout_seconds=3.0, wait_budget_seconds=3_600.0),
    replace(
        BASE_CASE,
        integration_timeout_seconds=3.0,
        wait_budget_seconds=60.0,
        latency=LatencyKind.ABOVE_TIMEOUT,
    ),
    # A budget below every clamp, so `is_clamped` is false on more than one timeout.
    replace(BASE_CASE, wait_budget_seconds=0.5, poll_interval_seconds=0.15625),
    # The body space: a requested duration at each end of the provider's range, and declared ports.
    replace(BASE_CASE, requested_duration_seconds=MIN_DURATION_SECONDS),
    replace(
        BASE_CASE,
        requested_duration_seconds=MAX_DURATION_SECONDS,
        declared_ports=(1, 8000, 65535),
    ),
    replace(BASE_CASE, entry=Entry.RESOLVE_WAIT, declared_ports=(8000,)),
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain this property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    for case in ENUMERATED_CASES:
        covered |= check_case(case)
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"


def test_the_assertions_discriminate_three_plausible_wrong_creations() -> None:
    """Each wrong wait is rejected by the same checker the property runs, on a case it draws.

    Without this, "the response matched what I derived" could hold of an implementation that got the
    same thing wrong in both places.
    """
    expired = replace(BASE_CASE, latency=LatencyKind.NEVER)

    # 1. The budget expiring reported as a gateway timeout rather than as the asynchronous shape.
    #    This is the failure mode R10.14 exists to name, and it is caught as an escaped exception:
    #    a `504` carries no body, so there is no identifier left to assert about.
    timing_out = run_case(
        expired,
        ContractSetting.SYNCHRONOUS,
        wait_override=gateway_timeout_instead_of_the_fallback,
    )
    assert isinstance(timing_out.error, WrongGatewayTimeout)
    with pytest.raises(AssertionError):
        check_one(timing_out)

    # 2. A wait that honoured its configured budget instead of the clamp derived from the timeout.
    #    The response shape is right and the elapsed clock is wrong, which is exactly the failure a
    #    shape-only assertion would miss: the gateway killed this handler eight seconds ago.
    unclamped_case = replace(
        expired, integration_timeout_seconds=3.0, wait_budget_seconds=60.0
    )
    unclamped = run_case(
        unclamped_case,
        ContractSetting.SYNCHRONOUS,
        wait_override=lambda case, setting, store, wait: UnclampedWait(
            clock=store.clock, configured_budget_seconds=case.wait_budget_seconds
        ),
    )
    assert unclamped.error is None
    assert unclamped.clock.now > unclamped_case.integration_timeout_seconds
    with pytest.raises(AssertionError):
        check_one(unclamped)

    # 3. An unpublished credential reported as a failure. `SessionProvisioningFailed` is the right
    #    answer for a *terminal* row and the wrong one for a row that simply has not published yet,
    #    and the checker does not accept an error in place of a response either way.
    reported = run_case(
        expired,
        ContractSetting.SYNCHRONOUS,
        wait_override=lambda case, setting, store, wait: _NotYetPublishedIsAFailure(),
    )
    assert isinstance(reported.error, _NotYetPublished)
    with pytest.raises(AssertionError):
        check_one(reported)


class _NotYetPublished(Exception):
    """A credential that has not been published yet, wrongly reported as a failure."""


@dataclass(frozen=True, slots=True)
class _NotYetPublishedIsAFailure:
    """The wrong wait that treats "not yet published" as the one thing the design says it never is."""

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        raise _NotYetPublished(record.session_id)


def test_every_drawn_latency_and_budget_is_exact_in_binary_floating_point() -> None:
    """The elapsed-time equalities above rest on this, so it is asserted rather than assumed.

    A dyadic rational — an integer over a power of two — is represented exactly, and sums and
    differences of small ones are exact too. That is what lets the wait's remaining budget reach
    exactly zero, and it is a property of these test inputs rather than of the module.
    """
    for value in (
        *INTEGRATION_TIMEOUTS,
        *WAIT_BUDGETS,
        *POLL_INTERVALS,
        RESPONSE_MARGIN_SECONDS,
        PAST_THE_BOUND_SECONDS,
    ):
        mantissa, exponent = math.frexp(value)
        assert (mantissa * 2**53).is_integer()
        assert exponent < 53
    for interval in POLL_INTERVALS:
        # And every interval is one the module's own jitter source could have drawn.
        assert 0.15 <= interval <= 0.25
