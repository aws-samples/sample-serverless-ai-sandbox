# kiro-classification: public
"""Property 36: concurrent same-key resolutions produce one Session and one Sandbox (R6.17, R6.19).

`test_control_plane_resolution.py` pins the examples underneath this — two requests for one key, and
thirty-two of them arriving one after another — and it establishes the store double this file drives.
What is generalised here is the *domain*: any degree of concurrency, any interleaving of the requests
against each other, and any prior state of the binding they contend for.

## Concurrency without a race

The requests run on real threads, but **the interleaving is drawn rather than raced**. `_Baton` hands
exactly one worker the right to proceed, and a worker may proceed only as far as its next interaction
with the store; then it returns the baton and waits to be chosen again. Which worker is chosen is
read off the drawn schedule. Two consequences, and both are the point:

- **Exactly one worker is ever runnable**, so the conditional writes serialise the way DynamoDB
  serialises them and no two transactions are ever half-applied against each other.
- **The realised interleaving is a function of the drawn schedule alone.** No `sleep`, no wall clock,
  no dependence on the order in which the operating system happens to start threads: `_Baton.run`
  waits at a barrier until every worker has arrived at its first yield point before it grants a
  single turn, so `ready` at every later decision point is exactly "every worker that has not
  finished", whatever the thread startup order was. A fixed Hypothesis seed therefore replays a
  fixed interleaving, and a counterexample is reproducible.

A version of this property that started N threads and let them race would pass on a machine that
happened to serialise them and prove nothing on any machine, which is why the schedule is an input
rather than an accident. The one wall-clock value in the file is `_BATON_TIMEOUT_SECONDS`: it is a
deadlock detector, converting a hypothetical stuck handoff into a failure rather than a hung suite,
and a correct run never waits on it because the baton is always already available.

The granularity is the conditional write, as the design specifies: every seam a resolution reaches —
both binding transactions, both reads, the Session row write, `StartExecution` and the wait — is a
yield point, so a request can be preempted at any of them.

**One ordering the double has to restore by hand.** A real provision takes seconds; `ScheduledWait`
collapses it into a single poll. Left at that, the drawn schedule could publish a credential onto the
winner's row *before* the winner had recorded that it started the execution — an effect ordered before
its own cause — and the creator's `ORCHESTRATING` write would then land on top of the published state.
So the wait reports nothing until the row carries `orchestrationExecutionArn`, and publishes exactly
once per Session. Both constraints are properties of a real orchestration rather than conveniences;
without them the property fails against correct code, which is how they were found.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| the degree, 2 to 32 | that the guarantee is over a *set* of requests rather than over a pair |
| the interleaving schedule | every order in which the requests can reach their next store operation |
| the prior binding: absent, live, or terminal | the two cases in which more than one request could create, plus the case in which none can |
| the lifecycle states the winner's row passes through while losers wait | that a loser branches on what the row says *now*, not on what it said when the claim lost |
| how many polls precede publication, including never | both the credential and the asynchronous shape on the waiting branch (R6.19, R9.16) |
| a winner that becomes unresolvable mid-wait | the re-entry that a conditional replacement has to survive |
| a store whose claims never commit | the bounded `ResolutionDidNotSettle`, under concurrency rather than in isolation |

The terminal prior states are drawn with raised weight, because the terminal case is the one that
discriminates a conditional replacement from a delete-then-create: without the condition, N
concurrent requests finding one terminal binding each delete and create, and produce N Sessions.

**At most one Session is ever made unresolvable by the wait**, and that bound is deliberate. A drawn
sequence in which every newly created Session died mid-wait would exhaust `MAX_CLAIM_ATTEMPTS` and
turn a converging race into `ResolutionDidNotSettle`, which is a different claim — it is drawn
separately, as its own arm, where nothing commits at all.

## The invariants, and how they are phrased

The exactly-once guarantee is asserted as **at most one Session for the Affinity_Key is resolvable**,
where resolvable means the loser branch table would return it rather than treat it as absent. Phrased
over `is_terminal` it would be wrong twice: `TERMINATING` is not terminal and yet is treated as
absent, and a `PENDING` row that a second claim had wrongly created is not terminal either — which is
precisely the defect the property exists to catch. Alongside it:

- exactly one binding item exists, in the caller's own partition, naming the resolvable Session;
- the set of Session rows created during the run equals the set of Sessions an execution was started
  for, so a losing request left no orphan row behind *and* no Session was provisioned twice;
- no request fails: every one returns a Session identifier with a freshly minted credential, or the
  asynchronous shape (identifier, no `connection`, `202`) where the wait budget expired. Never a
  `504` and never an error (R6.19);
- where no Session died mid-wait, the counts are exact: one Session, one `StartExecution`, and every
  request in the set naming that one Session.

## Non-vacuity

Two deterministic tests follow the property. The first enumerates one case per bucket and asserts the
buckets are all reached, so no drawn dimension is dead. The second drives the same checker against
`_UnconditionalStore` — a store that commits the claim with the condition removed, which is the shape
R6.18 forbids — and asserts the invariants *fail*. A property that no wrong implementation could
break would be an expensive way to assert nothing.

## Budget

300 examples rather than the design's floor of 100. Every example runs a bounded number of baton
handoffs over in-memory dictionaries with an injected clock: no subprocess, no filesystem, no network
and no wait, so the whole property runs in about two seconds even with the degree-32 examples in it.
Seven drawn dimensions multiply out far past 100 combinations, and at 300 the rarest bucket — a prior
binding found `FAILED` — is still observed in several per cent of examples.

## Duplication worth consolidating later

The autouse Tenant fixture below repeats the one in `test_control_plane_resolution.py`, because a
fixture is not importable and Property 35's file is being written at the same time as this one.
Consolidating the two into a shared fixture is a later tidy-up, not a behaviour change.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import partial
from http import HTTPStatus
from typing import Any, Final

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.api.creation import EXECUTION_NAME_PREFIX, OrchestrationStart
from control_plane.api.handlers import OperationResult
from control_plane.api.resolution import (
    LOSER_BRANCHES,
    MAX_CLAIM_ATTEMPTS,
    RESOLUTION_FIELD,
    BindingConditionFailed,
    LoserBranch,
    ResolutionDidNotSettle,
    ResolutionOutcome,
)
from control_plane.state.keys import session_sort_key
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.state.table import PARTITION_KEY_ATTRIBUTE, SORT_KEY_ATTRIBUTE
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)
from tests.test_control_plane_resolution import (
    DIGEST,
    FAKE_TOKEN,
    NOW_MS,
    PUBLISHED,
    SANDBOX_HANDLE,
    TENANT,
    FakeStore,
    RecordingStarter,
    operations,
    principal,
    resolve,
    seated_session,
)

#: How long a handoff may take before the test calls it a deadlock. Never reached by a correct run:
#: a worker waits only for a baton the scheduler has already decided to grant it, so this is a
#: failure detector rather than a timing assumption. Generous, so a loaded machine cannot trip it.
_BATON_TIMEOUT_SECONDS: Final = 30.0

#: The design's ceiling on the drawn degree. Reached by a sampled arm rather than by the uniform one,
#: so most examples stay small and the ceiling is still visited.
MAX_DEGREE: Final = 32

#: Degrees drawn by name. Two is the smallest set that can contend; 32 is the design's ceiling and
#: the number the deterministic suite already drives sequentially.
DEGREE_POOL: Final = (2, 3, 8, 12, MAX_DEGREE)

#: A poll count no run reaches, so the orchestration never publishes and every waiting request takes
#: the asynchronous branch. `MAX_DEGREE` waiters can poll at most `MAX_DEGREE` times.
NEVER_PUBLISHES: Final = MAX_DEGREE + 1

#: The attribute the creator writes once `StartExecution` has returned. Its absence is the design's
#: orphan window: a row carrying one is a row whose execution the store has recorded as started, and
#: therefore the earliest point at which anything that execution does can be observed.
ORCHESTRATION_ARN_ATTRIBUTE: Final = "orchestrationExecutionArn"

#: The states a Session row may hold while a loser waits on it. Every one of them maps to
#: `WAIT_FOR_THE_WINNER`, so a loser reading any of them waits rather than resolving or recreating.
WAITING_STATES: Final = tuple(
    state
    for state in LifecycleState
    if LOSER_BRANCHES[state] is LoserBranch.WAIT_FOR_THE_WINNER
)

_RESOLVED: Final = ResolutionOutcome.RESOLVED.value
_CREATED: Final = ResolutionOutcome.CREATED.value


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


# --- The interleaving, drawn rather than raced ----------------------------------------------------


class _Baton:
    """One right-to-proceed, granted to one worker at a time in the drawn order.

    A worker calls :meth:`step` before every interaction with the store and blocks until the
    schedule chooses it, so no two workers are ever inside the store together and the sequence of
    store operations is exactly the sequence this object hands out.

    :meth:`run` executes on the main thread. It waits at a barrier until every worker has arrived at
    its first yield point, which is what removes thread startup order from the outcome: from that
    point on the set of workers waiting for a turn is exactly the set that has not finished.
    """

    def __init__(self, *, degree: int, schedule: tuple[int, ...]) -> None:
        self._condition = threading.Condition()
        self._degree = degree
        self._schedule = schedule
        self._ready: set[int] = set()
        self._done: set[int] = set()
        self._turn: int | None = None
        self._step = 0
        self._local = threading.local()
        #: The realised interleaving, in the order turns were granted.
        self.handoffs: list[int] = []
        #: True once a turn was granted to a worker other than the one that had just run, while that
        #: one was still mid-resolution. The difference between an interleaving and a queue.
        self.preempted = False

    # -- the worker side ------------------------------------------------------------------

    def enter(self, worker: int) -> None:
        """Name the calling thread, so :meth:`step` needs no argument at every call site."""
        self._local.worker = worker

    def step(self) -> None:
        """Offer the baton back and wait to be chosen again."""
        worker: int = self._local.worker
        with self._condition:
            self._ready.add(worker)
            self._condition.notify_all()
            while self._turn != worker:
                if not self._condition.wait(timeout=_BATON_TIMEOUT_SECONDS):
                    raise AssertionError(
                        f"worker {worker} waited {_BATON_TIMEOUT_SECONDS}s for a turn: "
                        f"the handoff deadlocked"
                    )
            # Consumed, so the next yield point waits rather than passing straight through.
            self._turn = None

    def finish(self, worker: int) -> None:
        """Report that this worker will ask for no further turns."""
        with self._condition:
            self._done.add(worker)
            self._condition.notify_all()

    # -- the scheduler side ---------------------------------------------------------------

    def run(self) -> None:
        """Grant turns in the drawn order until every worker has finished."""
        with self._condition:
            self._await(
                lambda: len(self._ready) == self._degree, "every worker to arrive"
            )
            while len(self._done) < self._degree:
                self._await(
                    lambda: bool(self._ready) or len(self._done) == self._degree,
                    "a worker to want a turn",
                )
                if not self._ready:
                    return
                picked = self._pick()
                self._ready.discard(picked)
                if (
                    self.handoffs
                    and picked != self.handoffs[-1]
                    and self.handoffs[-1] not in self._done
                ):
                    self.preempted = True
                self.handoffs.append(picked)
                self._turn = picked
                self._condition.notify_all()
                self._await(
                    partial(self._yielded_or_finished, picked),
                    f"worker {picked} to yield or finish",
                )

    def _yielded_or_finished(self, worker: int) -> bool:
        """Whether this worker has offered the baton back or will never ask for it again."""
        return worker in self._ready or worker in self._done

    def _pick(self) -> int:
        """The next worker the schedule names, among those waiting for a turn.

        Taken modulo the number waiting, so every drawn schedule is a valid one and shrinking a
        schedule cannot produce a case that cannot run.
        """
        waiting = sorted(self._ready)
        chosen = self._schedule[self._step % len(self._schedule)] % len(waiting)
        self._step += 1
        return waiting[chosen]

    def _await(self, reached: Callable[[], bool], what: str) -> None:
        """Wait until `reached`, failing rather than hanging if the handoff has deadlocked."""
        while not reached():
            if not self._condition.wait(timeout=_BATON_TIMEOUT_SECONDS):
                raise AssertionError(
                    f"waited {_BATON_TIMEOUT_SECONDS}s for {what}: the handoff deadlocked"
                )


def _step(baton: _Baton | None) -> None:
    """Yield at a store seam. `None` is a construction mistake rather than "no scheduling"."""
    if baton is None:
        raise AssertionError("a scheduled double was built without its baton")
    baton.step()


# --- The doubles, each seam a yield point --------------------------------------------------------


@dataclass
class ScheduledStore(FakeStore):
    """`FakeStore` with the drawn schedule interposed at every seam.

    The serialisation of the conditional writes is inherited, not reimplemented: a claim still
    commits both items or neither, and its condition is still `attribute_not_exists(pk)` on the
    binding item alone. What is added is only *when* each request gets to attempt one.
    """

    baton: _Baton | None = None

    def put_new_session(self, item: Any) -> None:
        _step(self.baton)
        super().put_new_session(item)

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        _step(self.baton)
        super().mark_orchestration_started(start)

    def read_session(self, *, partition_key: str, sort_key: str) -> Any:
        _step(self.baton)
        return super().read_session(partition_key=partition_key, sort_key=sort_key)

    def read_binding(self, *, partition_key: str, sort_key: str) -> Any:
        _step(self.baton)
        return super().read_binding(partition_key=partition_key, sort_key=sort_key)

    def claim_binding(self, *, session_item: Any, binding_item: Any) -> None:
        _step(self.baton)
        super().claim_binding(session_item=session_item, binding_item=binding_item)

    def replace_binding(
        self, *, session_item: Any, binding_item: Any, expected_session_id: str
    ) -> None:
        _step(self.baton)
        super().replace_binding(
            session_item=session_item,
            binding_item=binding_item,
            expected_session_id=expected_session_id,
        )


@dataclass
class _RefusingStore(ScheduledStore):
    """Every claim loses its condition and nothing ever commits.

    Contention that does not converge, driven under concurrency: `MAX_CLAIM_ATTEMPTS` bounds each
    request's loop and every attempt was a transaction, so the table is empty afterwards.
    """

    def claim_binding(self, *, session_item: Any, binding_item: Any) -> None:
        _step(self.baton)
        self.log.append("claim_binding")
        raise BindingConditionFailed("somebody else always wins")

    def replace_binding(
        self, *, session_item: Any, binding_item: Any, expected_session_id: str
    ) -> None:
        _step(self.baton)
        self.log.append("replace_binding")
        raise BindingConditionFailed("somebody else always wins")


@dataclass
class _UnconditionalStore(ScheduledStore):
    """The shape R6.18 forbids: a claim that commits whatever it finds.

    Used by the non-vacuity test alone. Every concurrent request commits its own Session row and
    overwrites the binding, so the invariants must — and do — fail against it.
    """

    def claim_binding(self, *, session_item: Any, binding_item: Any) -> None:
        _step(self.baton)
        self.log.append("claim_binding")
        for item in (session_item, binding_item):
            key = (item[PARTITION_KEY_ATTRIBUTE], item[SORT_KEY_ATTRIBUTE])
            self.keys_touched.append(key)
            self.items[key] = dict(item)


@dataclass
class ScheduledStarter(RecordingStarter):
    """`StartExecution`, reached only through the schedule."""

    baton: _Baton | None = None

    def start_execution(self, *, name: str, payload: Any) -> str:
        _step(self.baton)
        return super().start_execution(name=name, payload=payload)


@dataclass
class ScheduledWait:
    """The winner's orchestration, advanced one drawn step per poll rather than by a clock.

    Held by every request in the set, because in a deployment they all poll the same row: the poll
    count is per Session rather than per caller, so an orchestration progresses whether it was the
    winner or a loser that looked. Until publication each poll writes a drawn transient state and
    reports nothing, which is the wait budget expiring — the asynchronous shape (R9.16). At
    publication it writes the credential, the `RUNNING` state and the Sandbox handle, in the one
    order an orchestration can produce them.

    `case.winner_goes_terminal` applies to the **first** Session to reach publication and to no
    other, so re-entry is bounded and the race converges. See the module docstring.
    """

    store: ScheduledStore
    case: ConcurrencyCase
    polls: dict[str, int] = field(default_factory=dict)
    published: set[str] = field(default_factory=set)
    calls: list[str] = field(default_factory=list)
    #: True once a Session was published into a state the loser branch table treats as absent.
    made_unresolvable: bool = False

    def await_connection(self, record: SessionRecord) -> Any:
        _step(self.store.baton)
        self.calls.append(record.session_id)
        row = self.store.items.get((record.pk, session_sort_key(record.session_id)))
        if row is None:  # pragma: no cover - nothing on this path deletes a row
            return None
        if record.session_id in self.published:
            # Published once and polled again by a second waiter. The credential is on the row and
            # the lifecycle state has moved on, so this returns what is there and writes nothing:
            # one orchestration publishes once, and a Session that reached `FAILED` does not go back
            # to `PENDING` because somebody looked at it again.
            return PUBLISHED
        if ORCHESTRATION_ARN_ATTRIBUTE not in row:
            # The creator has not yet recorded that it started the execution, so no execution can
            # have published anything. This is the one ordering the double has to restore by hand:
            # collapsing a provision that really takes seconds down to a single poll would otherwise
            # let a credential appear *before* its own execution was recorded as started, and the
            # creator's own `ORCHESTRATING` write would then land on top of it. Nothing has
            # progressed, so this costs the drawn poll budget nothing.
            return None
        polled = self.polls.get(record.session_id, 0)
        self.polls[record.session_id] = polled + 1
        if polled < self.case.polls_before_publication:
            row["lifecycleState"] = self.case.waiting_state(polled).value
            row["updatedAt"] = NOW_MS
            return None
        terminal = self.case.winner_goes_terminal and not self.published
        self.published.add(record.session_id)
        row["lifecycleState"] = (
            LifecycleState.FAILED.value if terminal else LifecycleState.RUNNING.value
        )
        row["connection"] = PUBLISHED.to_map()
        row["connectionPublishedAt"] = NOW_MS
        if terminal:
            self.made_unresolvable = True
        else:
            # A credential is published only after `/run` returned 200, so the handle is there too.
            row["sandboxHandle"] = dict(SANDBOX_HANDLE)
        return PUBLISHED


# --- The drawn case ------------------------------------------------------------------------------


class PriorBinding(Enum):
    """The state of the binding the concurrent set contends for, before any of it arrives."""

    ABSENT = "absent"
    RUNNING = "live: RUNNING"
    SUSPENDED = "live: SUSPENDED"
    TERMINATED = "terminal: TERMINATED"
    FAILED = "terminal: FAILED"
    TERMINATING = "terminal: TERMINATING"

    @property
    def state(self) -> LifecycleState | None:
        """The lifecycle state of the Session the prior binding names, or `None` for no binding."""
        return None if self is PriorBinding.ABSENT else LifecycleState(self.name)

    @property
    def is_resolvable(self) -> bool:
        """Whether a request finding this binding returns it rather than creating over it."""
        state = self.state
        return (
            state is not None
            and LOSER_BRANCHES[state] is not LoserBranch.TREAT_AS_ABSENT
        )


@dataclass(frozen=True, slots=True)
class ConcurrencyCase:
    """One degree, one interleaving, one prior binding and one orchestration progression."""

    degree: int
    schedule: tuple[int, ...]
    prior: PriorBinding
    polls_before_publication: int
    waiting_states: tuple[LifecycleState, ...]
    winner_goes_terminal: bool
    contention_never_converges: bool

    def waiting_state(self, poll: int) -> LifecycleState:
        """The state the row holds after this poll, cycling through the drawn progression."""
        return self.waiting_states[poll % len(self.waiting_states)]

    def buckets(self) -> frozenset[str]:
        """The drawn buckets this case occupies. Observed ones are added by the checker."""
        if self.degree == 2:
            degree = "degree: 2"
        elif self.degree <= 8:
            degree = "degree: 3 to 8"
        else:
            degree = "degree: above 8"
        found = {degree, f"prior: {self.prior.value}"}
        if self.contention_never_converges:
            found.add("contention: never converges")
        if self.polls_before_publication == 0:
            found.add("publication: on the first poll")
        elif self.polls_before_publication >= NEVER_PUBLISHES:
            found.add("publication: never")
        else:
            found.add("publication: after some polls")
        return frozenset(found)


@st.composite
def concurrency_case(drawn: st.DrawFn) -> ConcurrencyCase:
    """A degree, an interleaving, a prior binding, and how the winner's row progresses.

    The non-converging arm is drawn with no prior binding, and that is a property of the arm rather
    than a convenience: a store that refuses every claim and a binding that already exists are not
    the same situation. A request finding a resolvable binding resolves it and never claims at all,
    and a request finding a terminal one attempts a replacement the refusing store also refuses --
    so the "nothing was committed" half of the claim would be asserted against a table that was
    seeded before any request arrived. Contention that does not converge is contention over a key
    nobody holds.
    """
    never_converges = drawn(
        # One arm in eight: it asserts a different outcome over a domain of its own, so it needs to
        # be reached often enough to be meaningful and rarely enough to leave the converging domain
        # -- which is where the exactly-once guarantee lives -- well covered.
        st.sampled_from((*(False,) * 7, True))
    )
    return ConcurrencyCase(
        degree=drawn(
            st.one_of(
                st.integers(min_value=2, max_value=6), st.sampled_from(DEGREE_POOL)
            )
        ),
        # Cycled by `_Baton._pick`, so a short schedule is a repeating one rather than an invalid
        # one. Values are taken modulo the number of workers waiting, so every draw is usable.
        schedule=tuple(
            drawn(
                st.lists(
                    st.integers(min_value=0, max_value=MAX_DEGREE - 1),
                    min_size=1,
                    max_size=48,
                )
            )
        ),
        # The terminal states carry raised weight: they are where a delete-then-create would produce
        # one Session per request and a conditional replacement produces one in total.
        prior=PriorBinding.ABSENT
        if never_converges
        else drawn(
            st.sampled_from(
                (
                    PriorBinding.ABSENT,
                    PriorBinding.ABSENT,
                    PriorBinding.ABSENT,
                    PriorBinding.TERMINATED,
                    PriorBinding.TERMINATED,
                    PriorBinding.FAILED,
                    PriorBinding.TERMINATING,
                    PriorBinding.RUNNING,
                    PriorBinding.SUSPENDED,
                )
            )
        ),
        # Weighted three to one towards a publication that happens, so the branch that returns a
        # credential is drawn about three times as often as the one where every waiter's budget
        # expires. An even split spends half the domain on runs in which no credential exists.
        polls_before_publication=drawn(
            st.one_of(
                st.integers(min_value=0, max_value=4),
                st.integers(min_value=0, max_value=4),
                st.integers(min_value=0, max_value=4),
                st.just(NEVER_PUBLISHES),
            )
        ),
        waiting_states=tuple(
            drawn(st.lists(st.sampled_from(WAITING_STATES), min_size=1, max_size=4))
        ),
        winner_goes_terminal=drawn(st.booleans()),
        contention_never_converges=never_converges,
    )


# --- Running one case ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Answer:
    """What one concurrent request came back with: a result, or the error it raised."""

    result: OperationResult | None = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _Run:
    """Everything one drawn set of concurrent requests left behind."""

    store: ScheduledStore
    starter: ScheduledStarter
    wait: ScheduledWait
    baton: _Baton
    seated: SessionRecord | None
    answers: tuple[_Answer, ...]


def _request(
    baton: _Baton,
    worker: int,
    store: ScheduledStore,
    starter: ScheduledStarter,
    wait: ScheduledWait,
    answers: list[_Answer | None],
) -> None:
    """One handler invocation, running only while it holds the baton.

    The first thing it does is take a turn, so nothing at all — not even the draw of a Session
    identifier — happens outside the schedule.
    """
    baton.enter(worker)
    try:
        baton.step()
        answers[worker] = _Answer(
            result=resolve(operations(store, starter=starter, wait=wait))
        )
    except Exception as exc:  # noqa: BLE001 - reported in the main thread, with its type
        answers[worker] = _Answer(error=exc)
    finally:
        baton.finish(worker)


def run_case(case: ConcurrencyCase, store_class: type[ScheduledStore]) -> _Run:
    """Issue `case.degree` concurrent resolutions for one Tenant and one Affinity_Key."""
    baton = _Baton(degree=case.degree, schedule=case.schedule)
    store = store_class(baton=baton)
    starter = ScheduledStarter(baton=baton)
    seated = (
        None
        if case.prior.state is None
        else seated_session(store, state=case.prior.state)
    )
    wait = ScheduledWait(store=store, case=case)
    answers: list[_Answer | None] = [None] * case.degree
    threads = [
        threading.Thread(
            target=_request,
            args=(baton, worker, store, starter, wait, answers),
            name=f"resolve-{worker}",
            daemon=True,
        )
        for worker in range(case.degree)
    ]
    for thread in threads:
        thread.start()
    baton.run()
    for thread in threads:
        thread.join(timeout=_BATON_TIMEOUT_SECONDS)
    assert not [thread for thread in threads if thread.is_alive()], (
        "a request never finished"
    )
    settled = [answer for answer in answers if answer is not None]
    assert len(settled) == case.degree, "a request produced no answer at all"
    return _Run(
        store=store,
        starter=starter,
        wait=wait,
        baton=baton,
        seated=seated,
        answers=tuple(settled),
    )


def _store_class_for(case: ConcurrencyCase) -> type[ScheduledStore]:
    return _RefusingStore if case.contention_never_converges else ScheduledStore


def check_case(
    case: ConcurrencyCase, *, store_class: type[ScheduledStore] | None = None
) -> frozenset[str]:
    """Assert the property against one case and return every bucket it occupied."""
    run = run_case(case, store_class or _store_class_for(case))
    buckets = set(case.buckets())
    buckets.add(
        "schedule: a request was preempted mid-resolution"
        if run.baton.preempted
        else "schedule: one request at a time, to completion"
    )
    if case.contention_never_converges:
        _check_unsettled(case, run)
        return frozenset(buckets)
    return frozenset(buckets | _check_settled(case, run))


def _check_unsettled(case: ConcurrencyCase, run: _Run) -> None:
    """Contention that never converges is bounded, visible, and leaves nothing behind."""
    for answer in run.answers:
        assert isinstance(answer.error, ResolutionDidNotSettle), answer
        assert answer.error.attempts == MAX_CLAIM_ATTEMPTS
        assert answer.error.response.status == HTTPStatus.SERVICE_UNAVAILABLE
    # Every attempt was a transaction that committed neither item, so nothing was left behind by
    # any of the concurrent requests -- no binding, and no orphan Session row.
    assert run.store.items == {}
    assert run.starter.executions == {}
    assert run.store.log.count("claim_binding") == case.degree * MAX_CLAIM_ATTEMPTS


def _check_settled(case: ConcurrencyCase, run: _Run) -> set[str]:
    """One Session, one Sandbox, one binding, and a usable answer for every request."""
    observed: set[str] = set()
    for answer in run.answers:
        assert answer.error is None, f"a concurrent request failed: {answer.error!r}"
    results = [answer.result for answer in run.answers if answer.result is not None]
    assert len(results) == case.degree

    rows = {record.session_id: record for record in run.store.sessions()}
    seated_ids = set() if run.seated is None else {run.seated.session_id}
    created = set(rows) - seated_ids
    started = {
        name.removeprefix(EXECUTION_NAME_PREFIX) for name in run.starter.executions
    }

    # R6.17's "exactly one Sandbox", as a bijection: every Session row created during the run had
    # exactly one execution started for it, and every execution has a row. A losing request that
    # had left an orphan row behind would appear here as a row with no execution, and a Session
    # provisioned twice as a repeated `StartExecution`.
    assert created == started, f"created {sorted(created)}, started {sorted(started)}"
    assert run.starter.log.count("start_execution") == len(created)

    # Exactly one binding, in the caller's own partition, for the one digest under contention.
    binding = run.store.only_binding()
    assert binding.affinity_key_digest == DIGEST
    assert binding.pk == pk_for(principal())

    # The exactly-once guarantee. Phrased over the loser branch table rather than over
    # `is_terminal`, because `TERMINATING` is not terminal and is treated as absent, and because a
    # second `PENDING` row -- the defect this property exists to catch -- is not terminal either.
    resolvable = sorted(
        record.session_id
        for record in rows.values()
        if LOSER_BRANCHES[record.lifecycle_state] is not LoserBranch.TREAT_AS_ABSENT
    )
    assert len(resolvable) <= 1, f"more than one Session is resolvable: {resolvable}"
    if resolvable:
        assert binding.session_id == resolvable[0]
    else:
        assert binding.session_id in rows

    if case.prior.is_resolvable:
        # Nothing could create: every request resolved the Session already bound.
        observed.add("outcome: every request resolved the bound Session")
        assert created == set()
        assert run.starter.executions == {}
        assert run.wait.calls == []
        assert {result.payload["sessionId"] for result in results} == seated_ids
        assert all(result.payload[RESOLUTION_FIELD] == _RESOLVED for result in results)
    elif run.wait.made_unresolvable:
        # A Session died while requests waited on it, so a replacement is licensed -- but only one,
        # and only over the Session that died.
        observed.add("outcome: a Session became unresolvable mid-wait")
        assert 1 <= len(created) <= 2
    else:
        # The design's claim, exactly: one Session record, one `StartExecution`, and every request
        # in the set naming that one Session.
        observed.add("outcome: exactly one Session served the whole set")
        assert len(created) == 1
        assert len(started) == 1
        assert {result.payload["sessionId"] for result in results} == created

    if run.store.log.count("replace_binding"):
        observed.add("a conditional replacement was attempted")

    for result in results:
        observed |= _check_answer(result, rows)
    return observed


def _check_answer(result: OperationResult, rows: dict[str, SessionRecord]) -> set[str]:
    """R6.19: a usable answer naming an existing Session, never a `504` and never an error."""
    payload = result.payload
    outcome = payload[RESOLUTION_FIELD]
    assert outcome in {_CREATED, _RESOLVED}
    assert payload["sessionId"] in rows
    assert result.status != HTTPStatus.GATEWAY_TIMEOUT
    if "connection" not in payload:
        # The wait budget expired: a Session identifier and no credential, which the SDK and the
        # tool interface both read as "not yet published" (R9.16). Omitted, never null.
        assert result.status == HTTPStatus.ACCEPTED
        return {"answer: the asynchronous shape, no credential yet"}
    connection = payload["connection"]
    if outcome == _RESOLVED:
        assert result.status == HTTPStatus.OK
        # R6.23: minted during this resolution, never the credential sitting on the row.
        assert connection["authHeaderValue"] == FAKE_TOKEN
        assert connection["authHeaderValue"] != PUBLISHED.auth_header_value
        return {"answer: a freshly minted credential"}
    assert result.status == HTTPStatus.CREATED
    # R6.13's other half: a creation returns what the orchestration published.
    assert connection == PUBLISHED.to_map()
    return {"answer: the credential the orchestration published"}


# Feature: aws-serverless-agent-sandbox, Property 36: For all concurrency degrees, for all arrival
# schedules, and for all prior binding states including absent and terminal, a set of simultaneous
# resolutions carrying one Tenant and one Affinity_Key results in exactly one Session record bound
# to that Affinity_Key, exactly one StartExecution, exactly one provisioned Sandbox, and no Session
# record left behind by a losing request; and every request in the set returns a usable connection
# credential naming that one Session rather than an error.
@given(case=concurrency_case())
@settings(max_examples=300)
def test_concurrent_same_key_requests_produce_one_session_and_one_sandbox(
    case: ConcurrencyCase,
) -> None:
    """**Validates: Requirements 6.17, 6.19**"""
    for bucket in check_case(case):
        event(bucket)


# --- Non-vacuity, both deterministic -------------------------------------------------------------

#: The case every enumerated one below varies from: three requests, no prior binding, a schedule
#: that interleaves them, and an orchestration that publishes on the first poll.
BASE_CASE: Final = ConcurrencyCase(
    degree=3,
    schedule=(0, 1, 2),
    prior=PriorBinding.ABSENT,
    polls_before_publication=0,
    waiting_states=(LifecycleState.PENDING,),
    winner_goes_terminal=False,
    contention_never_converges=False,
)

#: One case per bucket, stated rather than drawn, so every arm of the checker runs whatever the
#: generator happens to produce on a given run. `schedule=(0,)` always grants the turn to the
#: lowest-numbered waiting worker, which runs each request to completion before the next starts;
#: any other schedule interleaves them.
ENUMERATED_CASES: Final = (
    replace(BASE_CASE, degree=2),
    replace(BASE_CASE, degree=8),
    replace(BASE_CASE, degree=MAX_DEGREE),
    replace(BASE_CASE, schedule=(0,)),
    replace(BASE_CASE, prior=PriorBinding.RUNNING),
    replace(BASE_CASE, prior=PriorBinding.SUSPENDED),
    replace(BASE_CASE, prior=PriorBinding.TERMINATED),
    replace(BASE_CASE, prior=PriorBinding.FAILED),
    replace(BASE_CASE, prior=PriorBinding.TERMINATING),
    replace(BASE_CASE, polls_before_publication=2),
    replace(BASE_CASE, polls_before_publication=NEVER_PUBLISHES),
    replace(
        BASE_CASE,
        polls_before_publication=1,
        waiting_states=(LifecycleState.PROVISIONING, LifecycleState.STARTING),
    ),
    replace(BASE_CASE, winner_goes_terminal=True),
    replace(BASE_CASE, prior=PriorBinding.TERMINATED, winner_goes_terminal=True),
    replace(BASE_CASE, contention_never_converges=True),
)

#: Every bucket the enumerated cases must reach between them. A bucket that stopped being reachable
#: would mean a dimension of the domain had quietly closed.
BUCKETS: Final = frozenset(
    {
        "degree: 2",
        "degree: 3 to 8",
        "degree: above 8",
        "prior: absent",
        "prior: live: RUNNING",
        "prior: live: SUSPENDED",
        "prior: terminal: TERMINATED",
        "prior: terminal: FAILED",
        "prior: terminal: TERMINATING",
        "publication: on the first poll",
        "publication: after some polls",
        "publication: never",
        "contention: never converges",
        "schedule: a request was preempted mid-resolution",
        "schedule: one request at a time, to completion",
        "outcome: every request resolved the bound Session",
        "outcome: a Session became unresolvable mid-wait",
        "outcome: exactly one Session served the whole set",
        "a conditional replacement was attempted",
        "answer: the asynchronous shape, no credential yet",
        "answer: a freshly minted credential",
        "answer: the credential the orchestration published",
    }
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain the property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    for case in ENUMERATED_CASES:
        covered |= check_case(case)
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"


def test_the_invariants_fail_against_a_claim_with_its_condition_removed() -> None:
    """A store that commits the claim unconditionally must break the property, and does.

    This is the shape R6.18 forbids -- a write that does not fail when a binding already exists.
    Three concurrent requests each commit their own Session row and each start an execution, so
    three Sessions are resolvable for one Affinity_Key where one is permitted. Without this test,
    the property above could be true of an implementation that had lost its condition entirely.
    """
    with pytest.raises(AssertionError, match="more than one Session is resolvable"):
        check_case(BASE_CASE, store_class=_UnconditionalStore)


def test_a_serial_schedule_and_an_interleaved_one_are_both_realised() -> None:
    """The schedule is an input, so both a queue and a genuine interleaving are reachable.

    A property whose every example happened to run the requests one at a time would assert nothing
    about concurrency, so the two are distinguished here rather than assumed.
    """
    serial = run_case(replace(BASE_CASE, schedule=(0,)), ScheduledStore)
    assert not serial.baton.preempted

    interleaved = run_case(replace(BASE_CASE, schedule=(0, 1, 2)), ScheduledStore)
    assert interleaved.baton.preempted
    # And the realised interleaving is the schedule's, not the operating system's: replaying one
    # schedule twice grants the turns in the same order both times.
    assert (
        run_case(replace(BASE_CASE, schedule=(0, 1, 2)), ScheduledStore).baton.handoffs
        == interleaved.baton.handoffs
    )
