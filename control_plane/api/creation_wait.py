# kiro-classification: public
"""Step 4 of creation: the wait, and the two contracts a deployment configures it into.

:mod:`control_plane.api.creation` performs steps 2 and 3 — write the complete Session row, start the
execution — and then hands the written row to a :class:`~control_plane.api.creation.CreationWait`.
This module supplies the two waits that seam can hold and the switch that selects between them. It
renders nothing: the `201`/`202` mapping and the omitted-rather-than-null `connection` field belong
to :func:`~control_plane.api.creation.creation_payload` and are untouched here.

## What the wait is waiting for, and where it reads it

The Session_Orchestrator provisions the Sandbox, obtains the connection credential, and publishes it
onto the Session row inside that Session's Tenant scope (R6.12). The handler then reads the
credential it returns **from the State_Store** and never from a Compute_Provider call it issued
itself (R6.13). That is why :class:`PollingCreationWait` holds a
:class:`~control_plane.api.lookup.SessionLookup` and nothing else that could produce a credential:
there is no provider on it, no
:class:`~control_plane.credentials.ConnectionIssuer` on it, and every descriptor it returns is
:meth:`~control_plane.state.records.ConnectionDescriptor.from_map` applied to the `connection`
attribute of a row. `ci/lint_rules/sole_credential_issuer.py` keeps the mint reachable from one
module only, so the claim is structural rather than conventional.

## The polling loop

Polling rather than a callback or a synchronous execution start, for the reasons the design records:
a task token makes the *state machine* wait for an external actor, which is the wrong direction, and
`StartSyncExecution` exists only for Express workflows while the 28,800 second ceiling requires
Standard. So:

- **Strongly consistent reads**, through the seam whose contract is a single-item consistent
  `GetItem`. Eventually consistent is not an acceptable substitute here for the same reason
  :class:`~control_plane.api.lookup.SessionLookup` gives for `GetSession`: a stale replica can miss
  a credential that has already been published, which turns a successful creation into a spurious
  degradation to the asynchronous shape. The read is issued at the row's own
  `(pk, sort_key)`, taken from the record the handler wrote, so no partition key is spelled here.
- **Jittered intervals**, drawn uniformly from
  `POLL_INTERVAL_SECONDS ± POLL_JITTER_SECONDS` — 200 ms ± 50 ms, so 150 ms to 250 ms. Uniform and
  symmetric rather than exponential: the expected wait is one cold provision, not an overload to
  back away from, so the mean interval should not grow with the number of attempts. Jitter is what
  keeps many concurrent creations from synchronising into read bursts against a single partition,
  and it is not decoration on the get-or-create path: the loser of the conditional write waits on
  the *same row* as the winner (R6.19), so two unjittered waiters would poll in lockstep by
  construction rather than by coincidence.
- **Bounded by the clamp, not by an iteration count.** An attempt count bounds nothing a gateway
  cares about, because an attempt is not a duration. See below.
- **One read before the first sleep**, so a credential already on the row costs no wait. That is the
  common case for the get-or-create loser, whose winner may have published before the loser even
  read.

## The budget, and why it is derived rather than configured twice

`budget = min(configured wait budget, integration timeout − RESPONSE_MARGIN_SECONDS)`.

The clamp's upper bound is derived from the configured API integration timeout (R10.13) rather than
being a second independent number, so a deployment cannot set a budget that outlives the request it
is inside. The margin is a module constant rather than a third configuration value, because it pays
for one thing that does not vary with the deployment: rendering and returning the response after the
wait ends. A budget equal to the timeout would spend the whole request on the wait and hand the
gateway a `504` instead of a body.

A configured budget larger than the clamp is clamped rather than rejected. The deployment that sets
60 s against a 29 s timeout has made a mistake, and the safe reading of that mistake is the shorter
wait: refusing to run would take an API offline over a value whose only sound interpretation is
"wait as long as you can".

## The fallback, which is the point of R10.14

**Exceeding the budget is not an error.** The wait returns `None`, the handler renders the
asynchronous shape — the Session identifier with no `connection` — and the caller polls
`GetSession` for the credential the orchestration will publish. Three things follow, and each is a
thing R10.14 exists to prevent:

- **No `504`.** A gateway timeout carries no body, so it carries no Session identifier, and a caller
  holding no identifier cannot address, poll or terminate the Session that is now provisioning on
  their behalf. That is the failure mode: not a slow response, a *lost* Session. The budget expires
  strictly before the integration timeout by construction, so the gateway is never reached.
- **No lost work.** The row is written and the execution is started before the wait begins, so
  nothing the wait does or fails to do changes what was provisioned.
- **No new response shape.** The fallback is the asynchronous contract's own response, which the
  Client_SDK and the Agent_Tool_Interface already treat as "not yet published" (R9.16). An absent
  `connection` means one thing under both contracts, so the fallback needs no client support that
  the asynchronous contract did not already require.

The contract switch, `creationContract`, therefore changes no code path's existence:
:func:`wait_for_contract` returns :class:`~control_plane.api.creation.NoCreationWait` for
`asynchronous` and :class:`PollingCreationWait` for `synchronous`, both always deployed. Setting the
context value to `asynchronous` is how a deployment whose measured cold provision latency exceeds
the integration timeout discharges R10.14 without touching a handler, an SDK or a state machine.

## The one condition that is an error

A row that has reached a terminal lifecycle state will never publish a credential, so the wait stops
and reports the recorded `stateReason` (R6.14). Spinning to the end of the budget instead would bill
the caller for a wait that cannot succeed and would then report the failure as "not yet published",
which is the one thing the design says an absent `connection` never means.

The terminal check is evaluated **before** the published credential, which departs from the order
the design's terminal-condition list happens to use. The order is observable only in the race where
a row carries both — published at `STARTING → RUNNING`, then recorded terminal — and in that race
the credential names a Sandbox that is being torn down. Handing it to a caller would trade one
useful error for a sequence of connection failures against a dead endpoint.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import Any, Final

from control_plane.api.creation import CreationWait, NoCreationWait
from control_plane.api.errors import ControlPlaneError, error_response
from control_plane.api.lookup import SessionLookup
from control_plane.state.keys import ItemShapeError
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)

__all__ = [
    "CONNECTION_ATTRIBUTE",
    "LIFECYCLE_STATE_ATTRIBUTE",
    "POLL_INTERVAL_SECONDS",
    "POLL_JITTER_SECONDS",
    "PROVISIONING_FAILED_ERROR_CODE",
    "RESPONSE_MARGIN_SECONDS",
    "STATE_REASON_ATTRIBUTE",
    "CreationContract",
    "CreationWaitSettings",
    "PollingCreationWait",
    "SessionProvisioningFailed",
    "wait_for_contract",
]

#: The three row attributes the wait reads. Named here so the projection a deployed `GetItem` asks
#: for and the attributes this loop reads have one spelling; a projection that dropped one of these
#: would otherwise look correct until a Session failed.
CONNECTION_ATTRIBUTE: Final = "connection"
LIFECYCLE_STATE_ATTRIBUTE: Final = "lifecycleState"
STATE_REASON_ATTRIBUTE: Final = "stateReason"

#: The polling interval and the half-width of the jitter around it, in seconds: 200 ms ± 50 ms, so
#: every interval falls in [150 ms, 250 ms]. Constants rather than configuration, because the design
#: declares the wait *budget* and the *contract* as deployment configuration and neither names the
#: interval — and because R9.16 has the Client_SDK poll on "the same interval and budget the
#: Control_Plane would have used", which is a statement about one shared number.
POLL_INTERVAL_SECONDS: Final = 0.2
POLL_JITTER_SECONDS: Final = 0.05

#: What the clamp holds back from the integration timeout, in seconds. It pays for rendering and
#: returning the response once the wait ends, which is the difference between the asynchronous
#: fallback and a gateway timeout with no body.
RESPONSE_MARGIN_SECONDS: Final = 2.0

#: The `error` code of a creation whose orchestration recorded a failure (R6.14).
PROVISIONING_FAILED_ERROR_CODE: Final = "SessionProvisioningFailed"


class CreationContract(str, Enum):
    """The `creationContract` context value: which of two deployed behaviours `POST /sessions` runs.

    A `str` enum so a CDK context value maps onto it directly, and an enum rather than a bare string
    so a third value fails where it is read instead of being silently treated as one of the two.
    There is no default here: the deployment owns the choice, and the measured cold provision
    latency is what decides it (R10.12 against R10.13).
    """

    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"


class SessionProvisioningFailed(ControlPlaneError):
    """The orchestration recorded this Session as failed, and the wait reports its reason (R6.14).

    `502`, because the request was well formed and the failure happened behind the API in the
    orchestration or the Compute_Provider. Not a `404`: the Session is the caller's own and its
    existence is not somebody else's secret. Not the asynchronous fallback either — an absent
    `connection` means "not yet published" and a terminal row will never publish one.

    The reason is the one the orchestrator recorded, so a quota exhaustion names the exhausted quota
    the provider named (R6.8) rather than a message invented here.
    """

    def __init__(self, session_id: str, *, state: LifecycleState, reason: str) -> None:
        message = (
            f"Session {session_id} was recorded {state.value} before a connection "
            f"credential was published: {reason}"
        )
        super().__init__(
            error_response(
                HTTPStatus.BAD_GATEWAY, PROVISIONING_FAILED_ERROR_CODE, message
            ),
            message,
        )
        self.session_id = session_id
        self.state = state
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CreationWaitSettings:
    """The deployment-configured inputs to the wait: the contract, the timeout and the budget.

    Every field is required, with no class-level default, following
    :class:`~control_plane.api.admission.AdmissionPolicy` and
    :class:`~control_plane.api.creation.CreationSettings`. These are CDK context values, and a
    literal here would be a second source for a number the deployment owns — which is exactly the
    inconsistency the clamp below exists to survive.

    `integration_timeout_seconds` is the *configured* API integration timeout that R10.13 requires
    to be stated, not the service maximum it sits under. It appears here because the budget is
    derived from it rather than set beside it.
    """

    contract: CreationContract
    integration_timeout_seconds: float
    wait_budget_seconds: float

    def __post_init__(self) -> None:
        _require_positive_seconds(
            "integration_timeout_seconds", self.integration_timeout_seconds
        )
        _require_positive_seconds("wait_budget_seconds", self.wait_budget_seconds)
        if self.integration_timeout_seconds <= RESPONSE_MARGIN_SECONDS:
            raise ValueError(
                f"integration_timeout_seconds must exceed the {RESPONSE_MARGIN_SECONDS} "
                f"second response margin, so some budget remains to wait in: "
                f"{self.integration_timeout_seconds}"
            )

    @property
    def budget_seconds(self) -> float:
        """The wait's actual budget: the configured one, clamped inside the integration timeout.

        `min(configured, timeout − margin)`. The upper bound is *derived*, so a deployment that
        configures a budget longer than the request it runs inside gets the safe one rather than a
        handler the gateway kills mid-wait.
        """
        return min(
            self.wait_budget_seconds,
            self.integration_timeout_seconds - RESPONSE_MARGIN_SECONDS,
        )

    @property
    def is_clamped(self) -> bool:
        """Whether the configured budget was longer than the integration timeout allows.

        Reported rather than raised, so a deployment can surface the disagreement it configured
        without the wait's own behaviour depending on which of the two numbers was smaller.
        """
        return self.wait_budget_seconds > self.budget_seconds


@dataclass(frozen=True, slots=True)
class PollingCreationWait:
    """The synchronous contract's wait: poll the Session row until the credential appears.

    Holds a read seam and nothing that can produce a credential. Every descriptor it returns was
    parsed out of a row the orchestration wrote (R6.12, R6.13).

    The clock is `time.monotonic` rather than the wall clock the records use, because this measures
    an elapsed budget and a wall clock that steps backwards would extend it. Both the clock and the
    sleep are injected, so the offline suite drives every path — publication on the first read, on a
    later read, and never — with no real waiting.
    """

    lookup: SessionLookup
    settings: CreationWaitSettings
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    #: Draws one interval from `[low, high]`. Injected so a test fixes the draw; `random.uniform`
    #: rather than a cryptographic source because the only thing jitter has to defeat is two
    #: waiters agreeing, not an adversary predicting them.
    jitter: Callable[[float, float], float] = random.uniform

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        """Return the published credential, or `None` when none appeared inside the budget.

        `None` is the fallback R10.14 requires, not a failure: the caller receives the asynchronous
        response shape carrying the Session identifier and reads the credential subsequently.

        Raises:
            SessionProvisioningFailed: the row reached a terminal state, so no credential will be
                published and the recorded reason is the answer (R6.14).
        """
        deadline = self.clock() + self.settings.budget_seconds
        while True:
            published = self._published_connection(record)
            if published is not None:
                return published
            remaining = deadline - self.clock()
            if remaining <= 0:
                return None
            # Clamped to the remaining budget, so the wait cannot overshoot the clamp by up to one
            # interval and eat into the margin the response needs.
            self.sleep(min(self._next_interval(), remaining))

    def _published_connection(
        self, record: SessionRecord
    ) -> ConnectionDescriptor | None:
        """One strongly consistent read of the row, at the key the handler already holds.

        An absent row is treated as nothing-yet-published rather than as a not-found. The handler
        wrote this row moments ago, so absence means it was removed underneath the creation, and
        answering a caller `404` for a Session whose orchestration may already be provisioning would
        lose that Session exactly as a `504` would. The bounded degradation to the asynchronous
        shape keeps it addressable.

        A row that is present but malformed is *not* absorbed: an item in the caller's own partition
        with the wrong shape is a defect in this system, and reporting it as "not yet published"
        would hide a bug behind a legitimate response. That is the posture
        :func:`~control_plane.api.lookup.resolve_session` takes for the same reason.
        """
        item = self.lookup.read_session(
            partition_key=record.pk, sort_key=record.sort_key
        )
        if item is None:
            return None
        state = _lifecycle_state(item)
        if state is not None and state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise SessionProvisioningFailed(
                record.session_id, state=state, reason=_state_reason(item, state)
            )
        return _published_descriptor(item)

    def _next_interval(self) -> float:
        """Draw the next interval, uniform in `POLL_INTERVAL_SECONDS ± POLL_JITTER_SECONDS`."""
        return self.jitter(
            POLL_INTERVAL_SECONDS - POLL_JITTER_SECONDS,
            POLL_INTERVAL_SECONDS + POLL_JITTER_SECONDS,
        )


def wait_for_contract(
    settings: CreationWaitSettings,
    *,
    lookup: SessionLookup,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
) -> CreationWait:
    """Return the wait this deployment's `creationContract` selects.

    Both waits are always deployed and this is the whole of the switch: `synchronous` waits for the
    credential inside a clamped budget, `asynchronous` waits for nothing and the caller reads the
    credential from `GetSession` (R10.14). Neither changes where the credential comes from — under
    both contracts it is published to the State_Store by the orchestration and read from there, so
    the asynchronous contract removes a wait rather than a data path.
    """
    if settings.contract is CreationContract.ASYNCHRONOUS:
        return NoCreationWait()
    return PollingCreationWait(
        lookup=lookup, settings=settings, clock=clock, sleep=sleep, jitter=jitter
    )


def _require_positive_seconds(name: str, value: float) -> None:
    """Refuse a value that is not a positive number of seconds.

    One condition rather than two, so a misconfigured deployment fails as the misconfiguration it
    is: a `ValueError` naming the field, matching
    :class:`~control_plane.api.admission.AdmissionPolicy`, rather than a `TypeError` for the string
    half and a `ValueError` for the negative half of the same mistake.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{name} must be a positive number of seconds, got {value!r}")


def _lifecycle_state(item: Mapping[str, Any]) -> LifecycleState | None:
    """Read `lifecycleState`, or `None` when the read projected it away.

    Absent is tolerated and unparseable is not, so a deployment whose `GetItem` projects only
    `connection` still works while a row carrying a state nothing in this system defines fails
    loudly.
    """
    value = item.get(LIFECYCLE_STATE_ATTRIBUTE)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ItemShapeError(f"{LIFECYCLE_STATE_ATTRIBUTE} is not a string")
    try:
        return LifecycleState(value)
    except ValueError as exc:
        raise ItemShapeError(
            f"{LIFECYCLE_STATE_ATTRIBUTE} is not a lifecycle state: {value!r}"
        ) from exc


def _state_reason(item: Mapping[str, Any], state: LifecycleState) -> str:
    """The recorded reason a terminal row carries, or a true statement when it carries none."""
    value = item.get(STATE_REASON_ATTRIBUTE)
    if value is None:
        return f"the orchestration recorded {state.value} without a reason"
    if not isinstance(value, str):
        raise ItemShapeError(f"{STATE_REASON_ATTRIBUTE} is not a string")
    return value


def _published_descriptor(item: Mapping[str, Any]) -> ConnectionDescriptor | None:
    """Parse the published `connection` attribute, or `None` when the row carries none."""
    value = item.get(CONNECTION_ATTRIBUTE)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ItemShapeError(f"{CONNECTION_ATTRIBUTE} is not a map")
    return ConnectionDescriptor.from_map(value)
