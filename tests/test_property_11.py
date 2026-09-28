# kiro-classification: public
"""Property 11: Session admission validation (R6.4, R6.5, R10.3).

The deterministic examples are in `test_control_plane_admission.py`. What is generalised here is
the *domain*, in two directions at once:

- every shape a caller can give one of the three duration fields — omitted, sent as `null`, sent
  as an integer anywhere around a provider's declared window, or sent as a `bool`;
- every deployment's configured defaults, drawn rather than fixed, so a resolved value cannot be
  confused with a constant this file chose.

## Why more than one Compute_Provider

R6.5's clause is not "reject above the ceiling", it is that the rejection carries the ceiling the
selected provider *published*. A property quantified over one provider cannot fail against a
Control_Plane holding a hardcoded 28,800, so every drawn body is admitted or refused by three
providers whose declared windows share no bound:

| Provider | Declared window, seconds | Reached by a drawn duration of |
| --- | --- | --- |
| `narrow-window` | 300 to 7,200 | 7,201: refused here, admitted by both others |
| `local-firecracker` | 1 to 28,800 | 28,801: refused here, admitted by `fargate-task` |
| `fargate-task` | 1 to 86,400 | 86,401: refused by all three |

So a hardcoded ceiling fails in the *accepting* direction — it refuses a duration `fargate-task`
declares admissible — and a hardcoded number in the message fails in the rejecting direction,
because the message must carry 7,200, 28,800 and 86,400 in turn for one drawn value.

`narrow-window` exists for the floor. Both shipped providers declare a minimum of one second, so
against them alone the floor rejection is indistinguishable from "not a positive duration" and its
number is indistinguishable from a literal `1`. `narrow-window` declares 300, which makes the floor
an interior boundary: 299 is refused naming 300, and 300 itself is admitted.

## What the property is able to fail on

Each of these is a plausible implementation and each is refused by the assertions below:

- a hardcoded ceiling or floor, in the decision or in the message — the table above;
- a default applied when the caller did supply a value, or a supplied value ignored — the drawn
  policy is independent of the drawn request, so the two disagree on almost every example;
- `>=` where `>` was meant at either bound — the anchors include each bound exactly, one below and
  one above it;
- treating an explicit `null` as a value rather than as absence — `null` and omission are asserted
  to resolve identically;
- admitting `{"idleSeconds": true}` as one second, which `bool` being an `int` in Python invites;
- blaming the wrong field: a message may name only fields that were actually violated.

One implementation this property deliberately *cannot* distinguish is R10.3 applied to the body
rather than to the resolved value. `AdmissionPolicy` refuses to exist with a non-positive default,
so a resolved-but-not-requested duration is never non-positive and the two implementations agree on
every reachable input. That half of R10.3 is asserted where it is reachable — against the policy's
own construction, in `test_control_plane_admission.py` — rather than pretended to here.

`test_the_drawn_domain_reaches_every_region_the_property_needs` asserts the coverage the first
three of those rely on, so the domain cannot quietly shrink to the vacuous part of itself.

## Offline

Both shipped providers are constructed directly, as every other test of them is: they are absent
from `ISOLATION_APPROVED`, the registry refuses them, and nothing here registers anything.
Admission reads two attributes of whichever provider it is handed and touches no store, no key and
no network, so the whole property is a pure function under test.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from http import HTTPStatus
from itertools import pairwise
from typing import Any, Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import DrawFn, SearchStrategy

from control_plane.api import (
    ADMISSION_ERROR_CODE,
    AUTO_RESUME_FIELD,
    IDLE_SECONDS_FIELD,
    MAX_DURATION_FIELD,
    SUSPENDED_SECONDS_FIELD,
    AdmissionPolicy,
    AdmittedLimits,
    SessionAdmissionRejected,
    admit_session_creation,
)
from control_plane.providers.base import ComputeProvider, ProviderLimits
from control_plane.providers.fargate_task import FargateTaskProvider
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from tests.harness import MINIMUM_EXAMPLES

# Admission is a pure function over three fields, so an example costs microseconds and the budget
# is set by the size of the domain rather than by the clock: three shapes per field over a
# twenty-value anchor set, against three providers, is a product the floor of 100 samples thinly.
ADMISSION_EXAMPLES: Final = 500

#: Every field a rejection is allowed to name. Used to assert that a message names no field that
#: was not actually violated.
ADMISSION_FIELDS: Final = (
    MAX_DURATION_FIELD,
    IDLE_SECONDS_FIELD,
    SUSPENDED_SECONDS_FIELD,
    AUTO_RESUME_FIELD,
)


class NarrowWindowProvider(LocalFirecrackerProvider):
    """A Compute_Provider declaring a duration window with a minimum above one second.

    Only the declaration differs, because only the declaration is what admission reads: it calls
    `limits()` once and interpolates `name` into a rejection. Nothing in this module provisions,
    so the inherited lifecycle — which enforces the shipped module's own constants — is never
    reached and cannot disagree with the window declared here.

    The window is contained in both shipped providers' windows, so a duration inside it is
    admissible everywhere and the three providers disagree only about the region between their
    bounds.
    """

    name = "narrow-window"

    def limits(self) -> ProviderLimits:
        return replace(
            super().limits(), min_duration_seconds=300, max_duration_seconds=7_200
        )


#: The providers every drawn body is put to. Constructed directly; the registry is not involved.
PROVIDERS: Final[tuple[ComputeProvider, ...]] = (
    NarrowWindowProvider(),
    LocalFirecrackerProvider(),
    FargateTaskProvider(),
)


def _declared_windows() -> tuple[ProviderLimits, ...]:
    return tuple(provider.limits() for provider in PROVIDERS)


#: The widest declared minimum and the narrowest declared maximum, so a value between them is
#: admissible against every provider.
UNIVERSAL_FLOOR: Final = max(
    limits.min_duration_seconds for limits in _declared_windows()
)
UNIVERSAL_CEILING: Final = min(
    limits.max_duration_seconds for limits in _declared_windows()
)


def _anchored_durations() -> tuple[int, ...]:
    """Every boundary of every declared window, plus the values around and far outside them."""
    values: set[int] = {-86_400, -600, -1, 0, 1}
    for limits in _declared_windows():
        for bound in (limits.min_duration_seconds, limits.max_duration_seconds):
            values.update({bound - 1, bound, bound + 1})
        values.add(
            (limits.min_duration_seconds + limits.max_duration_seconds) // 2
        )  # mid-range
        values.add(limits.max_duration_seconds * 10)  # far beyond
    return tuple(sorted(values))


#: The design's `duration()` anchor set: negatives, zero, one, each provider minimum, a mid-range
#: value, one below and one above each declared maximum, the maxima themselves, and values far
#: beyond them.
ANCHORED_DURATIONS: Final = _anchored_durations()

_FAR_BEYOND: Final = max(ANCHORED_DURATIONS)


class Absent:
    """The field is not in the body at all.

    Distinct from the `None` a client sends when it serialises an unset option as `null`: the two
    are asserted to be the *same request*, which is a claim the property can fail rather than an
    assumption it encodes.
    """

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = Absent()

#: One drawn field: absent, an explicit null, an integer, or a `bool` — which is an `int` in
#: Python and so is the one wrong type that could be admitted as a duration by accident.
type FieldValue = Absent | int | None

_VALUE: Final = "value"
_NULL: Final = "null"
_BOOL: Final = "bool"
_OMITTED: Final = "omitted"

#: Shapes drawn per field, weighted towards a supplied integer: with three independent fields, an
#: even split would spend most examples on a rejection that never reaches a window comparison.
_SHAPES: Final = (_VALUE, _VALUE, _VALUE, _VALUE, _VALUE, _NULL, _BOOL, _OMITTED)


def duration() -> SearchStrategy[int]:
    """Draw a requested duration in seconds (the design's `duration()`, minus the absent case)."""
    return st.one_of(
        st.sampled_from(ANCHORED_DURATIONS),
        # Inside the widest declared window, so the admissible interior is sampled densely.
        st.integers(min_value=1, max_value=UNIVERSAL_CEILING * 12),
        st.integers(min_value=-_FAR_BEYOND, max_value=_FAR_BEYOND),
    )


@st.composite
def requested_duration(draw: DrawFn) -> FieldValue:
    """Draw one field of a create request, across every shape a caller can give it."""
    shape = draw(st.sampled_from(_SHAPES))
    if shape == _VALUE:
        return draw(duration())
    if shape == _NULL:
        return None
    if shape == _BOOL:
        return draw(st.booleans())
    return ABSENT


@dataclass(frozen=True, slots=True)
class DrawnRequest:
    """The three duration fields of a `CreateSession` body, before it is assembled."""

    max_duration: FieldValue
    idle: FieldValue
    suspended: FieldValue

    def fields(self) -> tuple[tuple[str, FieldValue], ...]:
        return (
            (MAX_DURATION_FIELD, self.max_duration),
            (IDLE_SECONDS_FIELD, self.idle),
            (SUSPENDED_SECONDS_FIELD, self.suspended),
        )

    def body(self) -> dict[str, Any]:
        """The request body. An absent field is missing; an explicit null is present as `None`."""
        return {
            field: value
            for field, value in self.fields()
            if not isinstance(value, Absent)
        }


def create_request() -> SearchStrategy[DrawnRequest]:
    return st.builds(
        DrawnRequest,
        max_duration=requested_duration(),
        idle=requested_duration(),
        suspended=requested_duration(),
    )


def admission_policy() -> SearchStrategy[AdmissionPolicy]:
    """Draw a deployment's configured defaults (R6.4).

    The default duration is drawn inside every provider's declared window. That is deliberate
    rather than incidental: whether a *defaulted* duration is itself checked against the window is
    a question the design does not settle, so the property stays out of it and asserts only what
    R6.4 states — that an absent field takes the configured value.
    """
    return st.builds(
        AdmissionPolicy,
        default_duration_seconds=st.integers(
            min_value=UNIVERSAL_FLOOR, max_value=UNIVERSAL_CEILING
        ),
        default_idle_seconds=st.integers(min_value=1, max_value=86_400),
        default_suspended_seconds=st.integers(min_value=1, max_value=86_400),
        default_auto_resume=st.booleans(),
    )


WRONG_TYPE: Final = "wrong-type"
CEILING: Final = "above the declared ceiling"
FLOOR: Final = "below the declared floor"
NON_POSITIVE: Final = "not greater than zero"


@dataclass(frozen=True, slots=True)
class Violation:
    """One rule a drawn request breaks, and the field it breaks it on."""

    field: str
    kind: str


@dataclass(frozen=True, slots=True)
class Expectation:
    """What admission owes a drawn request against one provider's declared window."""

    admitted: AdmittedLimits | None
    violations: tuple[Violation, ...]
    #: The value each well-typed field resolves to, whether from the request or from the policy.
    resolved: dict[str, int]


def expected_outcome(
    drawn: DrawnRequest, *, policy: AdmissionPolicy, limits: ProviderLimits
) -> Expectation:
    """The outcome the three requirements demand, computed from the drawn inputs alone.

    Written as the requirements read rather than as `admission.py` is written: resolve absence to
    the configured default (R6.4), compare a *requested* maximum duration against the window the
    provider declared (R6.5), and require every *resolved* idle and suspended duration to be
    greater than zero (R10.3). Nothing here reproduces the module's ordering, so the assertions
    below hold whatever order the checks are made in.
    """
    violations: list[Violation] = []
    resolved: dict[str, int] = {}
    defaults = {
        MAX_DURATION_FIELD: policy.default_duration_seconds,
        IDLE_SECONDS_FIELD: policy.default_idle_seconds,
        SUSPENDED_SECONDS_FIELD: policy.default_suspended_seconds,
    }

    for field, value in drawn.fields():
        if isinstance(value, bool):
            # A `bool` is an `int` in Python and is not a number of seconds.
            violations.append(Violation(field, WRONG_TYPE))
            continue
        if value is None or isinstance(value, Absent):
            resolved[field] = defaults[field]  # R6.4: absence, however it was spelled.
            continue
        resolved[field] = value
        if field != MAX_DURATION_FIELD:
            continue
        if value > limits.max_duration_seconds:  # R6.5, in both directions.
            violations.append(Violation(field, CEILING))
        elif value < limits.min_duration_seconds:
            violations.append(Violation(field, FLOOR))

    # R10.3 governs every configured duration, so this reads the resolved value and not the body.
    for field in (IDLE_SECONDS_FIELD, SUSPENDED_SECONDS_FIELD):
        seconds = resolved.get(field)
        if seconds is not None and seconds <= 0:
            violations.append(Violation(field, NON_POSITIVE))

    admitted = (
        None
        if violations
        else AdmittedLimits(
            max_duration_seconds=resolved[MAX_DURATION_FIELD],
            idle_seconds=resolved[IDLE_SECONDS_FIELD],
            suspended_seconds=resolved[SUSPENDED_SECONDS_FIELD],
            # Never supplied in a drawn body, so R6.4 owns it on every example.
            auto_resume=policy.default_auto_resume,
        )
    )
    return Expectation(
        admitted=admitted, violations=tuple(violations), resolved=resolved
    )


def _assert_rejection_is_about_what_was_wrong(
    message: str, expected: Expectation, *, limits: ProviderLimits, provider_name: str
) -> None:
    """A rejection names a violated field, names no other, and carries the provider's own number."""
    named = {field for field in ADMISSION_FIELDS if field in message}
    violated = {violation.field for violation in expected.violations}
    assert named, f"rejection names no field at all: {message!r}"
    assert named <= violated, (
        f"rejection blames {sorted(named - violated)}, which nothing was wrong with: {message!r}"
    )

    if len(expected.violations) != 1:
        # More than one rule is broken, so which one the message reports is the module's choice
        # and not this property's business.
        return

    violation = expected.violations[0]
    assert violation.field in message
    if violation.kind == CEILING:
        # R6.5: the number is the one this provider published, not one the Control_Plane holds.
        assert str(limits.max_duration_seconds) in message
        assert provider_name in message
    elif violation.kind == FLOOR:
        assert str(limits.min_duration_seconds) in message
        assert provider_name in message
    elif violation.kind == NON_POSITIVE:
        # R10.3 reports the resolved value, which is the one that would have been configured.
        assert str(expected.resolved[violation.field]) in message


def _outcome(
    body: dict[str, Any], *, provider: ComputeProvider, policy: AdmissionPolicy
) -> AdmittedLimits | str:
    """The resolved limits, or the rejection message, so two requests can be compared as one."""
    try:
        return admit_session_creation(body, provider=provider, policy=policy)
    except SessionAdmissionRejected as rejected:
        return rejected.message


# Feature: aws-serverless-agent-sandbox, Property 11: For all requested maximum durations, idle
# durations and suspended durations, the Control_Plane accepts a create request exactly when the
# maximum duration lies within the registered provider's declared limits and both other durations
# are greater than zero; a rejected duration produces an error carrying the provider's declared
# maximum; and an absent maximum duration produces the configured default.
@given(drawn=create_request(), policy=admission_policy())
@settings(max_examples=ADMISSION_EXAMPLES)
def test_session_admission_is_the_declared_window_and_positive_resolved_durations(
    drawn: DrawnRequest, policy: AdmissionPolicy
) -> None:
    """**Validates: Requirements 6.4, 6.5, 10.3**"""
    body = drawn.body()

    for provider in PROVIDERS:
        limits = provider.limits()
        expected = expected_outcome(drawn, policy=policy, limits=limits)

        if expected.admitted is not None:
            assert (
                admit_session_creation(body, provider=provider, policy=policy)
                == expected.admitted
            )
            continue

        with pytest.raises(SessionAdmissionRejected) as raised:
            admit_session_creation(body, provider=provider, policy=policy)
        rejection = raised.value
        assert rejection.response.status == HTTPStatus.BAD_REQUEST
        assert ADMISSION_ERROR_CODE.encode() in rejection.response.body
        _assert_rejection_is_about_what_was_wrong(
            rejection.message,
            expected,
            limits=limits,
            provider_name=provider.name,
        )

    # Admission validates; it does not edit the body it was handed.
    assert body == drawn.body()

    # An explicit null is the same request as an absent field: dropping every null must not change
    # the outcome, whether that outcome is an admission or a rejection.
    omitted = DrawnRequest(
        max_duration=ABSENT if drawn.max_duration is None else drawn.max_duration,
        idle=ABSENT if drawn.idle is None else drawn.idle,
        suspended=ABSENT if drawn.suspended is None else drawn.suspended,
    )
    if omitted != drawn:
        for provider in PROVIDERS:
            assert _outcome(body, provider=provider, policy=policy) == _outcome(
                omitted.body(), provider=provider, policy=policy
            )


def test_the_drawn_domain_reaches_every_region_the_property_needs() -> None:
    """The anchors cover each declared bound and the gaps between providers (non-vacuity).

    Without this, the property could pass while the domain had shrunk to values every provider
    agrees about — where a hardcoded ceiling is indistinguishable from a published one.
    """
    anchors = set(ANCHORED_DURATIONS)
    assert any(value <= 0 for value in anchors)

    windows = _declared_windows()
    for limits in windows:
        floor, ceiling = limits.min_duration_seconds, limits.max_duration_seconds
        # Exactly at each bound, and one step either side of it.
        assert {
            floor - 1,
            floor,
            floor + 1,
            ceiling - 1,
            ceiling,
            ceiling + 1,
        } <= anchors
        assert any(floor < value < ceiling for value in anchors)

    # The regions where the providers disagree: a duration admitted by one and refused by another.
    ceilings = sorted({limits.max_duration_seconds for limits in windows})
    assert len(ceilings) == len(windows), "two providers declare the same ceiling"
    for lower, higher in pairwise(ceilings):
        assert any(lower < value <= higher for value in anchors), (
            f"no drawn duration falls between the ceilings {lower} and {higher}"
        )

    # The floor is an interior boundary for at least one provider, so a rejection naming it is
    # distinguishable from a rejection naming a literal one second.
    assert UNIVERSAL_FLOOR > 1
    assert UNIVERSAL_FLOOR < UNIVERSAL_CEILING

    assert ADMISSION_EXAMPLES >= MINIMUM_EXAMPLES


def test_the_providers_declare_windows_that_share_no_ceiling() -> None:
    """R6.5 is only testable against providers that disagree, so the disagreement is asserted."""
    windows = _declared_windows()
    assert len({limits.max_duration_seconds for limits in windows}) == len(windows)
    assert len({limits.min_duration_seconds for limits in windows}) > 1
    assert len({provider.name for provider in PROVIDERS}) == len(PROVIDERS)
