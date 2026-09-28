# kiro-classification: public
"""Session admission validation: the default duration, the provider ceiling, and R10.3.

Every assertion here is deterministic. Property 11, "Session admission validation", belongs to its
own task, so nothing in this file draws inputs.

The load-bearing test is `test_the_ceiling_in_the_message_is_the_providers_own_value`. R6.5 requires
the rejection to name the provider-declared maximum, and the only way to show that the number is not
a second hardcoded copy is to run the same request against two providers that declare different
maxima and watch the message change. `local-firecracker` declares 28,800 seconds and `fargate-task`
declares 86,400; neither number is written into the Control_Plane.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

import pytest

from control_plane.api import (
    ADMISSION_ERROR_CODE,
    NOT_FOUND_RESPONSE,
    AdmissionPolicy,
    AdmittedLimits,
    SessionAdmissionRejected,
    admit_session_creation,
)
from control_plane.providers.base import ComputeProvider
from control_plane.providers.fargate_task import FargateTaskProvider
from control_plane.providers.local_firecracker import LocalFirecrackerProvider

#: The deployment's configured defaults, as a test fixture rather than as a value this repository
#: asserts: the design makes each of these a CDK context value, so the numbers here stand in for a
#: deployment's configuration and no production default is claimed by choosing them.
POLICY = AdmissionPolicy(
    default_duration_seconds=3600,
    default_idle_seconds=300,
    default_suspended_seconds=600,
    default_auto_resume=True,
)


def admit(
    body: dict[str, Any], provider: ComputeProvider | None = None
) -> AdmittedLimits:
    return admit_session_creation(
        body,
        provider=provider if provider is not None else LocalFirecrackerProvider(),
        policy=POLICY,
    )


# --- The configured default when a field is absent (R6.4) ---------------------------------------


def test_an_empty_body_resolves_to_the_configured_defaults() -> None:
    # `CreateSession` with every field defaulted is a valid request, which is why an absent body
    # reaches this function as `{}` rather than as an error.
    assert admit({}) == AdmittedLimits(
        max_duration_seconds=POLICY.default_duration_seconds,
        idle_seconds=POLICY.default_idle_seconds,
        suspended_seconds=POLICY.default_suspended_seconds,
        auto_resume=POLICY.default_auto_resume,
    )


def test_an_absent_duration_takes_the_default_while_other_fields_are_honoured() -> None:
    admitted = admit({"idleSeconds": 120, "suspendedSeconds": 240, "autoResume": False})
    assert admitted.max_duration_seconds == POLICY.default_duration_seconds
    assert (admitted.idle_seconds, admitted.suspended_seconds) == (120, 240)
    assert admitted.auto_resume is False


@pytest.mark.parametrize(
    "field", ["maxDurationSeconds", "idleSeconds", "suspendedSeconds", "autoResume"]
)
def test_an_explicit_null_is_the_same_request_as_an_absent_field(field: str) -> None:
    # A client that serialises an unset option as `null` means "I did not choose".
    assert admit({field: None}) == admit({})


def test_the_default_duration_is_configuration_rather_than_a_constant() -> None:
    """Two deployments configured differently get different durations from the same request.

    R6.4 says "a configured default", and the design lists the default among the decisions that are
    declared configuration. If a literal lived in the module, this would fail.
    """
    other = AdmissionPolicy(
        default_duration_seconds=1800,
        default_idle_seconds=60,
        default_suspended_seconds=90,
        default_auto_resume=False,
    )
    resolved = admit_session_creation(
        {}, provider=LocalFirecrackerProvider(), policy=other
    )
    assert resolved.max_duration_seconds == 1800
    assert resolved.auto_resume is False
    assert admit({}).max_duration_seconds == POLICY.default_duration_seconds


# --- The provider's declared duration ceiling (R6.5) --------------------------------------------


def test_a_duration_at_the_declared_ceiling_is_admitted() -> None:
    provider = LocalFirecrackerProvider()
    ceiling = provider.limits().max_duration_seconds
    assert (
        admit({"maxDurationSeconds": ceiling}, provider).max_duration_seconds == ceiling
    )


def test_a_duration_above_the_declared_ceiling_is_rejected() -> None:
    provider = LocalFirecrackerProvider()
    ceiling = provider.limits().max_duration_seconds
    with pytest.raises(SessionAdmissionRejected) as raised:
        admit({"maxDurationSeconds": ceiling + 1}, provider)

    response = raised.value.response
    assert response.status == HTTPStatus.BAD_REQUEST
    assert ADMISSION_ERROR_CODE.encode() in response.body
    # The ceiling is named, so the caller learns the bound rather than only that they missed it.
    assert str(ceiling).encode() in response.body


def test_the_ceiling_in_the_message_is_the_providers_own_value() -> None:
    """R6.5's clause: the value comes from `provider.limits()`, not from the Control_Plane.

    The same request is refused by both providers, and each message states that provider's own
    maximum. A hardcoded copy in the Control_Plane would be wrong for one of the two.
    """
    firecracker = LocalFirecrackerProvider()
    fargate = FargateTaskProvider()
    lower_ceiling = firecracker.limits().max_duration_seconds
    higher_ceiling = fargate.limits().max_duration_seconds
    assert lower_ceiling != higher_ceiling
    requested = higher_ceiling + 1

    messages: dict[str, str] = {}
    for provider in (firecracker, fargate):
        with pytest.raises(SessionAdmissionRejected) as raised:
            admit({"maxDurationSeconds": requested}, provider)
        messages[provider.name] = raised.value.message
        assert str(provider.limits().max_duration_seconds) in messages[provider.name]

    assert messages[firecracker.name] != messages[fargate.name]
    # And neither message carries the other provider's number.
    assert str(higher_ceiling) not in messages[firecracker.name]
    assert str(lower_ceiling) not in messages[fargate.name]


def test_a_duration_below_the_declared_minimum_is_rejected_naming_it() -> None:
    # The Session record's own table states this field is validated against `provider.limits()`,
    # and refusing here turns what would be a `CapabilityUnsupported` from `provision` into a 400.
    provider = LocalFirecrackerProvider()
    floor = provider.limits().min_duration_seconds
    with pytest.raises(SessionAdmissionRejected) as raised:
        admit({"maxDurationSeconds": floor - 1}, provider)
    assert str(floor) in raised.value.message


# --- Idle and suspended durations greater than zero (R10.3) -------------------------------------


@pytest.mark.parametrize("field", ["idleSeconds", "suspendedSeconds"])
@pytest.mark.parametrize("seconds", [0, -1, -600])
def test_a_non_positive_idle_or_suspended_duration_is_rejected(
    field: str, seconds: int
) -> None:
    with pytest.raises(SessionAdmissionRejected) as raised:
        admit({field: seconds})
    assert raised.value.response.status == HTTPStatus.BAD_REQUEST
    assert field in raised.value.message


def test_the_smallest_positive_duration_is_admitted() -> None:
    admitted = admit({"idleSeconds": 1, "suspendedSeconds": 1})
    assert (admitted.idle_seconds, admitted.suspended_seconds) == (1, 1)


@pytest.mark.parametrize("seconds", [0, -1])
def test_a_deployment_cannot_configure_a_non_positive_idle_default(
    seconds: int,
) -> None:
    """R10.3 governs every configured duration, so a misconfigured policy cannot be constructed.

    A `ValueError` rather than a rejection: this is a deployment's mistake, and turning it into a
    `400` would blame every caller for it.
    """
    with pytest.raises(ValueError, match="default_idle_seconds"):
        AdmissionPolicy(
            default_duration_seconds=3600,
            default_idle_seconds=seconds,
            default_suspended_seconds=600,
            default_auto_resume=True,
        )


@pytest.mark.parametrize("seconds", [0, -1])
def test_a_deployment_cannot_configure_a_non_positive_suspended_default(
    seconds: int,
) -> None:
    with pytest.raises(ValueError, match="default_suspended_seconds"):
        AdmissionPolicy(
            default_duration_seconds=3600,
            default_idle_seconds=300,
            default_suspended_seconds=seconds,
            default_auto_resume=True,
        )


@pytest.mark.parametrize("seconds", [0, -1])
def test_a_deployment_cannot_configure_a_non_positive_duration_default(
    seconds: int,
) -> None:
    with pytest.raises(ValueError, match="default_duration_seconds"):
        AdmissionPolicy(
            default_duration_seconds=seconds,
            default_idle_seconds=300,
            default_suspended_seconds=600,
            default_auto_resume=True,
        )


# --- Field types --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maxDurationSeconds", "3600"),
        ("maxDurationSeconds", 3600.5),
        # `bool` is an `int` in Python, so an unexcluded `True` would be admitted as one second.
        ("idleSeconds", True),
        ("suspendedSeconds", [600]),
        ("autoResume", 1),
        ("autoResume", "true"),
    ],
)
def test_a_field_of_the_wrong_type_is_rejected(field: str, value: Any) -> None:
    with pytest.raises(SessionAdmissionRejected) as raised:
        admit({field: value})
    assert raised.value.response.status == HTTPStatus.BAD_REQUEST
    assert field in raised.value.message


def test_an_unknown_field_is_ignored_rather_than_rejected() -> None:
    # Admission validates the fields it owns; nothing here is a schema gate for the whole body.
    assert admit({"unrelated": "value"}) == admit({})


# --- A rejection is not the fixed not-found response --------------------------------------------


def test_a_rejection_carries_content_and_is_not_the_not_found_constant() -> None:
    """The two exist for opposite reasons and must not be confused.

    R6.9's constant is information-free because another Tenant's Session existing is the one fact a
    response may not carry. A duration the caller supplied themselves is already known to them, so
    naming the bound reveals nothing and makes the rejection actionable.
    """
    with pytest.raises(SessionAdmissionRejected) as raised:
        admit({"idleSeconds": 0})
    response = raised.value.response
    assert response is not NOT_FOUND_RESPONSE
    assert response.body != NOT_FOUND_RESPONSE.body
    assert response.status != NOT_FOUND_RESPONSE.status
    assert response.body != b""
    # The only request-derived content in a rejection is the offending number the caller sent.
    assert b"tenant" not in response.body.lower()
