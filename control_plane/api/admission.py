# kiro-classification: public
"""Step 1 of `CreateSession`: admission validation, and deliberately nothing after it.

The design fixes the creation sequence as validate, write the Session row, `StartExecution`, wait,
return. This module is step 1 alone. It writes nothing, reads no store, starts no execution and
provisions no Sandbox, so the ordering guarantee R6.10 and R6.11 rest on is not something this
module can weaken. Step 2 onwards compose with it by calling :func:`admit_session_creation` first
and building the Session row from the :class:`AdmittedLimits` it returns.

Validation lives here rather than inside the Session_Orchestrator for the reason the design gives:
a `400` for a duration above the ceiling should not cost an execution start, and the error has to
name the value `provider.limits()` supplies, which the handler already holds and the state machine
would have to be told.

**Three rules, and where each number comes from.**

- *Absent duration* → the configured deployment default (R6.4). The default is a field of
  :class:`AdmissionPolicy` with no literal behind it, because the design lists "the default
  duration applied when a caller supplies none" among the decisions that are declared
  configuration — a CDK context value — rather than code. A constant here would be a second
  source for a number the deployment owns.
- *Duration above the ceiling* → `400` naming :attr:`ProviderLimits.max_duration_seconds` (R6.5).
  The number in the message is read from the value the selected provider returned on this call and
  is never spelled in this module. That is the whole point of the clause: the same rejection reads
  28,800 against `lambda-microvm` and 86,400 against `fargate-task`, so a hardcoded copy would be
  wrong for one of them. The floor is checked against the same declaration, because the design's
  Session record table states `maxDurationSeconds` is validated against `provider.limits()` and a
  duration under the provider's declared minimum would otherwise be refused later by `provision`
  as a `CapabilityUnsupported` — a `500` for what is a caller's mistake.
- *Idle or suspended duration not greater than zero* → `400` (R10.3). Checked on the value that
  will actually be configured, whether it came from the request or from the policy, because R10.3
  governs *every* configured duration rather than only the ones a caller typed.

**Rejections are allowed to say what was wrong.** They are built with
:func:`~control_plane.api.errors.error_response` and not with the fixed not-found response. Those
are different things: R6.9's constant is information-free because the existence of another Tenant's
Session is the one fact a response may not carry, whereas a duration the caller themselves supplied
is already known to them, and naming the ceiling is what makes the rejection actionable. Nothing
here echoes a Session identifier, a Tenant, or any stored value — the only request-derived content
in a message is the offending number the caller sent.

`SessionRecord.__post_init__` enforces the same positivity rule at the storage boundary. That is not
redundancy to remove: this module turns a caller's mistake into a `400` before anything is written,
and the record's check turns a defect in *this* system into a loud failure rather than a row that
violates R10.3. One is a contract with the caller, the other an invariant of the store.
"""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Final

from control_plane.api.errors import ControlPlaneError, error_response

if TYPE_CHECKING:
    # Annotations only, so this module adds no runtime dependency on the providers package. That
    # package's `__init__` populates the registry as an import-time side effect, and admission
    # validation reads two attributes of whichever provider it is handed rather than selecting one,
    # so importing it here would attach a registration to every import of `control_plane.api`.
    from collections.abc import Mapping

    from control_plane.providers.base import ComputeProvider, ProviderLimits

__all__ = [
    "ADMISSION_ERROR_CODE",
    "AUTO_RESUME_FIELD",
    "IDLE_SECONDS_FIELD",
    "MAX_DURATION_FIELD",
    "SUSPENDED_SECONDS_FIELD",
    "AdmissionPolicy",
    "AdmittedLimits",
    "SessionAdmissionRejected",
    "admit_session_creation",
]

#: The `CreateSession` body fields this module reads. Spelled exactly as the Session record's own
#: attributes are, so a request field and the row attribute it becomes have one vocabulary and a
#: reader of the stored item does not have to translate.
MAX_DURATION_FIELD: Final = "maxDurationSeconds"
IDLE_SECONDS_FIELD: Final = "idleSeconds"
SUSPENDED_SECONDS_FIELD: Final = "suspendedSeconds"
AUTO_RESUME_FIELD: Final = "autoResume"

#: The `error` code every admission rejection carries. One code rather than one per rule: the
#: distinction a caller acts on is in the message, and a code per rule would be a second thing to
#: keep in step with the rules.
ADMISSION_ERROR_CODE: Final = "InvalidSessionConfiguration"


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """The deployment's configured defaults for the fields a caller may omit.

    Every field is required, with no literal default on the class. The design lists these among the
    lifecycle decisions that are declared configuration, supplied by the CDK context, so inventing
    a number here would create a second source for a value the deployment owns — and one that a
    deployment overriding it could silently disagree with.

    The defaults are validated at construction rather than per request. A deployment configured
    with a non-positive idle duration is a misconfiguration, not a caller's `400`, so it fails
    where it is built instead of turning every well-formed request into a rejection.
    """

    default_duration_seconds: int
    default_idle_seconds: int
    default_suspended_seconds: int
    default_auto_resume: bool

    def __post_init__(self) -> None:
        for name, value in (
            ("default_duration_seconds", self.default_duration_seconds),
            # R10.3 governs every configured duration, including the ones nobody requested.
            ("default_idle_seconds", self.default_idle_seconds),
            ("default_suspended_seconds", self.default_suspended_seconds),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(
                    f"{name} must be a positive integer number of seconds, got {value!r}"
                )


@dataclass(frozen=True, slots=True)
class AdmittedLimits:
    """The limits an admitted `CreateSession` request resolved to.

    Every value here has passed every rule, so the caller of :func:`admit_session_creation` writes
    the Session row from this object without repeating a check. The field names match
    :class:`~control_plane.state.records.SessionRecord`'s, so step 2 is an assignment rather than a
    mapping with somewhere to go wrong.
    """

    max_duration_seconds: int
    idle_seconds: int
    suspended_seconds: int
    auto_resume: bool


class SessionAdmissionRejected(ControlPlaneError):
    """A `CreateSession` request refused before anything was written (R6.5, R10.3).

    A `400` carrying a message, because a caller who supplied a value out of range needs to know
    which value and what the bound is. Distinct from
    :class:`~control_plane.api.errors.SessionNotFound`, whose response is fixed precisely so that
    it says nothing.
    """

    def __init__(self, message: str) -> None:
        super().__init__(
            error_response(HTTPStatus.BAD_REQUEST, ADMISSION_ERROR_CODE, message),
            message,
        )
        self.message = message


def admit_session_creation(
    body: Mapping[str, Any],
    *,
    provider: ComputeProvider,
    policy: AdmissionPolicy,
) -> AdmittedLimits:
    """Validate a `CreateSession` body and return the limits it resolved to.

    An empty mapping is a valid request in which every field is defaulted (R6.4), which is why
    :func:`~control_plane.api.request.request_body` reports an absent body as `{}` rather than as an
    error.

    Args:
        body: the decoded `CreateSession` body. `{}` when the request carried none.
        provider: the selected Compute_Provider. `limits()` is called exactly once, and the ceiling
            named in a rejection is read from that call rather than from any constant here (R6.5).
        policy: the deployment's configured defaults for omitted fields (R6.4).

    Returns:
        The validated limits to record on the Session row.

    Raises:
        SessionAdmissionRejected: the body names a duration outside the provider's declared range
            (R6.5), an idle or suspended duration that is not greater than zero (R10.3), or a field
            of the wrong type.
    """
    limits = provider.limits()

    max_duration_seconds = _requested_int(body, MAX_DURATION_FIELD)
    if max_duration_seconds is None:
        max_duration_seconds = policy.default_duration_seconds
    else:
        _require_within_provider_range(max_duration_seconds, provider.name, limits)

    idle_seconds = _requested_int(body, IDLE_SECONDS_FIELD)
    if idle_seconds is None:
        idle_seconds = policy.default_idle_seconds
    suspended_seconds = _requested_int(body, SUSPENDED_SECONDS_FIELD)
    if suspended_seconds is None:
        suspended_seconds = policy.default_suspended_seconds

    # R10.3, on the resolved values. A policy-supplied value cannot fail here, because
    # `AdmissionPolicy` refused to exist with one that would.
    _require_positive_duration(IDLE_SECONDS_FIELD, idle_seconds)
    _require_positive_duration(SUSPENDED_SECONDS_FIELD, suspended_seconds)

    auto_resume = body.get(AUTO_RESUME_FIELD)
    if auto_resume is None:
        auto_resume = policy.default_auto_resume
    elif not isinstance(auto_resume, bool):
        raise SessionAdmissionRejected(
            f"{AUTO_RESUME_FIELD} must be a boolean, got {_described(auto_resume)}"
        )

    return AdmittedLimits(
        max_duration_seconds=max_duration_seconds,
        idle_seconds=idle_seconds,
        suspended_seconds=suspended_seconds,
        auto_resume=auto_resume,
    )


def _requested_int(body: Mapping[str, Any], field_name: str) -> int | None:
    """Read an integer field, or `None` when the caller supplied none.

    `None` and absence are the same request: a client that serialises an unset option as `null`
    means "I did not choose", so it gets the configured default rather than a rejection.

    `bool` is excluded explicitly. It is a subclass of `int`, so `{"idleSeconds": true}` would
    otherwise be admitted as one second, which is a duration nobody asked for.
    """
    value = body.get(field_name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise SessionAdmissionRejected(
            f"{field_name} must be an integer number of seconds, got {_described(value)}"
        )
    return value


def _require_positive_duration(field_name: str, seconds: int) -> None:
    """Refuse a duration that is not greater than zero (R10.3).

    Zero and negative are one rule rather than two: a Sandbox that suspends after zero seconds of
    idleness is not a shorter-lived Sandbox, it is an unspecified one.
    """
    if seconds <= 0:
        raise SessionAdmissionRejected(
            f"{field_name} must be greater than zero seconds, got {seconds}"
        )


def _require_within_provider_range(
    seconds: int, provider_name: str, limits: ProviderLimits
) -> None:
    """Refuse a requested duration outside the provider's declared range (R6.5).

    Both bounds are interpolated from `limits`, so the message states this provider's ceiling and
    not a number this module believes about some provider. That is the clause: the ceiling is a
    value the Compute_Provider publishes, so a deployment on a provider declaring 86,400 seconds
    gets a rejection naming 86,400 without an edit here.
    """
    if seconds > limits.max_duration_seconds:
        raise SessionAdmissionRejected(
            f"{MAX_DURATION_FIELD} {seconds} exceeds the service ceiling of "
            f"{limits.max_duration_seconds} seconds declared by Compute_Provider "
            f"{provider_name!r}"
        )
    if seconds < limits.min_duration_seconds:
        raise SessionAdmissionRejected(
            f"{MAX_DURATION_FIELD} {seconds} is below the minimum of "
            f"{limits.min_duration_seconds} seconds declared by Compute_Provider "
            f"{provider_name!r}"
        )


def _described(value: object) -> str:
    """Name a rejected value's type without echoing an unbounded string into a response."""
    return f"a value of type {type(value).__name__}"
