# kiro-classification: public
"""The idle policy the Session_Orchestrator writes onto a Sandbox at provisioning (R10.2, R10.3).

Three numbers and a flag: how long a Sandbox may sit idle before it is suspended, how long it may
sit suspended before it is terminated, and whether an arriving request resumes it. R10.2 requires
the orchestrator to configure them **on the Sandbox**, which in this design means on the
:class:`~control_plane.providers.base.SandboxSpec` handed to `provision`, because that is the only
channel through which the Control_Plane tells a Compute_Provider anything about a Sandbox before it
exists.

This module owns the policy and its application. It owns neither the provisioning call nor the state
machine that makes it: :meth:`IdlePolicy.applied_to` returns a spec and provisions nothing, so the
whole of this module's blast radius is one `capabilities()` call.

## Why the policy is validated twice, and why that is not redundancy

The design fixes the split: validation stays in the `CreateSession` handler because a `400` should
not cost an execution, and the orchestrator *revalidates* as a cheap assertion rather than
provisioning against an out-of-range policy. So there are two checks with two different jobs.

- :func:`~control_plane.api.admission.admit_session_creation` turns a caller's mistake into a `400`
  before anything is written. It is a contract with the caller.
- :func:`idle_policy_from_execution_input` turns a defect in *this* system — an execution input that
  reached the orchestrator carrying a policy no handler should have admitted — into a failed
  execution before a Sandbox exists. It is an assertion about our own plumbing, and there is nobody
  to return a `400` to.

The second check is worth its cost precisely because it is cheap and because the thing it guards is
expensive: a Sandbox provisioned with a zero idle duration is a Sandbox whose suspension behaviour
is unspecified, and it is billable from the moment it starts. Failing the execution leaves the
Session row in a `FAILED` state with its binding deleted by the settlement path
(:mod:`control_plane.lifecycle`), which is a Session a caller can retry; provisioning against the
bad policy leaves a running MicroVM nobody has a stated rule for.

## Invalid policies are unrepresentable rather than merely refused

:class:`IdlePolicy` refuses a non-positive duration **at construction**. There is no value of the
type that violates R10.3, so every function below that accepts an :class:`IdlePolicy` accepts a
policy that has already passed the rule, and :meth:`IdlePolicy.applied_to` contains no check of its
own. The two readers — :func:`idle_policy_for` from a Session row and
:func:`idle_policy_from_execution_input` from an execution input — are the only places an untrusted
number becomes a policy, and both go through the constructor.

## The capability check, and why it is here rather than at admission

The seam's rule is that a capability which plausibly differs between backends is *discovered* rather
than assumed, and the design's provider mapping table says as much about idle handling: a provider
that expresses it differently maps these fields itself **or declares
`auto_resume_on_request=False`**. Two policies are therefore unsatisfiable rather than out of range:

- A provider declaring :attr:`~control_plane.providers.base.SuspendFidelity.NONE` cannot suspend at
  all, so an idle duration before suspension describes an event that will never happen.
- A policy with `auto_resume` set against a provider declaring `auto_resume_on_request=False` would
  promise R10.5 — a request arriving at a suspended endpoint resumes the Sandbox — from a backend
  that has stated it cannot deliver it. `fargate-task` declares exactly that, and it is honest about
  why: a stopped task has no ENI and therefore no endpoint for a request to arrive at.

Both are refused as :class:`~control_plane.providers.base.CapabilityUnsupported`, which the seam
documents as reaching the Control_Plane *before any Sandbox is provisioned*. Refusing at admission
instead would put a provider-capability branch in the handler, which is the coupling the seam
exists to prevent; refusing after `provision` would mean discovering it from a running Sandbox.

## What this module deliberately does not decide

**It does not decide when to suspend.** Nothing here reads a clock, and there is no
"has this Sandbox been idle long enough" predicate, because the answer is not the Control_Plane's to
give. The design's third cleanup layer is explicit: the idle and duration policy written onto the
MicroVM at provisioning time is enforced *by the compute service itself*, which is what makes a
Session outlive its limits only if the orchestrator, the Reaper and the provider's own enforcement
all fail together. A Control_Plane that decided idleness would be a fourth thing to fail and would
have to observe request traffic it deliberately does not sit in front of.

**It does not suspend, resume or terminate anything.** Applying a policy kills no process and closes
no terminal: a suspended Session retains filesystem *and* memory state and may be resumed by nothing
more than a request arriving (R13.2, R10.5). The observation of a suspension is
:mod:`control_plane.suspension`, and the enforcement of the suspended duration is the Reaper's
sweep (R10.7), which is its own task.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Final

from control_plane.providers.base import (
    CapabilityUnsupported,
    ComputeProvider,
    SandboxSpec,
    SuspendFidelity,
)
from control_plane.state.records import SessionRecord

__all__ = [
    "AUTO_RESUME_FIELD",
    "EXECUTION_INPUT_LIMITS_FIELD",
    "IDLE_SECONDS_FIELD",
    "SUSPENDED_SECONDS_FIELD",
    "AutoResumeUnsupported",
    "IdlePolicy",
    "IdlePolicyRejected",
    "SuspensionUnsupported",
    "idle_policy_for",
    "idle_policy_from_execution_input",
]

#: The three attribute names the idle policy travels under, from the `CreateSession` body through
#: the Session row to the orchestrator's execution input. One vocabulary end to end, so a reader of
#: an execution history and a reader of a stored item are reading the same three words.
#:
#: Spelled here rather than imported from :mod:`control_plane.api.admission`, which spells the same
#: three for the request body. The duplication is deliberate and is the posture this repository
#: already takes for `MAX_RUN_CONFIG_BYTES` and the Sandbox_Protocol control port: this module is
#: reached by the orchestrator's provisioning task, and importing the API package to borrow three
#: string constants would attach that package's import graph — and any future orchestration module
#: inside it — to the provisioning path. A test asserts the two spellings agree, which is the thing
#: that actually needs to hold. **Consolidation candidate** once the orchestrator's own module
#: layout settles.
IDLE_SECONDS_FIELD: Final = "idleSeconds"
SUSPENDED_SECONDS_FIELD: Final = "suspendedSeconds"
AUTO_RESUME_FIELD: Final = "autoResume"

#: The execution-input key under which the three above arrive. The `CreateSession` handler nests
#: them beside `maxDurationSeconds` and `memoryBytes` in one admitted-limits map, so the
#: orchestrator reads one map rather than five top-level keys.
EXECUTION_INPUT_LIMITS_FIELD: Final = "limits"


class IdlePolicyRejected(ValueError):
    """A configured idle policy that R10.3 refuses, or that carries no usable value at all.

    One exception for both, because to the orchestrator they mean the same thing: the execution
    input does not carry a policy this execution may provision against. A `ValueError`, so a task
    Lambda raising it fails the execution rather than being retried against a value that cannot
    become valid.

    Zero, negative, a missing field and a field of the wrong type are one rule rather than four. A
    Sandbox that suspends after zero seconds of idleness is not a shorter-lived Sandbox, it is an
    unspecified one — the same reading :mod:`control_plane.api.admission` gives the caller-facing
    half of this rule.
    """

    def __init__(self, field_name: str, value: object) -> None:
        super().__init__(
            f"{field_name} must be a configured value R10.3 admits, got {value!r}"
        )
        self.field_name = field_name
        self.value = value


class SuspensionUnsupported(CapabilityUnsupported):
    """The selected provider cannot suspend, so an idle duration before suspension is unmeaning.

    A :class:`~control_plane.providers.base.CapabilityUnsupported`, so the refusal reaches a caller
    through the seam's own failure rather than through a new one this module invented, and it does
    so before any Sandbox is provisioned.
    """

    def __init__(self, provider_name: str) -> None:
        super().__init__("suspend", provider_name)


class AutoResumeUnsupported(CapabilityUnsupported):
    """The policy enables automatic resume and the selected provider declares it cannot.

    R10.5 promises that a request arriving at a suspended Sandbox's endpoint resumes it. A provider
    declaring `auto_resume_on_request=False` has stated that it cannot keep that promise — for
    `fargate-task`, because a stopped task has no endpoint for a request to arrive at — so a Session
    provisioned with the flag set would carry a guarantee nothing enforces.
    """

    def __init__(self, provider_name: str) -> None:
        super().__init__("auto-resume on request", provider_name)


@dataclass(frozen=True, slots=True)
class IdlePolicy:
    """The idle policy of one Session: the three values R10.2 names, and nothing else.

    Field names are :class:`~control_plane.providers.base.SandboxSpec`'s rather than the Session
    row's, because this object exists in order to reach a Sandbox and
    :meth:`applied_to` is therefore an assignment with no mapping step in it. The row's shorter
    spellings are read by :func:`idle_policy_for`, in one place.

    Raises:
        IdlePolicyRejected: either duration is not a positive integer number of seconds (R10.3).
            There is deliberately no value of this type that violates the rule.
    """

    idle_seconds_before_suspend: int
    suspended_seconds_before_terminate: int
    auto_resume: bool

    def __post_init__(self) -> None:
        for field_name, seconds in (
            (IDLE_SECONDS_FIELD, self.idle_seconds_before_suspend),
            (SUSPENDED_SECONDS_FIELD, self.suspended_seconds_before_terminate),
        ):
            _admissible_duration(field_name, seconds)
        # `bool` is a subclass of `int`, so an integer here would configure automatic resume as
        # truthiness rather than as the decision R10.2 requires to be recorded.
        if not isinstance(self.auto_resume, bool):
            raise IdlePolicyRejected(AUTO_RESUME_FIELD, self.auto_resume)

    def applied_to(
        self, spec: SandboxSpec, *, provider: ComputeProvider
    ) -> SandboxSpec:
        """Return `spec` with this policy's three values on it, or refuse the provider (R10.2).

        The one route by which an idle policy reaches a Sandbox. It provisions nothing, calls no
        lifecycle method, and asks the provider exactly one question — `capabilities()` — so
        applying a policy cannot start, suspend or stop anything.

        `provider` is passed rather than a capability set, so the answer is discovered from the same
        object the caller is about to call `provision` on. A caller that read `capabilities()`
        itself and passed the parts it liked could pass a set no provider declared.

        Args:
            spec: the Sandbox specification the orchestrator is assembling. Its three idle fields
                are required by the seam, so they already hold something; this is what makes them
                hold a validated policy.
            provider: the Compute_Provider this Session was admitted against.

        Returns:
            A new spec, identical but for the three idle-policy fields.

        Raises:
            SuspensionUnsupported: the provider declares it cannot suspend at all.
            AutoResumeUnsupported: this policy enables automatic resume and the provider declares
                it cannot resume on an arriving request.
        """
        capabilities = provider.capabilities()
        if capabilities.suspend_fidelity is SuspendFidelity.NONE:
            raise SuspensionUnsupported(provider.name)
        if self.auto_resume and not capabilities.auto_resume_on_request:
            raise AutoResumeUnsupported(provider.name)
        return replace(
            spec,
            idle_seconds_before_suspend=self.idle_seconds_before_suspend,
            suspended_seconds_before_terminate=self.suspended_seconds_before_terminate,
            auto_resume=self.auto_resume,
        )


def idle_policy_for(record: SessionRecord) -> IdlePolicy:
    """The idle policy recorded on one Session row.

    The row is the authoritative copy: `SessionRecord.__post_init__` already refuses a non-positive
    duration, so this reader cannot produce a policy the constructor would reject — which is why it
    is a three-field read and not a second validation.
    """
    return IdlePolicy(
        idle_seconds_before_suspend=record.idle_seconds,
        suspended_seconds_before_terminate=record.suspended_seconds,
        auto_resume=record.auto_resume,
    )


def idle_policy_from_execution_input(payload: Mapping[str, Any]) -> IdlePolicy:
    """Revalidate the idle policy carried in an orchestration's execution input (R10.2, R10.3).

    The orchestrator's cheap assertion, and the reason it is cheap is that it is three reads and two
    comparisons against a value the execution already holds — no store read, no provider call, and
    it happens before `provision`. An execution input that reached here with an out-of-range policy
    is a defect in the creation path rather than a caller's mistake, so it fails the execution.

    Raises:
        IdlePolicyRejected: the input carries no `limits` map, or a field of that map is absent, of
            the wrong type, or a duration that is not greater than zero.
    """
    limits = _limits_of(payload)
    return IdlePolicy(
        idle_seconds_before_suspend=_admissible_duration(
            IDLE_SECONDS_FIELD, limits.get(IDLE_SECONDS_FIELD)
        ),
        suspended_seconds_before_terminate=_admissible_duration(
            SUSPENDED_SECONDS_FIELD, limits.get(SUSPENDED_SECONDS_FIELD)
        ),
        auto_resume=_flag(limits, AUTO_RESUME_FIELD),
    )


def _limits_of(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """The `limits` map of an execution input, refusing an input that carries none."""
    limits = payload.get(EXECUTION_INPUT_LIMITS_FIELD)
    if isinstance(limits, Mapping):
        return limits
    raise IdlePolicyRejected(EXECUTION_INPUT_LIMITS_FIELD, limits)


def _admissible_duration(field_name: str, seconds: object) -> int:
    """Return one configured duration, admitting only a positive integer of seconds (R10.3).

    The admitted set is stated once, here, and both readers and the constructor go through it, so
    "greater than zero seconds" has a single spelling. `bool` is excluded because it is a subclass of
    `int`, and `True` would otherwise configure a one-second idle duration nobody asked for — the
    same exclusion admission makes on the request body.

    Raises:
        IdlePolicyRejected: `seconds` is absent, of the wrong type, or not greater than zero.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
        raise IdlePolicyRejected(field_name, seconds)
    return seconds


def _flag(limits: Mapping[str, Any], field_name: str) -> bool:
    """One configured boolean, admitted only as a boolean.

    R10.2 requires the policy to specify *whether* automatic resume is enabled, so an absent field
    is not "off": it is an execution input that never recorded the decision, and defaulting it here
    would invent a lifecycle decision the design lists as declared configuration.
    """
    flag = limits.get(field_name)
    if isinstance(flag, bool):
        return flag
    raise IdlePolicyRejected(field_name, flag)
