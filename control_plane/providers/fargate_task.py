# kiro-classification: public
"""The `fargate-task` Compute_Provider: the seam's conformance exercise (R5.6).

The design writes this provider for one reason, and it is a negative one. `lambda-microvm` and
`local-firecracker` declare the same capability set, so a seam that had quietly been shaped like
AWS Lambda MicroVMs would look perfectly healthy against both. This provider is deliberately
**weaker**: Amazon ECS on AWS Fargate stops a task rather than snapshotting it, so what survives
a stop and start is the volume, not the memory. It therefore declares
`suspend_fidelity=DISK_ONLY` and `fork_from_running_state=False`, and the interesting question
is what a request for memory-preserving suspend does about that.

The answer is the point of the exercise: it fails by name, with
:class:`~control_plane.providers.base.CapabilityUnsupported`, and **nothing else changes**. No
Sandbox_Protocol message is added, renamed or given a fidelity field, and no Client_SDK
signature grows a parameter, a flag or a branch, because suspend fidelity is never on the wire
and never in a caller's arguments — it is discovered through `capabilities()` and refused before
a Sandbox exists. That failure mode is the seam working, not the seam breaking.

Four divergences from the isolation provider are carried on purpose, because a conformance
exercise that differed in only the one field the design names would still leave three of the
seam's assumptions untested:

  1. **`suspend_fidelity=DISK_ONLY`, and `auto_resume_on_request=False` with it.** A stopped
     Fargate task has no task ENI and therefore no endpoint, so there is nothing for an arriving
     request to wake. `suspend` consequently revokes the Sandbox's connection credentials, where
     `local-firecracker` keeps them; both are correct for their own declared capability, which is
     exactly why a caller reads the capability rather than assuming one.
  2. **Capacity is counted in `VCPU_PER_REGION`.** The anchored MicroVM quota counts memory
     bytes; the Fargate On-Demand quota counts vCPU. `consumed_capacity()` is meaningful for both
     only because :class:`~control_plane.providers.base.CapacityDimension` travels beside the
     number (R14.5).
  3. **A suspended Sandbox holds no capacity.** The MicroVM ceiling counts `RUNNING` and
     `SUSPENDED` together; a stopped Fargate task consumes no vCPU. So `resume` can raise
     `QuotaExhausted` on this provider, which cannot happen on the other two. "Suspended capacity
     still counts" is a property of one backend, not of the contract.
  4. **Different published ceilings and a third authentication scheme.** 86,400 s rather than
     28,800 s, an 8 KB task-override payload rather than 16 KB, and `X-Sandbox-Task-Token`
     rather than `X-aws-proxy-auth` or `Authorization: Bearer`. Each proves the corresponding
     value is read from `limits()` or from `ConnectionDescriptor` instead of being a constant
     somewhere upstream (R6.5, R7.11, R9.4).

Its public surface is exactly the eleven methods of the contract and no more, which is the
demonstrable form of "no Client_SDK signature changes": there is nothing extra here for a caller
to reach for, so accommodating the weaker backend cannot have widened the interface.

Like `local-firecracker`, it is not an isolation boundary. `fargate-task` is absent from
`ISOLATION_APPROVED`, so :func:`control_plane.providers.registry.register` refuses it and it can
only be constructed directly. Nothing in this module imports the registry and nothing here is
imported by :mod:`control_plane.providers`, which is what keeps it away from Untrusted_Code.
It makes no AWS calls: an exercise about the shape of an interface does not need a running task,
and the offline suite has neither credentials nor egress (R15.9).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import uuid4

from control_plane.providers.base import (
    CapabilityUnsupported,
    CapacityDimension,
    ComputeProvider,
    ConnectionDescriptor,
    ProviderCapabilities,
    ProviderLimits,
    QuotaExhausted,
    SandboxHandle,
    SandboxSpec,
    SandboxState,
    SandboxStatus,
    SuspendFidelity,
)

__all__ = [
    "AUTH_HEADER_NAME",
    "BOOLEAN_CAPABILITIES",
    "DEFAULT_CAPACITY_LIMIT_VCPU",
    "DEFAULT_ENDPOINT_HOST",
    "DEFAULT_ENDPOINT_PORT",
    "FARGATE_MEMORY_BYTES_CHOICES",
    "FARGATE_VCPU_MILLIS_CHOICES",
    "MAX_DURATION_SECONDS",
    "MAX_RUN_CONFIG_BYTES",
    "MEMORY_DISCARDED_REASON",
    "MIN_DURATION_SECONDS",
    "PROVIDER_NAME",
    "QUOTA_NAME",
    "FargateTaskProvider",
    "InvalidSandboxTransition",
    "UnknownSandbox",
    "require_capability",
    "require_suspend_fidelity",
]

PROVIDER_NAME: Final = "fargate-task"

# ECS imposes no ceiling of its own on how long a task may run, so this is a deployment-chosen
# limit. It deliberately differs from the MicroVM 28,800 s: R6.5's rejection message is built
# from `limits().max_duration_seconds`, and a message that read the same against both providers
# would not have proved that.
MAX_DURATION_SECONDS: Final = 86_400
MIN_DURATION_SECONDS: Final = 1

# The task-override payload ECS will carry, half the MicroVM `runHookPayload` ceiling. Above it
# a caller passes `SandboxSpec.start_config_ref` instead, which is R7.11's general overflow path
# keyed off a provider-declared limit rather than off a constant.
MAX_RUN_CONFIG_BYTES: Final = 8_192

_GIB: Final = 1_073_741_824
_MILLIS_PER_VCPU: Final = 1_000

# Whole-vCPU task sizes only. Fargate also offers 0.25 and 0.5 vCPU, and they are left out for a
# reason that belongs to this provider rather than to the seam: capacity is published in
# `VCPU_PER_REGION`, an integer count, and a fractional task would make `consumed_capacity()`
# either lossy or a lie.
FARGATE_VCPU_MILLIS_CHOICES: Final = (
    1 * _MILLIS_PER_VCPU,
    2 * _MILLIS_PER_VCPU,
    4 * _MILLIS_PER_VCPU,
    8 * _MILLIS_PER_VCPU,
    16 * _MILLIS_PER_VCPU,
)

FARGATE_MEMORY_BYTES_CHOICES: Final = (
    2 * _GIB,
    4 * _GIB,
    8 * _GIB,
    16 * _GIB,
    32 * _GIB,
)

# Counted in vCPU, not bytes: the Fargate On-Demand quota is a vCPU count. Small and finite so
# that the exhaustion path is reachable without pretending to fill a Region.
DEFAULT_CAPACITY_LIMIT_VCPU: Final = 16

# Provider-supplied, so a refusal recorded against a Session names this provider's own quota
# rather than a string the Control_Plane invented (R6.8, R6.14).
QUOTA_NAME: Final = "FargateOnDemandVcpuPerRegion"

# A third scheme, distinct from `lambda-microvm`'s `X-aws-proxy-auth` and
# `local-firecracker`'s `Authorization: Bearer`. Two schemes prove a header name can differ;
# three make it uncomfortable to argue the Client_SDK is quietly branching on one (R9.4).
AUTH_HEADER_NAME: Final = "X-Sandbox-Task-Token"

DEFAULT_ENDPOINT_HOST: Final = "127.0.0.1"
DEFAULT_ENDPOINT_PORT: Final = 8082

# Recorded on `SandboxStatus.state_reason`, which is a field of the contract. The fidelity gap is
# therefore *observable* through the existing status rather than through a new message or a new
# SDK field, which is the whole claim this provider exists to support.
MEMORY_DISCARDED_REASON: Final = (
    "memory discarded at suspend: this provider's fidelity is disk-only"
)

# Every boolean capability on `ProviderCapabilities`, derived from the dataclass rather than
# retyped, so a capability added to the seam is gated by `require_capability` without an edit
# here.
BOOLEAN_CAPABILITIES: Final = frozenset(
    declared.name
    for declared in fields(ProviderCapabilities)
    if declared.type in ("bool", bool)
)

# Weakest first. A request is refused when the provider's declared fidelity sits below the
# fidelity the request needs.
_FIDELITY_ORDER: Final = (
    SuspendFidelity.NONE,
    SuspendFidelity.DISK_ONLY,
    SuspendFidelity.MEMORY_AND_DISK,
)

_TERMINAL_STATES: Final = frozenset({SandboxState.TERMINATED, SandboxState.FAILED})


def require_capability(provider: ComputeProvider, capability: str) -> None:
    """Refuse a request that needs a boolean capability the provider does not declare.

    This is the check the Control_Plane makes before it provisions anything, written against
    `ComputeProvider` rather than against this provider: it reads `capabilities()` and the
    provider's own name, so it refuses `fargate-task` and admits `lambda-microvm` without naming
    either. It lives beside the provider whose refusals it demonstrates.

    Args:
        provider: the provider a Session has been assigned.
        capability: the name of a boolean field on `ProviderCapabilities`.

    Raises:
        CapabilityUnsupported: the provider declares that capability `False`.
        KeyError: `capability` is not a boolean capability of the seam. A silent `False` for a
            misspelled name would refuse every provider and look like a working gate.
    """
    if capability not in BOOLEAN_CAPABILITIES:
        raise KeyError(
            f"{capability!r} is not a capability of the Compute_Provider seam"
        )
    if not getattr(provider.capabilities(), capability):
        raise CapabilityUnsupported(capability, provider.name)


def require_suspend_fidelity(
    provider: ComputeProvider, required: SuspendFidelity
) -> None:
    """Refuse a request needing more suspend fidelity than the provider declares.

    A Session that needs its memory to survive a suspend calls this with
    `SuspendFidelity.MEMORY_AND_DISK`. Against `fargate-task` that raises, naming the capability
    as `suspend_fidelity=memory-and-disk`; against a provider declaring `MEMORY_AND_DISK` it
    returns. Stronger-than-required is accepted, because a Session asking for disk-only
    durability is served by a provider that preserves memory too.

    Raises:
        CapabilityUnsupported: the declared fidelity is weaker than `required`.
    """
    declared = provider.capabilities().suspend_fidelity
    if _FIDELITY_ORDER.index(declared) < _FIDELITY_ORDER.index(required):
        raise CapabilityUnsupported(f"suspend_fidelity={required.value}", provider.name)


class UnknownSandbox(LookupError):
    """Raised when a handle names no Sandbox this provider instance holds.

    A `LookupError`, as on the other two providers, so a caller that holds a stale handle
    handles every provider with one `except LookupError` clause.
    """

    def __init__(self, handle: SandboxHandle) -> None:
        super().__init__(
            f"no Sandbox {handle.sandbox_id!r} from provider "
            f"{handle.provider_name!r} is held by {PROVIDER_NAME}"
        )
        self.handle = handle


class InvalidSandboxTransition(ValueError):
    """Raised when an operation is asked of a Sandbox whose state cannot serve it.

    Distinct from `CapabilityUnsupported`, and the distinction matters most on this provider:
    a refused `suspend` on a terminated task is a state error, while a refused
    memory-preserving suspend is a capability error. Collapsing the two would hide the failure
    mode this provider exists to show.
    """

    def __init__(self, operation: str, state: SandboxState) -> None:
        super().__init__(f"cannot {operation} a Sandbox in state {state.value}")
        self.operation = operation
        self.state = state


@dataclass(frozen=True, slots=True)
class _Credential:
    """One issued task credential, held so that revocation on suspend is observable."""

    sandbox_id: str
    ports: tuple[int, ...]
    expires_at: datetime


@dataclass(slots=True)
class _Task:
    """One simulated Fargate task. Mutable, because a lifecycle is a sequence of changes."""

    sandbox_id: str
    spec: SandboxSpec
    state: SandboxState
    started_at: datetime | None
    revision: int = 1
    state_reason: str | None = None
    credential_tokens: set[str] = field(default_factory=set)

    @property
    def handle(self) -> SandboxHandle:
        # Provider-private continuation data: a stopped task starts again as a new task, so the
        # revision advances on every resume. No caller parses it, and lookups key on
        # `sandbox_id` alone so a handle held across a resume still works.
        return SandboxHandle(
            provider_name=PROVIDER_NAME,
            sandbox_id=self.sandbox_id,
            opaque={"revision": str(self.revision)},
        )

    @property
    def vcpu(self) -> int:
        return self.spec.vcpu_millis // _MILLIS_PER_VCPU

    @property
    def holds_capacity(self) -> bool:
        """Whether this task still counts against the vCPU quota.

        A suspended task does not: it is a stopped task, and a stopped task consumes no Fargate
        vCPU. That is the opposite of the anchored MicroVM ceiling, which counts suspended
        memory, and it is why `consumed_capacity()` is read together with its dimension.
        """
        return self.state not in _TERMINAL_STATES and self.state is not (
            SandboxState.SUSPENDED
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


class FargateTaskProvider(ComputeProvider):
    """Amazon ECS on AWS Fargate as a deliberately weaker Compute_Provider (R5.6).

    Args:
        clock: source of the current time, injected so credential expiry is asserted against a
            controlled clock rather than waited for.
        capacity_limit_vcpu: the vCPU quota this provider publishes and enforces. `None`
            publishes no ceiling.
        endpoint_host: host of the issued `base_url`.
        endpoint_port: port of the issued `base_url`.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = _utc_now,
        capacity_limit_vcpu: int | None = DEFAULT_CAPACITY_LIMIT_VCPU,
        endpoint_host: str = DEFAULT_ENDPOINT_HOST,
        endpoint_port: int = DEFAULT_ENDPOINT_PORT,
    ) -> None:
        if capacity_limit_vcpu is not None and capacity_limit_vcpu <= 0:
            raise ValueError("capacity_limit_vcpu must be greater than zero or None")
        self._clock = clock
        self._capacity_limit_vcpu = capacity_limit_vcpu
        self._endpoint_host = endpoint_host
        self._endpoint_port = endpoint_port
        self._tasks: dict[str, _Task] = {}
        self._credentials: dict[str, _Credential] = {}

    # ------------------------------------------------------------------ discovery

    def capabilities(self) -> ProviderCapabilities:
        """Declare the weaker capability set this exercise exists to publish.

        `suspend_fidelity=DISK_ONLY` and `fork_from_running_state=False` are the two the design
        names. `auto_resume_on_request=False` travels with the first of them: a stopped task has
        no endpoint, so there is nothing an arriving request could wake.
        """
        return ProviderCapabilities(
            suspend_fidelity=SuspendFidelity.DISK_ONLY,
            auto_resume_on_request=False,
            fork_from_running_state=False,
            # ECS Exec gives an interactive session, the task ENI takes inbound traffic, and a
            # restarted task mounts the volume it stopped with. Weaker where it is weaker, and
            # not pessimistic elsewhere: an exercise that declared everything `False` would
            # prove only that a caller can refuse everything.
            interactive_pty=True,
            inbound_port_exposure=True,
            restore_state_at_start=True,
            egress_is_policy_controlled=True,
        )

    def limits(self) -> ProviderLimits:
        return ProviderLimits(
            max_duration_seconds=MAX_DURATION_SECONDS,
            min_duration_seconds=MIN_DURATION_SECONDS,
            max_run_config_bytes=MAX_RUN_CONFIG_BYTES,
            capacity_dimension=CapacityDimension.VCPU_PER_REGION,
            capacity_limit=self._capacity_limit_vcpu,
            memory_bytes_choices=FARGATE_MEMORY_BYTES_CHOICES,
        )

    # ------------------------------------------------------------------ lifecycle

    def provision(self, spec: SandboxSpec) -> SandboxStatus:
        """Run one task for one Session, refusing what this provider cannot serve.

        A spec asking for `auto_resume` is refused by capability name before anything is
        created, which is the shape R5.6 requires of every gap: named, early, and with no
        protocol or SDK consequence.

        Raises:
            CapabilityUnsupported: the spec needs a capability this provider does not declare.
            QuotaExhausted: the published vCPU ceiling would be crossed.
            ValueError: the spec violates a published limit.
        """
        if spec.auto_resume:
            require_capability(self, "auto_resume_on_request")
        self._validate(spec)
        vcpu = spec.vcpu_millis // _MILLIS_PER_VCPU
        self._require_capacity(vcpu)
        task = _Task(
            sandbox_id=f"task-{uuid4().hex}",
            spec=spec,
            state=SandboxState.RUNNING,
            started_at=self._clock(),
        )
        self._tasks[task.sandbox_id] = task
        return self._status(task)

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(self._lookup(handle))

    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        """Stop the task, keeping its volume and discarding its memory.

        This provider *can* suspend, so this is not where a memory-preserving request fails;
        that refusal is `require_suspend_fidelity`, made before a Session is ever placed here.
        What this method does instead is be honest about the fidelity it delivered: the
        discarded memory is recorded on `state_reason`, and the task's connection credentials
        are revoked, because a stopped task has no endpoint for them to reach.
        """
        task = self._lookup(handle)
        if task.state is SandboxState.SUSPENDED:
            return self._status(task)
        if task.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("suspend", task.state)
        task.state = SandboxState.SUSPENDED
        task.state_reason = MEMORY_DISCARDED_REASON
        self._revoke_credentials(task)
        return self._status(task)

    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        """Start the task again from its volume, reacquiring the vCPU it gave up.

        Raises:
            InvalidSandboxTransition: the task is terminal.
            QuotaExhausted: the vCPU released at suspend is no longer available. Unreachable on
                a provider whose suspended Sandboxes keep holding capacity, and reachable here,
                which is precisely why capacity is a provider-reported quantity.
        """
        task = self._lookup(handle)
        if task.state is SandboxState.RUNNING:
            return self._status(task)
        if task.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("resume", task.state)
        self._require_capacity(task.vcpu)
        task.state = SandboxState.RUNNING
        task.revision += 1
        # The reason stays: the memory this Session had before its suspend is gone, and a caller
        # reading the resumed status should be able to see that it was.
        # `started_at` still records when the Sandbox first started, so cold provision and
        # resume remain two separate measurements (R10.10, R10.12).
        return self._status(task)

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Stop the task for good, releasing capacity and revoking credentials. Idempotent."""
        task = self._lookup(handle)
        if task.state in _TERMINAL_STATES:
            return self._status(task)
        task.state = SandboxState.TERMINATED
        self._revoke_credentials(task)
        return self._status(task)

    # ------------------------------------------------------------------ connection

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> ConnectionDescriptor:
        """Mint a task-scoped, port-scoped, expiring credential.

        Refused for a suspended task, and that refusal is this provider's declared
        `auto_resume_on_request=False` made concrete: there is no stopped-task endpoint to hand
        a credential for. The header name travels beside the value, so a caller copies both
        without knowing which of the three schemes it received (R9.4).

        Raises:
            InvalidSandboxTransition: the task is suspended or terminal.
            ValueError: the TTL is not positive, no port was named, or a named port is not one
                the task exposes.
        """
        task = self._lookup(handle)
        if task.state in _TERMINAL_STATES or task.state is SandboxState.SUSPENDED:
            raise InvalidSandboxTransition("issue a connection to", task.state)
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be greater than zero: {ttl_seconds}")
        if not ports:
            raise ValueError("a connection is scoped to at least one port")
        unexposed = sorted(set(ports) - set(task.spec.exposed_ports))
        if unexposed:
            raise ValueError(
                f"ports not exposed by this Sandbox: {unexposed}"
                f" (exposed: {sorted(task.spec.exposed_ports)})"
            )
        scoped_ports = tuple(sorted(set(ports)))
        expires_at = self._clock() + timedelta(seconds=ttl_seconds)
        token = secrets.token_urlsafe(32)
        self._credentials[token] = _Credential(
            sandbox_id=task.sandbox_id, ports=scoped_ports, expires_at=expires_at
        )
        task.credential_tokens.add(token)
        return ConnectionDescriptor(
            base_url=(
                f"http://{self._endpoint_host}:{self._endpoint_port}"
                f"/tasks/{task.sandbox_id}"
            ),
            auth_header_name=AUTH_HEADER_NAME,
            auth_header_value=token,
            ports=scoped_ports,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------ operations

    def consumed_capacity(self) -> int:
        """vCPU held across every running task, in `VCPU_PER_REGION` (R14.5).

        Suspended tasks are excluded, because a stopped Fargate task consumes no vCPU. A caller
        that assumed the MicroVM rule and summed the suspended ones too would over-report
        against this provider's own quota, which is the mistake the dimension exists to prevent.
        """
        return sum(task.vcpu for task in self._tasks.values() if task.holds_capacity)

    def release_check(self, handle: SandboxHandle) -> list[str]:
        """Return the identifiers of resources still allocated to a task (R10.9).

        The identifier shapes match the other two providers', so one Session_Orchestrator
        assertion covers all three. Empty for a terminated task and for one this provider never
        held, so emptiness is asserted rather than `terminate` trusted.
        """
        task = self._tasks.get(handle.sandbox_id)
        if task is None or task.state in _TERMINAL_STATES:
            return []
        outstanding = [f"sandbox/{task.sandbox_id}"]
        if task.spec.egress_attachment_ref is not None:
            outstanding.append(f"network-interface/{task.spec.egress_attachment_ref}")
        if task.credential_tokens:
            outstanding.append(f"endpoint/{task.sandbox_id}")
        return outstanding

    def discover(self, tags: Mapping[str, str]) -> list[SandboxStatus]:
        """Find tasks whose tags include every pair in `tags`, terminal ones included.

        The Reaper reaches a Sandbox whose handle was never recorded using only the Tenant and
        Session tags R11.7 requires. Terminal tasks are returned because a sweep that could not
        see a stopped task could not confirm its own work.
        """
        return [
            self._status(task)
            for task in sorted(self._tasks.values(), key=lambda t: t.sandbox_id)
            if all(task.spec.tags.get(key) == value for key, value in tags.items())
        ]

    # ------------------------------------------------------------------ internals

    def _validate(self, spec: SandboxSpec) -> None:
        if (
            not MIN_DURATION_SECONDS
            <= spec.max_duration_seconds
            <= MAX_DURATION_SECONDS
        ):
            raise ValueError(
                f"max_duration_seconds outside this provider's declared limits "
                f"[{MIN_DURATION_SECONDS}, {MAX_DURATION_SECONDS}]: "
                f"{spec.max_duration_seconds}"
            )
        if spec.idle_seconds_before_suspend <= 0:
            raise ValueError("idle_seconds_before_suspend must be greater than zero")
        if spec.suspended_seconds_before_terminate <= 0:
            raise ValueError(
                "suspended_seconds_before_terminate must be greater than zero"
            )
        if spec.memory_bytes not in FARGATE_MEMORY_BYTES_CHOICES:
            raise ValueError(
                f"memory_bytes is not one of this provider's declared choices "
                f"{list(FARGATE_MEMORY_BYTES_CHOICES)}: {spec.memory_bytes}"
            )
        if spec.vcpu_millis not in FARGATE_VCPU_MILLIS_CHOICES:
            raise ValueError(
                f"vcpu_millis is not one of this provider's declared task sizes "
                f"{list(FARGATE_VCPU_MILLIS_CHOICES)}: {spec.vcpu_millis}"
            )
        if (
            spec.start_config_ref is None
            and len(spec.start_config) > MAX_RUN_CONFIG_BYTES
        ):
            raise ValueError(
                f"start_config exceeds max_run_config_bytes "
                f"({len(spec.start_config)} > {MAX_RUN_CONFIG_BYTES}); pass it by "
                f"reference in start_config_ref instead"
            )
        out_of_range = sorted(
            port for port in spec.exposed_ports if not 1 <= port <= 65535
        )
        if out_of_range:
            raise ValueError(
                f"exposed_ports contains out-of-range ports: {out_of_range}"
            )

    def _require_capacity(self, vcpu: int) -> None:
        limit = self._capacity_limit_vcpu
        if limit is None:
            return
        if self.consumed_capacity() + vcpu > limit:
            raise QuotaExhausted(QUOTA_NAME, CapacityDimension.VCPU_PER_REGION)

    def _lookup(self, handle: SandboxHandle) -> _Task:
        if handle.provider_name != PROVIDER_NAME:
            raise UnknownSandbox(handle)
        task = self._tasks.get(handle.sandbox_id)
        if task is None:
            raise UnknownSandbox(handle)
        return task

    def _revoke_credentials(self, task: _Task) -> None:
        for token in task.credential_tokens:
            self._credentials.pop(token, None)
        task.credential_tokens.clear()

    def _status(self, task: _Task) -> SandboxStatus:
        return SandboxStatus(
            handle=task.handle,
            state=task.state,
            memory_bytes=task.spec.memory_bytes,
            started_at=task.started_at,
            state_reason=task.state_reason,
        )
