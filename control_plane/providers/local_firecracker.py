# kiro-classification: public
"""The `local-firecracker` Compute_Provider: the one the offline suite provisions against.

R15.9 requires an automated test suite that runs with no deployed AWS resources. Protocol,
lifecycle and allocation behaviour all need a Sandbox to exist, so the suite needs a provider
that produces one without calling AWS. This is that provider.

Three decisions shape it, and each is a decision about fidelity rather than convenience:

  1. **It declares the same capability set as the isolation provider.** An offline run therefore
     takes the same branches a deployed run takes. A provider that quietly declared, say,
     `auto_resume_on_request=False` would make every offline test pass through a code path no
     deployment uses, and the suite would be measuring itself.
  2. **It publishes a small, finite `capacity_limit`.** That is the one place it deliberately
     differs in *value* from the isolation provider, and the reason is R6.8 and R6.14: the
     quota-exhaustion path has to be reachable offline, deterministically, in a handful of
     Sandboxes rather than by allocating a Region's worth of memory. Suspended Sandboxes keep
     consuming it, which mirrors the anchored fact that the ceiling counts running and
     suspended capacity together.
  3. **Its connection credential authenticates through `Authorization: Bearer`.** The isolation
     provider uses a provider-specific header. Carrying a different scheme here is what proves
     the claim in the design's mapping table: the header name is data on
     :class:`ConnectionDescriptor`, so neither the Sandbox_Protocol nor the Client_SDK changes
     when the scheme does (R9.4).

It is **not** an isolation boundary, and :mod:`control_plane.providers.registry` refuses to
register it: `local-firecracker` is absent from `ISOLATION_APPROVED`, so it can only be
constructed directly, which is what keeps it away from Untrusted_Code. Nothing in this module
imports the registry, and nothing calls `register`.

What it does not simulate is as deliberate as what it does. There is no boot delay, because
there is no machine to boot and a sleep would only slow the suite; readiness is gated by the
Sandbox_Runtime's `/run` hook rather than by a provider state. There is no idle timer either:
`idle_seconds_before_suspend` and `suspended_seconds_before_terminate` are recorded on the
Sandbox and acted on by the Session_Orchestrator, and a provider that suspended itself on a
wall-clock timer would hide the orchestration the offline suite is there to assert.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import uuid4

from control_plane.providers.base import (
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
    "AUTH_SCHEME",
    "DEFAULT_CAPACITY_LIMIT_BYTES",
    "DEFAULT_ENDPOINT_HOST",
    "DEFAULT_ENDPOINT_PORT",
    "LOCAL_MEMORY_BYTES_CHOICES",
    "MAX_DURATION_SECONDS",
    "MAX_RUN_CONFIG_BYTES",
    "MIN_DURATION_SECONDS",
    "PROVIDER_NAME",
    "QUOTA_NAME",
    "InvalidSandboxTransition",
    "LocalFirecrackerProvider",
    "UnknownSandbox",
]

PROVIDER_NAME: Final = "local-firecracker"

# Mirrors the isolation provider's ceiling, so an offline assertion on R6.5's rejection message
# reads the same number a deployed one does. It is a value on this provider, not a constant the
# Control_Plane holds.
MAX_DURATION_SECONDS: Final = 28_800
MIN_DURATION_SECONDS: Final = 1

# The payload this provider will carry to a start hook. Above it, a caller passes
# `SandboxSpec.start_config_ref` instead (R7.11).
MAX_RUN_CONFIG_BYTES: Final = 16_384

_GIB: Final = 1_073_741_824
LOCAL_MEMORY_BYTES_CHOICES: Final = (
    1 * _GIB,
    2 * _GIB,
    4 * _GIB,
    8 * _GIB,
    16 * _GIB,
)

# Small on purpose: 32 GiB is two 16 GiB Sandboxes, so a generator drawing memory sizes whose sum
# crosses the quota does so within a handful of examples.
DEFAULT_CAPACITY_LIMIT_BYTES: Final = 32 * _GIB

# Provider-supplied, so the reason recorded against a Session is this provider's name for its own
# quota rather than a string the Control_Plane invented (R6.8, R6.14).
QUOTA_NAME: Final = "LocalSandboxMemoryPerRegion"

# A different scheme from the isolation provider's, on purpose. See the module docstring.
AUTH_HEADER_NAME: Final = "Authorization"
AUTH_SCHEME: Final = "Bearer"

# Loopback stays reachable under the offline suite's network guard, so an endpoint URL that names
# it is one a local stub can actually serve.
DEFAULT_ENDPOINT_HOST: Final = "127.0.0.1"
DEFAULT_ENDPOINT_PORT: Final = 8081

_TERMINAL_STATES: Final = frozenset({SandboxState.TERMINATED, SandboxState.FAILED})


class UnknownSandbox(LookupError):
    """Raised when a handle names no Sandbox this provider instance holds.

    A `LookupError` for the same reason the registry raises one on an unregistered name: the
    caller asked for something that was never there, which is a lookup failure and not a
    lifecycle failure.
    """

    def __init__(self, handle: SandboxHandle) -> None:
        super().__init__(
            f"no Sandbox {handle.sandbox_id!r} from provider "
            f"{handle.provider_name!r} is held by {PROVIDER_NAME}"
        )
        self.handle = handle


class InvalidSandboxTransition(ValueError):
    """Raised when an operation is asked of a Sandbox whose state cannot serve it.

    Distinct from `CapabilityUnsupported`: the provider *can* suspend, resume and issue
    credentials; this Sandbox is simply in a state from which that operation has no meaning.
    """

    def __init__(self, operation: str, state: SandboxState) -> None:
        super().__init__(f"cannot {operation} a Sandbox in state {state.value}")
        self.operation = operation
        self.state = state


@dataclass(frozen=True, slots=True)
class _Credential:
    """One issued connection credential, held so that its scope and expiry are checkable."""

    sandbox_id: str
    ports: tuple[int, ...]
    expires_at: datetime


@dataclass(slots=True)
class _Sandbox:
    """One simulated Sandbox. Mutable, because a lifecycle is a sequence of state changes."""

    sandbox_id: str
    spec: SandboxSpec
    state: SandboxState
    started_at: datetime | None
    incarnation: int = 1
    state_reason: str | None = None
    credential_tokens: set[str] = field(default_factory=set)

    @property
    def handle(self) -> SandboxHandle:
        # `incarnation` is provider-private continuation data: it advances on every resume and
        # no caller parses it. Lookups key on `sandbox_id` alone, so a caller holding a handle
        # from before a resume is not punished for it.
        return SandboxHandle(
            provider_name=PROVIDER_NAME,
            sandbox_id=self.sandbox_id,
            opaque={"incarnation": str(self.incarnation)},
        )

    @property
    def holds_capacity(self) -> bool:
        """Whether this Sandbox still counts against the quota.

        Every non-terminal state does, which is the point: a suspended Sandbox that stopped
        counting would make the offline quota arithmetic disagree with the deployed ceiling.
        """
        return self.state not in _TERMINAL_STATES


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LocalFirecrackerProvider(ComputeProvider):
    """An in-process Compute_Provider for the offline suite (R15.9).

    Args:
        clock: source of the current time, injected so lifecycle and credential-expiry
            assertions are made against a controlled clock rather than a real one.
        capacity_limit_bytes: the quota this provider publishes and enforces. `None` publishes
            no ceiling, which is how a test that does not care about quota avoids tripping it.
        endpoint_host: host of the issued `base_url`. Loopback by default.
        endpoint_port: port of the issued `base_url`.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = _utc_now,
        capacity_limit_bytes: int | None = DEFAULT_CAPACITY_LIMIT_BYTES,
        endpoint_host: str = DEFAULT_ENDPOINT_HOST,
        endpoint_port: int = DEFAULT_ENDPOINT_PORT,
    ) -> None:
        if capacity_limit_bytes is not None and capacity_limit_bytes <= 0:
            raise ValueError("capacity_limit_bytes must be greater than zero or None")
        self._clock = clock
        self._capacity_limit_bytes = capacity_limit_bytes
        self._endpoint_host = endpoint_host
        self._endpoint_port = endpoint_port
        self._sandboxes: dict[str, _Sandbox] = {}
        self._credentials: dict[str, _Credential] = {}

    # ------------------------------------------------------------------ discovery

    def capabilities(self) -> ProviderCapabilities:
        """Declare the isolation provider's capability set, so offline runs take live branches."""
        return ProviderCapabilities(
            suspend_fidelity=SuspendFidelity.MEMORY_AND_DISK,
            auto_resume_on_request=True,
            fork_from_running_state=False,
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
            capacity_dimension=CapacityDimension.MEMORY_BYTES_PER_REGION,
            capacity_limit=self._capacity_limit_bytes,
            memory_bytes_choices=LOCAL_MEMORY_BYTES_CHOICES,
        )

    # ------------------------------------------------------------------ lifecycle

    def provision(self, spec: SandboxSpec) -> SandboxStatus:
        """Create one simulated Sandbox, enforcing every limit this provider publishes.

        The limits are enforced rather than assumed so that a caller which skipped a validation
        R6.5 or R7.11 requires fails here, offline, instead of in a deployment.

        Raises:
            QuotaExhausted: the published capacity ceiling would be crossed.
            ValueError: the spec violates a published limit.
        """
        self._validate(spec)
        self._require_capacity(spec.memory_bytes)
        sandbox = _Sandbox(
            sandbox_id=f"sbx-{uuid4().hex}",
            spec=spec,
            state=SandboxState.RUNNING,
            started_at=self._clock(),
        )
        self._sandboxes[sandbox.sandbox_id] = sandbox
        return self._status(sandbox)

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(self._lookup(handle))

    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        sandbox = self._lookup(handle)
        if sandbox.state is SandboxState.SUSPENDED:
            return self._status(sandbox)
        if sandbox.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("suspend", sandbox.state)
        sandbox.state = SandboxState.SUSPENDED
        # Credentials survive: this provider declares `auto_resume_on_request`, so a request
        # arriving on an existing credential is exactly what resumes the Sandbox.
        return self._status(sandbox)

    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        sandbox = self._lookup(handle)
        if sandbox.state is SandboxState.RUNNING:
            return self._status(sandbox)
        if sandbox.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("resume", sandbox.state)
        sandbox.state = SandboxState.RUNNING
        sandbox.incarnation += 1
        # `started_at` is when this Sandbox started, not when it last resumed. Overwriting it
        # would make a resumed Sandbox indistinguishable from a freshly provisioned one, and the
        # design keeps cold-provision and resume latency as two separate metrics (R10.10, R10.12).
        return self._status(sandbox)

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Terminate a Sandbox, releasing its capacity and revoking its credentials."""
        sandbox = self._lookup(handle)
        if sandbox.state in _TERMINAL_STATES:
            return self._status(sandbox)
        sandbox.state = SandboxState.TERMINATED
        self._revoke_credentials(sandbox)
        return self._status(sandbox)

    # ------------------------------------------------------------------ connection

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> ConnectionDescriptor:
        """Mint a Sandbox-scoped, port-scoped, expiring credential.

        Raises:
            InvalidSandboxTransition: the Sandbox is terminal, so no credential can reach it.
            ValueError: the TTL is not positive, or a requested port is not an exposed one.
        """
        sandbox = self._lookup(handle)
        if sandbox.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("issue a connection to", sandbox.state)
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be greater than zero: {ttl_seconds}")
        if not ports:
            raise ValueError("a connection is scoped to at least one port")
        unexposed = sorted(set(ports) - set(sandbox.spec.exposed_ports))
        if unexposed:
            raise ValueError(
                f"ports not exposed by this Sandbox: {unexposed}"
                f" (exposed: {sorted(sandbox.spec.exposed_ports)})"
            )
        scoped_ports = tuple(sorted(set(ports)))
        expires_at = self._clock() + timedelta(seconds=ttl_seconds)
        token = secrets.token_urlsafe(32)
        self._credentials[token] = _Credential(
            sandbox_id=sandbox.sandbox_id,
            ports=scoped_ports,
            expires_at=expires_at,
        )
        sandbox.credential_tokens.add(token)
        return ConnectionDescriptor(
            base_url=(
                f"http://{self._endpoint_host}:{self._endpoint_port}"
                f"/sandboxes/{sandbox.sandbox_id}"
            ),
            auth_header_name=AUTH_HEADER_NAME,
            auth_header_value=f"{AUTH_SCHEME} {token}",
            ports=scoped_ports,
            expires_at=expires_at,
        )

    def resolve_connection(
        self, auth_header_value: str, port: int, at: datetime | None = None
    ) -> SandboxHandle | None:
        """Return the Sandbox a credential admits, or `None` when it admits nothing.

        Not part of the Compute_Provider contract; the deployed backend does this inside its own
        endpoint. It exists here because "Sandbox-scoped, port-scoped and expiring" is otherwise
        a claim the offline suite cannot check, and an unchecked credential is a decorative one.
        """
        now = self._clock() if at is None else at
        scheme, _, token = auth_header_value.partition(" ")
        if scheme != AUTH_SCHEME or not token:
            return None
        credential = self._credentials.get(token)
        if credential is None or port not in credential.ports:
            return None
        if credential.expires_at <= now:
            return None
        sandbox = self._sandboxes.get(credential.sandbox_id)
        if sandbox is None or sandbox.state in _TERMINAL_STATES:
            return None
        return sandbox.handle

    # ------------------------------------------------------------------ operations

    def consumed_capacity(self) -> int:
        """Memory held across every non-terminal Sandbox, in `MEMORY_BYTES_PER_REGION` (R14.5)."""
        return sum(
            sandbox.spec.memory_bytes
            for sandbox in self._sandboxes.values()
            if sandbox.holds_capacity
        )

    def release_check(self, handle: SandboxHandle) -> list[str]:
        """Return the identifiers of resources still allocated to a Sandbox (R10.9).

        Empty for a terminated Sandbox and for one this provider never held, so the
        Session_Orchestrator asserts emptiness rather than trusting that `terminate` succeeded.
        """
        sandbox = self._sandboxes.get(handle.sandbox_id)
        if sandbox is None or not sandbox.holds_capacity:
            return []
        outstanding = [f"sandbox/{sandbox.sandbox_id}"]
        if sandbox.spec.egress_attachment_ref is not None:
            outstanding.append(
                f"network-interface/{sandbox.spec.egress_attachment_ref}"
            )
        if sandbox.credential_tokens:
            outstanding.append(f"endpoint/{sandbox.sandbox_id}")
        return outstanding

    def discover(self, tags: Mapping[str, str]) -> list[SandboxStatus]:
        """Find Sandboxes whose tags include every pair in `tags`, terminal ones included.

        Terminal Sandboxes are returned rather than filtered out because the Reaper's question is
        what state a Sandbox is in, and a sweep that could not see a terminated one could not
        confirm its own work.
        """
        return [
            self._status(sandbox)
            for sandbox in sorted(self._sandboxes.values(), key=lambda s: s.sandbox_id)
            if all(sandbox.spec.tags.get(key) == value for key, value in tags.items())
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
        if spec.memory_bytes not in LOCAL_MEMORY_BYTES_CHOICES:
            raise ValueError(
                f"memory_bytes is not one of this provider's declared choices "
                f"{list(LOCAL_MEMORY_BYTES_CHOICES)}: {spec.memory_bytes}"
            )
        if len(spec.start_config) > MAX_RUN_CONFIG_BYTES:
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

    def _require_capacity(self, memory_bytes: int) -> None:
        limit = self._capacity_limit_bytes
        if limit is None:
            return
        if self.consumed_capacity() + memory_bytes > limit:
            raise QuotaExhausted(QUOTA_NAME, CapacityDimension.MEMORY_BYTES_PER_REGION)

    def _lookup(self, handle: SandboxHandle) -> _Sandbox:
        if handle.provider_name != PROVIDER_NAME:
            raise UnknownSandbox(handle)
        sandbox = self._sandboxes.get(handle.sandbox_id)
        if sandbox is None:
            raise UnknownSandbox(handle)
        return sandbox

    def _revoke_credentials(self, sandbox: _Sandbox) -> None:
        for token in sandbox.credential_tokens:
            self._credentials.pop(token, None)
        sandbox.credential_tokens.clear()

    def _status(self, sandbox: _Sandbox) -> SandboxStatus:
        return SandboxStatus(
            handle=sandbox.handle,
            state=sandbox.state,
            memory_bytes=sandbox.spec.memory_bytes,
            started_at=sandbox.started_at,
            state_reason=sandbox.state_reason,
        )
