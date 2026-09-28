# kiro-classification: public
#
# The Compute_Provider seam (R5.6, R5.10).
#
# Three rules govern every name in this module, and they are what keep the seam from being
# an AWS Lambda MicroVMs interface wearing an abstraction's clothes:
#
#   1. No method and no type names a concept private to one backend. Durations, payload
#      ceilings, endpoint header names and network attachments are values or opaque data.
#   2. Every capability that plausibly differs between backends is discovered through
#      `capabilities()` and `limits()` rather than assumed by the caller.
#   3. The endpoint authentication scheme is carried as data on ConnectionDescriptor, so a
#      backend that authenticates differently changes neither the Sandbox_Protocol nor the
#      Client_SDK public interface.
#
# GPU is deliberately absent from ProviderCapabilities. R5.10 settles it: a GPU_Target is
# reached from inside a Sandbox through the Egress_Controller, which makes it a
# permitted-destination entry and an IAM denial, not a compute capability of this contract.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

__all__ = [
    "CapabilityUnsupported",
    "CapacityDimension",
    "ComputeProvider",
    "ConnectionDescriptor",
    "ProviderCapabilities",
    "ProviderLimits",
    "QuotaExhausted",
    "SandboxHandle",
    "SandboxSpec",
    "SandboxState",
    "SandboxStatus",
    "SuspendFidelity",
]


class SandboxState(Enum):
    """The lifecycle states of a Sandbox, as reported by a Compute_Provider.

    These are Sandbox states, not Session states. `ORCHESTRATING` is a state of the Session
    record rather than of a Sandbox and so maps to no member here.
    """

    PENDING = "PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUSPENDING = "SUSPENDING"
    SUSPENDED = "SUSPENDED"
    RESUMING = "RESUMING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class SuspendFidelity(Enum):
    """How much of a Sandbox survives a suspend and resume cycle."""

    NONE = "none"  # provider cannot suspend
    DISK_ONLY = "disk-only"  # disk survives, memory does not
    MEMORY_AND_DISK = "memory-and-disk"


class CapacityDimension(Enum):
    """The unit in which a provider's regional capacity ceiling is counted.

    A provider reports its own dimension rather than being forced into a memory number, so
    that `consumed_capacity()` remains meaningful for a backend whose quota is counted in
    vCPU or in Sandbox count.
    """

    MEMORY_BYTES_PER_REGION = "memory-bytes-per-region"
    VCPU_PER_REGION = "vcpu-per-region"
    SANDBOX_COUNT_PER_REGION = "sandbox-count-per-region"


@dataclass(frozen=True)
class ProviderCapabilities:
    """What a provider can do, discovered rather than assumed.

    A caller that needs a capability a provider does not declare receives
    `CapabilityUnsupported` at the Control_Plane, before any Sandbox is provisioned.
    """

    suspend_fidelity: SuspendFidelity
    auto_resume_on_request: bool
    fork_from_running_state: bool
    interactive_pty: bool
    inbound_port_exposure: bool
    restore_state_at_start: bool
    egress_is_policy_controlled: bool


@dataclass(frozen=True)
class ProviderLimits:
    """The numeric ceilings a provider publishes.

    The Control_Plane builds its duration-ceiling rejection message from
    `max_duration_seconds` rather than from a constant of its own (R6.5), and keys the
    oversized-configuration path off `max_run_config_bytes` (R7.11).
    """

    max_duration_seconds: int
    min_duration_seconds: int
    max_run_config_bytes: int  # payload the provider will carry to start hooks
    capacity_dimension: CapacityDimension
    capacity_limit: int | None  # None when the provider does not publish one
    memory_bytes_choices: tuple[int, ...]


@dataclass(frozen=True)
class SandboxSpec:
    """Everything a provider needs in order to provision one Sandbox for one Session."""

    session_id: str
    tenant_id: str
    image_ref: str
    memory_bytes: int
    vcpu_millis: int
    max_duration_seconds: int
    idle_seconds_before_suspend: int
    suspended_seconds_before_terminate: int
    auto_resume: bool
    exposed_ports: tuple[int, ...]
    execution_role_arn: str
    # Opaque provider-side network attachment identity. Never parsed by a caller.
    egress_attachment_ref: str | None
    egress_endpoint: str  # NLB proxy DNS for https_proxy env injection in the runtime
    start_config: bytes  # serialised per-Session config
    start_config_ref: str | None  # State_Store reference used when config is oversized
    tags: dict[str, str]
    # S3 Files persistent storage params — only set when persistence=true
    s3files_filesystem_id: str = ""
    s3files_access_point_id: str = ""
    s3files_mount_target_ip: str = ""


@dataclass(frozen=True)
class SandboxHandle:
    """The reference by which a provisioned Sandbox is addressed again.

    `opaque` is provider-private continuation data. No caller parses it, which is what
    keeps backend-specific identity out of the contract.
    """

    provider_name: str
    sandbox_id: str
    opaque: dict[str, str]  # provider-private continuation data


@dataclass(frozen=True)
class SandboxStatus:
    """The observed state of one Sandbox, returned by every lifecycle method."""

    handle: SandboxHandle
    state: SandboxState
    memory_bytes: int
    started_at: datetime | None
    state_reason: str | None


@dataclass(frozen=True)
class ConnectionDescriptor:
    """A Sandbox-scoped, port-scoped, expiring connection credential.

    The authentication scheme is data: the header name travels beside its value, so a
    provider using a bearer token instead supplies that, and the Client_SDK copies the
    header name and value it was given without branching on either (R9.4).
    """

    base_url: str
    auth_header_name: str  # e.g. "X-aws-proxy-auth"
    auth_header_value: str
    ports: tuple[int, ...]
    expires_at: datetime


class QuotaExhausted(Exception):
    """Raised when a provider refuses to provision because a service quota is exhausted.

    The exhausted quota name and its dimension are carried on the exception so that the
    reason recorded against the Session, and returned to the caller, is provider-supplied
    rather than hardcoded by the Control_Plane (R6.8, R6.14).
    """

    def __init__(self, quota_name: str, dimension: CapacityDimension) -> None:
        super().__init__(
            f"quota {quota_name!r} exhausted in dimension {dimension.value}"
        )
        self.quota_name = quota_name
        self.dimension = dimension


class CapabilityUnsupported(Exception):
    """Raised when a request needs a capability the selected provider does not declare.

    This failure is the seam working: the request is refused by name, and no
    Sandbox_Protocol message and no Client_SDK signature changes to accommodate the
    weaker backend.
    """

    def __init__(self, capability: str, provider_name: str) -> None:
        super().__init__(f"provider {provider_name!r} does not support {capability!r}")
        self.capability = capability
        self.provider_name = provider_name


class ComputeProvider(ABC):
    """The contract a Compute_Provider satisfies.

    An additional provider is registered by implementing this class and adding it to the
    registry, with no change to the Sandbox_Protocol and no change to the Client_SDK
    public interface (R5.6).
    """

    name: str

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """Return what this provider can do."""
        ...

    @abstractmethod
    def limits(self) -> ProviderLimits:
        """Return the numeric ceilings this provider publishes."""
        ...

    @abstractmethod
    def provision(self, spec: SandboxSpec) -> SandboxStatus:
        """Create a Sandbox for one Session.

        Raises:
            QuotaExhausted: the backend refused because a service quota is exhausted.
            CapabilityUnsupported: the spec needs a capability this provider lacks.
        """
        ...

    @abstractmethod
    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        """Return the current observed state of a Sandbox."""
        ...

    @abstractmethod
    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        """Suspend a Sandbox at this provider's declared suspend fidelity.

        Raises:
            CapabilityUnsupported: this provider declares `SuspendFidelity.NONE`.
        """
        ...

    @abstractmethod
    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        """Resume a suspended Sandbox."""
        ...

    @abstractmethod
    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Terminate a Sandbox. Idempotent on an already terminal Sandbox."""
        ...

    @abstractmethod
    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> ConnectionDescriptor:
        """Mint a Sandbox-scoped, port-scoped connection credential that expires."""
        ...

    @abstractmethod
    def consumed_capacity(self) -> int:
        """Return capacity currently consumed, in the unit `limits().capacity_dimension` names.

        R14.5 requires an emitted metric for capacity held across running and suspended
        Sandboxes so an operator watches it against the regional quota rather than meeting
        it as a provisioning failure.
        """
        ...

    @abstractmethod
    def release_check(self, handle: SandboxHandle) -> list[str]:
        """Return the identifiers of resources still allocated to a terminated Sandbox.

        R10.9 requires confirmation that no Sandbox, network interface or endpoint remains
        allocated. Returning the outstanding identifiers lets the Session_Orchestrator
        assert emptiness rather than trust that `terminate` succeeded.
        """
        ...

    @abstractmethod
    def discover(self, tags: dict[str, str]) -> list[SandboxStatus]:
        """Find Sandboxes by tag, without a recorded handle.

        The Reaper needs this to reach a Sandbox whose handle was never recorded, using
        only the Tenant and Session tags that R11.7 requires on every Sandbox.
        """
        ...
