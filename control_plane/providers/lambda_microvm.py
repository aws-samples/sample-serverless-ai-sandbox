# kiro-classification: public
"""The `lambda-microvm` Compute_Provider: AWS Lambda MicroVMs behind the seam (R5.6).

This is the deployment's isolation boundary and the only name in `ISOLATION_APPROVED`. Its job
is narrow and worth stating precisely: it maps the anchored Lambda MicroVMs facts onto the
Compute_Provider contract, and it leaves every one of them on this side of the seam.

The mapping, exactly as the design's table fixes it:

===============================================  ==================================================
Anchored fact                                    Where it lands
===============================================  ==================================================
1 to 28,800 s ``maximumDurationInSeconds``       :data:`MIN_DURATION_SECONDS`,
                                                 :data:`MAX_DURATION_SECONDS`, published through
                                                 ``limits()`` so R6.5's rejection message is built
                                                 from a provider value rather than a Control_Plane
                                                 constant
``autoResumeEnabled``,                           `SandboxSpec.auto_resume`,
``maxIdleDurationSeconds``,                      `idle_seconds_before_suspend`,
``suspendedDurationSeconds``                     `suspended_seconds_before_terminate`
Dedicated HTTPS endpoint, port-scoped JWE in     :data:`AUTH_HEADER_NAME` and the token, both as
the ``X-aws-proxy-auth`` header                  data on `ConnectionDescriptor`
``runHookPayload`` capped at 16 KB               :data:`MAX_RUN_CONFIG_BYTES`, with
                                                 `SandboxSpec.start_config_ref` as the overflow
                                                 path (R7.11)
Network connector, fixed while running           `SandboxSpec.egress_attachment_ref`, passed
                                                 through and never parsed
Quota on total memory across ``RUNNING`` and     ``MEMORY_BYTES_PER_REGION`` plus
``SUSPENDED`` per Region                         `consumed_capacity` (R14.5)
Firecracker, one MicroVM per Session             Not represented at all. Isolation strength is a
                                                 deployment decision made in the registry's
                                                 allowlist, not a field a provider sets
===============================================  ==================================================

Four implementation decisions are worth the reader's attention.

**The endpoint authentication scheme is opaque descriptor data.** `issue_connection` returns the
JWE the service minted as `ConnectionDescriptor.auth_header_value` and the header name beside it.
Nothing here parses the token, and no Sandbox_Protocol message or Client_SDK signature names
either, which is what keeps `local-firecracker`'s `Authorization: Bearer` and this provider's
`X-aws-proxy-auth` interchangeable to a caller (R9.4).

**The AWS client is injected and, when it is not, built lazily.** Importing this module must not
construct a boto3 client: the offline suite imports it with no credentials, no configured Region
and no egress (R15.9), and a client built at import time would need all three. The client surface
is stated once, as :class:`MicroVmClient`, so the set of API operations this provider depends on
is auditable in one place and a stub in a test implements the same shape a deployment calls.

**Published limits are enforced here, before the call.** A caller that skipped a validation R6.5
or R7.11 requires fails locally with a message naming the limit, rather than by a remote error
whose wording is not ours. The service remains the authority on capacity: a quota refusal is
translated into `QuotaExhausted` carrying this provider's own quota name, so the reason recorded
against the Session is provider-supplied (R6.8, R6.14).

**Lifecycle transitions read before they write.** `suspend`, `resume` and `terminate` describe
first and return unchanged on a Sandbox already in the target state, so they are idempotent and
so their semantics match `local-firecracker`'s to the letter. That parity is the point: an
offline assertion about lifecycle behaviour is worth something only if the deployed provider
behaves the same way. It costs one extra API call per transition, which is the right trade
against a divergence the offline suite could not see.

The provider is admitted to the registry by an explicit `register` call in
:mod:`control_plane.providers` — this module has no import side effect, so a test may construct
it freely without mutating deployment-global state.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

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
    "MAX_DURATION_SECONDS",
    "MAX_RUN_CONFIG_BYTES",
    "MICROVM_MEMORY_CHOICES",
    "MIN_DURATION_SECONDS",
    "PROVIDER_NAME",
    "QUOTA_CODE_UNIT_BYTES",
    "QUOTA_NAME",
    "QUOTA_SERVICE_CODE",
    "InvalidSandboxTransition",
    "LambdaMicroVmProvider",
    "MicroVmClient",
    "MissingNetworkConnector",
    "ServiceQuotasClient",
    "UnknownSandbox",
    "UnrecognisedSandboxState",
]

PROVIDER_NAME: Final = "lambda-microvm"

# The anchored `maximumDurationInSeconds` range. R6.5's error message is built from the upper
# bound as a published value, which is why it lives here and not in the Control_Plane.
MAX_DURATION_SECONDS: Final = 28_800
MIN_DURATION_SECONDS: Final = 1

# The anchored `runHookPayload` ceiling. Above it a caller passes `start_config_ref` (R7.11).
MAX_RUN_CONFIG_BYTES: Final = 16_384

_MIB: Final = 1_048_576
_GIB: Final = 1_073_741_824

# The configurable MicroVM sizes, taken from the anchored endpoint-bandwidth table, which runs
# from 0.5 GB / 0.25 vCPU to 8 GB / 4 vCPU.
MICROVM_MEMORY_CHOICES: Final = (
    512 * _MIB,
    1 * _GIB,
    2 * _GIB,
    4 * _GIB,
    8 * _GIB,
)

# The anchored endpoint authentication scheme. A name and a value, both data on the descriptor.
AUTH_HEADER_NAME: Final = "X-aws-proxy-auth"

# Provider-supplied, so a quota refusal names this provider's quota rather than a string the
# Control_Plane invented (R6.8, R6.14).
QUOTA_NAME: Final = "MicroVMMemoryPerRegion"

# Where the published ceiling is read from, when a deployment configures the quota code. Service
# Quotas reports this quota in GiB; a deployment whose quota reports another unit configures the
# multiplier rather than editing this module.
QUOTA_SERVICE_CODE: Final = "lambda"
QUOTA_CODE_UNIT_BYTES: Final = _GIB

# The states the anchored quota counts, and therefore the states R14.5's metric sums over. The
# transitional states are excluded deliberately: the number an operator compares against the
# Region quota has to be the number the quota itself counts.
_CAPACITY_HOLDING_STATES: Final = frozenset(
    {SandboxState.RUNNING, SandboxState.SUSPENDED}
)

_TERMINAL_STATES: Final = frozenset({SandboxState.TERMINATED, SandboxState.FAILED})

# Service error codes this provider translates. Everything else propagates unchanged: a
# provider that swallowed an unrecognised failure would report a healthy Sandbox that is not.
_QUOTA_ERROR_CODES: Final = frozenset(
    {
        "ServiceQuotaExceededException",
        "ResourceLimitExceededException",
        "LimitExceededException",
    }
)
_NOT_FOUND_ERROR_CODES: Final = frozenset({"ResourceNotFoundException"})


class MicroVmClient(Protocol):
    """The MicroVM API surface this provider depends on, stated once.

    Field names follow the anchored request shape (`maximumDurationInSeconds`,
    `autoResumeEnabled`, `maxIdleDurationSeconds`, `suspendedDurationSeconds`,
    `runHookPayload`). Keeping the surface in one Protocol means a stub in the offline suite
    implements exactly what a deployment calls, and a change to the API is one edit here.
    """

    def create_micro_vm(self, **request: Any) -> Mapping[str, Any]: ...

    def get_micro_vm(self, **request: Any) -> Mapping[str, Any]: ...

    def suspend_micro_vm(self, **request: Any) -> Mapping[str, Any]: ...

    def resume_micro_vm(self, **request: Any) -> Mapping[str, Any]: ...

    def terminate_micro_vm(self, **request: Any) -> Mapping[str, Any]: ...

    def list_micro_vms(self, **request: Any) -> Mapping[str, Any]: ...

    def create_micro_vm_endpoint_token(self, **request: Any) -> Mapping[str, Any]: ...


class ServiceQuotasClient(Protocol):
    """The one Service Quotas operation this provider reads its published ceiling from."""

    def get_service_quota(self, **request: Any) -> Mapping[str, Any]: ...


class UnknownSandbox(LookupError):
    """Raised when a handle names no MicroVM the service knows.

    A `LookupError` for the same reason the registry raises one on an unregistered name, and
    the same type `local-firecracker` raises, so a caller handles both providers with one
    `except` clause.
    """

    def __init__(self, handle: SandboxHandle) -> None:
        super().__init__(
            f"no Sandbox {handle.sandbox_id!r} from provider "
            f"{handle.provider_name!r} is known to {PROVIDER_NAME}"
        )
        self.handle = handle


class InvalidSandboxTransition(ValueError):
    """Raised when an operation is asked of a Sandbox whose state cannot serve it.

    Distinct from `CapabilityUnsupported`: this provider *can* suspend, resume and issue
    credentials; the Sandbox is simply in a state from which the operation has no meaning.
    """

    def __init__(self, operation: str, state: SandboxState) -> None:
        super().__init__(f"cannot {operation} a Sandbox in state {state.value}")
        self.operation = operation
        self.state = state


class MissingNetworkConnector(ValueError):
    """Raised when a spec carries no network attachment reference, which would be open egress.

    A MicroVM's default is public internet access, and a connector replaces that default rather
    than restricting an already-closed path, so `egress_attachment_ref=None` provisions a Sandbox
    with unrestricted internet and no Egress_Controller in front of it (R12.2, R12.3, R12.6,
    R12.8). `None` stays legitimate on the seam, for a provider that governs egress by other
    means; it is not legitimate here, so the refusal sits in this adapter.

    A `ValueError` because it is a malformed spec, alongside every other refusal `_validate`
    raises, and not `CapabilityUnsupported`: this provider does declare policy-controlled egress,
    and naming a capability would send an operator looking for a provider that supports the thing
    being refused.
    """

    def __init__(self) -> None:
        super().__init__(
            f"{PROVIDER_NAME} refuses to provision without egress_attachment_ref: a MicroVM "
            "with no network connector attached has unrestricted internet access, so the "
            "deployment must supply the Egress_Controller's connector"
        )


class UnrecognisedSandboxState(ValueError):
    """Raised when the service reports a lifecycle state this provider cannot map.

    Fail closed rather than guess. Lifecycle state drives suspend, resume, termination and
    reaping decisions, so mapping an unknown value onto a plausible neighbour would let a
    wrong decision be taken quietly, which is worse than a loud refusal.
    """

    def __init__(self, reported: str) -> None:
        super().__init__(
            f"{PROVIDER_NAME} reported the unrecognised Sandbox state {reported!r}"
        )
        self.reported = reported


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _sandbox_state(reported: object) -> SandboxState:
    """Map a service-reported state onto the seam's state, or refuse."""
    if reported is None:
        # The service may return null during a transition (suspend/resume in progress).
        # Default to PENDING; callers that know the expected transition override this.
        return SandboxState.PENDING
    if isinstance(reported, SandboxState):
        return reported
    try:
        return SandboxState(str(reported))
    except ValueError:
        raise UnrecognisedSandboxState(str(reported)) from None


def _as_datetime(value: object) -> datetime | None:
    """Read a timestamp the service may return as a datetime or as an ISO-8601 string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    raise TypeError(f"cannot read a timestamp from {type(value).__name__}")


def _error_code(exc: BaseException) -> str | None:
    """Return the AWS error code carried on a client error, without importing botocore.

    Reading the code off the exception rather than catching a concrete botocore type keeps
    this module free of an untyped AWS SDK import and lets an offline stub raise an error of
    the same shape.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            code = error.get("Code")
            if isinstance(code, str):
                return code
    return None


class LambdaMicroVmProvider(ComputeProvider):
    """AWS Lambda MicroVMs as one implementation of the Compute_Provider contract.

    Args:
        client: the MicroVM API client. Built lazily from boto3 when omitted, so importing
            this module needs neither credentials nor a Region.
        quotas_client: the Service Quotas client used to read the published ceiling. Built
            lazily from boto3 when omitted, and consulted only when `memory_quota_code` is
            configured.
        memory_quota_code: the Service Quotas quota code for the Region memory quota. Until a
            deployment supplies it, `limits().capacity_limit` is `None`: the provider declines
            to publish a ceiling it has not read, and the service stays the enforcer.
        region_name: the Region for lazily built clients. `None` defers to the ambient
            configuration boto3 would use.
        clock: source of the current time, injected so credential expiry is asserted against
            a controlled clock rather than a real one.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        client: MicroVmClient | None = None,
        quotas_client: ServiceQuotasClient | None = None,
        memory_quota_code: str | None = None,
        region_name: str | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._client = client
        self._quotas_client = quotas_client
        self._memory_quota_code = memory_quota_code
        self._region_name = region_name
        self._clock = clock
        self._quota_bytes: int | None = None
        self._quota_read = False

    # ------------------------------------------------------------------ discovery

    def capabilities(self) -> ProviderCapabilities:
        """Declare the anchored MicroVM capability set.

        `fork_from_running_state` is `False` because the anchored facts offer no fork: it is a
        recorded capability gap versus E2B, not something this provider can claim.
        """
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
            capacity_limit=self._region_memory_quota(),
            memory_bytes_choices=MICROVM_MEMORY_CHOICES,
        )

    # ------------------------------------------------------------------ lifecycle

    def provision(self, spec: SandboxSpec) -> SandboxStatus:
        """Create one MicroVM for one Session.

        Raises:
            QuotaExhausted: the service refused because the Region memory quota is exhausted.
            MissingNetworkConnector: the spec names no connector, so the Sandbox would have
                unrestricted internet access.
            ValueError: the spec violates a limit this provider publishes.
        """
        self._validate(spec)
        request: dict[str, Any] = {
            "imageIdentifier": spec.image_ref,
            "maximumDurationInSeconds": spec.max_duration_seconds,
            "idlePolicy": {
                "autoResumeEnabled": spec.auto_resume,
                "maxIdleDurationSeconds": spec.idle_seconds_before_suspend,
                "suspendedDurationSeconds": spec.suspended_seconds_before_terminate,
            },
            "executionRoleArn": spec.execution_role_arn,
            # Opaque: the fixed pipe, never parsed here. `RunMicrovm` spells this
            # `egressNetworkConnectors` and takes a list of 0 to 10 connector ARNs, and one
            # connector is reused across many MicroVMs, so a generation is one element.
            "egressNetworkConnectors": [spec.egress_attachment_ref],
            "runHookPayload": _run_hook_payload(spec).decode("utf-8"),
        }
        with self._translated_errors():
            payload = self._micro_vms.create_micro_vm(**request)
        return self._status(payload, fallback_memory_bytes=spec.memory_bytes)

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(self._get(handle), handle=handle)

    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        status = self.describe(handle)
        if status.state is SandboxState.SUSPENDED:
            return status
        if status.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("suspend", status.state)
        with self._translated_errors(handle):
            payload = self._micro_vms.suspend_micro_vm(microVmId=handle.sandbox_id)
        result = self._status(payload, handle=handle)
        # The service may return null state during transition; treat as SUSPENDING.
        if result.state is SandboxState.PENDING:
            from dataclasses import replace
            result = replace(result, state=SandboxState.SUSPENDING)
        return result

    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        status = self.describe(handle)
        if status.state is SandboxState.RUNNING:
            return status
        if status.state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("resume", status.state)
        with self._translated_errors(handle):
            payload = self._micro_vms.resume_micro_vm(microVmId=handle.sandbox_id)
        result = self._status(payload, handle=handle)
        # The service may return null state during transition; treat as RESUMING.
        if result.state is SandboxState.PENDING:
            from dataclasses import replace
            result = replace(result, state=SandboxState.RESUMING)
        return result

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        """Terminate a MicroVM. Idempotent on an already terminal or already absent Sandbox.

        R9.9 requires termination to succeed on a Session that is already terminal, so a
        MicroVM the service no longer knows is reported terminated rather than raised over.
        """
        try:
            status = self.describe(handle)
        except UnknownSandbox:
            return self._terminated(handle)
        if status.state in _TERMINAL_STATES:
            return status
        with self._translated_errors(handle):
            payload = self._micro_vms.terminate_micro_vm(microVmId=handle.sandbox_id)
        return self._status(payload, handle=handle)

    # ------------------------------------------------------------------ connection

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> ConnectionDescriptor:
        """Mint the port-scoped, expiring endpoint token for a Sandbox.

        The token is carried verbatim as `auth_header_value` beside its header name. A
        suspended Sandbox is served: the first request delivered to the endpoint resumes it,
        which is what R6.20 relies on.

        Raises:
            InvalidSandboxTransition: the Sandbox is terminal, so no credential reaches it.
            ValueError: the TTL is not positive, no port was named, or a named port is not one
                the Sandbox exposes.
        """
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be greater than zero: {ttl_seconds}")
        if not ports:
            raise ValueError("a connection is scoped to at least one port")
        payload = self._get(handle)
        state = _sandbox_state(payload.get("state"))
        if state in _TERMINAL_STATES:
            raise InvalidSandboxTransition("issue a connection to", state)
        scoped_ports = tuple(sorted(set(ports)))
        exposed = payload.get("exposedPorts")
        if exposed is not None:
            unexposed = sorted(set(scoped_ports) - {int(port) for port in exposed})
            if unexposed:
                raise ValueError(
                    f"ports not exposed by this Sandbox: {unexposed}"
                    f" (exposed: {sorted(int(port) for port in exposed)})"
                )
        with self._translated_errors(handle):
            minted = self._micro_vms.create_micro_vm_endpoint_token(
                microVmId=handle.sandbox_id,
                allowedPorts=[{"port": p} for p in sorted(set(scoped_ports) | {8080})],
                expirationInMinutes=max(1, ttl_seconds // 60),
            )
        base_url = minted.get("endpoint") or minted.get("endpointUrl") or payload.get("endpoint") or payload.get("endpointUrl")
        if isinstance(base_url, str) and base_url and not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        if not isinstance(base_url, str) or not base_url:
            raise ValueError(
                f"no endpoint URL was reported for Sandbox {handle.sandbox_id!r}"
            )
        auth_token_map = minted.get("authToken", {})
        if isinstance(auth_token_map, dict):
            token = auth_token_map.get("X-aws-proxy-auth") or minted.get("token")
        else:
            token = minted.get("token")
        if not isinstance(token, str) or not token:
            raise ValueError(
                f"no endpoint token was minted for Sandbox {handle.sandbox_id!r}"
            )
        expires_at = _as_datetime(minted.get("expiresAt")) or (
            self._clock() + timedelta(seconds=ttl_seconds)
        )
        return ConnectionDescriptor(
            base_url=base_url,
            auth_header_name=AUTH_HEADER_NAME,
            auth_header_value=token,
            ports=scoped_ports,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------ operations

    def consumed_capacity(self) -> int:
        """Memory held across every `RUNNING` and `SUSPENDED` MicroVM in the Region (R14.5)."""
        return sum(
            self._memory_bytes(payload)
            for payload in self._list_micro_vms()
            if _sandbox_state(payload.get("state")) in _CAPACITY_HOLDING_STATES
        )

    def release_check(self, handle: SandboxHandle) -> list[str]:
        """Return the identifiers of resources still allocated to a Sandbox (R10.9).

        Empty for a terminated Sandbox and for one the service no longer knows, so the
        Session_Orchestrator asserts emptiness rather than trusting that `terminate` succeeded.
        The identifier shapes match `local-firecracker`'s, so one assertion covers both.
        """
        try:
            payload = self._get(handle)
        except UnknownSandbox:
            return []
        if _sandbox_state(payload.get("state")) in _TERMINAL_STATES:
            return []
        sandbox_id = str(payload.get("microvmId", handle.sandbox_id))
        outstanding = [f"sandbox/{sandbox_id}"]
        # Reported the way the request spells it: a list, so each entry is one attachment.
        for connector in payload.get("egressNetworkConnectors") or ():
            outstanding.append(f"network-interface/{connector}")
        if payload.get("endpoint") or payload.get("endpointUrl"):
            outstanding.append(f"endpoint/{sandbox_id}")
        return outstanding

    def discover(self, tags: Mapping[str, str]) -> list[SandboxStatus]:
        """Find MicroVMs whose tags include every pair in `tags`, terminal ones included.

        Matching is a superset test performed here rather than pushed into the API's own filter
        semantics, so it means the same thing as `local-firecracker`'s. Terminal Sandboxes are
        returned because the Reaper's question is what state a Sandbox is in, and a sweep that
        could not see a terminated one could not confirm its own work.
        """
        matched = [
            payload
            for payload in self._list_micro_vms()
            if _tags_of(payload).items() >= tags.items()
        ]
        matched.sort(key=lambda payload: str(payload.get("microvmId", "")))
        return [self._status(payload) for payload in matched]

    # ------------------------------------------------------------------ internals

    @property
    def _micro_vms(self) -> MicroVmClient:
        if self._client is None:
            region = self._region_name or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION", "us-east-1")
            self._client = _HttpMicroVmClient(region)
        return self._client

    @property
    def _quotas(self) -> ServiceQuotasClient:
        if self._quotas_client is None:
            self._quotas_client = _build_client("service-quotas", self._region_name)
        return self._quotas_client

    def _region_memory_quota(self) -> int | None:
        """Return the published Region memory ceiling in bytes, or `None`.

        Read once and cached, including a failed read. `limits()` sits on the request
        validation path, and the ceiling is published for observation against R14.5's metric
        rather than for enforcement, so a Service Quotas outage must not fail Session creation.
        """
        if self._memory_quota_code is None:
            return None
        if self._quota_read:
            return self._quota_bytes
        self._quota_read = True
        try:
            response = self._quotas.get_service_quota(
                ServiceCode=QUOTA_SERVICE_CODE, QuotaCode=self._memory_quota_code
            )
            quota = response["Quota"]
            self._quota_bytes = int(float(quota["Value"]) * QUOTA_CODE_UNIT_BYTES)
        except Exception:  # noqa: BLE001 - see the docstring: publish nothing, never fail here
            self._quota_bytes = None
        return self._quota_bytes

    def _validate(self, spec: SandboxSpec) -> None:
        if not spec.egress_attachment_ref:
            raise MissingNetworkConnector
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
        if spec.memory_bytes not in MICROVM_MEMORY_CHOICES:
            raise ValueError(
                f"memory_bytes is not one of this provider's declared choices "
                f"{list(MICROVM_MEMORY_CHOICES)}: {spec.memory_bytes}"
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

    def _get(self, handle: SandboxHandle) -> Mapping[str, Any]:
        if handle.provider_name != PROVIDER_NAME:
            raise UnknownSandbox(handle)
        with self._translated_errors(handle):
            return self._micro_vms.get_micro_vm(microVmId=handle.sandbox_id)

    def _list_micro_vms(self) -> list[Mapping[str, Any]]:
        """Read every MicroVM in the Region, following the service's pagination token."""
        collected: list[Mapping[str, Any]] = []
        request: dict[str, Any] = {}
        seen_tokens: set[str] = set()
        while True:
            with self._translated_errors():
                page = self._micro_vms.list_micro_vms(**request)
            entries = page.get("microVms") or ()
            collected.extend(entry for entry in entries if isinstance(entry, Mapping))
            token = page.get("nextToken")
            # A repeated token is a service or stub bug; refusing to loop on it is cheaper
            # than a hang the suite's timeout would report as an unrelated failure.
            if not isinstance(token, str) or not token or token in seen_tokens:
                return collected
            seen_tokens.add(token)
            request = {"nextToken": token}

    @contextmanager
    def _translated_errors(self, handle: SandboxHandle | None = None) -> Iterator[None]:
        """Translate the service's refusals into the seam's, leaving everything else alone."""
        try:
            yield
        except Exception as exc:
            code = _error_code(exc)
            if code in _QUOTA_ERROR_CODES:
                raise QuotaExhausted(
                    QUOTA_NAME, CapacityDimension.MEMORY_BYTES_PER_REGION
                ) from exc
            if code in _NOT_FOUND_ERROR_CODES and handle is not None:
                raise UnknownSandbox(handle) from exc
            raise

    def _memory_bytes(
        self, payload: Mapping[str, Any], fallback: int | None = None
    ) -> int:
        reported = payload.get("memoryBytes")
        if reported is not None:
            return int(reported)
        if fallback is not None:
            return fallback
        return 0

    def _status(
        self,
        payload: Mapping[str, Any],
        *,
        handle: SandboxHandle | None = None,
        fallback_memory_bytes: int | None = None,
    ) -> SandboxStatus:
        """Build a `SandboxStatus` from a service payload.

        `opaque` carries the memory size and, when the service reported one, the endpoint URL.
        Both are provider-private continuation data: no caller parses them, and holding them
        lets a terminal status still report the size the Sandbox held.
        """
        held = dict(handle.opaque) if handle is not None else {}
        sandbox_id = str(
            payload.get("microvmId")
            or (handle.sandbox_id if handle is not None else "")
        )
        if not sandbox_id:
            raise ValueError("the service reported a MicroVM with no identifier")
        fallback = fallback_memory_bytes
        if fallback is None and "memoryBytes" in held:
            fallback = int(held["memoryBytes"])
        memory_bytes = self._memory_bytes(payload, fallback)
        opaque = dict(held)
        opaque["memoryBytes"] = str(memory_bytes)
        endpoint_url = payload.get("endpoint") or payload.get("endpointUrl")
        if isinstance(endpoint_url, str) and endpoint_url:
            opaque["endpoint"] = endpoint_url
        reason = payload.get("stateReason")
        return SandboxStatus(
            handle=SandboxHandle(
                provider_name=PROVIDER_NAME, sandbox_id=sandbox_id, opaque=opaque
            ),
            state=_sandbox_state(payload.get("state")),
            memory_bytes=memory_bytes,
            started_at=_as_datetime(payload.get("startedAt")),
            state_reason=str(reason) if reason is not None else None,
        )

    def _terminated(self, handle: SandboxHandle) -> SandboxStatus:
        """The status of a Sandbox the service no longer knows: terminated, by definition."""
        return SandboxStatus(
            handle=handle,
            state=SandboxState.TERMINATED,
            memory_bytes=int(handle.opaque.get("memoryBytes", 0)),
            started_at=None,
            state_reason="the Sandbox is no longer known to the provider",
        )


def _run_hook_payload(spec: SandboxSpec) -> bytes:
    """Return the `runHookPayload` for a spec, by value or by reference (R7.11).

    Oversized configuration is passed as a State_Store reference inside the payload, which is
    the mechanism R7.11 names: the Sandbox_Runtime retrieves the configuration itself rather
    than receiving it inline.

    The ``egressEndpoint`` field (the NLB proxy DNS name) is injected alongside the
    configuration so the runtime can set ``https_proxy`` / ``http_proxy`` for child
    processes. It rides in the payload because the RunMicrovm API has no environment-
    variable parameter, and the image-level env vars are baked at build time.
    """
    if spec.start_config_ref is None:
        config = spec.start_config
    else:
        config = json.dumps(
            {"startConfigRef": spec.start_config_ref}, separators=(",", ":")
        ).encode()

    # Inject runtime configuration alongside the start config.
    # The runtime extracts these from the envelope on /run.
    extras: dict[str, str] = {}
    if spec.egress_endpoint:
        extras["egressEndpoint"] = spec.egress_endpoint
    if spec.s3files_filesystem_id:
        extras["s3filesFileSystemId"] = spec.s3files_filesystem_id
        extras["s3filesAccessPointId"] = spec.s3files_access_point_id
        extras["s3filesMountTargetIp"] = spec.s3files_mount_target_ip
        extras["s3filesRegion"] = "us-east-1"  # TODO: derive from deployment region

    if extras:
        try:
            config_obj = json.loads(config)
            config_obj.update(extras)
            payload = json.dumps(config_obj, separators=(",", ":")).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = json.dumps(extras, separators=(",", ":")).encode()
    else:
        payload = config

    if len(payload) > MAX_RUN_CONFIG_BYTES:
        raise ValueError(
            f"run_hook_payload does not fit in max_run_config_bytes "
            f"({len(payload)} > {MAX_RUN_CONFIG_BYTES})"
        )
    return payload


def _tags_of(payload: Mapping[str, Any]) -> dict[str, str]:
    tags = payload.get("tags")
    if not isinstance(tags, Mapping):
        return {}
    return {str(key): str(value) for key, value in tags.items()}


class _HttpApiError(Exception):
    """Error from the MicroVM HTTP API, shaped so `_error_code` reads it unchanged.

    `_error_code` duck-types on ``exc.response["Error"]["Code"]``, which is the same shape
    botocore's ``ClientError`` carries, so `_translated_errors` handles both without an
    import-time dependency on botocore.
    """

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.response: dict[str, Any] = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status_code},
        }
        self.code = code


class _HttpMicroVmClient:
    """Satisfies :class:`MicroVmClient` using SigV4-signed HTTP to the Lambda MicroVM API.

    The boto3 SDK has no ``lambda-microvms`` service model, so a ``boto3.client("lambda")``
    returns a Lambda client whose operation set predates MicroVMs.  This class issues raw HTTP
    against the versioned REST surface (``/2025-09-09/…``), signs every request with SigV4 via
    ``botocore.auth``, and raises :class:`_HttpApiError` on non-2xx responses so that
    ``_error_code`` / ``_translated_errors`` handle them identically to a botocore
    ``ClientError``.

    Imports of ``botocore`` and ``urllib`` are deferred to :meth:`_request` for the same reason
    ``_build_client`` deferred ``boto3``: the offline suite imports this module with no
    credentials, no configured Region and no egress, and a top-level import would need all
    three.
    """

    _API_DATE: Final = "2025-09-09"
    _SERVICE: Final = "lambda"  # SigV4 service name

    def __init__(self, region: str) -> None:
        self._region = region
        self._base = f"https://lambda.{region}.amazonaws.com/{self._API_DATE}"

    # -- MicroVmClient Protocol surface ----------------------------------------

    def create_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        return self._request("POST", "/microvms", body=request)

    def get_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        vm_id = request.pop("microVmId")
        return self._request("GET", f"/microvms/{vm_id}")

    def suspend_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        vm_id = request.pop("microVmId")
        return self._request("POST", f"/microvms/{vm_id}/suspend", body=request or None)

    def resume_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        vm_id = request.pop("microVmId")
        return self._request("POST", f"/microvms/{vm_id}/resume", body=request or None)

    def terminate_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        vm_id = request.pop("microVmId")
        return self._request("DELETE", f"/microvms/{vm_id}")

    def list_micro_vms(self, **request: Any) -> Mapping[str, Any]:
        query = "&".join(f"{k}={v}" for k, v in request.items()) if request else ""
        path = f"/microvms?{query}" if query else "/microvms"
        return self._request("GET", path)

    def create_micro_vm_endpoint_token(self, **request: Any) -> Mapping[str, Any]:
        vm_id = request.pop("microVmId")
        return self._request("POST", f"/microvms/{vm_id}/auth-token", body=request or None)

    # -- transport -------------------------------------------------------------

    def _request(self, method: str, path: str, body: Any | None = None) -> Mapping[str, Any]:
        import json as _json
        import urllib.error
        import urllib.request

        import botocore.auth  # type: ignore[import-untyped]
        import botocore.awsrequest  # type: ignore[import-untyped]
        import botocore.session  # type: ignore[import-untyped]

        url = f"{self._base}{path}"
        data = _json.dumps(body, default=lambda o: base64.b64encode(o).decode("ascii") if isinstance(o, bytes) else str(o)).encode() if body else None
        headers: dict[str, str] = {"Content-Type": "application/json"} if data else {}

        aws_req = botocore.awsrequest.AWSRequest(
            method=method, url=url, data=data, headers=headers
        )
        session = botocore.session.get_session()
        creds = session.get_credentials().get_frozen_credentials()
        botocore.auth.SigV4Auth(creds, self._SERVICE, self._region).add_auth(aws_req)

        req = urllib.request.Request(
            url, data=data, headers=dict(aws_req.headers), method=method
        )
        try:
            with urllib.request.urlopen(req) as resp: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
                return _json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode(errors="replace")
            try:
                error_data = _json.loads(error_body)
            except _json.JSONDecodeError:
                error_data = {"message": error_body}
            error_code = (
                error_data.get("__type", "").rsplit("#", 1)[-1]
                or error_data.get("error", "ServiceError")
            )
            raise _HttpApiError(
                exc.code,
                error_code,
                error_data.get("message") or error_data.get("Message") or str(exc),
            ) from exc


def _build_client(service_name: str, region_name: str | None) -> Any:
    """Build a boto3 client on first use.

    Only Service Quotas still uses this path. The MicroVM API surface is served by
    :class:`_HttpMicroVmClient`, which issues SigV4-signed HTTP directly.

    The import is deliberately inside the function: the offline suite imports this module with
    no credentials, no configured Region and no egress, and a module-level boto3 client would
    need all three.
    """
    import boto3  # type: ignore[import-untyped]

    if region_name is None:
        return boto3.client(service_name)
    return boto3.client(service_name, region_name=region_name)
