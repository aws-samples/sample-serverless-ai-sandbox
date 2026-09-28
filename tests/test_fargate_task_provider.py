# kiro-classification: public
"""The `fargate-task` conformance exercise: a weaker provider behind the same seam (R5.6).

These are deterministic unit tests rather than properties, because the claim under test is not a
statement about all inputs. It is a statement about one interface: a Session that needs
memory-preserving suspend is refused by name against this provider, and the Sandbox_Protocol
catalogue and the caller-facing contract are the same documents afterwards as before.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from control_plane.providers import registry
from control_plane.providers.base import (
    CapabilityUnsupported,
    CapacityDimension,
    ComputeProvider,
    ProviderCapabilities,
    QuotaExhausted,
    SandboxHandle,
    SandboxSpec,
    SandboxState,
    SuspendFidelity,
)
from control_plane.providers.fargate_task import (
    AUTH_HEADER_NAME,
    BOOLEAN_CAPABILITIES,
    DEFAULT_CAPACITY_LIMIT_VCPU,
    FARGATE_MEMORY_BYTES_CHOICES,
    FARGATE_VCPU_MILLIS_CHOICES,
    MAX_DURATION_SECONDS,
    MAX_RUN_CONFIG_BYTES,
    MEMORY_DISCARDED_REASON,
    MIN_DURATION_SECONDS,
    PROVIDER_NAME,
    QUOTA_NAME,
    FargateTaskProvider,
    InvalidSandboxTransition,
    UnknownSandbox,
    require_capability,
    require_suspend_fidelity,
)
from control_plane.providers.lambda_microvm import (
    AUTH_HEADER_NAME as MICROVM_AUTH_HEADER,
)
from control_plane.providers.lambda_microvm import LambdaMicroVmProvider
from control_plane.providers.local_firecracker import (
    AUTH_HEADER_NAME as LOCAL_AUTH_HEADER,
)
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from protocol.schema import load_catalogue

START = datetime(2026, 1, 1, tzinfo=UTC)
SMALL_MEMORY = FARGATE_MEMORY_BYTES_CHOICES[0]
ONE_VCPU = FARGATE_VCPU_MILLIS_CHOICES[0]
HALF_QUOTA_VCPU = FARGATE_VCPU_MILLIS_CHOICES[3]
LARGEST_VCPU = FARGATE_VCPU_MILLIS_CHOICES[-1]

CONTRACT_METHODS = frozenset(ComputeProvider.__abstractmethods__)


class Clock:
    """A controlled clock, so credential expiry is asserted rather than waited for."""

    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def spec(**overrides: object) -> SandboxSpec:
    base = SandboxSpec(
        session_id="ses-1",
        tenant_id="tnt-1",
        image_ref="sandbox-image:1",
        memory_bytes=SMALL_MEMORY,
        vcpu_millis=ONE_VCPU,
        max_duration_seconds=3_600,
        idle_seconds_before_suspend=300,
        suspended_seconds_before_terminate=3_600,
        # False, because this provider declares no auto-resume. A spec that asked for it is a
        # test of its own, below.
        auto_resume=False,
        exposed_ports=(8080,),
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        egress_attachment_ref="attachment-1",
        egress_endpoint="",
        start_config=b"{}",
        start_config_ref=None,
        tags={"tenantId": "tnt-1", "sessionId": "ses-1"},
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def provider(clock: Clock) -> FargateTaskProvider:
    return FargateTaskProvider(clock=clock)


# ------------------------------------------------- the failure mode this exercise exists for


def test_a_session_needing_memory_preserving_suspend_is_refused_by_name(
    provider: FargateTaskProvider,
) -> None:
    # The whole point of the exercise. The refusal names the capability and the provider, and it
    # happens before anything is provisioned.
    with pytest.raises(CapabilityUnsupported) as raised:
        require_suspend_fidelity(provider, SuspendFidelity.MEMORY_AND_DISK)

    assert raised.value.capability == "suspend_fidelity=memory-and-disk"
    assert raised.value.provider_name == PROVIDER_NAME == "fargate-task"
    assert provider.discover({}) == []
    assert provider.consumed_capacity() == 0


@pytest.mark.parametrize("other", [LambdaMicroVmProvider(), LocalFirecrackerProvider()])
def test_the_same_request_is_admitted_by_a_provider_that_declares_the_fidelity(
    other: ComputeProvider,
) -> None:
    # The gate reads `capabilities()` and the provider's own name, so it refuses one provider and
    # admits another without either being named in its code.
    require_suspend_fidelity(other, SuspendFidelity.MEMORY_AND_DISK)


def test_disk_only_fidelity_is_enough_for_a_session_that_only_needs_the_disk(
    provider: FargateTaskProvider,
) -> None:
    require_suspend_fidelity(provider, SuspendFidelity.DISK_ONLY)
    require_suspend_fidelity(provider, SuspendFidelity.NONE)


def test_a_session_needing_fork_from_running_state_is_refused_by_name(
    provider: FargateTaskProvider,
) -> None:
    with pytest.raises(CapabilityUnsupported) as raised:
        require_capability(provider, "fork_from_running_state")

    assert raised.value.capability == "fork_from_running_state"
    assert raised.value.provider_name == PROVIDER_NAME


def test_a_spec_asking_for_auto_resume_is_refused_before_a_task_exists(
    provider: FargateTaskProvider,
) -> None:
    # R5.6's shape for every capability gap: named, early, and with no protocol or SDK
    # consequence. A stopped Fargate task has no endpoint, so there is nothing to wake.
    with pytest.raises(CapabilityUnsupported) as raised:
        provider.provision(spec(auto_resume=True))

    assert raised.value.capability == "auto_resume_on_request"
    assert provider.discover({}) == []


def test_a_capability_the_provider_declares_is_admitted(
    provider: FargateTaskProvider,
) -> None:
    for capability in (
        "interactive_pty",
        "inbound_port_exposure",
        "restore_state_at_start",
    ):
        require_capability(provider, capability)


def test_the_gate_covers_every_boolean_capability_of_the_seam() -> None:
    # Derived from the dataclass rather than retyped, so a capability added to the seam is gated
    # without an edit to this provider.
    declared = {
        name
        for name, annotation in ProviderCapabilities.__annotations__.items()
        if annotation in ("bool", bool)
    }
    assert BOOLEAN_CAPABILITIES == declared
    assert "suspend_fidelity" not in BOOLEAN_CAPABILITIES


def test_a_misspelled_capability_is_a_lookup_failure_rather_than_a_silent_refusal(
    provider: FargateTaskProvider,
) -> None:
    # A silent `False` for an unknown name would refuse every provider and look like a gate.
    with pytest.raises(KeyError, match="not a capability"):
        require_capability(provider, "fork_from_runing_state")


# ----------------------------------------- and nothing else changed to accommodate it


def test_the_contract_surface_is_signature_identical_to_the_isolation_providers() -> (
    None
):
    # "No Client_SDK signature changes" made checkable: the eleven methods a caller reaches for
    # take the same parameters on the weaker backend as on the isolation boundary.
    for method in sorted(CONTRACT_METHODS):
        weaker = inspect.signature(getattr(FargateTaskProvider, method))
        anchor = inspect.signature(getattr(LambdaMicroVmProvider, method))
        assert weaker == anchor, method


def test_the_provider_adds_no_public_method_for_a_caller_to_reach_for() -> None:
    # Accommodating the weaker backend cannot have widened the interface, because there is
    # nothing here beyond the contract. `name` is the contract's own class attribute.
    public = {
        name
        for name, value in vars(FargateTaskProvider).items()
        if not name.startswith("_") and callable(value)
    }
    assert public == CONTRACT_METHODS


def test_no_sandbox_protocol_message_names_suspend_fidelity_or_a_provider() -> None:
    # Suspend fidelity is never on the wire, which is why a weaker backend needs no message
    # added, renamed or given a field (R8.1, R5.6).
    catalogue = load_catalogue()
    names = [
        f"{message.t}.{field.name}"
        for message in catalogue.messages.values()
        for field in message.body
    ] + list(catalogue.message_types)

    offenders = [
        name
        for name in names
        for term in ("fidelity", "fargate", "provider", "microvm", "suspend")
        if term in re.sub(r"[^a-z]", "", name.lower())
    ]
    assert offenders == []


def test_the_capability_gap_is_observable_through_the_existing_status_fields(
    provider: FargateTaskProvider,
) -> None:
    # The fidelity gap surfaces on `SandboxStatus.state_reason`, a field the contract already
    # had. No new message and no new SDK field carries it.
    handle = provider.provision(spec()).handle

    suspended = provider.suspend(handle)
    assert suspended.state_reason == MEMORY_DISCARDED_REASON
    # It survives the resume: the memory this Session held before the suspend is gone, and a
    # caller reading the resumed status can see that it was.
    assert provider.resume(handle).state_reason == MEMORY_DISCARDED_REASON


# ------------------------------------------------------------------- the seam and the registry


def test_it_implements_the_contract_and_names_itself() -> None:
    provider = FargateTaskProvider()

    assert isinstance(provider, ComputeProvider)
    assert provider.name == PROVIDER_NAME == "fargate-task"


def test_it_cannot_be_registered_because_it_is_not_an_isolation_boundary() -> None:
    assert PROVIDER_NAME not in registry.ISOLATION_APPROVED
    with pytest.raises(ValueError, match="not approved as an isolation boundary"):
        registry.register(FargateTaskProvider())
    assert PROVIDER_NAME not in registry.REGISTRY


def test_it_declares_the_weaker_capability_set() -> None:
    capabilities = FargateTaskProvider().capabilities()

    assert capabilities.suspend_fidelity is SuspendFidelity.DISK_ONLY
    assert capabilities.fork_from_running_state is False
    assert capabilities.auto_resume_on_request is False
    # Weaker where it is weaker, and not pessimistic elsewhere.
    assert capabilities.interactive_pty is True
    assert capabilities.inbound_port_exposure is True
    assert capabilities.restore_state_at_start is True
    assert capabilities.egress_is_policy_controlled is True


def test_it_declares_a_weaker_fidelity_than_the_isolation_provider() -> None:
    assert (
        FargateTaskProvider().capabilities().suspend_fidelity
        is not LambdaMicroVmProvider().capabilities().suspend_fidelity
    )


def test_limits_publish_this_providers_own_ceilings_in_its_own_dimension() -> None:
    limits = FargateTaskProvider().limits()

    # Deliberately not the MicroVM numbers: R6.5's message and R7.11's overflow path are keyed
    # off these values, and identical numbers would not have proved that.
    assert limits.max_duration_seconds == MAX_DURATION_SECONDS == 86_400
    assert limits.min_duration_seconds == MIN_DURATION_SECONDS == 1
    assert limits.max_run_config_bytes == MAX_RUN_CONFIG_BYTES == 8_192
    assert (
        limits.max_duration_seconds
        != LambdaMicroVmProvider().limits().max_duration_seconds
    )
    # Counted in vCPU, not memory bytes: `consumed_capacity()` is meaningful only with its
    # dimension beside it (R14.5).
    assert limits.capacity_dimension is CapacityDimension.VCPU_PER_REGION
    assert limits.capacity_limit == DEFAULT_CAPACITY_LIMIT_VCPU
    assert limits.memory_bytes_choices == FARGATE_MEMORY_BYTES_CHOICES


def test_a_connection_carries_a_third_authentication_scheme_as_data(
    provider: FargateTaskProvider,
) -> None:
    # Two schemes prove a header name can differ; three make it uncomfortable to argue the
    # Client_SDK is quietly branching on one (R9.4).
    handle = provider.provision(spec(exposed_ports=(8080, 9000))).handle

    descriptor = provider.issue_connection(handle, (9000, 8080), 120)

    assert descriptor.auth_header_name == AUTH_HEADER_NAME == "X-Sandbox-Task-Token"
    assert len({AUTH_HEADER_NAME, MICROVM_AUTH_HEADER, LOCAL_AUTH_HEADER}) == 3
    assert descriptor.ports == (8080, 9000)
    assert descriptor.expires_at == START + timedelta(seconds=120)
    assert descriptor.base_url == f"http://127.0.0.1:8082/tasks/{handle.sandbox_id}"


# ------------------------------------------------------------------------------- lifecycle


def test_provision_returns_a_running_task_with_a_handle_naming_this_provider(
    provider: FargateTaskProvider,
) -> None:
    status = provider.provision(spec())

    assert status.state is SandboxState.RUNNING
    assert status.handle.provider_name == PROVIDER_NAME
    assert status.memory_bytes == SMALL_MEMORY
    assert status.started_at == START
    assert status.state_reason is None
    assert provider.describe(status.handle) == status


def test_suspend_and_resume_round_trip_and_are_idempotent(
    provider: FargateTaskProvider,
) -> None:
    running = provider.provision(spec())

    assert provider.suspend(running.handle).state is SandboxState.SUSPENDED
    assert provider.suspend(running.handle).state is SandboxState.SUSPENDED

    resumed = provider.resume(running.handle)
    assert resumed.state is SandboxState.RUNNING
    assert provider.resume(running.handle).state is SandboxState.RUNNING
    # Cold provision and resume stay two separate measurements (R10.10, R10.12).
    assert resumed.started_at == running.started_at


def test_resume_advances_the_opaque_continuation_data_and_a_stale_handle_still_works(
    provider: FargateTaskProvider,
) -> None:
    stale = provider.provision(spec()).handle
    provider.suspend(stale)

    resumed = provider.resume(stale)

    assert resumed.handle.opaque != stale.opaque
    assert provider.describe(stale).handle == resumed.handle


def test_terminate_is_idempotent_and_leaves_the_task_terminal(
    provider: FargateTaskProvider,
) -> None:
    handle = provider.provision(spec()).handle

    assert provider.terminate(handle).state is SandboxState.TERMINATED
    assert provider.terminate(handle).state is SandboxState.TERMINATED
    assert provider.describe(handle).state is SandboxState.TERMINATED


@pytest.mark.parametrize("operation", ["suspend", "resume", "issue_connection"])
def test_a_terminated_task_refuses_further_operations(
    provider: FargateTaskProvider, operation: str
) -> None:
    handle = provider.provision(spec()).handle
    provider.terminate(handle)

    with pytest.raises(InvalidSandboxTransition) as raised:
        if operation == "issue_connection":
            provider.issue_connection(handle, (8080,), 60)
        else:
            getattr(provider, operation)(handle)

    assert raised.value.state is SandboxState.TERMINATED


@pytest.mark.parametrize(
    "handle",
    [
        SandboxHandle(PROVIDER_NAME, "task-absent", {}),
        SandboxHandle("lambda-microvm", "sbx-elsewhere", {}),
    ],
)
def test_an_unheld_handle_is_a_lookup_failure(
    provider: FargateTaskProvider, handle: SandboxHandle
) -> None:
    provider.provision(spec())

    with pytest.raises(UnknownSandbox):
        provider.describe(handle)


# ---------------------------------------------- the consequences of no auto-resume


def test_a_suspended_task_has_no_endpoint_to_issue_a_credential_for(
    provider: FargateTaskProvider,
) -> None:
    # This provider's `auto_resume_on_request=False` made concrete, and the exact opposite of
    # `local-firecracker`, where a suspended Sandbox still accepts its credential. Both are
    # correct for their own declared capability, which is why a caller reads the capability.
    handle = provider.provision(spec()).handle
    provider.suspend(handle)

    with pytest.raises(InvalidSandboxTransition) as raised:
        provider.issue_connection(handle, (8080,), 60)

    assert raised.value.state is SandboxState.SUSPENDED


def test_suspend_revokes_the_credentials_it_can_no_longer_serve(
    provider: FargateTaskProvider,
) -> None:
    handle = provider.provision(spec()).handle
    provider.issue_connection(handle, (8080,), 3_600)
    assert f"endpoint/{handle.sandbox_id}" in provider.release_check(handle)

    provider.suspend(handle)

    assert f"endpoint/{handle.sandbox_id}" not in provider.release_check(handle)


# -------------------------------------------------------------------------------- capacity


def test_capacity_is_counted_in_vcpu_and_a_suspended_task_holds_none(
    provider: FargateTaskProvider,
) -> None:
    first = provider.provision(spec(session_id="ses-1", vcpu_millis=HALF_QUOTA_VCPU))
    provider.provision(spec(session_id="ses-2", vcpu_millis=HALF_QUOTA_VCPU))
    # vCPU, not bytes: two 8 vCPU tasks are 16, not 34 GiB.
    assert provider.consumed_capacity() == 16

    # The opposite of the anchored MicroVM ceiling, which counts suspended memory: a stopped
    # Fargate task consumes no vCPU.
    provider.suspend(first.handle)
    assert provider.consumed_capacity() == 8

    provider.terminate(first.handle)
    assert provider.consumed_capacity() == 8


def test_crossing_the_published_quota_raises_with_the_provider_supplied_reason(
    provider: FargateTaskProvider,
) -> None:
    provider.provision(spec(session_id="ses-1", vcpu_millis=LARGEST_VCPU))

    with pytest.raises(QuotaExhausted) as raised:
        provider.provision(spec(session_id="ses-2", vcpu_millis=ONE_VCPU))

    assert raised.value.quota_name == QUOTA_NAME
    assert raised.value.dimension is CapacityDimension.VCPU_PER_REGION
    assert provider.consumed_capacity() == 16
    assert len(provider.discover({})) == 1


def test_resume_can_be_refused_because_the_released_vcpu_was_taken(
    provider: FargateTaskProvider,
) -> None:
    # Unreachable on a provider whose suspended Sandboxes keep holding capacity, and reachable
    # here, which is precisely why capacity is a provider-reported quantity rather than a rule
    # of the contract.
    suspended = provider.provision(spec(session_id="ses-1", vcpu_millis=LARGEST_VCPU))
    provider.suspend(suspended.handle)
    provider.provision(spec(session_id="ses-2", vcpu_millis=LARGEST_VCPU))

    with pytest.raises(QuotaExhausted):
        provider.resume(suspended.handle)

    assert provider.describe(suspended.handle).state is SandboxState.SUSPENDED


def test_a_provider_with_no_published_quota_never_exhausts() -> None:
    provider = FargateTaskProvider(capacity_limit_vcpu=None)

    assert provider.limits().capacity_limit is None
    for index in range(4):
        provider.provision(spec(session_id=f"ses-{index}", vcpu_millis=LARGEST_VCPU))
    assert provider.consumed_capacity() == 64


def test_a_non_positive_capacity_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="capacity_limit_vcpu"):
        FargateTaskProvider(capacity_limit_vcpu=0)


# ------------------------------------------------------------------------------ validation


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"max_duration_seconds": MAX_DURATION_SECONDS + 1}, "max_duration_seconds"),
        ({"max_duration_seconds": 0}, "max_duration_seconds"),
        ({"idle_seconds_before_suspend": 0}, "idle_seconds_before_suspend"),
        ({"suspended_seconds_before_terminate": 0}, "suspended_seconds"),
        ({"memory_bytes": SMALL_MEMORY + 1}, "memory_bytes"),
        ({"vcpu_millis": 250}, "vcpu_millis"),
        ({"start_config": b"x" * (MAX_RUN_CONFIG_BYTES + 1)}, "start_config_ref"),
        ({"exposed_ports": (0, 70_000)}, "out-of-range"),
    ],
)
def test_provision_enforces_every_limit_it_publishes(
    provider: FargateTaskProvider, overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        provider.provision(spec(**overrides))

    assert provider.consumed_capacity() == 0
    assert provider.discover({}) == []


def test_the_declared_maximum_duration_and_payload_size_are_accepted(
    provider: FargateTaskProvider,
) -> None:
    status = provider.provision(
        spec(
            max_duration_seconds=MAX_DURATION_SECONDS,
            start_config=b"x" * MAX_RUN_CONFIG_BYTES,
        )
    )

    assert status.state is SandboxState.RUNNING


def test_an_oversized_configuration_passed_by_reference_provisions(
    provider: FargateTaskProvider,
) -> None:
    # R7.11's overflow path, keyed off this provider's own 8 KB ceiling.
    status = provider.provision(
        spec(
            start_config=b"x" * (MAX_RUN_CONFIG_BYTES + 1),
            start_config_ref="s3://ref/1",
        )
    )

    assert status.state is SandboxState.RUNNING


@pytest.mark.parametrize(
    ("ports", "ttl", "message"),
    [
        ((), 60, "at least one port"),
        ((9999,), 60, "not exposed"),
        ((8080,), 0, "ttl_seconds"),
        ((8080,), -1, "ttl_seconds"),
    ],
)
def test_issue_connection_refuses_an_unscopeable_request(
    provider: FargateTaskProvider, ports: tuple[int, ...], ttl: int, message: str
) -> None:
    handle = provider.provision(spec()).handle

    with pytest.raises(ValueError, match=message):
        provider.issue_connection(handle, ports, ttl)


# ------------------------------------------------------- release check and discovery


def test_release_check_reports_outstanding_resources_until_terminate(
    provider: FargateTaskProvider,
) -> None:
    handle = provider.provision(spec()).handle
    provider.issue_connection(handle, (8080,), 60)

    outstanding = provider.release_check(handle)
    # The identifier shapes match the other two providers', so one orchestrator assertion covers
    # all three (R10.9).
    assert f"sandbox/{handle.sandbox_id}" in outstanding
    assert "network-interface/attachment-1" in outstanding
    assert f"endpoint/{handle.sandbox_id}" in outstanding

    provider.terminate(handle)
    assert provider.release_check(handle) == []


def test_release_check_on_an_unheld_handle_is_empty(
    provider: FargateTaskProvider,
) -> None:
    assert provider.release_check(SandboxHandle(PROVIDER_NAME, "task-absent", {})) == []


def test_discover_matches_on_the_tenant_and_session_tags(
    provider: FargateTaskProvider,
) -> None:
    first = provider.provision(
        spec(session_id="ses-1", tags={"tenantId": "tnt-1", "sessionId": "ses-1"})
    )
    provider.provision(
        spec(session_id="ses-2", tags={"tenantId": "tnt-2", "sessionId": "ses-2"})
    )

    found = provider.discover({"tenantId": "tnt-1"})

    assert [status.handle for status in found] == [first.handle]
    assert provider.discover({"tenantId": "tnt-1", "sessionId": "ses-2"}) == []
    assert len(provider.discover({})) == 2


def test_discover_reports_terminated_tasks_with_their_state(
    provider: FargateTaskProvider,
) -> None:
    handle = provider.provision(spec()).handle
    provider.terminate(handle)

    (found,) = provider.discover({"sessionId": "ses-1"})

    assert found.state is SandboxState.TERMINATED


def test_two_provider_instances_hold_separate_tasks(clock: Clock) -> None:
    first = FargateTaskProvider(clock=clock)
    second = FargateTaskProvider(clock=clock)
    handle = first.provision(spec()).handle

    with pytest.raises(UnknownSandbox):
        second.describe(handle)
    assert second.consumed_capacity() == 0


@pytest.fixture(autouse=True)
def _registry_untouched() -> Iterator[None]:
    """This module must not admit anything to the registry, even by accident."""
    saved = dict(registry.REGISTRY)
    try:
        yield
    finally:
        assert registry.REGISTRY == saved
