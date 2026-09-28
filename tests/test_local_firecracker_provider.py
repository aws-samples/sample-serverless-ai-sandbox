# kiro-classification: public
"""The `local-firecracker` provider the offline suite provisions against (R15.9)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from control_plane.providers import registry
from control_plane.providers.base import (
    CapacityDimension,
    ComputeProvider,
    QuotaExhausted,
    SandboxHandle,
    SandboxSpec,
    SandboxState,
    SuspendFidelity,
)
from control_plane.providers.local_firecracker import (
    AUTH_HEADER_NAME,
    AUTH_SCHEME,
    DEFAULT_CAPACITY_LIMIT_BYTES,
    LOCAL_MEMORY_BYTES_CHOICES,
    MAX_DURATION_SECONDS,
    MAX_RUN_CONFIG_BYTES,
    PROVIDER_NAME,
    QUOTA_NAME,
    InvalidSandboxTransition,
    LocalFirecrackerProvider,
    UnknownSandbox,
)

START = datetime(2026, 1, 1, tzinfo=UTC)
SMALLEST_MEMORY = LOCAL_MEMORY_BYTES_CHOICES[0]
LARGEST_MEMORY = LOCAL_MEMORY_BYTES_CHOICES[-1]


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
        memory_bytes=SMALLEST_MEMORY,
        vcpu_millis=2_000,
        max_duration_seconds=3_600,
        idle_seconds_before_suspend=300,
        suspended_seconds_before_terminate=3_600,
        auto_resume=True,
        exposed_ports=(8080,),
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        egress_attachment_ref="attachment-1",
        egress_endpoint="proxy.example.com",
        start_config=b"{}",
        start_config_ref=None,
        tags={"tenantId": "tnt-1", "sessionId": "ses-1"},
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def provider(clock: Clock) -> LocalFirecrackerProvider:
    return LocalFirecrackerProvider(clock=clock)


# --------------------------------------------------------------------- the seam


def test_it_implements_the_contract_and_names_itself() -> None:
    provider = LocalFirecrackerProvider()

    assert isinstance(provider, ComputeProvider)
    assert provider.name == PROVIDER_NAME == "local-firecracker"


def test_it_cannot_be_registered_because_it_is_not_an_isolation_boundary() -> None:
    # The whole reason this provider is safe to hand a test suite: the registry refuses it, so no
    # deployment can route Untrusted_Code to it (R5.6).
    assert PROVIDER_NAME not in registry.ISOLATION_APPROVED
    with pytest.raises(ValueError, match="not approved as an isolation boundary"):
        registry.register(LocalFirecrackerProvider())
    assert PROVIDER_NAME not in registry.REGISTRY


def test_it_declares_the_isolation_providers_capability_set() -> None:
    # Same capabilities, so an offline run takes the branches a deployed run takes.
    capabilities = LocalFirecrackerProvider().capabilities()

    assert capabilities.suspend_fidelity is SuspendFidelity.MEMORY_AND_DISK
    assert capabilities.auto_resume_on_request is True
    assert capabilities.fork_from_running_state is False
    assert capabilities.interactive_pty is True
    assert capabilities.inbound_port_exposure is True
    assert capabilities.restore_state_at_start is True
    assert capabilities.egress_is_policy_controlled is True


def test_limits_publish_a_finite_quota_and_the_shared_ceilings() -> None:
    limits = LocalFirecrackerProvider().limits()

    assert limits.max_duration_seconds == MAX_DURATION_SECONDS == 28_800
    assert limits.min_duration_seconds == 1
    assert limits.max_run_config_bytes == MAX_RUN_CONFIG_BYTES == 16_384
    assert limits.capacity_dimension is CapacityDimension.MEMORY_BYTES_PER_REGION
    # Finite on purpose: the quota-exhaustion path has to be reachable offline (R6.8, R6.14).
    assert limits.capacity_limit == DEFAULT_CAPACITY_LIMIT_BYTES
    assert limits.memory_bytes_choices == LOCAL_MEMORY_BYTES_CHOICES


def test_a_provider_with_no_published_quota_never_exhausts() -> None:
    provider = LocalFirecrackerProvider(capacity_limit_bytes=None)

    assert provider.limits().capacity_limit is None
    for index in range(8):
        provider.provision(spec(session_id=f"ses-{index}", memory_bytes=LARGEST_MEMORY))
    assert provider.consumed_capacity() == 8 * LARGEST_MEMORY


# --------------------------------------------------------------------- lifecycle


def test_provision_returns_a_running_sandbox_with_a_handle_naming_this_provider(
    provider: LocalFirecrackerProvider,
) -> None:
    status = provider.provision(spec())

    assert status.state is SandboxState.RUNNING
    assert status.handle.provider_name == PROVIDER_NAME
    assert status.handle.sandbox_id
    assert status.memory_bytes == SMALLEST_MEMORY
    assert status.started_at == START
    assert status.state_reason is None
    assert provider.describe(status.handle) == status


def test_each_provision_yields_a_distinct_sandbox_identifier(
    provider: LocalFirecrackerProvider,
) -> None:
    # R11.10's non-reuse rule is asserted over batches, which needs pairwise distinct identifiers.
    ids = {
        provider.provision(spec(session_id=f"ses-{index}")).handle.sandbox_id
        for index in range(16)
    }
    assert len(ids) == 16


def test_suspend_and_resume_round_trip_and_are_idempotent(
    provider: LocalFirecrackerProvider,
) -> None:
    running = provider.provision(spec())

    suspended = provider.suspend(running.handle)
    assert suspended.state is SandboxState.SUSPENDED
    assert provider.suspend(running.handle).state is SandboxState.SUSPENDED

    resumed = provider.resume(running.handle)
    assert resumed.state is SandboxState.RUNNING
    assert provider.resume(running.handle).state is SandboxState.RUNNING
    # `started_at` records when this Sandbox started, not when it last resumed: cold provision and
    # resume are two separate measurements (R10.10, R10.12).
    assert resumed.started_at == running.started_at


def test_resume_advances_the_opaque_continuation_data_and_a_stale_handle_still_works(
    provider: LocalFirecrackerProvider,
) -> None:
    stale = provider.provision(spec()).handle
    provider.suspend(stale)

    resumed = provider.resume(stale)

    assert resumed.handle.opaque != stale.opaque
    # Lookups key on the Sandbox identifier, so holding a pre-resume handle is not punished.
    assert provider.describe(stale).handle == resumed.handle


def test_terminate_is_idempotent_and_leaves_the_sandbox_terminal(
    provider: LocalFirecrackerProvider,
) -> None:
    handle = provider.provision(spec()).handle

    assert provider.terminate(handle).state is SandboxState.TERMINATED
    assert provider.terminate(handle).state is SandboxState.TERMINATED
    assert provider.describe(handle).state is SandboxState.TERMINATED


@pytest.mark.parametrize("operation", ["suspend", "resume", "issue_connection"])
def test_a_terminated_sandbox_refuses_further_operations(
    provider: LocalFirecrackerProvider, operation: str
) -> None:
    handle = provider.provision(spec()).handle
    provider.terminate(handle)

    with pytest.raises(InvalidSandboxTransition) as raised:
        if operation == "issue_connection":
            provider.issue_connection(handle, (8080,), 60)
        else:
            getattr(provider, operation)(handle)

    assert raised.value.state is SandboxState.TERMINATED
    assert "TERMINATED" in str(raised.value)


@pytest.mark.parametrize(
    "handle",
    [
        SandboxHandle(PROVIDER_NAME, "sbx-absent", {}),
        SandboxHandle("lambda-microvm", "sbx-elsewhere", {}),
    ],
)
def test_an_unheld_handle_is_a_lookup_failure(
    provider: LocalFirecrackerProvider, handle: SandboxHandle
) -> None:
    provider.provision(spec())

    with pytest.raises(UnknownSandbox):
        provider.describe(handle)


# --------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"max_duration_seconds": MAX_DURATION_SECONDS + 1}, "max_duration_seconds"),
        ({"max_duration_seconds": 0}, "max_duration_seconds"),
        ({"idle_seconds_before_suspend": 0}, "idle_seconds_before_suspend"),
        ({"suspended_seconds_before_terminate": 0}, "suspended_seconds"),
        ({"memory_bytes": SMALLEST_MEMORY + 1}, "memory_bytes"),
        ({"start_config": b"x" * (MAX_RUN_CONFIG_BYTES + 1)}, "start_config_ref"),
        ({"exposed_ports": (0, 70_000)}, "out-of-range"),
    ],
)
def test_provision_enforces_every_limit_it_publishes(
    provider: LocalFirecrackerProvider, overrides: dict[str, object], message: str
) -> None:
    # Enforced rather than assumed, so a caller that skipped a validation R6.5 or R7.11 requires
    # fails offline instead of in a deployment.
    with pytest.raises(ValueError, match=message):
        provider.provision(spec(**overrides))

    assert provider.consumed_capacity() == 0
    assert provider.discover({}) == []


def test_the_declared_maximum_duration_and_payload_size_are_accepted(
    provider: LocalFirecrackerProvider,
) -> None:
    status = provider.provision(
        spec(
            max_duration_seconds=MAX_DURATION_SECONDS,
            start_config=b"x" * MAX_RUN_CONFIG_BYTES,
        )
    )

    assert status.state is SandboxState.RUNNING


def test_an_oversized_configuration_passed_by_reference_provisions(
    provider: LocalFirecrackerProvider,
) -> None:
    # R7.11's overflow path: the payload travels as a State_Store reference, not inline.
    status = provider.provision(spec(start_config=b"", start_config_ref="s3://ref/1"))

    assert status.state is SandboxState.RUNNING


def test_a_non_positive_capacity_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="capacity_limit_bytes"):
        LocalFirecrackerProvider(capacity_limit_bytes=0)


# --------------------------------------------------------------------- capacity


def test_capacity_counts_running_and_suspended_and_is_released_on_terminate(
    provider: LocalFirecrackerProvider,
) -> None:
    first = provider.provision(spec(session_id="ses-1"))
    second = provider.provision(spec(session_id="ses-2"))
    assert provider.consumed_capacity() == 2 * SMALLEST_MEMORY

    # The anchored ceiling counts running and suspended capacity together, so suspending frees
    # nothing (R14.5).
    provider.suspend(first.handle)
    assert provider.consumed_capacity() == 2 * SMALLEST_MEMORY

    provider.terminate(first.handle)
    assert provider.consumed_capacity() == SMALLEST_MEMORY
    provider.terminate(second.handle)
    assert provider.consumed_capacity() == 0


def test_crossing_the_published_quota_raises_with_the_provider_supplied_reason(
    provider: LocalFirecrackerProvider,
) -> None:
    provider.provision(spec(session_id="ses-1", memory_bytes=LARGEST_MEMORY))
    provider.provision(spec(session_id="ses-2", memory_bytes=LARGEST_MEMORY))

    with pytest.raises(QuotaExhausted) as raised:
        provider.provision(spec(session_id="ses-3", memory_bytes=SMALLEST_MEMORY))

    assert raised.value.quota_name == QUOTA_NAME
    assert raised.value.dimension is CapacityDimension.MEMORY_BYTES_PER_REGION
    # A refused provision leaves nothing behind.
    assert provider.consumed_capacity() == 2 * LARGEST_MEMORY
    assert len(provider.discover({})) == 2


def test_terminating_a_sandbox_makes_room_under_the_quota(
    provider: LocalFirecrackerProvider,
) -> None:
    first = provider.provision(spec(session_id="ses-1", memory_bytes=LARGEST_MEMORY))
    provider.provision(spec(session_id="ses-2", memory_bytes=LARGEST_MEMORY))
    provider.terminate(first.handle)

    assert (
        provider.provision(spec(session_id="ses-3", memory_bytes=LARGEST_MEMORY)).state
        is SandboxState.RUNNING
    )


# --------------------------------------------------------------------- connection


def test_a_connection_carries_a_bearer_scheme_as_data(
    provider: LocalFirecrackerProvider,
) -> None:
    # A different scheme from the isolation provider's, which is what proves the header name is
    # data on the descriptor rather than a branch in the SDK (R9.4).
    handle = provider.provision(spec(exposed_ports=(8080, 9000))).handle

    descriptor = provider.issue_connection(handle, (9000, 8080), 120)

    assert descriptor.auth_header_name == AUTH_HEADER_NAME == "Authorization"
    assert descriptor.auth_header_value.startswith(f"{AUTH_SCHEME} ")
    assert descriptor.ports == (8080, 9000)
    assert descriptor.expires_at == START + timedelta(seconds=120)
    assert descriptor.base_url == f"http://127.0.0.1:8081/sandboxes/{handle.sandbox_id}"


def test_each_issued_credential_is_distinct(provider: LocalFirecrackerProvider) -> None:
    handle = provider.provision(spec()).handle

    values = {
        provider.issue_connection(handle, (8080,), 60).auth_header_value
        for _ in range(8)
    }
    assert len(values) == 8


def test_a_credential_is_scoped_to_its_sandbox_its_ports_and_its_expiry(
    provider: LocalFirecrackerProvider, clock: Clock
) -> None:
    first = provider.provision(spec(session_id="ses-1", exposed_ports=(8080, 9000)))
    second = provider.provision(spec(session_id="ses-2", exposed_ports=(8080,)))
    descriptor = provider.issue_connection(first.handle, (8080,), 60)

    assert provider.resolve_connection(descriptor.auth_header_value, 8080) == (
        first.handle
    )
    # Port-scoped: an exposed port the credential was not issued for is not admitted.
    assert provider.resolve_connection(descriptor.auth_header_value, 9000) is None
    # Sandbox-scoped: nothing about this value reaches the other Sandbox.
    assert (
        provider.resolve_connection(descriptor.auth_header_value, 8080) != second.handle
    )
    # Expiring: the credential stops admitting anything once its expiry has passed.
    clock.advance(60)
    assert provider.resolve_connection(descriptor.auth_header_value, 8080) is None


def test_a_suspended_sandbox_still_accepts_its_credential(
    provider: LocalFirecrackerProvider,
) -> None:
    # This provider declares `auto_resume_on_request`, so a request on an existing credential is
    # what resumes the Sandbox; revoking on suspend would make that impossible.
    handle = provider.provision(spec()).handle
    descriptor = provider.issue_connection(handle, (8080,), 60)
    provider.suspend(handle)

    assert provider.resolve_connection(descriptor.auth_header_value, 8080) == handle


def test_terminate_revokes_every_issued_credential(
    provider: LocalFirecrackerProvider,
) -> None:
    handle = provider.provision(spec()).handle
    descriptor = provider.issue_connection(handle, (8080,), 3_600)

    provider.terminate(handle)

    assert provider.resolve_connection(descriptor.auth_header_value, 8080) is None


@pytest.mark.parametrize(
    "value", ["", "Bearer", "Bearer ", "Basic abc", "unknown-token"]
)
def test_a_malformed_or_unknown_credential_admits_nothing(
    provider: LocalFirecrackerProvider, value: str
) -> None:
    provider.provision(spec())

    assert provider.resolve_connection(value, 8080) is None


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
    provider: LocalFirecrackerProvider,
    ports: tuple[int, ...],
    ttl: int,
    message: str,
) -> None:
    handle = provider.provision(spec()).handle

    with pytest.raises(ValueError, match=message):
        provider.issue_connection(handle, ports, ttl)


# --------------------------------------------------------- release check and discovery


def test_release_check_reports_outstanding_resources_until_terminate(
    provider: LocalFirecrackerProvider,
) -> None:
    handle = provider.provision(spec()).handle
    provider.issue_connection(handle, (8080,), 60)

    outstanding = provider.release_check(handle)
    assert f"sandbox/{handle.sandbox_id}" in outstanding
    assert "network-interface/attachment-1" in outstanding
    assert f"endpoint/{handle.sandbox_id}" in outstanding

    provider.terminate(handle)
    # R10.9: the Session_Orchestrator asserts emptiness rather than trusting terminate.
    assert provider.release_check(handle) == []


def test_release_check_reports_no_network_interface_without_an_attachment(
    provider: LocalFirecrackerProvider,
) -> None:
    handle = provider.provision(spec(egress_attachment_ref=None)).handle

    assert provider.release_check(handle) == [f"sandbox/{handle.sandbox_id}"]


def test_release_check_on_an_unheld_handle_is_empty(
    provider: LocalFirecrackerProvider,
) -> None:
    assert provider.release_check(SandboxHandle(PROVIDER_NAME, "sbx-absent", {})) == []


def test_discover_matches_on_the_tenant_and_session_tags(
    provider: LocalFirecrackerProvider,
) -> None:
    # The Reaper reaches a Sandbox whose handle was never recorded using only these tags (R11.7).
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


def test_discover_reports_terminated_sandboxes_with_their_state(
    provider: LocalFirecrackerProvider,
) -> None:
    handle = provider.provision(spec()).handle
    provider.terminate(handle)

    (found,) = provider.discover({"sessionId": "ses-1"})

    assert found.state is SandboxState.TERMINATED


def test_two_provider_instances_hold_separate_sandboxes(clock: Clock) -> None:
    # Each test gets its own provider, so one test's Sandboxes cannot leak into another's quota.
    first = LocalFirecrackerProvider(clock=clock)
    second = LocalFirecrackerProvider(clock=clock)
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
