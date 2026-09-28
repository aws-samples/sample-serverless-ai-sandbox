# kiro-classification: public
#
# Unit tests for the explicit Compute_Provider registry and the isolation allowlist (R5.6).

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from control_plane.providers import registry
from control_plane.providers.base import (
    CapacityDimension,
    ComputeProvider,
    ConnectionDescriptor,
    ProviderCapabilities,
    ProviderLimits,
    SandboxHandle,
    SandboxSpec,
    SandboxState,
    SandboxStatus,
    SuspendFidelity,
)


class StubProvider(ComputeProvider):
    """A complete but inert implementation, so registration is what is under test."""

    def __init__(self, name: str) -> None:
        self.name = name

    def capabilities(self) -> ProviderCapabilities:
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
            max_duration_seconds=28_800,
            min_duration_seconds=1,
            max_run_config_bytes=16_384,
            capacity_dimension=CapacityDimension.MEMORY_BYTES_PER_REGION,
            capacity_limit=None,
            memory_bytes_choices=(2_147_483_648,),
        )

    def _status(self, handle: SandboxHandle) -> SandboxStatus:
        return SandboxStatus(
            handle=handle,
            state=SandboxState.RUNNING,
            memory_bytes=2_147_483_648,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            state_reason=None,
        )

    def provision(self, spec: SandboxSpec) -> SandboxStatus:
        return self._status(SandboxHandle(self.name, spec.session_id, {}))

    def describe(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(handle)

    def suspend(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(handle)

    def resume(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(handle)

    def terminate(self, handle: SandboxHandle) -> SandboxStatus:
        return self._status(handle)

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> ConnectionDescriptor:
        return ConnectionDescriptor(
            base_url="https://example.invalid",
            auth_header_name="X-Stub-Auth",
            auth_header_value="stub",
            ports=ports,
            expires_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    def consumed_capacity(self) -> int:
        return 0

    def release_check(self, handle: SandboxHandle) -> list[str]:
        return []

    def discover(self, tags: dict[str, str]) -> list[SandboxStatus]:
        return []


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    """Restore the module-level registry, so one test cannot admit a provider for another."""
    saved = dict(registry.REGISTRY)
    registry.REGISTRY.clear()
    try:
        yield
    finally:
        registry.REGISTRY.clear()
        registry.REGISTRY.update(saved)


def test_importing_the_registry_populates_nothing() -> None:
    # Registration is by explicit call from an explicit import, never by discovery, so a
    # freshly imported registry holds nothing at all.
    assert registry.REGISTRY == {}
    assert registry.registered_names() == ()


def test_an_approved_provider_registers_and_is_retrievable_by_name() -> None:
    provider = StubProvider("lambda-microvm")

    registry.register(provider)

    assert registry.REGISTRY == {"lambda-microvm": provider}
    assert registry.get("lambda-microvm") is provider
    assert registry.registered_names() == ("lambda-microvm",)


@pytest.mark.parametrize(
    "name", ["local-firecracker", "fargate-task", "lambda-mi-gpu", ""]
)
def test_a_provider_absent_from_the_allowlist_is_refused(name: str) -> None:
    with pytest.raises(
        ValueError, match="not approved as an isolation boundary"
    ) as raised:
        registry.register(StubProvider(name))

    assert name in str(raised.value)
    # Refusal leaves no trace: a rejected provider is not reachable through the registry.
    assert registry.REGISTRY == {}


def test_the_allowlist_holds_only_the_isolation_boundary() -> None:
    assert isinstance(registry.ISOLATION_APPROVED, frozenset)
    assert registry.ISOLATION_APPROVED == frozenset({"lambda-microvm"})


def test_get_on_an_unregistered_name_reports_what_is_registered() -> None:
    registry.register(StubProvider("lambda-microvm"))

    with pytest.raises(LookupError) as raised:
        registry.get("fargate-task")

    message = str(raised.value)
    assert "fargate-task" in message
    assert "lambda-microvm" in message


def test_get_before_any_registration_says_none_are_registered() -> None:
    with pytest.raises(LookupError, match="none"):
        registry.get("lambda-microvm")
