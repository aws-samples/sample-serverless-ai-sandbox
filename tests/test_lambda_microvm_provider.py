"""The `lambda-microvm` provider's connector obligation (R12.2, R12.3, R12.6, R12.8).

A MicroVM reaches the public internet by default and a connector replaces that default rather than
restricting it, so a spec with no attachment reference provisions a Sandbox with no
Egress_Controller in front of it. The refusal is asserted here, on the adapter, because that is
where the design places the obligation: `SandboxSpec.egress_attachment_ref` stays `str | None` for
a provider that governs egress by other means.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import pytest

from control_plane.providers.base import SandboxHandle, SandboxSpec, SandboxState
from control_plane.providers.lambda_microvm import (
    MICROVM_MEMORY_CHOICES,
    PROVIDER_NAME,
    LambdaMicroVmProvider,
    MissingNetworkConnector,
)

ATTACHMENT_REF = (
    "arn:aws:lambda:us-east-1:123456789012:network-connector/egress-connector-g1"
)


class RecordingClient:
    """`create_micro_vm` and `get_micro_vm`, with every request recorded, and nothing else."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.described: Mapping[str, Any] = {}

    def create_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        self.requests.append(dict(request))
        return {
            "microvmId": "mv-1",
            "state": SandboxState.RUNNING.value,
            "memoryBytes": MICROVM_MEMORY_CHOICES[0],
        }

    def get_micro_vm(self, **request: Any) -> Mapping[str, Any]:
        self.requests.append(dict(request))
        return self.described

    def _unreached(self, **request: Any) -> Mapping[str, Any]:
        raise NotImplementedError(
            "only create_micro_vm and get_micro_vm are served here"
        )

    suspend_micro_vm = _unreached
    resume_micro_vm = _unreached
    terminate_micro_vm = _unreached
    list_micro_vms = _unreached
    create_micro_vm_endpoint_token = _unreached


def spec(**overrides: object) -> SandboxSpec:
    base = SandboxSpec(
        session_id="ses-1",
        tenant_id="tnt-1",
        image_ref="sandbox-image:1",
        memory_bytes=MICROVM_MEMORY_CHOICES[0],
        vcpu_millis=2_000,
        max_duration_seconds=3_600,
        idle_seconds_before_suspend=300,
        suspended_seconds_before_terminate=3_600,
        auto_resume=True,
        exposed_ports=(8080,),
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        egress_attachment_ref=ATTACHMENT_REF,
        egress_endpoint="proxy.example.com",
        start_config=b"{}",
        start_config_ref=None,
        tags={"tenantId": "tnt-1", "sessionId": "ses-1"},
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


@pytest.fixture(name="client")
def _client() -> RecordingClient:
    return RecordingClient()


@pytest.fixture(name="provider")
def _provider(client: RecordingClient) -> LambdaMicroVmProvider:
    return LambdaMicroVmProvider(client=client)


@pytest.mark.parametrize("absent", [None, ""])
def test_provision_refuses_a_spec_with_no_network_connector(
    provider: LambdaMicroVmProvider, client: RecordingClient, absent: str | None
) -> None:
    with pytest.raises(MissingNetworkConnector) as raised:
        provider.provision(spec(egress_attachment_ref=absent))

    # The message has to read as a refusal rather than a defect, so an operator seeing a failed
    # provision knows the deployment omitted the connector.
    assert "unrestricted internet access" in str(raised.value)
    # Refused, not provisioned then reported: the service was never called.
    assert client.requests == []


def test_the_refusal_is_the_value_error_provision_documents() -> None:
    assert issubclass(MissingNetworkConnector, ValueError)


def test_provision_passes_the_attachment_reference_through_unparsed(
    provider: LambdaMicroVmProvider, client: RecordingClient
) -> None:
    status = provider.provision(spec())

    # `RunMicrovm` takes `egressNetworkConnectors`, a list of up to ten ARNs. A wrong key name is
    # the failure worth asserting against: the service would ignore or reject it, and an ignored
    # connector is a Sandbox on the open internet.
    assert client.requests[0]["egressNetworkConnectors"] == [ATTACHMENT_REF]
    assert status.state is SandboxState.RUNNING


def test_release_check_reports_the_attachment_the_service_reports(
    provider: LambdaMicroVmProvider, client: RecordingClient
) -> None:
    """Read back under the same name it was sent, so an outstanding attachment is seen (R10.9)."""
    client.described = {
        "microVmId": "mv-1",
        "state": SandboxState.RUNNING.value,
        "memoryBytes": MICROVM_MEMORY_CHOICES[0],
        "egressNetworkConnectors": [ATTACHMENT_REF],
    }
    handle = SandboxHandle(provider_name=PROVIDER_NAME, sandbox_id="mv-1", opaque={})

    assert provider.release_check(handle) == [
        "sandbox/mv-1",
        f"network-interface/{ATTACHMENT_REF}",
    ]
