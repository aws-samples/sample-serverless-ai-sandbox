# kiro-classification: public
#
# Unit tests for the Compute_Provider seam (R5.6, R5.10).

import dataclasses
import inspect
import re
from typing import Any

import pytest

from control_plane.providers import base
from control_plane.providers.base import (
    CapabilityUnsupported,
    CapacityDimension,
    ComputeProvider,
    QuotaExhausted,
)

EXPECTED_ABSTRACT_METHODS = frozenset(
    {
        "capabilities",
        "limits",
        "provision",
        "describe",
        "suspend",
        "resume",
        "terminate",
        "issue_connection",
        "consumed_capacity",
        "release_check",
        "discover",
    }
)

# Concepts private to one backend. None may appear in a public name of the seam, because a
# contract that names them is that backend's interface rather than an abstraction (R5.6).
BACKEND_SPECIFIC_TERMS = (
    "lambda",
    "microvm",
    "micro_vm",
    "firecracker",
    "function",
    "invoke",
    "invocation",
    "jwe",
    "runhook",
    "run_hook",
    "layer",
    "aws",
)


def _public_names() -> list[str]:
    """Every public name the seam exports, including members of its types."""
    names: list[str] = []
    for exported in base.__all__:
        names.append(exported)
        obj = getattr(base, exported)
        names.extend(n for n in vars(obj) if not n.startswith("_"))
    return names


def test_no_public_name_names_a_backend_specific_concept() -> None:
    offenders = [
        (name, term)
        for name in _public_names()
        for term in BACKEND_SPECIFIC_TERMS
        if term in re.sub(r"[^a-z_]", "", name.lower())
    ]
    assert offenders == []


def test_compute_provider_is_abstract_and_fixes_the_expected_method_set() -> None:
    assert ComputeProvider.__abstractmethods__ == EXPECTED_ABSTRACT_METHODS
    with pytest.raises(TypeError):
        ComputeProvider()  # type: ignore[abstract]


def test_a_partial_implementation_cannot_be_instantiated() -> None:
    class Partial(ComputeProvider):
        name = "partial"

        def capabilities(self) -> base.ProviderCapabilities:  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(TypeError):
        Partial()  # type: ignore[abstract]


@pytest.mark.parametrize(
    "type_name",
    [
        "ProviderCapabilities",
        "ProviderLimits",
        "SandboxSpec",
        "SandboxHandle",
        "SandboxStatus",
        "ConnectionDescriptor",
    ],
)
def test_contract_types_are_frozen_dataclasses(type_name: str) -> None:
    cls: Any = getattr(base, type_name)
    assert cls.__dataclass_params__.frozen
    assert dataclasses.is_dataclass(cls)


def test_quota_exhausted_carries_the_provider_supplied_reason() -> None:
    error = QuotaExhausted(
        "MicroVMMemoryPerRegion", CapacityDimension.MEMORY_BYTES_PER_REGION
    )
    assert error.quota_name == "MicroVMMemoryPerRegion"
    assert error.dimension is CapacityDimension.MEMORY_BYTES_PER_REGION
    assert "MicroVMMemoryPerRegion" in str(error)
    assert "memory-bytes-per-region" in str(error)


def test_capability_unsupported_names_the_capability_and_the_provider() -> None:
    error = CapabilityUnsupported("suspend_fidelity=memory-and-disk", "fargate-task")
    assert error.capability == "suspend_fidelity=memory-and-disk"
    assert error.provider_name == "fargate-task"
    assert "fargate-task" in str(error)


def test_issue_connection_takes_ports_and_a_ttl_rather_than_a_scheme() -> None:
    signature = inspect.signature(ComputeProvider.issue_connection)
    assert list(signature.parameters) == ["self", "handle", "ports", "ttl_seconds"]
