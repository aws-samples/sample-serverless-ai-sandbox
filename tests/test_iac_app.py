# kiro-classification: public
"""The CDK app synthesises, and its seven stacks carry the designed dependency edges.

Synthesis runs through the Python API rather than the `cdk` CLI so that the assertion holds in the
offline suite, which has no network access and no deployed resources (R15.9).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
from aws_cdk.cx_api import CloudAssembly, CloudFormationStackArtifact

from iac.app import STACK_NAMES, build_app

#: Each stack against the stacks it depends on. Read off the design's IaC_Package table: the
#: network and the state store stand alone, the image publishes a version, the proxy fleet lands
#: in the VPC, the Control_Plane needs state, image, egress and the network connector generation
#: the orchestrator passes as `SandboxSpec.egress_attachment_ref`, the tool surface hangs off the
#: Control_Plane API and writes its per-tool-session entries to the state table, and the
#: demonstration drives both surfaces.
#:
#: The last two edges are declared rather than left transitive. Threading `network=` and `state=`
#: into those constructors puts the dependency in the signature a reviewer reads, and keeps this
#: assertion an equality: tasks 12.9 and 12.11 reference those exported values, at which point CDK
#: would add the edges itself and a subset check would have hidden the difference.
EXPECTED_EDGES: Final[dict[str, set[str]]] = {
    "NetworkStack": set(),
    "StateStack": set(),
    "ImageStack": set(),
    "EgressStack": {"NetworkStack"},
    "ControlPlaneStack": {"StateStack", "ImageStack", "EgressStack", "NetworkStack"},
    "AgentToolStack": {"ControlPlaneStack", "StateStack"},
    "DemoStack": {"ControlPlaneStack", "AgentToolStack"},
}

#: The stacks whose templates are still empty, each waiting on the task that fills it: 12.11 fills
#: `ControlPlaneStack` and `AgentToolStack`, and phase 17 fills `DemoStack`. Each of those tasks
#: removes its stacks from here; task 12.8 filled `ImageStack`, task 12.9 filled `NetworkStack`
#: and `EgressStack`, and task 12.10 filled `StateStack`, which is why none of those four is named
#: here.
STACKS_AWAITING_THEIR_FILLING_TASK: Final[frozenset[str]] = frozenset(
    {
        "ImageStack",
        "DemoStack",
    }
)

REPOSITORY_ROOT: Final = Path(__file__).resolve().parent.parent


@pytest.fixture(name="assembly")
def _assembly(tmp_path: Path) -> Iterator[CloudAssembly]:
    yield build_app(outdir=str(tmp_path)).synth()


def _stacks(assembly: CloudAssembly) -> list[CloudFormationStackArtifact]:
    return list(assembly.stacks)


def test_synthesis_emits_the_seven_stacks_the_design_names(
    assembly: CloudAssembly,
) -> None:
    names = [stack.stack_name for stack in _stacks(assembly)]
    assert len(names) == 7
    assert set(names) == set(STACK_NAMES)


def test_stack_names_are_declared_in_dependency_order() -> None:
    # The declaration order in `build_app` is the deploy order, so no stack may be named ahead of
    # one it depends on.
    position = {name: index for index, name in enumerate(STACK_NAMES)}
    for name, upstreams in EXPECTED_EDGES.items():
        for upstream in upstreams:
            assert position[upstream] < position[name]


def test_every_stack_depends_on_exactly_the_stacks_the_design_gives_it(
    assembly: CloudAssembly,
) -> None:
    observed = {
        stack.stack_name: {
            dependency.stack_name
            for dependency in stack.dependencies
            if isinstance(dependency, CloudFormationStackArtifact)
        }
        for stack in _stacks(assembly)
    }
    assert observed == EXPECTED_EDGES


def test_exactly_the_stacks_awaiting_their_task_declare_no_resources(
    assembly: CloudAssembly,
) -> None:
    # Asserted in both directions, which is what keeps the set above from drifting: a stack that
    # gains resources while still named there fails the first assertion, and a stack named nowhere
    # yet still empty fails the second. Either way the failure names the stack.
    #
    # The dependency wiring in `build_app` emits nothing itself — `add_stack_dependency` is the
    # supported name in aws-cdk-lib 2.266.0, where `add_dependency` is deprecated — so an empty
    # template means the stack declares no resources, not that the edges were lost.
    for stack in _stacks(assembly):
        resources = stack.template.get("Resources", {})
        if stack.stack_name in STACKS_AWAITING_THEIR_FILLING_TASK:
            assert resources == {}, stack.stack_name
        else:
            assert resources != {}, stack.stack_name


def test_cdk_json_invokes_this_app() -> None:
    config = json.loads((REPOSITORY_ROOT / "cdk.json").read_text(encoding="utf-8"))
    assert "iac.app" in config["app"]
