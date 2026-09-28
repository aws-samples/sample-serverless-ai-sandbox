# kiro-classification: public
"""The two synthesis-time context guards: the Region allowlist and the Deployment_Profile.

Property 26 (Region admission) is paused in favour of these example cases, because the allowlist
is five pinned strings and the interesting neighbourhood around them — other real Regions,
one-character edits, case variants, malformed values — is enumerable by hand.

Every case calls `build_app` rather than `main`, which is also what makes the placement checkable:
a guard living in `main` would be invisible to this file and to any other programmatic caller.

**Validates: Requirements 15.4, 11.15, 11.16, 11.19**
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest
from aws_cdk.cx_api import CloudAssembly

from control_plane.tenancy import DeploymentProfileError
from iac.app import (
    DEFAULT_REGION,
    MICROVM_LAUNCH_REGIONS,
    PROFILE_CONTEXT_KEY,
    REGION_CONTEXT_KEY,
    RegionUnavailableError,
    build_app,
)
from iac.control_plane_stack import ControlPlaneStack

#: Real AWS Regions in which AWS Lambda MicroVMs did not launch. A Region existing is not the
#: question the guard answers.
OTHER_REAL_REGIONS: Final = (
    "us-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-2",
    "ap-northeast-2",
    "sa-east-1",
    "ca-central-1",
    "us-gov-west-1",
)

#: One character added, dropped or substituted against an allowlist entry. These are the values an
#: operator most plausibly types and least plausibly notices.
NEAR_MISSES: Final = (
    "us-east-l",
    "us-east-11",
    "us-east-",
    "us-eest-2",
    "us-west-3",
    "ap-northeast-l",
    "eu-west-l",
)

CASE_VARIANTS: Final = (
    "US-EAST-1",
    "Us-East-1",
    "us-East-1",
    "EU-WEST-1",
    "ap-Northeast-1",
)

MALFORMED_REGIONS: Final = (
    "",
    "   ",
    "us east 1",
    "us_east_1",
    "arn:aws:ec2:us-east-1",
    "us-east-1,us-east-2",
    "*",
)

#: Values CDK context can carry that are not strings at all: `-c region` with no value yields
#: `True`, and `cdk.json` context is JSON, so a number or a list can arrive.
NON_STRING_VALUES: Final = (True, 3, 1.0, ["us-east-1"], {"region": "us-east-1"})


def _synthesise(outdir: Path, **context: Any) -> CloudAssembly:
    return build_app(outdir=str(outdir), context=context).synth()


def _control_plane(outdir: Path, **context: Any) -> ControlPlaneStack:
    app = build_app(outdir=str(outdir), context=context)
    stack = app.node.find_child("ControlPlaneStack")
    assert isinstance(stack, ControlPlaneStack)
    return stack


# --- The Region allowlist (R15.4) ---------------------------------------------------------------


def test_the_allowlist_is_the_five_launch_regions() -> None:
    assert MICROVM_LAUNCH_REGIONS == (
        "us-east-1",
        "us-east-2",
        "us-west-2",
        "ap-northeast-1",
        "eu-west-1",
    )


@pytest.mark.parametrize("region", MICROVM_LAUNCH_REGIONS)
def test_each_launch_region_synthesises_and_places_every_stack_in_itself(
    region: str, tmp_path: Path
) -> None:
    assembly = _synthesise(tmp_path, **{REGION_CONTEXT_KEY: region})
    placements = {
        stack.stack_name: stack.environment.region for stack in assembly.stacks
    }
    assert len(placements) == 7
    assert set(placements.values()) == {region}


def test_an_absent_region_resolves_to_the_default(tmp_path: Path) -> None:
    assembly = _synthesise(tmp_path)
    assert {stack.environment.region for stack in assembly.stacks} == {DEFAULT_REGION}
    assert DEFAULT_REGION in MICROVM_LAUNCH_REGIONS


@pytest.mark.parametrize(
    "region",
    [
        *OTHER_REAL_REGIONS,
        *NEAR_MISSES,
        *CASE_VARIANTS,
        *MALFORMED_REGIONS,
    ],
)
def test_a_region_outside_the_allowlist_fails_synthesis(
    region: str, tmp_path: Path
) -> None:
    with pytest.raises(RegionUnavailableError) as raised:
        build_app(outdir=str(tmp_path), context={REGION_CONTEXT_KEY: region})
    message = str(raised.value)
    assert repr(region) in message
    for admitted in MICROVM_LAUNCH_REGIONS:
        assert admitted in message


@pytest.mark.parametrize("region", NON_STRING_VALUES)
def test_a_region_that_is_not_a_string_fails_synthesis(
    region: object, tmp_path: Path
) -> None:
    with pytest.raises(RegionUnavailableError):
        build_app(outdir=str(tmp_path), context={REGION_CONTEXT_KEY: region})


def test_the_region_guard_precedes_every_stack(tmp_path: Path) -> None:
    """`build_app`, not `main`, and before the first construct: nothing reaches the output."""
    with pytest.raises(RegionUnavailableError):
        build_app(outdir=str(tmp_path), context={REGION_CONTEXT_KEY: "eu-central-1"})
    assert list(tmp_path.iterdir()) == []


# --- The Deployment_Profile (R11.15, R11.16, R11.19) --------------------------------------------


@pytest.mark.parametrize("profile", ["single-tenant", "multi-tenant"])
def test_each_accepted_profile_reaches_the_control_plane_stack(
    profile: str, tmp_path: Path
) -> None:
    assert _control_plane(tmp_path, **{PROFILE_CONTEXT_KEY: profile}).profile == profile


def test_an_absent_profile_is_not_an_error_and_resolves_to_single_tenant(
    tmp_path: Path,
) -> None:
    assert _control_plane(tmp_path).profile == "single-tenant"


@pytest.mark.parametrize(
    "profile",
    [
        "no-tenant",
        "Single-Tenant",
        "MULTI-TENANT",
        "single_tenant",
        "singletenant",
        "multi-tenant ",
        "",
        "   ",
        True,
        3,
        ["single-tenant"],
    ],
)
def test_a_third_profile_value_fails_synthesis_naming_it_and_both_literals(
    profile: object, tmp_path: Path
) -> None:
    with pytest.raises(DeploymentProfileError) as raised:
        build_app(outdir=str(tmp_path), context={PROFILE_CONTEXT_KEY: profile})
    message = str(raised.value)
    assert repr(profile) in message
    assert "'single-tenant'" in message and "'multi-tenant'" in message


def test_the_profile_guard_precedes_every_stack(tmp_path: Path) -> None:
    with pytest.raises(DeploymentProfileError):
        build_app(outdir=str(tmp_path), context={PROFILE_CONTEXT_KEY: "no-tenant"})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("profile", ["single-tenant", "multi-tenant"])
def test_no_stack_but_the_control_plane_is_handed_the_profile(
    profile: str, tmp_path: Path
) -> None:
    """The threading half of R11.19: five of the seven stacks never see the value at all.

    Property 44 owns the synthesised-output half — that nothing provisioned differs between the
    two profiles. This is the structural precondition for it.
    """
    app = build_app(outdir=str(tmp_path), context={PROFILE_CONTEXT_KEY: profile})
    holders = {
        child.node.id
        for child in app.node.children
        if getattr(child, "profile", None) is not None
    }
    assert holders == {"ControlPlaneStack"}
