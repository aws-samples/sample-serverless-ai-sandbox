# kiro-classification: public
"""The CDK application: seven stacks in dependency order (R15.1, R15.2).

`cdk.json` at the repository root names `build_app` through this module, so the CLI and the
offline suite synthesise the same graph. `build_app` returns the app rather than synthesising it
so that a test can synthesise into its own directory.

Two synthesis-time guards read CDK context inside `build_app`, ahead of the first stack: the
Region allowlist of R15.4 and the `deploymentProfile` resolution of R11.15 and R11.16. They sit in
`build_app` rather than in `main` because `main` is only what `cdk.json` invokes, so a guard placed
there would be bypassed by every test and by every programmatic caller.
"""

from __future__ import annotations

from typing import Any, Final

import aws_cdk as cdk

from control_plane.tenancy import DeploymentProfile, DeploymentProfileError
from iac.agent_tool_stack import AgentToolStack
from iac.control_plane_stack import ControlPlaneStack
from iac.demo_stack import DemoStack
from iac.egress_stack import EgressStack
from iac.image_stack import ImageStack
from iac.network_stack import NetworkStack
from iac.state_stack import StateStack

__all__ = [
    "DEFAULT_REGION",
    "MICROVM_LAUNCH_REGIONS",
    "PROFILE_CONTEXT_KEY",
    "REGION_CONTEXT_KEY",
    "STACK_NAMES",
    "RegionUnavailableError",
    "build_app",
    "main",
]

#: Every stack the app declares, in the order it declares them. The design's IaC_Package table
#: names each one, and `cdk destroy --all` (R15.5) unwinds this order.
STACK_NAMES: Final = (
    "NetworkStack",
    "StateStack",
    "ImageStack",
    "EgressStack",
    "ControlPlaneStack",
    "AgentToolStack",
    "DemoStack",
)

#: The context key naming the deployment Region, and the key naming the Deployment_Profile.
REGION_CONTEXT_KEY: Final = "region"
PROFILE_CONTEXT_KEY: Final = "deploymentProfile"

#: The five Regions AWS Lambda MicroVMs launched in, from Requirement 15's research findings:
#: N. Virginia, Ohio, Oregon, Tokyo and Ireland. Pinned rather than discovered, because synthesis
#: makes no network call and needs no credentials (R15.9).
MICROVM_LAUNCH_REGIONS: Final = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ap-northeast-1",
    "eu-west-1",
)

#: The Region an absent context value resolves to. A default keeps synthesis independent of the
#: ambient AWS environment; a Region the operator names is still admitted only if it is above.
DEFAULT_REGION: Final = MICROVM_LAUNCH_REGIONS[0]

#: The two literals R11.15 admits, read off the enum the handler parses the same value back with,
#: so the accepted set has one definition in this repository.
ACCEPTED_PROFILES: Final = tuple(profile.value for profile in DeploymentProfile)


class RegionUnavailableError(ValueError):
    """The named deployment Region is not one where AWS Lambda MicroVMs is available (R15.4)."""


def _resolve_region(app: cdk.App) -> str:
    """Admit only a pinned launch Region, failing before the first stack exists (R15.4)."""
    value = app.node.try_get_context(REGION_CONTEXT_KEY)
    if value is None:
        return DEFAULT_REGION
    if not isinstance(value, str) or value not in MICROVM_LAUNCH_REGIONS:
        available = ", ".join(repr(region) for region in MICROVM_LAUNCH_REGIONS)
        raise RegionUnavailableError(
            f"context {REGION_CONTEXT_KEY!r} must name a Region in which AWS Lambda MicroVMs "
            f"is available, one of {available}; received {value!r}"
        )
    return value


def _resolve_profile(app: cdk.App) -> str:
    """Resolve the Deployment_Profile, defaulting an absent value (R11.15, R11.16).

    Absent means the key is unconfigured. A present value is one of the two literals exactly: an
    empty or near-miss value is one the operator believes they declared, so it fails rather than
    silently becoming the default.
    """
    value = app.node.try_get_context(PROFILE_CONTEXT_KEY)
    if value is None:
        return DeploymentProfile.SINGLE_TENANT.value
    if not isinstance(value, str) or value not in ACCEPTED_PROFILES:
        accepted = ", ".join(repr(profile) for profile in ACCEPTED_PROFILES)
        raise DeploymentProfileError(
            f"context {PROFILE_CONTEXT_KEY!r} must be one of {accepted}; received {value!r}"
        )
    return value


def build_app(**kwargs: Any) -> cdk.App:
    """Construct the app and every stack, each one after the stacks it depends on.

    Both guards run before the first stack, so an unavailable Region or an undeclared
    Deployment_Profile fails synthesis with no resource created. The admitted Region is the one
    every stack is placed in; the resolved profile reaches `ControlPlaneStack` and nothing else.
    """
    app = cdk.App(**kwargs)
    env = cdk.Environment(region=_resolve_region(app))
    profile = _resolve_profile(app)

    network = NetworkStack(app, "NetworkStack", env=env)
    state = StateStack(app, "StateStack", env=env)
    image = ImageStack(app, "ImageStack", env=env)
    egress = EgressStack(app, "EgressStack", network=network, env=env)
    control_plane = ControlPlaneStack(
        app,
        "ControlPlaneStack",
        state=state,
        image=image,
        egress=egress,
        network=network,
        profile=profile,
        env=env,
    )
    agent_tool = AgentToolStack(
        app, "AgentToolStack", control_plane=control_plane, state=state, env=env
    )
    DemoStack(
        app, "DemoStack", control_plane=control_plane, agent_tool=agent_tool, env=env
    )

    # Cost allocation tags on every resource in every stack.
    cdk.Tags.of(app).add("Project", "AgentSandbox")
    cdk.Tags.of(app).add("ManagedBy", "CDK")

    return app


def main() -> None:
    """The entry point `cdk.json` invokes."""
    build_app().synth()


if __name__ == "__main__":
    main()
