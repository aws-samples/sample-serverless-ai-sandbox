# kiro-classification: public
"""`DemoStack`: the Demo_Application entry point and its role (R15.2, R16.1).

Skeleton. Phase 17 fills it. It is last because the demonstration drives both deployed surfaces:
the Control_Plane API for the main workload path and the Agent_Tool_Interface for the multi-turn
step of R20.6. It names no Deployment_Profile, so `build_app` resolves the main workload path to
the `single-tenant` default (R11.22).
"""

from __future__ import annotations

from typing import Any

import aws_cdk as cdk
from constructs import Construct

from iac.agent_tool_stack import AgentToolStack
from iac.control_plane_stack import ControlPlaneStack

__all__ = ["DemoStack"]


class DemoStack(cdk.Stack):
    """The demonstration entry point and its role. Filled by phase 17."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        control_plane: ControlPlaneStack,
        agent_tool: AgentToolStack,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.control_plane = control_plane
        self.agent_tool = agent_tool
        for upstream in (control_plane, agent_tool):
            self.add_stack_dependency(upstream)
