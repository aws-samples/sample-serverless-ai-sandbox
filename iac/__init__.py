# kiro-classification: public
"""The IaC_Package: one AWS CDK application in Python, seven stacks (R15.1, R15.2).

`iac.app.build_app` is the whole graph. The stacks are filled one task at a time, and each stack
module's docstring says whether it is still a skeleton and which task fills it.

`iac.app` is deliberately not imported here: `cdk.json` runs it as `python -m iac.app`, and a
package that imported it would leave it in `sys.modules` before runpy executed it.
"""

from iac.agent_tool_stack import AgentToolStack
from iac.control_plane_stack import ControlPlaneStack
from iac.demo_stack import DemoStack
from iac.egress_stack import EgressStack
from iac.image_stack import ImageStack
from iac.network_stack import NetworkStack
from iac.state_stack import StateStack

__all__ = [
    "AgentToolStack",
    "ControlPlaneStack",
    "DemoStack",
    "EgressStack",
    "ImageStack",
    "NetworkStack",
    "StateStack",
]
