# kiro-classification: public
"""`AgentToolStack`: the Agent_Tool_Interface (R15.2, R20.1).

Task 12.11 fills it with the MCP function, its route and authorizer on the Control_Plane API, its
Tenant role or per-Tenant role mapping, and the per-tool-session state table entries. It takes
`ControlPlaneStack` for the API and the authorizer, and `StateStack` for the table those
per-tool-session entries are written to.
"""

from __future__ import annotations

from typing import Any, Final

import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

from iac.control_plane_stack import _LAMBDA_ASSET_EXCLUDES, ControlPlaneStack
from iac.state_stack import StateStack

__all__ = ["AgentToolStack"]

#: The Python runtime the tool function uses.
LAMBDA_RUNTIME: Final = lambda_.Runtime.PYTHON_3_13

#: Log retention matching the Control_Plane.
LOG_RETENTION: Final = logs.RetentionDays.SIX_MONTHS

#: Timeout for the agent tool function.
TOOL_FUNCTION_TIMEOUT: Final = cdk.Duration.seconds(29)


class AgentToolStack(cdk.Stack):
    """The MCP function, its route and its Tenant role mapping. Filled by task 12.11."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        control_plane: ControlPlaneStack,
        state: StateStack,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.control_plane = control_plane
        self.state = state
        for upstream in (control_plane, state):
            self.add_stack_dependency(upstream)

        self.tool_function = self._tool_function()
        self.tool_integration = self._tool_integration()
        self._tool_route()

    def _tool_function(self) -> lambda_.Function:
        """The Agent_Tool_Interface Lambda function (MCP server)."""
        function = lambda_.Function(
            self,
            "AgentToolFunction",
            runtime=LAMBDA_RUNTIME,
            handler="agent_tools.handler.handler",
            code=lambda_.Code.from_asset(".", exclude=_LAMBDA_ASSET_EXCLUDES),
            timeout=TOOL_FUNCTION_TIMEOUT,
            log_group=logs.LogGroup(
                self, "AgentToolLogs",
                retention=LOG_RETENTION,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            ),
            environment={
                "TABLE_NAME": self.state.table.table_name,
                "API_HANDLER_FUNCTION_NAME": self.control_plane.api_handler.function_name,
                "TENANT_ID": self.control_plane.tenant_id,
            },
        )
        # Grant DynamoDB read/write for per-tool-session state entries.
        self.state.table.grant_read_write_data(function)

        # Grant the tool function permission to invoke the API handler Lambda directly.
        # This bypasses API Gateway, avoiding auth mismatches under multi-tenant
        # deployment (where the API uses a Lambda authorizer that rejects SigV4).
        self.control_plane.api_handler.grant_invoke(function)

        return function

    def _tool_integration(self) -> apigwv2.CfnIntegration:
        """Lambda proxy integration for the agent tool route on the Control_Plane API."""
        integration = apigwv2.CfnIntegration(
            self,
            "ToolIntegration",
            api_id=self.control_plane.http_api.ref,
            integration_type="AWS_PROXY",
            integration_uri=self.tool_function.function_arn,
            payload_format_version="2.0",
        )
        # Grant API Gateway permission to invoke the tool function.
        self.tool_function.add_permission(
            "ApiGatewayToolInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=self.control_plane.format_arn(
                service="execute-api",
                resource=self.control_plane.http_api.ref,
                resource_name="*",
            ),
        )
        return integration

    def _tool_route(self) -> apigwv2.CfnRoute:
        """The ``POST /tool`` route with ``AWS_IAM`` authorization (R6.3)."""
        return apigwv2.CfnRoute(
            self,
            "ToolRoute",
            api_id=self.control_plane.http_api.ref,
            route_key="POST /tool",
            authorization_type="AWS_IAM",
            target=f"integrations/{self.tool_integration.ref}",
        )
