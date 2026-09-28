# kiro-classification: public
"""`ControlPlaneStack`: the Control_Plane, the Session_Orchestrator and the Reaper (R15.2).

Task 12.6 adds the per-Session Sandbox execution role template; task 12.11 fills the rest with the
HTTP API and its `AWS_IAM` authorizer on every route, the handler functions,
`SessionDataAccessRole`, the Standard state machine, the EventBridge Scheduler and Reaper function
and the dashboard.

It takes all four of `StateStack` (the table and bucket the handlers address), `ImageStack` (the
MicroVM image version the orchestration provisions from), `EgressStack` (the proxy endpoint and
policy store a Sandbox is attached to) and `NetworkStack` (the connector generation the
orchestrator passes as `SandboxSpec.egress_attachment_ref`).

It is also the one stack the resolved Deployment_Profile reaches, and it reaches nothing but the
Tenant resolver named in the handler environment (R11.19).
"""

from __future__ import annotations

import json
from typing import Any, Final

import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_scheduler as scheduler
from aws_cdk import aws_stepfunctions as sfn
from constructs import Construct

from control_plane.api.routes import ROUTES
from control_plane.orchestrator.definition import (
    TASK_STATES,
    to_asl,
)
from iac.egress_stack import EgressStack
from iac.image_stack import ImageStack
from iac.network_stack import NetworkStack
from iac.state_stack import StateStack

__all__ = ["_LAMBDA_ASSET_EXCLUDES", "ControlPlaneStack"]

#: The Python runtime every handler uses.
LAMBDA_RUNTIME: Final = lambda_.Runtime.PYTHON_3_13

#: Directories and files excluded from Lambda ``Code.from_asset(".")`` bundles to prevent
#: ``ENAMETOOLONG`` errors caused by bundling ``.venv/``, ``cdk.out/``, ``node_modules/``, etc.
_LAMBDA_ASSET_EXCLUDES: Final = [
    ".venv",
    ".venv/**",
    "cdk.out",
    "cdk.out/**",
    "node_modules",
    "node_modules/**",
    ".git",
    ".git/**",
    "__pycache__",
    "**/__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    "*.egg-info",
    "dist",
    "build",
    ".github",
    ".kiro",
    "sdk/typescript/node_modules",
    "sdk/typescript/dist",
    "cdk.context.json",
    "*.tsbuildinfo",
    ".DS_Store",
    "uv.lock",
    "console",
    "console/**",
]

#: Log retention for all Control_Plane functions (R14.1).
LOG_RETENTION: Final = logs.RetentionDays.SIX_MONTHS

#: Default handler timeout: the API Gateway HTTP API maximum integration timeout is 30 s, the
#: configured integration timeout is 29 s (R10.13), so the function has 29 s to return.
API_HANDLER_TIMEOUT: Final = cdk.Duration.seconds(29)

#: Orchestrator tasks run inside a Step Functions execution; the 900 s Lambda ceiling is fine.
TASK_FUNCTION_TIMEOUT: Final = cdk.Duration.seconds(900)

#: The Reaper function: one sweep covers every shard, so it needs more than the API handler.
REAPER_TIMEOUT: Final = cdk.Duration.seconds(300)

#: The Reaper sweep interval (seconds). Must match the value the Reaper reads from its environment.
REAPER_SWEEP_INTERVAL_SECONDS: Final = 300

#: The number of reap shards. Must agree with the handler's shard assignment.
REAPER_SHARD_COUNT: Final = 4

#: Orchestrator defaults wired from the deployment.
ORCHESTRATOR_POLL_INTERVAL_SECONDS: Final = 15
ORCHESTRATOR_READINESS_ATTEMPTS: Final = 60
ORCHESTRATOR_READINESS_INTERVAL_SECONDS: Final = 5
ORCHESTRATOR_CONTINUATION_LEAD_SECONDS: Final = 300
ORCHESTRATOR_VCPU_MILLIS: Final = 2000

#: CloudWatch dashboard period for standard widgets.
DASHBOARD_PERIOD: Final = cdk.Duration.minutes(5)


class ControlPlaneStack(cdk.Stack):
    """The API, the handlers, the state machine and the Reaper. Filled by task 12.11."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        state: StateStack,
        image: ImageStack,
        egress: EgressStack,
        network: NetworkStack,
        profile: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.state = state
        self.image = image
        self.egress = egress
        self.network = network
        #: The value task 12.11 writes to `DEPLOYMENT_PROFILE` in the handler environment, and the
        #: only use this stack makes of it. Nothing provisioned may read it (R11.19).
        self.profile = profile
        #: Tenant identifier for single-tenant deployments.  Defaults to ``"operator"`` to match
        #: ``DEFAULT_IMAGE_TENANT_ID`` in the image stack.  Overridable via CDK context
        #: ``-c tenantId=<value>``.
        self.tenant_id: str = self.node.try_get_context("tenantId") or "operator"
        for upstream in (state, image, egress, network):
            self.add_stack_dependency(upstream)

        # --- Task 12.6: per-Session Sandbox execution role ---------------------------------------
        self.sandbox_execution_role_template = self._sandbox_execution_role_template()

        # --- Task 12.11: API, handler, state machine, Reaper, dashboard --------------------------
        self.session_data_access_role = self._session_data_access_role()
        self.api_handler = self._api_handler()
        self.task_function = self._task_function()
        self.http_api = self._http_api()
        self.api_integration = self._api_integration()

        # PCSR Finding 3: derive authorization from deployment profile.
        # Multi-tenant uses Lambda authorizer (CUSTOM); single-tenant uses AWS_IAM.
        if self.profile == "multi-tenant":
            self.authorizer_function = self._lambda_authorizer()
            self.authorizer_id = self._api_authorizer()
            self.authorization_type = "CUSTOM"
        else:
            self.authorizer_function = None
            self.authorizer_id = None
            self.authorization_type = "AWS_IAM"

        # PCSR Finding 9: tag the two functions that are allowed to assume the session data role.
        cdk.Tags.of(self.api_handler).add("SandboxComponent", "control-plane-handler")
        cdk.Tags.of(self.task_function).add("SandboxComponent", "control-plane-handler")

        self._api_routes()
        self.state_machine = self._state_machine()
        self.reaper_function = self._reaper_function()
        self.reaper_schedule = self._reaper_schedule()
        self.dashboard = self._dashboard()

        # Grant the orchestrator function permission to start executions on the state machine.
        # Uses a wildcard-scoped ARN instead of ``self.state_machine.attr_arn`` to avoid a
        # CloudFormation circular dependency: the state machine definition references the task
        # function, so the task function's role policy cannot reference the state machine back.
        sm_arn_pattern = self.format_arn(
            service="states",
            resource="stateMachine",
            resource_name="*",
            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
        )
        self.task_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["states:StartExecution"],
                resources=[sm_arn_pattern],
            )
        )

    # --- Per-Session Sandbox execution role (R5.12, R11.6, R12.5) --------------------------------

    def _sandbox_execution_role_template(self) -> iam.Role:
        """The IAM role every Sandbox MicroVM runs with.

        PCSR Finding 5: per-session role creation was documented but never implemented.
        This single role is shared by all MicroVMs. S3 access is scoped by:
        1. The ``tenants/*/sessions/*/*`` resource ARN pattern (IAM policy)
        2. The inline session policy applied at ``sts:AssumeRole`` time (``access.py``)
           which narrows the wildcard to one specific tenant prefix
        3. Network isolation — the S3 gateway endpoint is not routed from connector subnets

        The template carries:

        * An allow for ``s3:GetObject`` and ``s3:PutObject`` scoped to the artifact bucket under
          ``tenants/*/sessions/*/*``, further narrowed by session policies at assume time.
        * An explicit deny on the egress secrets, key and proxy role, so a Sandbox cannot read the
          credentials the Egress_Controller injects (R12.5).
        * An explicit deny on GPU_Target invocation actions, so a delegation cannot bypass the
          proxy (R5.12).
        """
        role = iam.Role(
            self,
            "SandboxExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description=(
                "Per-Session Sandbox execution role template (R11.6). "
                "Grants artifact access; denies egress credentials and GPU targets."
            ),
        )

        # PCSR Finding 5: S3 access is narrowed to the specific tenant at assume time
        # via the inline session policy in access.py. The base role uses a wildcard pattern
        # because the tenant/session IDs are not known at deploy time. The session policy
        # applied during sts:AssumeRole constrains the effective permissions to one tenant.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="AllowSessionArtifactAccess",
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject", "s3:PutObject"],
                resources=[
                    f"{self.state.bucket.bucket_arn}/tenants/*/sessions/*/*",
                ],
                conditions={
                    "StringEquals": {
                        "s3:ResourceAccount": cdk.Aws.ACCOUNT_ID,
                    },
                },
            )
        )

        # --- Deny: egress secrets, key and proxy role (R12.5) ------------------------------------
        role.add_to_policy(
            iam.PolicyStatement(
                sid="DenyEgressSecrets",
                effect=iam.Effect.DENY,
                actions=["secretsmanager:GetSecretValue"],
                resources=list(self.egress.upstream_secret_arns),
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="DenyEgressKey",
                effect=iam.Effect.DENY,
                actions=["kms:Decrypt"],
                resources=[self.egress.secret_key.key_arn],
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="DenyProxyRole",
                effect=iam.Effect.DENY,
                actions=["sts:AssumeRole"],
                resources=[self.egress.proxy_task_role.role_arn],
            )
        )

        # --- GPU_Target invocation deny (R5.12) ---------------------------------------------------
        # The execution role denies Bedrock/SageMaker invocation directly so that Sandboxes must
        # go through the Egress_Controller proxy (Tier 1 SigV4 re-signing).  The proxy's task
        # role holds the allow for bedrock:InvokeModel*, and re-signs the request on the upstream
        # leg.  Without this deny, a MicroVM could call Bedrock via the VPC endpoint directly,
        # bypassing the proxy's credential injection and audit trail.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="DenyBedrockDirect",
                effect=iam.Effect.DENY,
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:Converse",
                    "bedrock:ConverseStream",
                ],
                resources=["*"],
            )
        )

        # S3 Files mount access for persistent workspaces (only if configured)
        s3files_fs_id = self.node.try_get_context("s3filesFilesystemId") or ""
        if s3files_fs_id:
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="MountS3Files",
                    effect=iam.Effect.ALLOW,
                    actions=["s3files:Client*"],
                    resources=[
                        f"arn:aws:s3files:{self.region}:{self.account}:file-system/{s3files_fs_id}",
                        f"arn:aws:s3files:{self.region}:{self.account}:file-system/{s3files_fs_id}/*",
                    ],
                )
            )

        return role

    # --- SessionDataAccessRole (R11.3) -----------------------------------------------------------

    def _session_data_access_role(self) -> iam.Role:
        """The IAM role the handler assumes per-request to confine data access to one Tenant.

        Trust is limited to the API handler and the task function. The inline session policy uses
        ``dynamodb:LeadingKeys`` to confine DynamoDB access to one Tenant partition, and the S3
        prefix scopes artifact access the same way.
        """
        role = iam.Role(
            self,
            "SessionDataAccessRole",
            # PCSR Finding 9: restrict trust to functions in this stack only.
            # Uses a tag condition instead of naming role ARNs (which aren't known yet at
            # role-creation time). The API handler and task function are tagged below.
            assumed_by=iam.AccountPrincipal(cdk.Aws.ACCOUNT_ID).with_conditions({
                "StringEquals": {
                    "aws:PrincipalTag/SandboxComponent": "control-plane-handler",
                },
            }),
            description=(
                "Per-request role assumed with an inline session policy that confines "
                "DynamoDB and S3 access to one Tenant (R11.3)."
            ),
        )
        # Grant DynamoDB read/write on the table and its indexes.
        self.state.table.grant_read_write_data(role)
        # Grant S3 read/write on the artifact bucket.
        self.state.bucket.grant_read_write(role)
        # Grant KMS decrypt for the artifact key.
        self.state.artifact_key.grant_encrypt_decrypt(role)
        return role

    # --- API handler Lambda function -------------------------------------------------------------

    def _api_handler(self) -> lambda_.Function:
        """The Lambda function that handles all eight Control_Plane API routes."""
        function = lambda_.Function(
            self,
            "ApiHandler",
            runtime=LAMBDA_RUNTIME,
            handler="control_plane.api.lambda_handler.handler",
            code=lambda_.Code.from_asset(".", exclude=_LAMBDA_ASSET_EXCLUDES),
            timeout=API_HANDLER_TIMEOUT,
            log_group=logs.LogGroup(
                self, "ApiHandlerLogs",
                retention=LOG_RETENTION,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            ),
            environment={
                "TABLE_NAME": self.state.table.table_name,
                "BUCKET_NAME": self.state.bucket.bucket_name,
                "ARTIFACT_KEY_ARN": self.state.artifact_key.key_arn,
                "DEPLOYMENT_PROFILE": self.profile,
                "IMAGE_REF": self.image.image_version,
                "EGRESS_ENDPOINT": self.egress.proxy_endpoint,
                "POLICY_STORE_ID": self.egress.policy_application.application_id,
                "CONNECTOR_REF": self.network.attachment_ref,
                "SESSION_DATA_ACCESS_ROLE_ARN": self.session_data_access_role.role_arn,
                "SANDBOX_EXECUTION_ROLE_ARN": self.sandbox_execution_role_template.role_arn,
                "STATE_MACHINE_ARN": "",  # Resolved after state machine creation.
                "REAP_SHARD_COUNT": str(REAPER_SHARD_COUNT),
                "TENANT_ID": self.tenant_id,
            },
        )
        # Grant DynamoDB and S3 access to the handler.
        self.state.table.grant_read_write_data(function)
        self.state.bucket.grant_read_write(function)
        self.state.artifact_key.grant_encrypt_decrypt(function)
        # Grant STS assume role for the session data access role.
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[self.session_data_access_role.role_arn],  # Scoped to the session data access role.
            )
        )
        # The API handler suspends, resumes and terminates MicroVMs directly.
        # NOTE: Resource "*" is required — the Lambda MicroVM API does not yet support
        # resource-level IAM scoping for MicroVM actions. Scope to specific ARN patterns
        # when the service adds support. See: https://docs.aws.amazon.com/lambda/
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "lambda:SuspendMicrovm",
                    "lambda:ResumeMicrovm",
                    "lambda:GetMicrovm",
                    "lambda:TerminateMicrovm",
                    "lambda:CreateMicrovmAuthToken",
                ],
                resources=["*"],
            )
        )
        return function

    # --- Orchestrator task Lambda function -------------------------------------------------------

    def _task_function(self) -> lambda_.Function:
        """The Lambda function that handles all Step Functions task invocations."""
        function = lambda_.Function(
            self,
            "OrchestratorTask",
            runtime=LAMBDA_RUNTIME,
            handler="control_plane.orchestrator.lambda_handler.handler",
            code=lambda_.Code.from_asset(".", exclude=_LAMBDA_ASSET_EXCLUDES),
            timeout=TASK_FUNCTION_TIMEOUT,
            memory_size=512,
            log_group=logs.LogGroup(
                self, "OrchestratorTaskLogs",
                retention=LOG_RETENTION,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            ),
            environment={
                "TABLE_NAME": self.state.table.table_name,
                "BUCKET_NAME": self.state.bucket.bucket_name,
                "ARTIFACT_KEY_ARN": self.state.artifact_key.key_arn,
                "IMAGE_REF": self.image.image_version,
                "EGRESS_ENDPOINT": self.egress.proxy_endpoint,
                "CONNECTOR_REF": self.network.attachment_ref,
                "VCPU_MILLIS": str(ORCHESTRATOR_VCPU_MILLIS),
                "POLL_INTERVAL_SECONDS": str(ORCHESTRATOR_POLL_INTERVAL_SECONDS),
                "READINESS_ATTEMPTS": str(ORCHESTRATOR_READINESS_ATTEMPTS),
                "READINESS_INTERVAL_SECONDS": str(
                    ORCHESTRATOR_READINESS_INTERVAL_SECONDS
                ),
                "CONTINUATION_LEAD_SECONDS": str(
                    ORCHESTRATOR_CONTINUATION_LEAD_SECONDS
                ),
                "SANDBOX_EXECUTION_ROLE_ARN": self.sandbox_execution_role_template.role_arn,
                "TENANT_ID": self.tenant_id,
                # S3 Files persistent storage — set via CDK context or empty to disable
                "S3FILES_FILESYSTEM_ID": self.node.try_get_context("s3filesFilesystemId") or "",
                "S3FILES_ACCESS_POINT_ID": self.node.try_get_context("s3filesAccessPointId") or "",
                "S3FILES_MOUNT_TARGET_IPS": self.node.try_get_context("s3filesMountTargetIps") or "",
            },
        )
        # Grant DynamoDB and S3 access.
        self.state.table.grant_read_write_data(function)
        self.state.bucket.grant_read_write(function)
        self.state.artifact_key.grant_encrypt_decrypt(function)
        # S3 Files access point management (for per-session AP creation)
        s3files_fs_id = self.node.try_get_context("s3filesFilesystemId") or ""
        if s3files_fs_id:
            function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "s3files:CreateAccessPoint",
                        "s3files:GetAccessPoint",
                        "s3files:ListAccessPoints",
                        "s3files:DeleteAccessPoint",
                    ],
                    resources=[
                        f"arn:aws:s3files:{self.region}:{self.account}:file-system/{s3files_fs_id}",
                        f"arn:aws:s3files:{self.region}:{self.account}:file-system/{s3files_fs_id}/*",
                    ],
                )
            )
        # The orchestrator provisions MicroVMs.
        # NOTE: Resource "*" is required — the Lambda MicroVM API does not yet support
        # resource-level IAM scoping. Scope to specific ARN patterns when supported.
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "lambda:RunMicrovm",
                    "lambda:GetMicrovm",
                    "lambda:TerminateMicrovm",
                    "lambda:SuspendMicrovm",
                    "lambda:ResumeMicrovm",
                    "lambda:ListMicrovms",
                    "lambda:CreateMicrovmAuthToken",
                    "lambda:PassNetworkConnector",
                ],
                resources=["*"],
            )
        )
        # The orchestrator passes the Sandbox execution role to the provider.
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["iam:PassRole"],
                resources=[self.sandbox_execution_role_template.role_arn],
            )
        )
        return function

    # --- HTTP API with AWS_IAM authorizer (R6.3) -------------------------------------------------

    def _http_api(self) -> apigwv2.CfnApi:
        """The HTTP API. Every route carries the ``AWS_IAM`` authorizer (R6.3, R6.22)."""
        return apigwv2.CfnApi(
            self,
            "ControlPlaneApi",
            name="ControlPlaneApi",
            protocol_type="HTTP",
        )

    def _api_integration(self) -> apigwv2.CfnIntegration:
        """The single Lambda proxy integration shared by all routes."""
        integration = apigwv2.CfnIntegration(
            self,
            "ApiIntegration",
            api_id=self.http_api.ref,
            integration_type="AWS_PROXY",
            integration_uri=self.api_handler.function_arn,
            payload_format_version="2.0",
            timeout_in_millis=29000,  # R10.13: 29 s integration timeout.
        )
        # Grant API Gateway permission to invoke the handler.
        self.api_handler.add_permission(
            "ApiGatewayInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=self.format_arn(
                service="execute-api",
                resource=self.http_api.ref,
                resource_name="*",
            ),
        )
        # Auto-deploy stage with access logging (PCSR: was missing).
        api_log_group = logs.LogGroup(
            self,
            "ApiAccessLogs",
            retention=LOG_RETENTION,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        apigwv2.CfnStage(
            self,
            "DefaultStage",
            api_id=self.http_api.ref,
            stage_name="$default",
            auto_deploy=True,
            access_log_settings=apigwv2.CfnStage.AccessLogSettingsProperty(
                destination_arn=api_log_group.log_group_arn,
                format='{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","routeKey":"$context.routeKey","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength","integrationError":"$context.integrationErrorMessage","tenantId":"$context.authorizer.tenantId"}',
            ),
        )
        return integration

    def _api_routes(self) -> None:
        """One route per operation, with the authorizer selected by Deployment_Profile.

        Under ``single-tenant`` every route carries ``AWS_IAM`` (R6.3, R6.22). Under
        ``multi-tenant`` routes use the Lambda authorizer (``CUSTOM``) instead.
        """
        for route in ROUTES:
            route_key = route.route_key
            safe_id = route.operation.value
            route_props: dict[str, Any] = {
                "api_id": self.http_api.ref,
                "route_key": route_key,
                "target": f"integrations/{self.api_integration.ref}",
            }
            if self.authorization_type == "CUSTOM" and self.authorizer_id:
                route_props["authorization_type"] = "CUSTOM"
                route_props["authorizer_id"] = self.authorizer_id
            else:
                route_props["authorization_type"] = "AWS_IAM"

            apigwv2.CfnRoute(self, f"Route{safe_id}", **route_props)

    # --- Lambda authorizer for multi-tenant (N2) ---------------------------------------------------

    def _lambda_authorizer(self) -> lambda_.Function:
        """The Lambda authorizer for multi-tenant: validates tokens and returns tenant context."""
        function = lambda_.Function(
            self,
            "TenantAuthorizer",
            runtime=LAMBDA_RUNTIME,
            handler="control_plane.authorizer.handler.handler",
            code=lambda_.Code.from_asset(".", exclude=_LAMBDA_ASSET_EXCLUDES),
            timeout=cdk.Duration.seconds(10),
            log_group=logs.LogGroup(
                self,
                "TenantAuthorizerLogs",
                retention=LOG_RETENTION,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            ),
            environment={
                # WARNING: Demo tokens below are for development/testing only.
                # For production, load tokens from Secrets Manager or SSM Parameter Store.
                # See README.md "Multi-tenancy" section for Cognito migration guide.
                "TENANT_TOKEN_MAP": json.dumps(
                    {
                        "demo-token-tenant-a": "tenant-a",
                        "demo-token-tenant-b": "tenant-b",
                    }
                ),
            },
        )
        # Grant API Gateway permission to invoke the authorizer.
        function.add_permission(
            "ApiGatewayAuthorizerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=self.format_arn(
                service="execute-api",
                resource=self.http_api.ref,
                resource_name="authorizers/*",
            ),
        )
        return function

    def _api_authorizer(self) -> str:
        """Create the HTTP API authorizer resource, return its ID for route references."""
        authorizer = apigwv2.CfnAuthorizer(
            self,
            "TenantLambdaAuthorizer",
            api_id=self.http_api.ref,
            authorizer_type="REQUEST",
            name="TenantAuthorizer",
            authorizer_uri=(
                f"arn:aws:apigateway:{cdk.Aws.REGION}:lambda:path/2015-03-31/functions/"
                f"{self.authorizer_function.function_arn}/invocations"
            ),
            authorizer_payload_format_version="2.0",
            enable_simple_responses=True,
            identity_source=["$request.header.Authorization"],
            authorizer_result_ttl_in_seconds=300,
        )
        return authorizer.ref

    # --- Step Functions Standard state machine (R10.1) -------------------------------------------

    def _state_machine(self) -> sfn.CfnStateMachine:
        """The Standard state machine, its definition derived from the orchestrator graph.

        Every ``Task`` state in the graph is backed by the task function. The ``to_asl`` function
        renders the Amazon States Language definition.
        """
        task_resources = {
            state: self.task_function.function_arn for state in TASK_STATES
        }
        definition = to_asl(task_resources)

        # The state machine execution role.
        sm_role = iam.Role(
            self,
            "StateMachineRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            description="Session_Orchestrator Standard state machine execution role",
        )
        # Grant the state machine permission to invoke the task function.
        self.task_function.grant_invoke(sm_role)

        machine = sfn.CfnStateMachine(
            self,
            "SessionOrchestrator",
            definition_string=json.dumps(definition, sort_keys=True),
            role_arn=sm_role.role_arn,
            state_machine_type="STANDARD",
        )

        # Wire the state machine ARN back into the API handler environment.  Uses the
        # ``Ref`` intrinsic (which returns the ARN for ``AWS::StepFunctions::StateMachine``)
        # instead of ``Fn::GetAtt`` to avoid a CloudFormation dependency from the API handler
        # back to the state machine (the API handler is created before the state machine in the
        # construct tree, so a ``GetAtt`` would introduce a circular reference).
        sm_ref = machine.ref  # Ref for CfnStateMachine returns the ARN.
        cfn_function = self.api_handler.node.default_child
        if isinstance(cfn_function, lambda_.CfnFunction):
            cfn_function.add_property_override(
                "Environment.Variables.STATE_MACHINE_ARN", sm_ref
            )

        # Grant the API handler permission to start executions.  Same wildcard-scoped ARN
        # pattern as the task function grant (see ``__init__``) for the same reason.
        sm_arn_pattern = self.format_arn(
            service="states",
            resource="stateMachine",
            resource_name="*",
            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
        )
        self.api_handler.add_to_role_policy(
            iam.PolicyStatement(
                actions=["states:StartExecution"],
                resources=[sm_arn_pattern],
            )
        )

        return machine

    # --- Reaper Lambda function (R10.6, R10.7, R10.8) -------------------------------------------

    def _reaper_function(self) -> lambda_.Function:
        """The Reaper: scheduled sweep of the deadline index."""
        function = lambda_.Function(
            self,
            "Reaper",
            runtime=LAMBDA_RUNTIME,
            handler="control_plane.reaper_handler.handler",
            code=lambda_.Code.from_asset(".", exclude=_LAMBDA_ASSET_EXCLUDES),
            timeout=REAPER_TIMEOUT,
            log_group=logs.LogGroup(
                self, "ReaperLogs",
                retention=LOG_RETENTION,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            ),
            environment={
                "TABLE_NAME": self.state.table.table_name,
                "SHARD_COUNT": str(REAPER_SHARD_COUNT),
                "SESSION_BUDGET_SECONDS": str(86400),
                "ORPHAN_THRESHOLD_SECONDS": str(120),
                "MAX_ROWS_PER_SHARD": str(100),
                "SWEEP_INTERVAL_SECONDS": str(REAPER_SWEEP_INTERVAL_SECONDS),
                "TENANT_ID": self.tenant_id,
            },
        )
        # The Reaper queries the deadline index and writes terminal states.
        self.state.table.grant_read_write_data(function)
        # The Reaper terminates MicroVMs.
        # NOTE: Resource "*" is required — the Lambda MicroVM API does not yet support
        # resource-level IAM scoping. Scope to specific ARN patterns when supported.
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "lambda:TerminateMicrovm",
                    "lambda:GetMicrovm",
                ],
                resources=["*"],
            )
        )
        # The Reaper emits CloudWatch metrics.
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
            )
        )
        return function

    # --- EventBridge Scheduler for the Reaper (R10.17) -------------------------------------------

    def _reaper_schedule(self) -> scheduler.CfnSchedule:
        """A fixed-rate schedule invoking the Reaper function."""
        schedule_role = iam.Role(
            self,
            "ReaperScheduleRole",
            assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com"),
            description="EventBridge Scheduler role for the Reaper sweep",
        )
        self.reaper_function.grant_invoke(schedule_role)
        return scheduler.CfnSchedule(
            self,
            "ReaperSchedule",
            schedule_expression=f"rate({REAPER_SWEEP_INTERVAL_SECONDS // 60} minutes)",
            flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(
                mode="OFF",
            ),
            target=scheduler.CfnSchedule.TargetProperty(
                arn=self.reaper_function.function_arn,
                role_arn=schedule_role.role_arn,
            ),
        )

    # --- CloudWatch Dashboard (R14.4) ------------------------------------------------------------

    def _dashboard(self) -> cloudwatch.Dashboard:
        """Basic dashboard: Session counts, API latency, state machine executions, Reaper sweep."""
        return cloudwatch.Dashboard(
            self,
            "ControlPlaneDashboard",
            dashboard_name="ControlPlane",
            widgets=[
                [
                    cloudwatch.GraphWidget(
                        title="API Handler Invocations",
                        left=[
                            self.api_handler.metric_invocations(
                                period=DASHBOARD_PERIOD
                            ),
                            self.api_handler.metric_errors(period=DASHBOARD_PERIOD),
                        ],
                    ),
                    cloudwatch.GraphWidget(
                        title="API Handler Duration",
                        left=[
                            self.api_handler.metric_duration(period=DASHBOARD_PERIOD),
                        ],
                    ),
                ],
                [
                    cloudwatch.GraphWidget(
                        title="Orchestrator Task Invocations",
                        left=[
                            self.task_function.metric_invocations(
                                period=DASHBOARD_PERIOD
                            ),
                            self.task_function.metric_errors(period=DASHBOARD_PERIOD),
                        ],
                    ),
                    cloudwatch.GraphWidget(
                        title="Reaper Invocations",
                        left=[
                            self.reaper_function.metric_invocations(
                                period=DASHBOARD_PERIOD
                            ),
                            self.reaper_function.metric_errors(
                                period=DASHBOARD_PERIOD
                            ),
                        ],
                    ),
                ],
            ],
        )
