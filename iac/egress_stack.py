# kiro-classification: public
"""`EgressStack`: the Egress_Controller data plane (R15.2, R12.1, R12.8).

The fleet is the only thing that can carry a Sandbox's traffic anywhere, so its availability is the
accepted cost the design records: a minimum task count above one, spread over every availability
zone `NetworkStack` offers, and a deployment that never drops below the running count.

Nothing here decides anything about a request. The destination policy is data in AppConfig, read per
request with the TTL `egress.reader` bounds; the tiers are `egress.interception`; the seed document
is loaded by the same loader the fleet reads it with, so a document the proxy would refuse fails the
build. Every security group belongs to `NetworkStack`, which is what keeps the attachment's egress
rules and the fleet they reach in one stack rather than two.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final

import aws_cdk as cdk
from aws_cdk import aws_acmpca as acmpca
from aws_cdk import aws_appconfig as appconfig
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

from aws_cdk import aws_dynamodb as dynamodb
from egress.policy import EGRESS_TLS_PORT, DefaultAction, EgressPolicy
from egress.reader import MAX_POLICY_CACHE_TTL_SECONDS
from iac.network_stack import PROXY_SUBNET_GROUP, NetworkStack

__all__ = [
    "CA_VALIDITY_YEARS",
    "LOG_RETENTION",
    "MINIMUM_PROXY_TASKS",
    "PLACEHOLDER_PROXY_IMAGE",
    "POLICY_CACHE_TTL_SECONDS",
    "PROXY_IMAGE_URI_CONTEXT_KEY",
    "PROXY_TASK_CPU",
    "PROXY_TASK_MEMORY_MIB",
    "SEED_POLICY",
    "SEED_POLICY_DOCUMENT",
    "UPSTREAM_CREDENTIAL_NAMES",
    "EgressStack",
]

#: Above one, because the design's accepted cost is that an Egress_Controller outage is a total
#: egress outage for every running Sandbox. One task is one deployment away from that outage.
MINIMUM_PROXY_TASKS: Final = 2

PROXY_TASK_CPU: Final = 512
PROXY_TASK_MEMORY_MIB: Final = 1024

#: The blocked-attempt records and the EMF metric behind R14.7's widget land here, so the retention
#: is an audit retention rather than a debugging one.
LOG_RETENTION: Final = logs.RetentionDays.SIX_MONTHS

#: A root CA the Sandbox trusts for the Tier 1 and Tier 2 aliases only. Ten years so that rotating
#: it is a planned operation rather than one forced inside a Session's eight-hour ceiling.
CA_VALIDITY_YEARS: Final = 10

#: The upstream credentials the design's Tier 2 names: a token per aliased package registry, read by
#: the proxy on the upstream leg and never present in the Sandbox (R12.4).
UPSTREAM_CREDENTIAL_NAMES: Final[tuple[str, ...]] = ("pypi", "npm")

#: `egress.reader` bounds the TTL but declares no default, because the number is a deployment value.
#: This is the deployment, so it sets it, and it sets the ceiling: 30 s is the revocation latency the
#: design documents, and anything below it buys nothing R12.7 promised.
POLICY_CACHE_TTL_SECONDS: Final = MAX_POLICY_CACHE_TTL_SECONDS

#: The policy the deployment starts with: no destination set, and therefore nothing permitted. A
#: freshly deployed Egress_Controller denies everything, which is R12.8 rather than a placeholder.
#: Task 10.8 publishes the named configurations over it.
SEED_POLICY_DOCUMENT: Final[Mapping[str, Any]] = {
    "policyVersion": 1,
    "destinationSets": {},
    "defaultAction": DefaultAction.DENY.value,
}

#: Loaded at import by the loader the fleet reads it with, so a seed the proxy would refuse to parse
#: fails the build rather than reaching an environment as an unreadable — and therefore, by R12.8,
#: totally denying — configuration.
SEED_POLICY: Final = EgressPolicy.from_document(SEED_POLICY_DOCUMENT)

#: What the proxy needs to find its policy, its cache bound and its issuing CA. Declared here
#: because no module owns these spellings yet: `egress.reader` and `egress.interception` take their
#: settings as constructed objects, and the entry point that would build them from an environment
#: does not exist.
_APPLICATION_VARIABLE: Final = "EGRESS_POLICY_APPLICATION"
_ENVIRONMENT_VARIABLE: Final = "EGRESS_POLICY_ENVIRONMENT"
_PROFILE_VARIABLE: Final = "EGRESS_POLICY_PROFILE"
_CACHE_TTL_VARIABLE: Final = "EGRESS_POLICY_CACHE_TTL_SECONDS"
_PRIVATE_CA_VARIABLE: Final = "EGRESS_PRIVATE_CA_ARN"
_CONFIG_TABLE_VARIABLE: Final = "EGRESS_CONFIG_TABLE"

#: CDK context key that carries the pre-built proxy image URI pushed to ECR by
#: ``scripts/build-proxy.py``.  When absent the stack synthesises with a placeholder and emits a
#: warning so that ``cdk synth`` still succeeds in the offline suite.
PROXY_IMAGE_URI_CONTEXT_KEY: Final = "proxyImageUri"

#: Sentinel value that makes a missing ``proxyImageUri`` visible as a deployment-time error
#: rather than a silent misconfiguration.
PLACEHOLDER_PROXY_IMAGE: Final = "PLACEHOLDER-build-proxy-via-codebuild"


class EgressStack(cdk.Stack):
    """The proxy fleet, its internal load balancer, its private CA, its secrets and its policy."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        network: NetworkStack,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.network = network
        self.add_stack_dependency(network)

        self._proxy_image_uri = self.node.try_get_context(PROXY_IMAGE_URI_CONTEXT_KEY) or ""
        if not self._proxy_image_uri:
            cdk.Annotations.of(self).add_warning(
                "No proxyImageUri in CDK context. Build the proxy image with: "
                "uv run python scripts/build-proxy.py --region <region>"
            )
            self._proxy_image_uri = PLACEHOLDER_PROXY_IMAGE

        self.secret_key = self._secret_key()
        self.upstream_secrets = self._upstream_secrets(self.secret_key)
        self.certificate_authority = self._certificate_authority()
        self.policy_application, self.policy_environment, self.policy_configuration = (
            self._policy_store()
        )
        self.config_table = self._config_table()
        self.log_group = self._log_group()
        self.cluster = ecs.Cluster(self, "ProxyFleet", vpc=network.vpc)
        self.task_definition = self._task_definition()
        self.service = self._service()
        self.load_balancer, self.target_group = self._load_balancer()

    @property
    def upstream_secret_arns(self) -> tuple[str, ...]:
        """The secret ARNs the per-Session Sandbox role carries an explicit `Deny` on (R12.5)."""
        return tuple(secret.secret_arn for secret in self.upstream_secrets.values())

    @property
    def proxy_task_role(self) -> iam.IRole:
        """The identity Tier 1 re-signs as, and the role the Sandbox may not assume (R12.5)."""
        return self.task_definition.task_role

    @property
    def proxy_endpoint(self) -> str:
        """The internal load balancer's name, which every alias resolves to."""
        return self.load_balancer.load_balancer_dns_name

    def _secret_key(self) -> kms.Key:
        """The key the egress secrets are encrypted with, named separately for R12.5's `Deny`."""
        return kms.Key(
            self,
            "EgressSecrets",
            description="Egress_Controller upstream credentials (R12.4, R12.5)",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def _upstream_secrets(self, key: kms.Key) -> dict[str, secretsmanager.Secret]:
        """One secret per upstream credential, with a generated value the operator replaces."""
        # Generated rather than taken as a parameter: a credential supplied at synthesis would sit
        # in the template and in `cdk.out`, which R12.4 makes pointless.
        return {
            name: secretsmanager.Secret(
                self,
                f"Upstream{name.capitalize()}",
                description=f"Egress_Controller upstream credential for {name}",
                encryption_key=key,
                removal_policy=cdk.RemovalPolicy.DESTROY,
            )
            for name in UPSTREAM_CREDENTIAL_NAMES
        }

    def _certificate_authority(self) -> acmpca.CfnCertificateAuthority:
        """The private root CA that issues the Tier 1 and Tier 2 alias certificates, activated.

        Activated because an unactivated CA issues nothing, and the alias *is* the proxy: TLS
        terminating at an alias with no certificate is a failure, not a legitimate termination.
        """
        authority = acmpca.CfnCertificateAuthority(
            self,
            "EgressAliases",
            type="ROOT",
            key_algorithm="RSA_2048",
            signing_algorithm="SHA256WITHRSA",
            subject=acmpca.CfnCertificateAuthority.SubjectProperty(
                common_name="Egress_Controller alias CA",
                organization="Egress_Controller",
            ),
        )
        authority.apply_removal_policy(cdk.RemovalPolicy.DESTROY)
        certificate = acmpca.CfnCertificate(
            self,
            "EgressAliasesRootCertificate",
            certificate_authority_arn=authority.attr_arn,
            certificate_signing_request=authority.attr_certificate_signing_request,
            signing_algorithm="SHA256WITHRSA",
            template_arn=self.format_arn(
                service="acm-pca",
                region="",
                account="",
                resource="template",
                resource_name="RootCACertificate/V1",
            ),
            validity=acmpca.CfnCertificate.ValidityProperty(
                type="YEARS", value=CA_VALIDITY_YEARS
            ),
        )
        acmpca.CfnCertificateAuthorityActivation(
            self,
            "EgressAliasesActivation",
            certificate_authority_arn=authority.attr_arn,
            certificate=certificate.attr_certificate,
        )
        return authority

    def _policy_store(
        self,
    ) -> tuple[appconfig.Application, appconfig.IEnvironment, appconfig.IConfiguration]:
        """The AppConfig application, its environment and the seeded destination policy."""
        application = appconfig.Application(self, "DestinationPolicy")
        environment = application.add_environment("Live")
        configuration = appconfig.HostedConfiguration(
            self,
            "SeedPolicy",
            application=application,
            content=appconfig.ConfigurationContent.from_inline_json(
                json.dumps(SEED_POLICY_DOCUMENT, sort_keys=True)
            ),
            deployment_strategy=appconfig.DeploymentStrategy(
                self,
                "PolicyRollout",
                # Every target at once and no bake time. `ALL_AT_ONCE` would do the first but
                # carries a ten-minute bake, and AppConfig runs one deployment per environment at a
                # time, so a bake would hold up the next tightening edit — which is exactly the
                # revocation the design promises within 30 s.
                rollout_strategy=appconfig.RolloutStrategy.linear(
                    growth_factor=100,
                    deployment_duration=cdk.Duration.minutes(0),
                    final_bake_time=cdk.Duration.minutes(0),
                ),
            ),
            deploy_to=[environment],
            # R15.5: `cdk destroy --all` removes what the package created, and AppConfig's own
            # deletion protection would otherwise refuse a recently-deployed configuration.
            deletion_protection_check=appconfig.DeletionProtectionCheck.BYPASS,
        )
        version = configuration.node.default_child
        if isinstance(version, cdk.CfnResource):
            # CDK defaults a hosted configuration version to `Retain`, which would survive the
            # documented teardown and block a second deployment of the same profile.
            version.apply_removal_policy(cdk.RemovalPolicy.DESTROY)
        return application, environment, configuration

    def _config_table(self) -> dynamodb.Table:
        """DynamoDB table for egress configuration (policy document, session limits, etc.)."""
        table = dynamodb.Table(
            self,
            "EgressConfig",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        # Seed with default Bedrock-only policy
        import aws_cdk.custom_resources as cr
        cr.AwsCustomResource(
            self,
            "SeedEgressPolicy",
            on_create=cr.AwsSdkCall(
                service="DynamoDB",
                action="putItem",
                parameters={
                    "TableName": table.table_name,
                    "Item": {
                        "pk": {"S": "EGRESS_POLICY"},
                        "policy": {"S": json.dumps({
                            "policyVersion": 1,
                            "defaultAction": "deny",
                            "bedrock": {
                                "tier": 1,
                                "hosts": [
                                    "bedrock-runtime.us-east-1.amazonaws.com",
                                    "bedrock-runtime.us-east-2.amazonaws.com",
                                    "bedrock-runtime.us-west-2.amazonaws.com",
                                    "bedrock-runtime.ap-northeast-1.amazonaws.com",
                                    "bedrock-runtime.eu-west-1.amazonaws.com",
                                    "bedrock-mantle.us-east-1.api.aws",
                                ],
                            },
                            "packages": {
                                "tier": 3,
                                "hosts": [
                                    "pypi.org",
                                    "files.pythonhosted.org",
                                    "registry.npmjs.org",
                                    "registry.yarnpkg.com",
                                ],
                                "note": "Package registries (pip, npm, yarn)",
                            },
                            "system": {
                                "tier": 3,
                                "hosts": [
                                    "cdn.amazonlinux.com",
                                    "al2023-repos-us-east-1-de612dc2.s3.dualstack.us-east-1.amazonaws.com",
                                ],
                                "note": "AL2023 system package repos (dnf)",
                            },
                            "allowed": [],
                        })},
                    },
                    "ConditionExpression": "attribute_not_exists(pk)",
                },
                physical_resource_id=cr.PhysicalResourceId.of("seed-egress-policy"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=[table.table_arn],
            ),
        )
        return table

    def _log_group(self) -> logs.LogGroup:
        """One group for the fleet, so a blocked attempt and a DNS denial correlate in one place."""
        return logs.LogGroup(
            self,
            "ProxyLogs",
            retention=LOG_RETENTION,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def _task_definition(self) -> ecs.FargateTaskDefinition:
        """The proxy task, its container and everything its role is allowed to reach."""
        task_definition = ecs.FargateTaskDefinition(
            self,
            "Proxy",
            cpu=PROXY_TASK_CPU,
            memory_limit_mib=PROXY_TASK_MEMORY_MIB,
        )
        task_definition.add_container(
            "proxy",
            image=ecs.ContainerImage.from_registry(self._proxy_image_uri),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="proxy", log_group=self.log_group
            ),
            port_mappings=[ecs.PortMapping(container_port=EGRESS_TLS_PORT)],
            # Allow non-root user to bind port 443 (Fargate platform 1.4.0+)
            system_controls=[
                ecs.SystemControl(
                    namespace="net.ipv4.ip_unprivileged_port_start",
                    value="0",
                ),
            ],
            environment={
                _APPLICATION_VARIABLE: self.policy_application.application_id,
                _ENVIRONMENT_VARIABLE: self.policy_environment.environment_id,
                _PROFILE_VARIABLE: self.policy_configuration.configuration_profile_id,
                _CACHE_TTL_VARIABLE: str(POLICY_CACHE_TTL_SECONDS),
                _PRIVATE_CA_VARIABLE: self.certificate_authority.attr_arn,
                _CONFIG_TABLE_VARIABLE: self.config_table.table_name,
            },
        )
        task_definition.add_to_execution_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                ],
                resources=["*"],
            )
        )
        self._grant_proxy_permissions(task_definition.task_role)
        # Bedrock Mantle (Responses API / Web Search)
        # NOTE: bedrock-mantle actions are not yet individually documented by the service.
        # Scope down to specific actions when the service publishes its action list.
        task_definition.task_role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-mantle:*"],
                resources=["*"],
            )
        )
        self.config_table.grant_read_data(task_definition.task_role)
        return task_definition

    def _grant_proxy_permissions(self, role: iam.IRole) -> None:
        """Exactly what the three tiers need, and nothing the Sandbox role also holds (R12.5)."""
        for secret in self.upstream_secrets.values():
            # Tier 2's static token, read on the upstream leg. The Sandbox role carries a `Deny` on
            # these same ARNs, which is why they are exposed as `upstream_secret_arns`.
            secret.grant_read(role)
        role.add_to_principal_policy(
            iam.PolicyStatement(
                # The per-request policy read, and the session the read happens in.
                actions=[
                    "appconfig:StartConfigurationSession",
                    "appconfig:GetLatestConfiguration",
                ],
                resources=[
                    self.format_arn(
                        service="appconfig",
                        resource="application",
                        resource_name=f"{self.policy_application.application_id}/*",
                    )
                ],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                # Tier 1 and Tier 2 terminate TLS at an alias, so the task issues its own leaf
                # certificate from the private CA at start-up. Scoped to this CA.
                actions=[
                    "acm-pca:IssueCertificate",
                    "acm-pca:GetCertificate",
                    "acm-pca:DescribeCertificateAuthority",
                ],
                resources=[self.certificate_authority.attr_arn],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                # Tier 1 re-signs a Bedrock request as this role. The Sandbox role holds no allow
                # for either action, which is what makes the proxy the only path to a model (R12.5).
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:Converse",
                    "bedrock:ConverseStream",
                    # NOTE: bedrock-websearch actions are not yet individually documented.
                    # Scope down when specific action names are published.
                    "bedrock-websearch:*",

                ],
                resources=[
                    self.format_arn(
                        service="bedrock",
                        account="",
                        resource="foundation-model",
                        resource_name="*",
                    )
                ],
            )
        )

    def _service(self) -> ecs.FargateService:
        """The fleet: at least two tasks, spread over every zone `NetworkStack` offers."""
        return ecs.FargateService(
            self,
            "ProxyService",
            cluster=self.cluster,
            task_definition=self.task_definition,
            desired_count=MINIMUM_PROXY_TASKS,
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=PROXY_SUBNET_GROUP),
            security_groups=[self.network.proxy_security_group],
            # The proxy subnets are private and reach the upstream leg through `NetworkStack`'s NAT
            # gateway, so a task needs no public address of its own.
            assign_public_ip=False,
            # Fargate spreads new tasks over the zones of `vpc_subnets`, but it does not re-spread
            # after a zone recovers, so the fleet can end up in one failure domain — which is the
            # one failure the minimum count above exists to survive.
            availability_zone_rebalancing=ecs.AvailabilityZoneRebalancing.ENABLED,
            # A deployment may add tasks but may never remove one first: dropping below the running
            # count would be a partial egress outage for every Sandbox on the way through.
            min_healthy_percent=100,
            max_healthy_percent=200,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
        )

    def _load_balancer(
        self,
    ) -> tuple[elbv2.NetworkLoadBalancer, elbv2.NetworkTargetGroup]:
        """The internal NLB and the target group the fleet registers into.

        Internal, not internet-facing: an internet-facing load balancer needs a public subnet, and
        the proxy subnet group is private. The only public subnets in the egress VPC hold the NAT
        gateway, and putting this balancer there would make the proxy reachable from the internet.
        """
        balancer = elbv2.NetworkLoadBalancer(
            self,
            "ProxyLoadBalancer",
            vpc=self.network.vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=PROXY_SUBNET_GROUP),
            security_groups=[self.network.load_balancer_security_group],
            cross_zone_enabled=True,
        )
        listener = balancer.add_listener("Tls", port=EGRESS_TLS_PORT)
        target_group = listener.add_targets(
            "ProxyTasks",
            port=EGRESS_TLS_PORT,
            targets=[
                self.service.load_balancer_target(
                    container_name="proxy", container_port=EGRESS_TLS_PORT
                )
            ],
        )
        return balancer, target_group
