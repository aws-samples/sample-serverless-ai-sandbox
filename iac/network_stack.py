# kiro-classification: public
"""`NetworkStack`: the Egress VPC and the network surface attached to it (R15.2, R12.1, R12.8).

MicroVMs reach the public internet by default, and a VPC egress connector replaces that default
rather than restricting it, so the connector is the whole of egress control and a Sandbox without one
has unrestricted internet. Hence a real `AWS::Lambda::NetworkConnector` per generation, and
:meth:`NetworkStack._require_a_connector_per_generation`, which refuses a generation that lacks one.

Fail-closed (R12.8) is the absence of an alternative path, scoped to the subnets that matter. The
connector subnets carry no route at all, so Untrusted_Code cannot route around the proxy, cannot
reach an undeclared destination directly, and gets nothing when the proxy is down. The proxy subnets
do have one NAT gateway, because the proxy is what resolves and reaches `pypi.org` on the Sandbox's
behalf (R12.6) and a proxy that reaches no upstream enforces nothing.
:meth:`NetworkStack._require_no_alternative_route` keeps that path out of the connector subnets.

Connector generations (R12.7) are the second half: one subnet set, its security group and its own
connector, all three carrying the generation, so a cutover *adds* a generation rather than editing
one. A connector's `Name` cannot be updated in place, which is exactly those semantics.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

from egress.policy import EGRESS_TLS_PORT

__all__ = [
    "CONNECTOR_COMPUTE_RESOURCE_TYPES",
    "CONNECTOR_NAME_PREFIX",
    "CONNECTOR_NETWORK_PROTOCOL",
    "CONNECTOR_OPERATOR_MANAGED_POLICY_NAME",
    "CONNECTOR_SUBNET_GROUP_PREFIX",
    "DEFAULT_CONNECTOR_GENERATIONS",
    "EGRESS_ALIAS_ZONE",
    "EGRESS_GENERATION_TAG_KEY",
    "EGRESS_VPC_CIDR",
    "INTERFACE_ENDPOINTS",
    "MAX_AVAILABILITY_ZONES",
    "MAX_CONNECTOR_SECURITY_GROUPS",
    "MAX_CONNECTOR_SUBNETS",
    "MINIMUM_AVAILABILITY_ZONES",
    "NAT_SUBNET_GROUP",
    "OFF_VPC_ROUTE_TARGETS",
    "PROXY_SUBNET_GROUP",
    "SUBNET_CIDR_MASK",
    "SUBNET_SCOPED_EXIT_TYPES",
    "AlternativeEgressRouteError",
    "ConnectorAttachment",
    "MissingConnectorError",
    "NetworkStack",
]

#: The address space of the egress VPC. Stated rather than left to `ec2.Vpc`'s default, because
#: every other property of this VPC is stated for the reason the module docstring gives.
EGRESS_VPC_CIDR: Final = "10.0.0.0/16"

#: One `/24` per subnet group per availability zone. A group is the NAT subnets, the proxy fleet's
#: subnets or one connector generation's, so a `/16` holds far more generations than the eight-hour
#: drain allows.
SUBNET_CIDR_MASK: Final = 24

#: The availability zones asked for, and the floor the design's multi-AZ Fargate service needs. An
#: environment-agnostic synthesis resolves to two zones through `Fn::GetAZs`, which is why the floor
#: is separate from the request: two zones satisfy the design, three are taken when offered.
MAX_AVAILABILITY_ZONES: Final = 3
MINIMUM_AVAILABILITY_ZONES: Final = 2

#: The only public subnet group, and the only thing in it is the NAT gateway. Public because a NAT
#: gateway is reached from a private subnet and reaches the internet through the internet gateway,
#: and there is no form of NAT that does the second without sitting here.
NAT_SUBNET_GROUP: Final = "nat"

#: The subnet group the proxy fleet, its load balancer and the interface endpoints sit in. Not
#: generation-stamped: the design's separation of the fixed pipe from the mutable policy is exactly
#: that the fleet is reachable from every live generation.
#:
#: This group is the one with a path out. The proxy resolves and reaches the public package
#: registries R12.6 names, so Tier 2 and Tier 3 are functions of this route existing.
PROXY_SUBNET_GROUP: Final = "proxy"

#: The prefix of a connector generation's subnet group. The generation follows it, so a subnet's
#: logical identity carries the generation it belongs to.
CONNECTOR_SUBNET_GROUP_PREFIX: Final = "connector-g"

#: The generations live at deployment time. `SessionRecord.egress_generation` defaults to 1 and
#: refuses zero, so 1 is the first generation here too. A cutover deploys `(G, G + 1)`, which is
#: what makes the drain possible: both pipes exist while Sessions stamped with `G` finish.
DEFAULT_CONNECTOR_GENERATIONS: Final[tuple[int, ...]] = (1,)

#: The tag carrying a generation on the resources that belong to it. Spelled the way the Session
#: attribute is spelled, and the offline suite asserts the two agree against the projection in
#: `control_plane.state.table`, because a drain compares one against the other.
EGRESS_GENERATION_TAG_KEY: Final = "egressGeneration"

#: The connector's `Name`, with the generation appended. `Name` cannot be updated in place — a
#: change replaces the connector — which is why the generation and nothing else is in it: a cutover
#: is a new name and therefore a new connector, and every other edit leaves running pipes alone.
CONNECTOR_NAME_PREFIX: Final = "egress-connector-g"

#: The one compute resource type a connector may be associated with, and the only member the service
#: accepts. Stated as a constant so the assertion in the offline suite reads it rather than the
#: literal, and IPv4 rather than `DualStack` because IPv6 egress leaves a VPC by its own gateway and
#: this VPC's whole argument is which route tables carry a route.
CONNECTOR_COMPUTE_RESOURCE_TYPES: Final[tuple[str, ...]] = ("MicroVm",)
CONNECTOR_NETWORK_PROTOCOL: Final = "IPv4"

#: The service limits on one connector's VPC egress configuration.
MAX_CONNECTOR_SUBNETS: Final = 16
MAX_CONNECTOR_SECURITY_GROUPS: Final = 5

#: The AWS-managed policy that grants Lambda the minimum permissions to manage the elastic network
#: interfaces that put a MicroVM in the connector's subnets. There is no service default, so an
#: absent policy is a connector that cannot come up.
#:
#: The policy carries four statements — three scoped `ec2:CreateNetworkInterface` resources
#: (subnet, security-group, and network-interface with a tag-key condition) plus a guarded
#: `ec2:CreateTags`. Attaching the managed policy rather than inlining it keeps us in sync with
#: any future revisions AWS publishes.
#: Source: `https://docs.aws.amazon.com/lambda/latest/dg/microvms-networking.html`.
CONNECTOR_OPERATOR_MANAGED_POLICY_NAME: Final = (
    "AWSLambdaNetworkConnectorOperatorPolicy"
)

#: The private suffix every Tier 1 and Tier 2 alias sits under: `bedrock.egress.internal`,
#: `pypi.egress.internal`, `gpu.egress.internal`. The proxy *is* the alias, so this suffix is the
#: whole of what a Sandbox has any business resolving.
EGRESS_ALIAS_ZONE: Final = "egress.internal"

#: The interface endpoints, keyed by the construct id each gets.
#:
#: S3 and DynamoDB use **gateway** endpoints instead of interface endpoints.  DynamoDB's PrivateLink
#: interface does not support private DNS, and S3's interface endpoint requires a gateway endpoint to
#: exist first.  Gateway endpoints are free, route-table-based, and added only to the proxy and NAT
#: subnets so the connector subnets' zero-route invariant is preserved.
#:
#: The design's two remaining interface services, plus the three a Fargate task needs before it runs
#: at all — `ecr.api` and `ecr.dkr` to pull the proxy image, `logs` to ship its output.  Without
#: them the fleet never reaches steady state, so the whole egress path is down whatever the other
#: two permit.
INTERFACE_ENDPOINTS: Final[Mapping[str, ec2.InterfaceVpcEndpointAwsService]] = {
    # The runtime endpoint, not the control-plane one: `bedrock-runtime.<region>.amazonaws.com` is
    # the upstream host the design's policy document names for the `bedrock-runtime` set.
    "Bedrock": ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME,
    "SecretsManager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
    "EcrApi": ec2.InterfaceVpcEndpointAwsService.ECR,
    "EcrDocker": ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
    "CloudWatchLogs": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
}

#: Gateway endpoints for S3 and DynamoDB, scoped to the proxy and NAT subnets so that connector
#: subnets keep their zero-route invariant (R12.8).
GATEWAY_ENDPOINTS: Final[Mapping[str, ec2.GatewayVpcEndpointAwsService]] = {
    "S3": ec2.GatewayVpcEndpointAwsService.S3,
    "DynamoDb": ec2.GatewayVpcEndpointAwsService.DYNAMODB,
}

#: Every `AWS::EC2::Route` property naming a target outside this VPC, normalised the way
#: :func:`_normalised` normalises a rendered property name. Used to say *which kind* of exit a
#: rejected route was, not to decide whether it is one: a connector route table may carry no route
#: at all, so a target this set does not know is rejected just the same.
OFF_VPC_ROUTE_TARGETS: Final[frozenset[str]] = frozenset(
    {
        "gatewayId",
        "natGatewayId",
        "egressOnlyInternetGatewayId",
        "transitGatewayId",
        "vpcPeeringConnectionId",
        "carrierGatewayId",
        "localGatewayId",
        "coreNetworkArn",
        "instanceId",
        "networkInterfaceId",
        "vpcEndpointId",
    }
)

#: Resource types that sit *inside* a subnet and put a way out of the VPC there, mapped to the
#: property naming that subnet. A NAT gateway is legitimate — on the NAT subnet group — so what is
#: checked is which subnet it names rather than whether one exists.
SUBNET_SCOPED_EXIT_TYPES: Final[Mapping[str, str]] = {
    "AWS::EC2::NatGateway": "subnetId",
}

#: Where the fleet's own name resolution goes. The VPC resolver's address is inside the VPC, so DNS
#: egress from the proxy fleet is to the resolver rather than a public address.
_DNS_PORT: Final = 53

_ROUTE_TYPE: Final = "AWS::EC2::Route"
_ROUTE_TABLE_TYPE: Final = "AWS::EC2::RouteTable"
_ROUTE_TABLE_ASSOCIATION_TYPE: Final = "AWS::EC2::SubnetRouteTableAssociation"
_SUBNET_TYPE: Final = "AWS::EC2::Subnet"


class AlternativeEgressRouteError(RuntimeError):
    """A route table serving a connector subnet gained a route out of the VPC (R12.8).

    Raised at construction rather than reported, because fail-closed in this design is the absence
    of an alternative path *for the connector subnets*: a deployment that has one is not a degraded
    deployment, it is a different one. The message names every offending resource and its type.
    """


class MissingConnectorError(RuntimeError):
    """A connector generation has no `AWS::Lambda::NetworkConnector` (R12.1, R12.8).

    A MicroVM with no connector attached has public internet access, so an unattached generation
    fails open rather than closed. That is the one failure this stack cannot express as a missing
    resource, so it is stated as a refusal to synthesise.
    """


@dataclass(frozen=True)
class ConnectorAttachment:
    """One connector generation: the fixed pipe a Session is attached to for its whole life.

    `ref` is the connector ARN, which is what reaches `SandboxSpec.egress_attachment_ref`.
    """

    generation: int
    security_group: ec2.SecurityGroup
    subnet_ids: tuple[str, ...]
    connector: lambda_.CfnNetworkConnector
    ref: str


class NetworkStack(cdk.Stack):
    """The Egress VPC, its security groups, the connectors and the endpoints."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        connector_generations: Sequence[int] = DEFAULT_CONNECTOR_GENERATIONS,
        nat_gateway_per_availability_zone: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.connector_generations = _require_generations(connector_generations)
        #: The generation a new Session is stamped with, and the one the Reaper's drain
        #: classification (task 10.10) compares an older `egressGeneration` against.
        self.required_generation = self.connector_generations[-1]
        #: One NAT gateway by default. Per-AZ removes the cross-zone hop and survives a zone
        #: losing its NAT, at a second standing charge, so it is the operator's explicit choice
        #: rather than a default that doubles a bill nobody asked about.
        self.nat_gateway_per_availability_zone = nat_gateway_per_availability_zone

        self.vpc = self._vpc()
        self.proxy_subnet_ids = self._subnet_ids(PROXY_SUBNET_GROUP)
        # VPC Flow Logs for security audit (egress monitoring)
        self.vpc.add_flow_log(
            "EgressVpcFlowLog",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )
        self.endpoint_security_group = self._endpoint_security_group()
        self.load_balancer_security_group = self._load_balancer_security_group()
        self.proxy_security_group = self._proxy_security_group()
        self.connector_operator_role = self._connector_operator_role()
        self.attachments = {
            generation: self._attachment(generation)
            for generation in self.connector_generations
        }
        self.endpoints = self._interface_endpoints()
        self.gateway_endpoints = self._gateway_endpoints()

        # Last, so they see everything this stack declares.
        self._require_a_connector_per_generation()
        self._require_no_alternative_route()

    @property
    def attachment(self) -> ConnectorAttachment:
        """The newest connector generation, which is the one a new Session attaches to."""
        return self.attachments[self.required_generation]

    @property
    def attachment_ref(self) -> str:
        """The connector ARN `ControlPlaneStack` passes as `SandboxSpec.egress_attachment_ref`."""
        return self.attachment.ref

    def _vpc(self) -> ec2.Vpc:
        """The egress VPC: a NAT gateway the proxy subnets route to, and isolated connectors."""
        return ec2.Vpc(
            self,
            "Egress",
            ip_addresses=ec2.IpAddresses.cidr(EGRESS_VPC_CIDR),
            max_azs=MAX_AVAILABILITY_ZONES,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name=NAT_SUBNET_GROUP,
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=SUBNET_CIDR_MASK,
                    # The NAT gateway carries an elastic address; nothing else launches here, so an
                    # auto-assigned public address could only ever be an accident.
                    map_public_ip_on_launch=False,
                ),
                ec2.SubnetConfiguration(
                    name=PROXY_SUBNET_GROUP,
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=SUBNET_CIDR_MASK,
                ),
                *(
                    ec2.SubnetConfiguration(
                        name=_connector_subnet_group(generation),
                        # The invariant that matters: no route out, so Untrusted_Code cannot route
                        # around the proxy and gets nothing at all when the proxy is down.
                        subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                        cidr_mask=SUBNET_CIDR_MASK,
                    )
                    for generation in self.connector_generations
                ),
            ],
            nat_gateways=self._nat_gateways(),
            nat_gateway_subnets=ec2.SubnetSelection(subnet_group_name=NAT_SUBNET_GROUP),
            # Stated because the NAT gateway needs it and because the guard below now has to prove
            # something narrower than its absence.
            create_internet_gateway=True,
            # No `restrict_default_security_group`: the VPC's default group is attached to nothing
            # here — the fleet, the load balancer and the endpoints each carry an explicit group —
            # and restricting it deploys a Lambda-backed custom resource to do it.
        )

    def _nat_gateways(self) -> int:
        """One, or one per zone when the operator asked for it."""
        if self.nat_gateway_per_availability_zone:
            return len(self.availability_zones)
        return 1

    def _subnet_ids(self, group: str) -> tuple[str, ...]:
        subnets = self.vpc.select_subnets(subnet_group_name=group).subnets
        if len(subnets) < MINIMUM_AVAILABILITY_ZONES:
            # A connector whose availability-zone set changes needs a new generation, so a
            # single-zone group is fixed by a cutover rather than by an edit.
            raise ValueError(
                f"subnet group {group!r} spans {len(subnets)} availability zone(s); the design's "
                f"multi-AZ proxy service needs at least {MINIMUM_AVAILABILITY_ZONES}"
            )
        return tuple(subnet.subnet_id for subnet in subnets)

    def _endpoint_security_group(self) -> ec2.SecurityGroup:
        """The group on the interface endpoints. Ingress only, from inside this VPC."""
        return ec2.SecurityGroup(
            self,
            "InterfaceEndpoints",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Interface VPC endpoints reached by the connector attachment and the proxy",
        )

    def _load_balancer_security_group(self) -> ec2.SecurityGroup:
        """The group the internal NLB carries.

        Declared here rather than in `EgressStack` so that the attachment rule below can name the
        load balancer itself instead of the VPC's whole address range. `EgressStack` attaches it.
        """
        return ec2.SecurityGroup(
            self,
            "ProxyLoadBalancer",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Internal NLB fronting the Egress_Controller proxy fleet",
        )

    def _proxy_security_group(self) -> ec2.SecurityGroup:
        """The group the Fargate proxy tasks carry, reached only through the load balancer."""
        group = ec2.SecurityGroup(
            self,
            "ProxyFleet",
            vpc=self.vpc,
            # Enumerated rather than `allow_all_outbound`, which would open every port.
            allow_all_outbound=False,
            description="Egress_Controller proxy tasks",
        )
        group.add_ingress_rule(
            self.load_balancer_security_group,
            ec2.Port.tcp(EGRESS_TLS_PORT),
            "the internal NLB and its health checks",
        )
        group.add_egress_rule(
            self.endpoint_security_group,
            ec2.Port.tcp(EGRESS_TLS_PORT),
            "interface VPC endpoints",
        )
        # The upstream leg, over the NAT gateway. Deliberately not narrowed to an address set here:
        # which destinations are permitted is data in the policy store, read per request and revoked
        # within its cache TTL, and a security group rule cannot express a hostname at all. This is
        # the group the design's fixed pipe ends at, not the one it constrains.
        group.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(EGRESS_TLS_PORT),
            "permitted upstreams, whose set is the destination policy rather than this rule",
        )
        for protocol in (ec2.Port.udp(_DNS_PORT), ec2.Port.tcp(_DNS_PORT)):
            group.add_egress_rule(
                ec2.Peer.any_ipv4(),
                protocol,
                "the VPC resolver, filtered by DNS Firewall",
            )
        self.endpoint_security_group.add_ingress_rule(
            group, ec2.Port.tcp(EGRESS_TLS_PORT), "the proxy fleet"
        )
        self.load_balancer_security_group.add_egress_rule(
            group, ec2.Port.tcp(EGRESS_TLS_PORT), "the proxy fleet"
        )
        return group

    def _connector_operator_role(self) -> iam.Role:
        """The role Lambda assumes to manage this VPC's connector network interfaces.

        One role for every generation: it carries no generation identity, and replacing it would not
        replace a connector. There is no service-managed default, so this is not optional.

        The managed policy ``AWSLambdaNetworkConnectorOperatorPolicy`` grants the four statements
        Lambda requires (three scoped ``ec2:CreateNetworkInterface`` and one guarded
        ``ec2:CreateTags``). Attaching it instead of inlining those statements keeps the role in
        sync with any future revisions AWS publishes.
        """
        return iam.Role(
            self,
            "ConnectorOperator",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    CONNECTOR_OPERATOR_MANAGED_POLICY_NAME
                ),
            ],
            description="Lambda network connector ENI management in the egress VPC",
        )

    def _attachment(self, generation: int) -> ConnectorAttachment:
        """One generation's subnets, security group and connector, and the ARN naming the connector.

        Every construct id carries the generation, so bumping the generation adds resources rather
        than editing them. That is the design's distinction: editing the rules inside an attached
        group reaches running Sandboxes, swapping which group is attached does not.
        """
        group = ec2.SecurityGroup(
            self,
            f"ConnectorAttachmentGeneration{generation}",
            vpc=self.vpc,
            # The whole of R12.8's structural half that is expressible in a security group: the two
            # rules below are the only egress, and `allow_all_outbound` would silently add a third.
            allow_all_outbound=False,
            description=(
                f"Lambda network connector attachment, generation {generation}"
            ),
        )
        group.add_egress_rule(
            self.load_balancer_security_group,
            ec2.Port.tcp(EGRESS_TLS_PORT),
            "the proxy load balancer",
        )
        group.add_egress_rule(
            self.endpoint_security_group,
            ec2.Port.tcp(EGRESS_TLS_PORT),
            "the configured interface VPC endpoints",
        )
        self.load_balancer_security_group.add_ingress_rule(
            group, ec2.Port.tcp(EGRESS_TLS_PORT), f"connector generation {generation}"
        )
        self.endpoint_security_group.add_ingress_rule(
            group, ec2.Port.tcp(EGRESS_TLS_PORT), f"connector generation {generation}"
        )

        subnet_ids = self._subnet_ids(_connector_subnet_group(generation))
        security_group_ids = (group.security_group_id,)
        _require_connector_limits(generation, subnet_ids, security_group_ids)
        cdk.Tags.of(group).add(EGRESS_GENERATION_TAG_KEY, str(generation))
        for subnet in self.vpc.select_subnets(
            subnet_group_name=_connector_subnet_group(generation)
        ).subnets:
            cdk.Tags.of(subnet).add(EGRESS_GENERATION_TAG_KEY, str(generation))

        # Recorded risk, not handled here. Connector creation is asynchronous: it is `PENDING`
        # while the underlying ENIs are provisioned and only then `ACTIVE`, and a connector must be
        # `ACTIVE` before `run-microvm` may reference it. Whether `AWS::Lambda::NetworkConnector`
        # holds the stack in `CREATE_IN_PROGRESS` until then is not stated in the resource
        # documentation; if it does not, a stack can reach `CREATE_COMPLETE` carrying a connector
        # the first provision cannot use. Phase 18 confirms which it is against a real deployment.
        # No poller and no custom resource here: that would be building for a problem that may not
        # exist. Source: `https://docs.aws.amazon.com/lambda/latest/dg/microvms-networking.html`.
        connector = lambda_.CfnNetworkConnector(
            self,
            f"ConnectorGeneration{generation}",
            name=f"{CONNECTOR_NAME_PREFIX}{generation}",
            operator_role=self.connector_operator_role.role_arn,
            configuration=lambda_.CfnNetworkConnector.ConfigProperty(
                vpc_egress_configuration=lambda_.CfnNetworkConnector.VpcEgressConfigurationProperty(
                    associated_compute_resource_types=list(
                        CONNECTOR_COMPUTE_RESOURCE_TYPES
                    ),
                    subnet_ids=list(subnet_ids),
                    security_group_ids=list(security_group_ids),
                    network_protocol=CONNECTOR_NETWORK_PROTOCOL,
                )
            ),
        )
        cdk.Tags.of(connector).add(EGRESS_GENERATION_TAG_KEY, str(generation))

        return ConnectorAttachment(
            generation=generation,
            security_group=group,
            subnet_ids=subnet_ids,
            connector=connector,
            ref=connector.attr_arn,
        )

    def _interface_endpoints(self) -> dict[str, ec2.InterfaceVpcEndpoint]:
        """The endpoints the design names and the three the fleet needs, in the proxy subnets."""
        return {
            construct_id: self.vpc.add_interface_endpoint(
                construct_id,
                service=service,
                subnets=ec2.SubnetSelection(subnet_group_name=PROXY_SUBNET_GROUP),
                security_groups=[self.endpoint_security_group],
            )
            for construct_id, service in INTERFACE_ENDPOINTS.items()
        }

    def _gateway_endpoints(self) -> dict[str, ec2.GatewayVpcEndpoint]:
        """S3 and DynamoDB as gateway endpoints, scoped to proxy and NAT subnets.

        Gateway endpoints are free and route-table-based.  They are scoped to the proxy and NAT
        subnets so that no route is added to a connector subnet's route table, preserving the
        zero-route invariant that ``_require_no_alternative_route`` enforces.
        """
        return {
            construct_id: self.vpc.add_gateway_endpoint(
                construct_id,
                service=service,
                subnets=[
                    ec2.SubnetSelection(subnet_group_name=PROXY_SUBNET_GROUP),
                    ec2.SubnetSelection(subnet_group_name=NAT_SUBNET_GROUP),
                ],
            )
            for construct_id, service in GATEWAY_ENDPOINTS.items()
        }

    # --- The guards ------------------------------------------------------------------------------

    def _require_a_connector_per_generation(self) -> None:
        """Fail synthesis unless every generation has its own connector over its own subnets.

        The default for a MicroVM is public internet access, so this is the assertion that the
        Sandbox side of R12.8 is closed at all: one connector per generation, over that generation's
        subnets and its own security group, with an operator role and a name carrying the generation.
        """
        declared = {
            _key(self.resolve(properties.get("name"))): properties
            for _, properties in self._cfn_resources(
                lambda_.CfnNetworkConnector.CFN_RESOURCE_TYPE_NAME
            )
        }
        problems = []
        for generation, attachment in self.attachments.items():
            name = _key(f"{CONNECTOR_NAME_PREFIX}{generation}")
            properties = declared.pop(name, None)
            if properties is None:
                problems.append(f"generation {generation} declares no connector")
                continue
            egress = dict(properties["configuration"]["vpcEgressConfiguration"])
            expected = {
                "associatedComputeResourceTypes": list(
                    CONNECTOR_COMPUTE_RESOURCE_TYPES
                ),
                "subnetIds": [
                    self.resolve(subnet_id) for subnet_id in attachment.subnet_ids
                ],
                "securityGroupIds": [
                    self.resolve(attachment.security_group.security_group_id)
                ],
                "networkProtocol": CONNECTOR_NETWORK_PROTOCOL,
            }
            if egress != expected:
                problems.append(
                    f"generation {generation}'s connector is configured over {egress} "
                    f"rather than over its own subnets and group {expected}"
                )
            if not properties.get("operatorRole"):
                problems.append(
                    f"generation {generation}'s connector carries no operator role, so Lambda "
                    "cannot create its network interfaces"
                )
        if problems:
            raise MissingConnectorError(
                "a MicroVM with no network connector attached has unrestricted internet access, so "
                "every generation must carry one: " + "; ".join(sorted(problems))
            )

    def _require_no_alternative_route(self) -> None:
        """Fail synthesis if a route table serving a connector subnet carries any route (R12.8).

        Not "no NAT gateway anywhere" — the proxy subnets have one, deliberately. What is proved is
        narrower and is the property that matters: for the subnets a MicroVM's network interfaces
        land in, the only route is the implicit local one. Any explicit route is a path somebody
        added, whatever it targets, and a NAT gateway placed inside a connector subnet is refused
        for the same reason.

        A route or a gateway naming a route table or subnet this stack does not declare is refused
        too, because a guard that cannot tell which subnet is served cannot claim the subnet is
        closed.
        """
        subnets = self._connector_subnets()
        tables = self._route_tables_serving(subnets)
        known_tables = {
            _key(self.resolve(node.ref))
            for node, _ in self._cfn_resources(_ROUTE_TABLE_TYPE)
        }
        known_subnets = {
            _key(self.resolve(node.ref))
            for node, _ in self._cfn_resources(_SUBNET_TYPE)
        }

        found = []
        for node, properties in self._cfn_resources(_ROUTE_TYPE):
            table = _key(properties.get("routeTableId"))
            served = tables.get(table)
            if served is None and table in known_tables:
                continue
            targets = sorted(set(properties) & OFF_VPC_ROUTE_TARGETS) or [
                "an unnamed target"
            ]
            found.append(
                f"{node.node.path} ({node.cfn_resource_type} to {', '.join(targets)}) on the route "
                f"table of {served or 'a route table this stack does not declare'}"
            )
        for resource_type, subnet_property in SUBNET_SCOPED_EXIT_TYPES.items():
            for node, properties in self._cfn_resources(resource_type):
                subnet = _key(properties.get(subnet_property))
                if subnet not in subnets and subnet in known_subnets:
                    continue
                found.append(
                    f"{node.node.path} ({node.cfn_resource_type}) inside "
                    f"{subnets.get(subnet) or 'a subnet this stack does not declare'}"
                )
        if found:
            raise AlternativeEgressRouteError(
                "a connector subnet gained a path out of the egress VPC, which is what R12.8's "
                "fail-closed behaviour is the absence of: " + ", ".join(sorted(found))
            )

    def _connector_subnets(self) -> dict[str, str]:
        """Every connector generation's subnets, keyed by resolved id, valued by construct path."""
        return {
            _key(self.resolve(subnet.subnet_id)): subnet.node.path
            for generation in self.connector_generations
            for subnet in self.vpc.select_subnets(
                subnet_group_name=_connector_subnet_group(generation)
            ).subnets
        }

    def _route_tables_serving(self, subnets: Mapping[str, str]) -> dict[str, str]:
        """Resolved route table id to the connector subnet it serves.

        Read off the association resources rather than off each subnet's own table, so that
        re-associating a connector subnet with the proxy subnets' table brings that table — and
        therefore its route to the NAT gateway — into the set this refuses.
        """
        serving = {}
        for _, properties in self._cfn_resources(_ROUTE_TABLE_ASSOCIATION_TYPE):
            served = subnets.get(_key(properties.get("subnetId")))
            if served is not None:
                serving[_key(properties.get("routeTableId"))] = served
        for generation in self.connector_generations:
            # A subnet whose association resource is absent still has a table, and it is still a
            # subnet a MicroVM lands in.
            for subnet in self.vpc.select_subnets(
                subnet_group_name=_connector_subnet_group(generation)
            ).subnets:
                serving.setdefault(
                    _key(self.resolve(subnet.route_table.route_table_id)),
                    subnet.node.path,
                )
        return serving

    def _cfn_resources(
        self, resource_type: str
    ) -> Iterator[tuple[cdk.CfnResource, Mapping[str, Any]]]:
        """Every resource of one type in this stack, with its properties resolved and normalised.

        `_cfn_properties` is the rendering the template is built from, so this sees what will be
        deployed rather than what a construct's public surface reports. Reading it here rather than
        synthesising a template keeps the guards inside the constructor, which is where they have to
        be for a bad topology to fail rather than deploy.
        """
        for node in self.node.find_all():
            if (
                isinstance(node, cdk.CfnResource)
                and node.cfn_resource_type == resource_type
            ):
                yield node, _normalised(self.resolve(node._cfn_properties))


def _normalised(properties: Mapping[str, Any]) -> dict[str, Any]:
    """Rendered property names, however they were spelled.

    A typed L1 renders `natGatewayId` and a bare `CfnResource` renders `NatGatewayId`; both name the
    same property, and a guard that saw only one spelling would miss whichever it did not expect.
    """
    return {key[:1].lower() + key[1:]: value for key, value in properties.items()}


def _key(value: Any) -> str:
    """A comparable, hashable spelling of a resolved value, which is often an intrinsic."""
    return json.dumps(value, sort_keys=True, default=repr)


def _connector_subnet_group(generation: int) -> str:
    return f"{CONNECTOR_SUBNET_GROUP_PREFIX}{generation}"


def _require_connector_limits(
    generation: int, subnet_ids: Sequence[str], security_group_ids: Sequence[str]
) -> None:
    """One connector's subnets and groups against the limits on a VPC egress configuration.

    A generation that outgrew either limit is one that has to be split, so it fails here rather than
    at the deployment that would have carried it.
    """
    if len(subnet_ids) > MAX_CONNECTOR_SUBNETS:
        raise ValueError(
            f"connector generation {generation} spans {len(subnet_ids)} subnets; one connector "
            f"takes at most {MAX_CONNECTOR_SUBNETS}"
        )
    if len(security_group_ids) > MAX_CONNECTOR_SECURITY_GROUPS:
        raise ValueError(
            f"connector generation {generation} carries {len(security_group_ids)} security "
            f"groups; one connector takes at most {MAX_CONNECTOR_SECURITY_GROUPS}"
        )


def _require_generations(generations: Sequence[int]) -> tuple[int, ...]:
    """The live generations: ascending so the newest is read off the order, distinct, and positive.

    The floor is `SessionRecord.egress_generation`'s, so a generation this deploys is one a row records.
    """
    ordered = tuple(generations)
    if not ordered:
        raise ValueError("at least one connector generation must be live")
    if any(generation < 1 for generation in ordered):
        raise ValueError(f"connector generations are numbered from 1: {ordered}")
    if list(ordered) != sorted(set(ordered)):
        raise ValueError(
            f"connector generations must be distinct and ascending: {ordered}"
        )
    return ordered
