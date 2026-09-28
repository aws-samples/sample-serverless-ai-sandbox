# kiro-classification: public
"""`NetworkStack` synthesises connector subnets with no way out of them, and generation-stamped pipes.

Two load-bearing groups of assertions, and they pull in opposite directions on purpose.

The first is negative and scoped. R12.8's fail-closed behaviour is the *absence* of an alternative
path for the subnets a MicroVM's network interfaces land in, so what has to be proved is that no
route table serving a connector subnet carries a route — while the proxy subnets do route to a NAT
gateway, because the proxy is what resolves and reaches `pypi.org` on the Sandbox's behalf. A test
that merely counted NAT gateways would pass on a template that had put one on the wrong subnet, so
the checks here follow the association from subnet to route table to route.

The second is positive and is the newer half. A MicroVM with no connector attached has public
internet access by default, so an unattached generation fails *open*. The connector resource itself
therefore has to be asserted: one per generation, over that generation's subnets, with an operator
role, named for the generation because a name change is what replaces a connector.

Property 17's topology half (task 10.2) quantifies over deployment parameter combinations. These are
the example cases it will build on.
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from typing import Any, Final

import aws_cdk as cdk
import pytest
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Template

from control_plane.state import table as state_table
from control_plane.state.records import SessionRecord
from egress.policy import EGRESS_TLS_PORT
from iac.network_stack import (
    CONNECTOR_COMPUTE_RESOURCE_TYPES,
    CONNECTOR_NAME_PREFIX,
    CONNECTOR_NETWORK_PROTOCOL,
    CONNECTOR_OPERATOR_MANAGED_POLICY_NAME,
    DEFAULT_CONNECTOR_GENERATIONS,
    EGRESS_GENERATION_TAG_KEY,
    GATEWAY_ENDPOINTS,
    INTERFACE_ENDPOINTS,
    MINIMUM_AVAILABILITY_ZONES,
    NAT_SUBNET_GROUP,
    OFF_VPC_ROUTE_TARGETS,
    PROXY_SUBNET_GROUP,
    AlternativeEgressRouteError,
    MissingConnectorError,
    NetworkStack,
)

SUBNET_TYPE: Final = "AWS::EC2::Subnet"
ROUTE_TYPE: Final = "AWS::EC2::Route"
ROUTE_TABLE_TYPE: Final = "AWS::EC2::RouteTable"
ROUTE_TABLE_ASSOCIATION_TYPE: Final = "AWS::EC2::SubnetRouteTableAssociation"
NAT_GATEWAY_TYPE: Final = "AWS::EC2::NatGateway"
INTERNET_GATEWAY_TYPE: Final = "AWS::EC2::InternetGateway"
SECURITY_GROUP_TYPE: Final = "AWS::EC2::SecurityGroup"
EGRESS_RULE_TYPE: Final = "AWS::EC2::SecurityGroupEgress"
INGRESS_RULE_TYPE: Final = "AWS::EC2::SecurityGroupIngress"
ENDPOINT_TYPE: Final = "AWS::EC2::VPCEndpoint"
CONNECTOR_TYPE: Final = "AWS::Lambda::NetworkConnector"
ROLE_TYPE: Final = "AWS::IAM::Role"

#: CDK strips the punctuation out of a subnet group name when it builds a logical id, so
#: `connector-g1` reaches the template as `connectorg1`.
CONNECTOR_LOGICAL_FRAGMENT: Final = "connectorg"


def _synthesise(tmp_path: Path, **kwargs: Any) -> tuple[NetworkStack, Template]:
    app = cdk.App(outdir=str(tmp_path))
    stack = NetworkStack(
        app, "NetworkStack", env=cdk.Environment(region="us-east-1"), **kwargs
    )
    return stack, Template.from_stack(stack)


@pytest.fixture(name="synthesised")
def _synthesised(tmp_path: Path) -> tuple[NetworkStack, Template]:
    return _synthesise(tmp_path)


@pytest.fixture(name="template")
def _template(synthesised: tuple[NetworkStack, Template]) -> Template:
    return synthesised[1]


def _by_type(template: Template, resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: dict(resource)
        for logical_id, resource in template.find_resources(resource_type).items()
    }


def _properties(template: Template, resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: dict(resource["Properties"])
        for logical_id, resource in _by_type(template, resource_type).items()
    }


def _sole(template: Template, resource_type: str) -> dict[str, Any]:
    found = _properties(template, resource_type)
    assert len(found) == 1, sorted(found)
    return next(iter(found.values()))


def _group_id(template: Template, description: str) -> str:
    """The logical id of the one security group whose description contains `description`."""
    matches = [
        logical_id
        for logical_id, properties in _properties(template, SECURITY_GROUP_TYPE).items()
        if description in properties["GroupDescription"]
    ]
    assert len(matches) == 1, (description, matches)
    return matches[0]


def _as_list(value: Any) -> list[Any]:
    """A rendered policy field, which CloudFormation renders as a scalar when there is only one."""
    return list(value) if isinstance(value, list) else [value]


def _ec2_actions(statement: dict[str, Any]) -> set[str]:
    return {
        action
        for action in _as_list(statement.get("Action"))
        if isinstance(action, str) and action.startswith("ec2:")
    }


def _rules(template: Template, rule_type: str, group_id: str) -> list[dict[str, Any]]:
    reference = {"Fn::GetAtt": [group_id, "GroupId"]}
    return [
        properties
        for properties in _properties(template, rule_type).values()
        if properties["GroupId"] == reference
    ]


def _subnets(template: Template, fragment: str) -> set[str]:
    """The logical ids of the subnets whose group name contains `fragment`."""
    return {
        logical_id
        for logical_id in _properties(template, SUBNET_TYPE)
        if fragment in logical_id
    }


def _route_tables_serving(template: Template, fragment: str) -> dict[str, str]:
    """Route table logical id to the subnet logical id it is associated with.

    Followed through the association resources rather than read off a subnet, because which table
    serves which subnet is exactly what a change could alter without touching either.
    """
    served = _subnets(template, fragment)
    return {
        properties["RouteTableId"]["Ref"]: properties["SubnetId"]["Ref"]
        for properties in _properties(template, ROUTE_TABLE_ASSOCIATION_TYPE).values()
        if properties["SubnetId"].get("Ref") in served
    }


def _routes_on(template: Template, tables: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {
        logical_id: properties
        for logical_id, properties in _properties(template, ROUTE_TYPE).items()
        if properties["RouteTableId"].get("Ref") in tables
    }


def _availability_zones(template: Template, group: str) -> list[Any]:
    return [
        properties["AvailabilityZone"]
        for logical_id, properties in _properties(template, SUBNET_TYPE).items()
        if group.replace("-", "") in logical_id
    ]


def _connectors(template: Template) -> dict[str, dict[str, Any]]:
    """The connectors keyed by their `Name`, which is what carries the generation."""
    return {
        properties["Name"]: properties
        for properties in _properties(template, CONNECTOR_TYPE).values()
    }


def _connector_logical_id(template: Template, generation: int) -> str:
    matches = [
        logical_id
        for logical_id, properties in _properties(template, CONNECTOR_TYPE).items()
        if properties["Name"] == f"{CONNECTOR_NAME_PREFIX}{generation}"
    ]
    assert len(matches) == 1, (generation, matches)
    return matches[0]


# --- The absence that is the requirement, scoped to the connector subnets (R12.8) -----------------


def test_no_route_table_serving_a_connector_subnet_carries_a_route_at_all(
    template: Template,
) -> None:
    """Stronger than "no route to a gateway", and deliberately.

    A connector subnet's local route is implicit, so any explicit route on its table is a path
    somebody added and the target they chose does not matter. The mapping is asserted non-empty
    first, so an absence of routes is an absence of routes rather than an absence of tables.
    """
    tables = _route_tables_serving(template, CONNECTOR_LOGICAL_FRAGMENT)
    assert tables
    assert _routes_on(template, tables) == {}


def test_no_route_table_serving_a_connector_subnet_is_the_one_the_proxy_uses(
    template: Template,
) -> None:
    # The other half of the check above: re-associating a connector subnet with the proxy subnets'
    # table would hand it the route to the NAT gateway without adding a single route resource.
    connector_tables = set(_route_tables_serving(template, CONNECTOR_LOGICAL_FRAGMENT))
    proxy_tables = set(_route_tables_serving(template, PROXY_SUBNET_GROUP))
    nat_tables = set(_route_tables_serving(template, NAT_SUBNET_GROUP))
    assert connector_tables and proxy_tables and nat_tables
    assert connector_tables.isdisjoint(proxy_tables | nat_tables)


def test_every_connector_subnet_has_exactly_one_route_table_of_its_own(
    template: Template,
) -> None:
    tables = _route_tables_serving(template, CONNECTOR_LOGICAL_FRAGMENT)
    subnets = _subnets(template, CONNECTOR_LOGICAL_FRAGMENT)
    # A subnet with no association at all would fall back to the VPC's main route table, which is
    # not a table this template governs.
    assert sorted(tables.values()) == sorted(subnets)


def test_no_nat_gateway_sits_in_a_connector_subnet(template: Template) -> None:
    subnets = _subnets(template, CONNECTOR_LOGICAL_FRAGMENT)
    inside = {
        logical_id: properties["SubnetId"]
        for logical_id, properties in _properties(template, NAT_GATEWAY_TYPE).items()
        if properties["SubnetId"].get("Ref") in subnets
    }
    assert inside == {}


def test_no_endpoint_route_lands_on_a_connector_route_table(template: Template) -> None:
    # Gateway endpoints (S3, DynamoDB) add route-table entries, but are scoped to the proxy and NAT
    # subnets.  The connector subnets must carry no endpoint route at all.
    connector_tables = set(_route_tables_serving(template, CONNECTOR_LOGICAL_FRAGMENT))
    gateway_endpoints = _properties(template, ENDPOINT_TYPE)
    for logical_id, properties in gateway_endpoints.items():
        if properties["VpcEndpointType"] != "Gateway":
            continue
        route_table_ids = {
            rt.get("Ref") or rt
            for rt in properties.get("RouteTableIds", [])
        }
        assert route_table_ids.isdisjoint(connector_tables), (
            f"Gateway endpoint {logical_id} routes to a connector subnet route table"
        )


@pytest.mark.parametrize(
    "target",
    sorted(OFF_VPC_ROUTE_TARGETS - {"coreNetworkArn"}),
)
def test_a_route_out_of_a_connector_subnet_fails_synthesis(
    tmp_path: Path, target: str
) -> None:
    """The guard in the stack, not only the assertions above.

    A test can be deleted; the check inside the stack cannot be deleted by somebody who was only
    adding a subnet. The message has to name the offending resource and the exit it chose, or a
    deployment learns only that something is wrong.
    """
    stack, _ = _synthesise(tmp_path)
    subnet = stack.vpc.select_subnets(subnet_group_name="connector-g1").subnets[0]
    cdk.CfnResource(
        stack,
        "AddedLater",
        type=ROUTE_TYPE,
        properties={
            "RouteTableId": subnet.route_table.route_table_id,
            # CloudFormation-cased, which a hand-written resource is: the guard has to see the same
            # property whether a typed L1 rendered it or somebody spelled it out.
            target[:1].upper() + target[1:]: "whatever-it-points-at",
        },
    )
    with pytest.raises(AlternativeEgressRouteError) as raised:
        stack._require_no_alternative_route()
    message = str(raised.value)
    assert "AddedLater" in message
    assert target in message
    assert subnet.node.path in message


def test_a_route_on_the_proxy_route_table_is_left_alone(tmp_path: Path) -> None:
    """The rescoping, stated as a test: NAT is legitimate, on the subnets that may have it.

    Without this the guard could be "fixed" by forbidding every route again, which would take the
    proxy's path to `pypi.org` with it and leave Tier 2 and Tier 3 unable to function.
    """
    stack, _ = _synthesise(tmp_path)
    proxy = stack.vpc.select_subnets(subnet_group_name=PROXY_SUBNET_GROUP).subnets[0]
    ec2.CfnRoute(
        stack,
        "AnotherProxyRoute",
        route_table_id=proxy.route_table.route_table_id,
        destination_cidr_block="0.0.0.0/0",
        nat_gateway_id="nat-0123456789abcdef0",
    )
    stack._require_no_alternative_route()


def test_re_associating_a_connector_subnet_with_the_proxy_table_fails_synthesis(
    tmp_path: Path,
) -> None:
    """The attack the resource count could never have caught.

    Nothing is added that carries traffic. The connector subnet is simply pointed at a table that
    already has a route to the NAT gateway, so the guard has to reason about which subnet a table
    serves rather than about which resources exist.
    """
    stack, _ = _synthesise(tmp_path)
    connector = stack.vpc.select_subnets(subnet_group_name="connector-g1").subnets[0]
    proxy = stack.vpc.select_subnets(subnet_group_name=PROXY_SUBNET_GROUP).subnets[0]
    ec2.CfnSubnetRouteTableAssociation(
        stack,
        "Reassociated",
        subnet_id=connector.subnet_id,
        route_table_id=proxy.route_table.route_table_id,
    )
    with pytest.raises(AlternativeEgressRouteError) as raised:
        stack._require_no_alternative_route()
    assert connector.node.path in str(raised.value)


def test_a_nat_gateway_in_a_connector_subnet_fails_synthesis(tmp_path: Path) -> None:
    stack, _ = _synthesise(tmp_path)
    connector = stack.vpc.select_subnets(subnet_group_name="connector-g1").subnets[0]
    ec2.CfnNatGateway(
        stack,
        "SneakyNat",
        subnet_id=connector.subnet_id,
        allocation_id="eipalloc-0123456789abcdef0",
    )
    with pytest.raises(AlternativeEgressRouteError) as raised:
        stack._require_no_alternative_route()
    message = str(raised.value)
    assert "SneakyNat" in message
    assert connector.node.path in message


@pytest.mark.parametrize(
    ("resource_type", "properties"),
    [
        (ROUTE_TYPE, {"RouteTableId": "rtb-0123456789abcdef0", "GatewayId": "igw-1"}),
        (
            NAT_GATEWAY_TYPE,
            {"SubnetId": "subnet-0123456789abcdef0", "AllocationId": "eipalloc-1"},
        ),
    ],
)
def test_a_route_or_gateway_naming_something_this_stack_does_not_declare_fails_synthesis(
    tmp_path: Path, resource_type: str, properties: dict[str, str]
) -> None:
    # Fail-closed where the guard cannot see: a route table or subnet imported from elsewhere might
    # be a connector's, and a check that cannot tell may not claim the subnet is closed.
    stack, _ = _synthesise(tmp_path)
    cdk.CfnResource(stack, "Imported", type=resource_type, properties=properties)
    with pytest.raises(AlternativeEgressRouteError) as raised:
        stack._require_no_alternative_route()
    assert "does not declare" in str(raised.value)


# --- The path out that the proxy subnets do have --------------------------------------------------


def test_one_nat_gateway_serves_the_proxy_subnets(template: Template) -> None:
    """One, not one per zone: a second standing charge is the operator's decision to make."""
    nat = _sole(template, NAT_GATEWAY_TYPE)
    assert nat["SubnetId"]["Ref"] in _subnets(template, NAT_SUBNET_GROUP)
    proxy_tables = _route_tables_serving(template, PROXY_SUBNET_GROUP)
    routes = _routes_on(template, proxy_tables)
    assert routes, "the proxy fleet cannot reach a package registry without a route out"
    for properties in routes.values():
        assert properties["DestinationCidrBlock"] == "0.0.0.0/0"
        assert "NatGatewayId" in properties
        assert "GatewayId" not in properties


def test_the_nat_gateway_is_the_only_thing_in_the_only_public_subnet_group(
    template: Template,
) -> None:
    # The internet gateway exists because a NAT gateway cannot reach the internet without one, and
    # the public subnets exist because a NAT gateway cannot sit anywhere else.
    assert len(_properties(template, INTERNET_GATEWAY_TYPE)) == 1
    for logical_id in _subnets(template, NAT_SUBNET_GROUP):
        properties = _properties(template, SUBNET_TYPE)[logical_id]
        # Nothing launches here, so an auto-assigned public address could only be an accident.
        assert properties["MapPublicIpOnLaunch"] is False


def test_only_the_nat_and_proxy_subnet_groups_are_public_or_routed(
    template: Template,
) -> None:
    routed = {
        properties["RouteTableId"]["Ref"]
        for properties in _properties(template, ROUTE_TYPE).values()
    }
    served = {
        properties["RouteTableId"]["Ref"]: properties["SubnetId"]["Ref"]
        for properties in _properties(template, ROUTE_TABLE_ASSOCIATION_TYPE).values()
    }
    for table in routed:
        subnet = served[table]
        assert NAT_SUBNET_GROUP in subnet or PROXY_SUBNET_GROUP in subnet, subnet


def test_the_per_availability_zone_nat_knob_is_off_by_default(tmp_path: Path) -> None:
    stack, one = _synthesise(tmp_path / "one")
    assert stack.nat_gateway_per_availability_zone is False
    _, per_zone = _synthesise(
        tmp_path / "per-zone", nat_gateway_per_availability_zone=True
    )
    assert len(_properties(one, NAT_GATEWAY_TYPE)) == 1
    # One per zone, and every proxy subnet still routes out, so the knob buys zone independence
    # rather than a different topology.
    assert len(_properties(per_zone, NAT_GATEWAY_TYPE)) == len(
        _subnets(per_zone, NAT_SUBNET_GROUP)
    )
    assert len(
        _routes_on(per_zone, _route_tables_serving(per_zone, PROXY_SUBNET_GROUP))
    ) == len(_subnets(per_zone, PROXY_SUBNET_GROUP))


# --- The connector, and why an absent one fails open (R12.1, R12.8) ------------------------------


def test_each_generation_declares_one_connector_over_its_own_subnets_and_group(
    tmp_path: Path,
) -> None:
    """The resource R12.1 names, and the reason it cannot be optional.

    A MicroVM with no connector attached has public internet access, so a generation without one is
    not a generation with less egress control, it is a generation with none.
    """
    stack, template = _synthesise(tmp_path, connector_generations=(1, 2))
    connectors = _connectors(template)
    assert set(connectors) == {f"{CONNECTOR_NAME_PREFIX}{g}" for g in (1, 2)}
    for generation in (1, 2):
        attachment = stack.attachments[generation]
        egress = connectors[f"{CONNECTOR_NAME_PREFIX}{generation}"]["Configuration"][
            "VpcEgressConfiguration"
        ]
        assert (
            egress["AssociatedComputeResourceTypes"]
            == list(CONNECTOR_COMPUTE_RESOURCE_TYPES)
            == ["MicroVm"]
        )
        assert egress["SubnetIds"] == [
            stack.resolve(subnet_id) for subnet_id in attachment.subnet_ids
        ]
        assert egress["SecurityGroupIds"] == [
            stack.resolve(attachment.security_group.security_group_id)
        ]
        # IPv4 rather than `DualStack`: IPv6 egress leaves a VPC through its own gateway, and this
        # topology's whole argument is about which route tables carry a route.
        assert egress["NetworkProtocol"] == CONNECTOR_NETWORK_PROTOCOL == "IPv4"


def test_the_connector_name_carries_the_generation_and_nothing_else(
    tmp_path: Path,
) -> None:
    # `Name` cannot be updated in place — a change replaces the connector — so the generation being
    # the only thing in it is what makes a cutover a replacement and every other edit harmless.
    stack, template = _synthesise(tmp_path, connector_generations=(4, 5))
    for generation in (4, 5):
        name = _connectors(template)[f"{CONNECTOR_NAME_PREFIX}{generation}"]["Name"]
        assert name == f"{CONNECTOR_NAME_PREFIX}{generation}"
        assert str(generation) in name
        assert 1 <= len(name) <= 64
        assert name.replace("-", "").replace("_", "").isalnum()
    assert stack.required_generation == 5


def test_every_connector_carries_the_operator_role_lambda_needs(
    synthesised: tuple[NetworkStack, Template],
) -> None:
    """Without it Lambda cannot create the network interfaces, and there is no service default."""
    stack, template = synthesised
    role_arn = stack.resolve(stack.connector_operator_role.role_arn)
    for properties in _properties(template, CONNECTOR_TYPE).values():
        assert properties["OperatorRole"] == role_arn
    role = next(
        properties
        for properties in _properties(template, ROLE_TYPE).values()
        if "connector" in properties.get("Description", "").lower()
    )
    assert role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
        "Service": "lambda.amazonaws.com"
    }
    # The managed policy replaces the previous inline statements. The role should carry the
    # AWS-managed ``AWSLambdaNetworkConnectorOperatorPolicy`` and nothing besides.
    managed_arns = role.get("ManagedPolicyArns", [])
    expected_suffix = f"policy/{CONNECTOR_OPERATOR_MANAGED_POLICY_NAME}"
    assert any(
        arn.get("Fn::Join", ["", [""]])[1][-1].endswith(expected_suffix)
        if isinstance(arn, dict)
        else str(arn).endswith(expected_suffix)
        for arn in managed_arns
    ), f"Expected managed policy ending with {expected_suffix!r} in {managed_arns}"
    # No inline ec2 statements should remain — all permissions come from the managed policy.
    inline_ec2_statements = [
        statement
        for policy in _properties(template, "AWS::IAM::Policy").values()
        for statement in policy["PolicyDocument"]["Statement"]
        if _ec2_actions(statement)
    ]
    assert inline_ec2_statements == [], (
        f"Inline ec2: statements should not exist when using the managed policy: "
        f"{inline_ec2_statements}"
    )


def test_the_attachment_reference_is_the_newest_connectors_arn(tmp_path: Path) -> None:
    """What `ControlPlaneStack` passes as `SandboxSpec.egress_attachment_ref`, unparsed."""
    stack, template = _synthesise(tmp_path, connector_generations=(2, 3))
    assert stack.resolve(stack.attachment_ref) == {
        "Fn::GetAtt": [_connector_logical_id(template, 3), "Arn"]
    }
    assert stack.resolve(stack.attachments[2].ref) == {
        "Fn::GetAtt": [_connector_logical_id(template, 2), "Arn"]
    }
    # Deploy-time resolved rather than known now, and an ARN rather than a composed string: the
    # value identifies the connector the provider attaches, and nothing reads it apart.
    assert stack.attachment is stack.attachments[3]


def test_a_generation_left_without_a_connector_fails_synthesis(tmp_path: Path) -> None:
    """The one failure that cannot be expressed as a missing resource, so it is a refusal."""
    stack, _ = _synthesise(tmp_path)
    stack.attachment.connector.name = "renamed-so-no-generation-claims-it"
    with pytest.raises(MissingConnectorError) as raised:
        stack._require_a_connector_per_generation()
    message = str(raised.value)
    assert "unrestricted internet" in message
    assert "generation 1" in message


def test_a_connector_pointed_at_the_wrong_subnets_fails_synthesis(
    tmp_path: Path,
) -> None:
    # A connector over the proxy subnets would put the MicroVM on the far side of the NAT gateway,
    # which is open egress arrived at without adding a single route.
    stack, _ = _synthesise(tmp_path)
    stack.attachment.connector.configuration = (
        lambda_.CfnNetworkConnector.ConfigProperty(
            vpc_egress_configuration=lambda_.CfnNetworkConnector.VpcEgressConfigurationProperty(
                associated_compute_resource_types=list(
                    CONNECTOR_COMPUTE_RESOURCE_TYPES
                ),
                subnet_ids=list(stack.proxy_subnet_ids),
                security_group_ids=[stack.attachment.security_group.security_group_id],
                network_protocol=CONNECTOR_NETWORK_PROTOCOL,
            )
        )
    )
    with pytest.raises(MissingConnectorError):
        stack._require_a_connector_per_generation()


def test_a_connector_without_an_operator_role_fails_synthesis(tmp_path: Path) -> None:
    stack, _ = _synthesise(tmp_path)
    stack.attachment.connector.operator_role = None
    with pytest.raises(MissingConnectorError) as raised:
        stack._require_a_connector_per_generation()
    assert "operator role" in str(raised.value)


# --- The attachment security group ---------------------------------------------------------------


def test_the_attachment_permits_egress_only_to_the_load_balancer_and_the_endpoints(
    template: Template,
) -> None:
    balancer = _group_id(template, "Internal NLB")
    endpoints = _group_id(template, "Interface VPC endpoints")
    attachment = _group_id(template, "generation 1")

    destinations = [
        (
            rule.get("DestinationSecurityGroupId"),
            rule["IpProtocol"],
            rule["FromPort"],
            rule["ToPort"],
        )
        for rule in _rules(template, EGRESS_RULE_TYPE, attachment)
    ]
    assert sorted(destinations, key=repr) == sorted(
        [
            (
                {"Fn::GetAtt": [balancer, "GroupId"]},
                "tcp",
                EGRESS_TLS_PORT,
                EGRESS_TLS_PORT,
            ),
            (
                {"Fn::GetAtt": [endpoints, "GroupId"]},
                "tcp",
                EGRESS_TLS_PORT,
                EGRESS_TLS_PORT,
            ),
        ],
        key=repr,
    )


def test_the_attachment_reaches_no_address_range_and_no_other_port(
    template: Template,
) -> None:
    for rule in _rules(template, EGRESS_RULE_TYPE, _group_id(template, "generation 1")):
        # A CIDR destination is the shape that would let the attachment reach anything the VPC can
        # route to — which, now that the proxy subnets route to a NAT gateway, includes the
        # internet. This is the rule that keeps the fixed pipe pointed at the proxy.
        assert "CidrIp" not in rule and "CidrIpv6" not in rule
        assert rule["FromPort"] == rule["ToPort"] == EGRESS_TLS_PORT


def test_the_attachment_group_carries_no_open_egress_rule(
    synthesised: tuple[NetworkStack, Template],
) -> None:
    stack, template = synthesised
    # `allow_all_outbound=True` emits the open rule inline on the group rather than as a separate
    # resource, so the check has to look at the group's own properties too.
    properties = _properties(template, SECURITY_GROUP_TYPE)[
        _group_id(template, "generation 1")
    ]
    assert "SecurityGroupEgress" not in properties
    assert stack.attachment.security_group.allow_all_outbound is False


def test_the_proxy_fleet_reaches_the_upstream_leg_and_nothing_reaches_it_but_the_balancer(
    template: Template,
) -> None:
    """The one group with an address range in its egress rules, and why.

    The fleet originates the upstream TLS session, and which destinations are permitted is data in
    the policy store read per request, not a rule here. Ports are still enumerated: 443 for the
    upstream leg and 53 for the resolution the DNS Firewall allowlist governs.
    """
    fleet = _group_id(template, "Egress_Controller proxy tasks")
    balancer = _group_id(template, "Internal NLB")
    sources = [
        rule.get("SourceSecurityGroupId")
        for rule in _rules(template, INGRESS_RULE_TYPE, fleet)
    ]
    assert sources == [{"Fn::GetAtt": [balancer, "GroupId"]}]

    # A rule with a CIDR destination is rendered inline on the group; one naming another group is
    # rendered as its own resource, so both places have to be read.
    inline = _properties(template, SECURITY_GROUP_TYPE)[fleet]["SecurityGroupEgress"]
    open_ports = {
        (rule["IpProtocol"], rule["FromPort"], rule["ToPort"])
        for rule in inline
        if rule["CidrIp"] == "0.0.0.0/0"
    }
    assert open_ports == {
        ("tcp", EGRESS_TLS_PORT, EGRESS_TLS_PORT),
        ("udp", 53, 53),
        ("tcp", 53, 53),
    }
    assert len(inline) == len(open_ports), "no other address range and no other port"
    endpoints = _group_id(template, "Interface VPC endpoints")
    assert [
        rule["DestinationSecurityGroupId"]
        for rule in _rules(template, EGRESS_RULE_TYPE, fleet)
    ] == [{"Fn::GetAtt": [endpoints, "GroupId"]}]


def test_every_security_group_is_declared_here(template: Template) -> None:
    # `EgressStack` declares none: the load balancer's group and the fleet's group live here so that
    # the attachment's egress rules can name them without a cross-stack cycle.
    assert set(_properties(template, SECURITY_GROUP_TYPE)) == {
        _group_id(template, "Interface VPC endpoints"),
        _group_id(template, "Internal NLB"),
        _group_id(template, "Egress_Controller proxy tasks"),
        _group_id(template, "generation 1"),
    }


# --- Interface endpoints -------------------------------------------------------------------------


def test_the_interface_endpoints_of_the_topology_diagram_and_the_three_fargate_needs(
    synthesised: tuple[NetworkStack, Template],
) -> None:
    """The design's two interface services, plus `ecr.api`, `ecr.dkr` and `logs`.

    A Fargate task in a private subnet cannot pull its image or ship its logs without those three,
    so without them the proxy fleet never reaches steady state and the whole egress path is down.
    S3 and DynamoDB are gateway endpoints and checked separately.
    """
    stack, template = synthesised
    interface_services = {
        stack.resolve(properties["ServiceName"])
        for properties in _properties(template, ENDPOINT_TYPE).values()
        if properties["VpcEndpointType"] == "Interface"
    }
    assert len(interface_services) == len(INTERFACE_ENDPOINTS) == 5
    expected = {stack.resolve(service.name) for service in INTERFACE_ENDPOINTS.values()}
    assert interface_services == expected
    short_names = {service.short_name for service in INTERFACE_ENDPOINTS.values()}
    assert {"ecr.api", "ecr.dkr", "logs"} <= short_names

    # Gateway endpoints for S3 and DynamoDB.
    gateway_properties = [
        properties
        for properties in _properties(template, ENDPOINT_TYPE).values()
        if properties["VpcEndpointType"] == "Gateway"
    ]
    assert len(gateway_properties) == len(GATEWAY_ENDPOINTS) == 2
    gateway_services = {
        str(stack.resolve(properties["ServiceName"]))
        for properties in gateway_properties
    }
    expected_gw = {str(stack.resolve(service.name)) for service in GATEWAY_ENDPOINTS.values()}
    assert gateway_services == expected_gw


def test_every_endpoint_sits_behind_the_endpoint_security_group(
    template: Template,
) -> None:
    endpoints = _group_id(template, "Interface VPC endpoints")
    for properties in _properties(template, ENDPOINT_TYPE).values():
        if properties["VpcEndpointType"] != "Interface":
            continue
        assert properties["SecurityGroupIds"] == [
            {"Fn::GetAtt": [endpoints, "GroupId"]}
        ]


def test_every_endpoint_sits_in_the_proxy_subnets(
    synthesised: tuple[NetworkStack, Template],
) -> None:
    # Not in a connector subnet: an endpoint there would be reachable from a MicroVM without the
    # attachment security group's rule being involved at all.
    stack, template = synthesised
    expected = [stack.resolve(subnet_id) for subnet_id in stack.proxy_subnet_ids]
    for properties in _properties(template, ENDPOINT_TYPE).values():
        if properties["VpcEndpointType"] != "Interface":
            continue
        assert properties["SubnetIds"] == expected


# --- Availability zones --------------------------------------------------------------------------


def test_the_proxy_subnets_span_more_than_one_availability_zone(
    template: Template,
) -> None:
    zones = _availability_zones(template, PROXY_SUBNET_GROUP)
    assert len(zones) >= MINIMUM_AVAILABILITY_ZONES, zones
    # Distinct, so the design's multi-AZ Fargate service has somewhere to spread to. An
    # environment-agnostic synthesis resolves these through `Fn::GetAZs`, which is what makes
    # distinctness checkable without an account.
    assert len(zones) == len({repr(zone) for zone in zones})


def test_each_connector_generation_spans_more_than_one_availability_zone(
    tmp_path: Path,
) -> None:
    _, template = _synthesise(tmp_path, connector_generations=(4, 5))
    for generation in (4, 5):
        zones = _availability_zones(template, f"connector-g{generation}")
        assert len(zones) >= MINIMUM_AVAILABILITY_ZONES, (generation, zones)
        assert len(zones) == len({repr(zone) for zone in zones})


# --- Connector generations (R12.7) ---------------------------------------------------------------


def test_the_first_generation_is_the_one_a_session_row_records_by_default() -> None:
    # The mechanical tie to the Session record: a Session that nobody stamped and the generation a
    # fresh deployment offers have to be the same number, or every row would look drained.
    declared = next(
        field for field in fields(SessionRecord) if field.name == "egress_generation"
    )
    assert DEFAULT_CONNECTOR_GENERATIONS == (declared.default,) == (1,)


def test_the_generation_tag_is_spelled_the_way_the_session_attribute_is() -> None:
    # The Reaper's drain classification (task 10.10) compares a row's `egressGeneration` against the
    # required generation, so the tag this stack stamps and the attribute that index projects have
    # to be one spelling.
    assert EGRESS_GENERATION_TAG_KEY in state_table.DEADLINE_INDEX.non_key_attributes


def test_the_newest_generation_is_the_one_a_new_session_attaches_to(
    tmp_path: Path,
) -> None:
    stack, _ = _synthesise(tmp_path, connector_generations=(7, 8, 9))
    assert stack.required_generation == 9
    assert stack.attachment is stack.attachments[9]
    assert set(stack.attachments) == {7, 8, 9}


def test_a_cutover_adds_a_generation_rather_than_editing_one(tmp_path: Path) -> None:
    """Both pipes exist during the drain, which is the whole of the blue/green mechanism."""
    _, one = _synthesise(tmp_path / "one", connector_generations=(1,))
    _, two = _synthesise(tmp_path / "two", connector_generations=(1, 2))
    for resource_type in (SECURITY_GROUP_TYPE, CONNECTOR_TYPE):
        before = set(_properties(one, resource_type))
        after = set(_properties(two, resource_type))
        # The generation-1 resources keep their logical ids, so CloudFormation leaves them in place
        # and a Session stamped with generation 1 keeps the pipe it started on.
        assert before < after, resource_type
    assert _group_id(two, "generation 1") in set(_properties(one, SECURITY_GROUP_TYPE))
    assert _group_id(two, "generation 2") not in set(
        _properties(one, SECURITY_GROUP_TYPE)
    )
    # And generation 1's connector keeps its name, which is what stops CloudFormation replacing it.
    assert (
        _connectors(one)[f"{CONNECTOR_NAME_PREFIX}1"]["Name"]
        == (_connectors(two)[f"{CONNECTOR_NAME_PREFIX}1"]["Name"])
    )


def test_each_generation_stamps_its_subnets_its_group_and_its_connector(
    tmp_path: Path,
) -> None:
    _, template = _synthesise(tmp_path, connector_generations=(1, 2))
    for generation in (1, 2):
        tag = {"Key": EGRESS_GENERATION_TAG_KEY, "Value": str(generation)}
        group = _properties(template, SECURITY_GROUP_TYPE)[
            _group_id(template, f"generation {generation}")
        ]
        assert tag in group["Tags"]
        assert (
            tag in _connectors(template)[f"{CONNECTOR_NAME_PREFIX}{generation}"]["Tags"]
        )
        stamped = [
            properties
            for logical_id, properties in _properties(template, SUBNET_TYPE).items()
            if f"{CONNECTOR_LOGICAL_FRAGMENT}{generation}" in logical_id
        ]
        assert stamped
        for subnet in stamped:
            assert tag in subnet["Tags"]


@pytest.mark.parametrize(
    "generations", [(), (0,), (-1,), (1, 0), (2, 1), (1, 1), (1, 3, 2)]
)
def test_an_unusable_generation_set_is_refused(
    tmp_path: Path, generations: tuple[int, ...]
) -> None:
    # Ascending and distinct, because the newest generation is read off the order rather than named
    # by a second parameter that could disagree with it. Zero is refused for the reason
    # `SessionRecord` refuses it: a row recording generation 0 is a row recording nothing.
    with pytest.raises(ValueError):
        _synthesise(tmp_path, connector_generations=generations)
