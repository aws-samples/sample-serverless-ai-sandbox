# kiro-classification: public
"""`EgressStack` synthesises a multi-AZ proxy fleet behind an internal load balancer.

Every assertion reads the emitted CloudFormation, because only the template shows that the load
balancer is internal rather than internet-facing, that the fleet runs more than one task, that the
tasks carry `NetworkStack`'s security group rather than one of their own, and that the seeded policy
is the one the fleet's own loader accepts. The port, the policy cache bound and the fail-closed
default action are read from the modules that own them rather than restated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from egress.policy import EGRESS_TLS_PORT, DefaultAction, EgressPolicy
from egress.reader import MAX_POLICY_CACHE_TTL_SECONDS
from iac.egress_stack import (
    CA_VALIDITY_YEARS,
    MINIMUM_PROXY_TASKS,
    PLACEHOLDER_PROXY_IMAGE,
    POLICY_CACHE_TTL_SECONDS,
    PROXY_IMAGE_URI_CONTEXT_KEY,
    SEED_POLICY,
    SEED_POLICY_DOCUMENT,
    UPSTREAM_CREDENTIAL_NAMES,
    EgressStack,
)
from iac.network_stack import NetworkStack

SERVICE_TYPE: Final = "AWS::ECS::Service"
TASK_DEFINITION_TYPE: Final = "AWS::ECS::TaskDefinition"
LOAD_BALANCER_TYPE: Final = "AWS::ElasticLoadBalancingV2::LoadBalancer"
LISTENER_TYPE: Final = "AWS::ElasticLoadBalancingV2::Listener"
TARGET_GROUP_TYPE: Final = "AWS::ElasticLoadBalancingV2::TargetGroup"
AUTHORITY_TYPE: Final = "AWS::ACMPCA::CertificateAuthority"
CA_CERTIFICATE_TYPE: Final = "AWS::ACMPCA::Certificate"
CA_ACTIVATION_TYPE: Final = "AWS::ACMPCA::CertificateAuthorityActivation"
SECRET_TYPE: Final = "AWS::SecretsManager::Secret"
KEY_TYPE: Final = "AWS::KMS::Key"
POLICY_TYPE: Final = "AWS::IAM::Policy"
APPLICATION_TYPE: Final = "AWS::AppConfig::Application"
ENVIRONMENT_TYPE: Final = "AWS::AppConfig::Environment"
CONFIGURATION_VERSION_TYPE: Final = "AWS::AppConfig::HostedConfigurationVersion"


@pytest.fixture(name="synthesised", scope="module")
def _synthesised(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[NetworkStack, EgressStack, Template]:
    app = cdk.App(outdir=str(tmp_path_factory.mktemp("egress")))
    env = cdk.Environment(region="us-east-1")
    network = NetworkStack(app, "NetworkStack", env=env)
    egress = EgressStack(app, "EgressStack", network=network, env=env)
    return network, egress, Template.from_stack(egress)


@pytest.fixture(name="template")
def _template(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> Template:
    return synthesised[2]


@pytest.fixture(name="stack")
def _stack(synthesised: tuple[NetworkStack, EgressStack, Template]) -> EgressStack:
    return synthesised[1]


def _sole(template: Template, resource_type: str) -> dict[str, Any]:
    resources = template.find_resources(resource_type)
    assert len(resources) == 1, sorted(resources)
    return dict(next(iter(resources.values())))


def _properties(template: Template, resource_type: str) -> dict[str, Any]:
    return dict(_sole(template, resource_type)["Properties"])


def _container(template: Template) -> dict[str, Any]:
    containers = _properties(template, TASK_DEFINITION_TYPE)["ContainerDefinitions"]
    assert len(containers) == 1, containers
    return dict(containers[0])


def _environment(template: Template) -> dict[str, Any]:
    return {
        variable["Name"]: variable["Value"]
        for variable in _container(template)["Environment"]
    }


def _statements(template: Template, role_reference: Any) -> list[dict[str, Any]]:
    return [
        statement
        for policy in template.find_resources(POLICY_TYPE).values()
        if role_reference in policy["Properties"]["Roles"]
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
    ]


def _task_role_statements(template: Template) -> list[dict[str, Any]]:
    reference = _properties(template, TASK_DEFINITION_TYPE)["TaskRoleArn"][
        "Fn::GetAtt"
    ][0]
    return _statements(template, {"Ref": reference})


# --- The load balancer is internal ---------------------------------------------------------------


def test_the_load_balancer_is_internal_and_carries_the_networks_group(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    network, egress, template = synthesised
    balancer = _properties(template, LOAD_BALANCER_TYPE)
    # An internet-facing load balancer needs a public subnet, and the proxy subnet group is private:
    # the only public subnets in the egress VPC hold the NAT gateway, so `internet-facing` here would
    # be a deployment that cannot succeed as well as a proxy exposed to the internet.
    assert balancer["Scheme"] == "internal"
    assert balancer["Type"] == "network"
    # Resolved from inside `EgressStack`, so the assertion is that this template imports the group
    # `NetworkStack` exported rather than that some group with the right shape exists.
    assert balancer["SecurityGroups"] == [
        egress.resolve(network.load_balancer_security_group.security_group_id)
    ]


def test_the_listener_and_the_target_group_use_the_one_permitted_port(
    template: Template,
) -> None:
    listener = _properties(template, LISTENER_TYPE)
    target_group = _properties(template, TARGET_GROUP_TYPE)
    # Read from `egress.policy`, which owns the number: the connector attachment's security group
    # permits this port and no other, so a listener on anything else is unreachable.
    assert listener["Port"] == target_group["Port"] == EGRESS_TLS_PORT
    assert listener["Protocol"] == target_group["Protocol"] == "TCP"
    # `ip` targets, because a Fargate task has no instance to register.
    assert target_group["TargetType"] == "ip"


# --- The fleet -----------------------------------------------------------------------------------


def test_the_fleet_runs_more_than_one_task(template: Template) -> None:
    service = _properties(template, SERVICE_TYPE)
    # The design's accepted cost: an Egress_Controller outage is a total egress outage for every
    # running Sandbox, so one task is one deployment or one zone away from that outage.
    assert service["DesiredCount"] == MINIMUM_PROXY_TASKS
    assert MINIMUM_PROXY_TASKS > 1


def test_a_deployment_never_drops_below_the_running_task_count(
    template: Template,
) -> None:
    configuration = _properties(template, SERVICE_TYPE)["DeploymentConfiguration"]
    assert configuration["MinimumHealthyPercent"] == 100
    assert configuration["MaximumPercent"] > 100
    # And a deployment that cannot reach steady state rolls back rather than leaving the fleet short.
    assert configuration["DeploymentCircuitBreaker"] == {
        "Enable": True,
        "Rollback": True,
    }


def test_the_fleet_spreads_over_every_zone_the_network_offers(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    network, _, template = synthesised
    configuration = _properties(template, SERVICE_TYPE)["NetworkConfiguration"][
        "AwsvpcConfiguration"
    ]
    assert len(configuration["Subnets"]) == len(network.proxy_subnet_ids) >= 2
    # Fargate spreads new tasks over the subnets' zones but does not re-spread after a zone
    # recovers, so without this the fleet can settle into one failure domain.
    assert (
        _properties(template, SERVICE_TYPE)["AvailabilityZoneRebalancing"] == "ENABLED"
    )


def test_the_fleet_has_no_public_address_and_no_security_group_of_its_own(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    network, egress, template = synthesised
    configuration = _properties(template, SERVICE_TYPE)["NetworkConfiguration"][
        "AwsvpcConfiguration"
    ]
    assert configuration["AssignPublicIp"] == "DISABLED"
    assert configuration["SecurityGroups"] == [
        egress.resolve(network.proxy_security_group.security_group_id)
    ]
    # Every group is `NetworkStack`'s, which is what lets the attachment's egress rules name the
    # load balancer and the fleet without a cycle between the two stacks.
    template.resource_count_is("AWS::EC2::SecurityGroup", 0)


def test_the_container_listens_on_the_one_permitted_port(template: Template) -> None:
    assert _container(template)["PortMappings"] == [
        {"ContainerPort": EGRESS_TLS_PORT, "Protocol": "tcp"}
    ]


def test_the_fleet_image_defaults_to_the_placeholder_without_context(
    template: Template,
) -> None:
    # Without a proxyImageUri context value the stack falls back to the placeholder, which makes
    # synthesis succeed in the offline suite while making the misconfiguration obvious at deploy.
    image = _container(template)["Image"]
    assert image == PLACEHOLDER_PROXY_IMAGE
    template.resource_count_is("AWS::ECR::Repository", 0)


def test_the_fleet_image_uses_the_context_uri_when_provided(
    tmp_path: Path,
) -> None:
    explicit_uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sandbox-egress-proxy:latest"
    app = cdk.App(
        outdir=str(tmp_path),
        context={PROXY_IMAGE_URI_CONTEXT_KEY: explicit_uri},
    )
    env = cdk.Environment(region="us-east-1")
    network = NetworkStack(app, "NetworkStack", env=env)
    EgressStack(app, "EgressStack", network=network, env=env)
    tpl = Template.from_stack(app.node.find_child("EgressStack"))  # type: ignore[arg-type]
    # The container image is the literal URI, not a CDK asset reference.
    container_image = _properties(tpl, TASK_DEFINITION_TYPE)["ContainerDefinitions"][0]["Image"]
    assert container_image == explicit_uri


def test_the_execution_role_may_pull_from_ecr(template: Template) -> None:
    execution_role_ref = _properties(template, TASK_DEFINITION_TYPE)["ExecutionRoleArn"][
        "Fn::GetAtt"
    ][0]
    statements = _statements(template, {"Ref": execution_role_ref})
    ecr_pulls = [
        s for s in statements
        if "ecr:BatchGetImage" in (s.get("Action") or [])
    ]
    assert len(ecr_pulls) == 1, ecr_pulls
    assert "ecr:GetAuthorizationToken" in ecr_pulls[0]["Action"]
    assert "ecr:GetDownloadUrlForLayer" in ecr_pulls[0]["Action"]


# --- The policy store ----------------------------------------------------------------------------


def test_the_deployment_starts_with_a_policy_that_permits_nothing() -> None:
    # A freshly deployed Egress_Controller denying everything is R12.8 rather than a placeholder:
    # task 10.8 publishes the named configurations over this, and until it does nothing is reachable.
    assert SEED_POLICY.destination_sets == ()
    assert SEED_POLICY.default_action is DefaultAction.DENY


def test_the_seeded_document_is_the_one_the_fleets_own_loader_accepts(
    template: Template,
) -> None:
    content = _properties(template, CONFIGURATION_VERSION_TYPE)["Content"]
    document = json.loads(content)
    assert document == dict(SEED_POLICY_DOCUMENT)
    # Loaded here with the loader the proxy reads it with, so a seed the proxy would refuse cannot
    # reach an environment. `egress.reader` treats an unreadable document as no policy at all.
    assert EgressPolicy.from_document(document) == SEED_POLICY


def test_the_seeded_document_is_removed_by_the_documented_teardown(
    template: Template,
) -> None:
    # R15.5. CDK defaults a hosted configuration version to `Retain`, which would survive
    # `cdk destroy --all` and block a second deployment.
    assert _sole(template, CONFIGURATION_VERSION_TYPE)["DeletionPolicy"] == "Delete"


def test_the_fleet_is_told_where_its_policy_lives_and_how_long_it_may_cache_it(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    _, stack, template = synthesised
    environment = _environment(template)
    assert environment["EGRESS_POLICY_APPLICATION"] == stack.resolve(
        stack.policy_application.application_id
    )
    assert environment["EGRESS_POLICY_ENVIRONMENT"] == stack.resolve(
        stack.policy_environment.environment_id
    )
    assert environment["EGRESS_POLICY_PROFILE"] == stack.resolve(
        stack.policy_configuration.configuration_profile_id
    )
    # `egress.reader` bounds the TTL and declares no default, because the number is a deployment
    # value. This is the deployment, and it configures the bound: the design's documented revocation
    # latency is 30 s, and a value below it buys nothing R12.7 promised.
    assert environment["EGRESS_POLICY_CACHE_TTL_SECONDS"] == str(
        POLICY_CACHE_TTL_SECONDS
    )
    assert POLICY_CACHE_TTL_SECONDS == MAX_POLICY_CACHE_TTL_SECONDS


def test_the_fleet_may_read_only_its_own_application(template: Template) -> None:
    reads = [
        statement
        for statement in _task_role_statements(template)
        if "appconfig:GetLatestConfiguration" in statement["Action"]
    ]
    assert len(reads) == 1, reads
    assert "appconfig:StartConfigurationSession" in reads[0]["Action"]
    assert reads[0]["Resource"] != "*"


# --- The private CA ------------------------------------------------------------------------------


def test_the_private_ca_is_a_root_and_is_activated(template: Template) -> None:
    authority = _properties(template, AUTHORITY_TYPE)
    assert authority["Type"] == "ROOT"
    assert authority["KeyAlgorithm"].startswith("RSA")
    certificate = _properties(template, CA_CERTIFICATE_TYPE)
    assert certificate["Validity"] == {"Type": "YEARS", "Value": CA_VALIDITY_YEARS}
    # Without the activation the CA can issue nothing, and the alias *is* the proxy: TLS terminating
    # at an alias with no certificate for it is a failure rather than a legitimate termination.
    activation = _properties(template, CA_ACTIVATION_TYPE)
    assert activation["CertificateAuthorityArn"] == authority_arn(template)
    assert activation["Certificate"] is not None


def authority_arn(template: Template) -> dict[str, Any]:
    logical_id = next(iter(template.find_resources(AUTHORITY_TYPE)))
    return {"Fn::GetAtt": [logical_id, "Arn"]}


def test_the_fleet_may_issue_alias_certificates_from_that_ca_and_no_other(
    template: Template,
) -> None:
    issues = [
        statement
        for statement in _task_role_statements(template)
        if "acm-pca:IssueCertificate" in statement["Action"]
    ]
    assert len(issues) == 1, issues
    assert issues[0]["Resource"] == authority_arn(template)


# --- Upstream credentials (R12.4, R12.5) ---------------------------------------------------------


def test_one_secret_per_upstream_credential_encrypted_with_the_egress_key(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    _, stack, template = synthesised
    secrets = template.find_resources(SECRET_TYPE)
    assert len(secrets) == len(UPSTREAM_CREDENTIAL_NAMES) == 2
    key = {"Fn::GetAtt": [next(iter(template.find_resources(KEY_TYPE))), "Arn"]}
    for resource in secrets.values():
        # A separate key from the artifact key, because R12.5's `Deny` names the egress key alone: a
        # shared key could not be denied to the Sandbox without also denying it its own artifacts.
        assert resource["Properties"]["KmsKeyId"] == key
        # No value at synthesis: a credential supplied here would sit in the template and in
        # `cdk.out`, which is the one place R12.4 makes it pointless to keep it out of the Sandbox.
        assert "SecretStringValue" not in resource["Properties"]
    assert set(stack.upstream_secrets) == set(UPSTREAM_CREDENTIAL_NAMES)
    assert len(stack.upstream_secret_arns) == len(UPSTREAM_CREDENTIAL_NAMES)


def test_the_fleet_may_read_the_upstream_secrets_and_they_are_named_for_the_deny(
    synthesised: tuple[NetworkStack, EgressStack, Template],
) -> None:
    _, stack, template = synthesised
    reads = [
        statement
        for statement in _task_role_statements(template)
        if "secretsmanager:GetSecretValue" in statement["Action"]
    ]
    assert len(reads) == len(UPSTREAM_CREDENTIAL_NAMES)
    # Each scoped to one secret, never `*`: the per-Session Sandbox role carries an explicit `Deny`
    # on exactly these ARNs (R12.5, task 12.6), which is why they are exposed as an attribute.
    assert all(statement["Resource"] != "*" for statement in reads)
    assert stack.upstream_secret_arns


def test_the_fleet_may_invoke_the_model_the_sandbox_role_may_not(
    template: Template,
) -> None:
    invokes = [
        statement
        for statement in _task_role_statements(template)
        if "bedrock:InvokeModel" in statement["Action"]
    ]
    # Tier 1 re-signs as this role. The Sandbox role holds no allow for either action, which is what
    # makes the proxy the only path to a model and discharges R5.12 along with R12.5.
    assert len(invokes) == 1, invokes
    assert invokes[0]["Resource"] != "*"


def test_the_fleet_role_carries_no_wildcard_resource_on_a_credential_action(
    template: Template,
) -> None:
    for statement in _task_role_statements(template):
        actions = statement["Action"]
        actions = actions if isinstance(actions, list) else [actions]
        if any(
            action.startswith(("secretsmanager:", "kms:", "acm-pca:"))
            for action in actions
        ):
            assert statement["Resource"] != "*", statement


# --- What the rest of the app reads --------------------------------------------------------------


def test_the_stack_exposes_what_the_control_plane_and_the_session_role_need(
    stack: EgressStack,
) -> None:
    # `ControlPlaneStack` holds `self.egress` and needs the endpoint and the policy store; task 12.6
    # needs the secret ARNs, the key and the task role for the three explicit denials of R12.5.
    assert stack.proxy_endpoint
    assert stack.proxy_task_role.role_arn == stack.task_definition.task_role.role_arn
    assert stack.upstream_secret_arns
    assert stack.secret_key.key_arn
    assert stack.log_group.log_group_name


def test_the_stack_declares_one_fleet_one_balancer_and_one_policy_store(
    template: Template,
) -> None:
    counts: dict[str, int] = {}
    for resource in template.to_json()["Resources"].values():
        counts[resource["Type"]] = counts.get(resource["Type"], 0) + 1
    assert counts[SERVICE_TYPE] == 1
    assert counts[LOAD_BALANCER_TYPE] == 1
    assert counts[APPLICATION_TYPE] == counts[ENVIRONMENT_TYPE] == 1
    assert counts[AUTHORITY_TYPE] == 1
    # No VPC, no subnet, no route: the network is `NetworkStack`'s, and a second one here would be a
    # second topology to reason about.
    for absent in ("AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::Route"):
        assert absent not in counts, absent


def test_the_stack_synthesises_without_a_lookup(
    tmp_path: Path,
) -> None:
    """R15.9: nothing here consults an account, so the offline suite can synthesise it.

    A second synthesis into a fresh directory is the check that matters — `Vpc.from_lookup` and its
    relatives cache into `cdk.context.json` and would fail outright without credentials, so a stack
    that synthesises twice from nothing is a stack that made no lookup.
    """
    app = cdk.App(outdir=str(tmp_path))
    env = cdk.Environment(region="us-east-1")
    network = NetworkStack(app, "NetworkStack", env=env)
    EgressStack(app, "EgressStack", network=network, env=env)
    assembly = app.synth()

    assert {stack.stack_name for stack in assembly.stacks} == {
        "NetworkStack",
        "EgressStack",
    }
    # A lookup records a missing-context entry in the assembly manifest and asks the CLI to resolve
    # it against a live account, which is what would break the offline suite.
    manifest = json.loads(
        (Path(assembly.directory) / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest.get("missing") is None
    assert not (tmp_path / "cdk.context.json").exists()
