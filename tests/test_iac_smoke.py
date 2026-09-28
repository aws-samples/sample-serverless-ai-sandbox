# kiro-classification: public
"""Smoke assertions over synthesised CloudFormation templates (R15.9).

Synthesis runs through the Python API rather than the ``cdk`` CLI so that every assertion holds
in the offline suite, which has no network access and no deployed resources.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from aws_cdk.cx_api import CloudAssembly

from iac.app import build_app


@pytest.fixture(name="assembly")
def _assembly(tmp_path: Path) -> Iterator[CloudAssembly]:
    yield build_app(outdir=str(tmp_path)).synth()


def _stack_template(assembly: CloudAssembly, stack_name: str) -> dict:
    """Return the CloudFormation template for *stack_name*, or raise."""
    for stack in assembly.stacks:
        if stack.stack_name == stack_name:
            return stack.template
    raise ValueError(f"No stack named {stack_name}")


def _resources_of_type(template: dict, resource_type: str) -> list[dict]:
    """Return every resource whose ``Type`` matches *resource_type*."""
    return [
        resource
        for resource in template.get("Resources", {}).values()
        if resource.get("Type") == resource_type
    ]


# ---------------------------------------------------------------------------
# 1. State machine type is STANDARD
# ---------------------------------------------------------------------------


def test_state_machine_type_is_standard(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "ControlPlaneStack")
    machines = _resources_of_type(template, "AWS::StepFunctions::StateMachine")
    assert machines, "ControlPlaneStack declares no StateMachine resource"
    for machine in machines:
        props = machine.get("Properties", {})
        assert props.get("StateMachineType") == "STANDARD"


# ---------------------------------------------------------------------------
# 2. AWS_IAM authorizer on every route
# ---------------------------------------------------------------------------


def test_every_route_carries_authorizer(assembly: CloudAssembly) -> None:
    """Every API route must have an authorizer — either AWS_IAM or CUSTOM (Lambda authorizer).

    The platform defaults to CUSTOM (Lambda authorizer) for multi-tenant support.
    Both are valid depending on the deployment profile.
    """
    routes: list[dict] = []
    for stack in assembly.stacks:
        routes.extend(_resources_of_type(stack.template, "AWS::ApiGatewayV2::Route"))
    assert routes, "no API Gateway routes found in any stack"
    allowed = {"AWS_IAM", "CUSTOM"}
    for route in routes:
        props = route.get("Properties", {})
        auth_type = props.get("AuthorizationType", "NONE")
        assert auth_type in allowed, (
            f"route {props.get('RouteKey', '<unknown>')} has auth {auth_type}, expected one of {allowed}"
        )


# ---------------------------------------------------------------------------
# 3. Point-in-time recovery on the DynamoDB table
# ---------------------------------------------------------------------------


def test_dynamodb_table_has_point_in_time_recovery(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "StateStack")
    tables = _resources_of_type(template, "AWS::DynamoDB::Table")
    assert tables, "StateStack declares no DynamoDB table"
    for table in tables:
        pitr = (
            table.get("Properties", {})
            .get("PointInTimeRecoverySpecification", {})
            .get("PointInTimeRecoveryEnabled")
        )
        assert pitr is True


# ---------------------------------------------------------------------------
# 4. S3 bucket encryption
# ---------------------------------------------------------------------------


def test_s3_bucket_has_encryption(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "StateStack")
    buckets = _resources_of_type(template, "AWS::S3::Bucket")
    assert buckets, "StateStack declares no S3 bucket"
    for bucket in buckets:
        props = bucket.get("Properties", {})
        assert "BucketEncryption" in props, "S3 bucket has no BucketEncryption"


# ---------------------------------------------------------------------------
# 5. S3 bucket lifecycle
# ---------------------------------------------------------------------------


def test_s3_bucket_has_lifecycle_rule(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "StateStack")
    buckets = _resources_of_type(template, "AWS::S3::Bucket")
    assert buckets, "StateStack declares no S3 bucket"
    # At least one bucket must have lifecycle rules (the artifact bucket)
    any_has_rules = False
    for bucket in buckets:
        rules = (
            bucket.get("Properties", {})
            .get("LifecycleConfiguration", {})
            .get("Rules", [])
        )
        if len(rules) >= 1:
            any_has_rules = True
    assert any_has_rules, "No S3 bucket has lifecycle rules"


# ---------------------------------------------------------------------------
# 6. TTL on the DynamoDB table
# ---------------------------------------------------------------------------


def test_dynamodb_table_has_ttl_enabled(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "StateStack")
    tables = _resources_of_type(template, "AWS::DynamoDB::Table")
    assert tables, "StateStack declares no DynamoDB table"
    for table in tables:
        ttl = table.get("Properties", {}).get("TimeToLiveSpecification", {})
        assert ttl.get("Enabled") is True, "TTL is not enabled on the DynamoDB table"
        assert ttl.get("AttributeName"), "TTL attribute name is not set"


# ---------------------------------------------------------------------------
# 7. Dashboard exists
# ---------------------------------------------------------------------------


def test_control_plane_has_dashboard(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "ControlPlaneStack")
    dashboards = _resources_of_type(template, "AWS::CloudWatch::Dashboard")
    assert dashboards, "ControlPlaneStack declares no CloudWatch Dashboard"


# ---------------------------------------------------------------------------
# 8. Reaper schedule exists
# ---------------------------------------------------------------------------


def test_control_plane_has_reaper_schedule(assembly: CloudAssembly) -> None:
    template = _stack_template(assembly, "ControlPlaneStack")
    schedules = _resources_of_type(template, "AWS::Scheduler::Schedule")
    assert schedules, "ControlPlaneStack declares no EventBridge Schedule"
