# kiro-classification: public
"""`StateStack` synthesises the declared table schema, and an encrypted TLS-only bucket.

Every assertion reads the emitted CloudFormation rather than the stack source, because only the
template proves that the key schema, the projections, the TTL specification, the encryption
configuration and the lifecycle rule are what the design says. The expected values come from
`control_plane.state.table` and `control_plane.state.artifacts`, so a schema change moves one
number and this file follows it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from control_plane.state import table as t
from control_plane.state.artifacts import SERVER_SIDE_ENCRYPTION
from iac.state_stack import (
    ARTIFACT_EXPIRATION_RULE_ID,
    DEFAULT_ARTIFACT_RETENTION_DAYS,
    StateStack,
)

TABLE_TYPE: Final = "AWS::DynamoDB::Table"
BUCKET_TYPE: Final = "AWS::S3::Bucket"
BUCKET_POLICY_TYPE: Final = "AWS::S3::BucketPolicy"
KEY_TYPE: Final = "AWS::KMS::Key"


def _synthesise(tmp_path: Path, **kwargs: Any) -> Template:
    app = cdk.App(outdir=str(tmp_path))
    return Template.from_stack(StateStack(app, "StateStack", **kwargs))


@pytest.fixture(name="template")
def _template(tmp_path: Path) -> Template:
    return _synthesise(tmp_path)


def _sole(template: Template, resource_type: str, *, exclude_prefix: str = "") -> dict[str, Any]:
    resources = template.find_resources(resource_type)
    if exclude_prefix:
        resources = {k: v for k, v in resources.items() if not k.startswith(exclude_prefix)}
    assert len(resources) == 1, resources
    return dict(next(iter(resources.values())))


def _properties(template: Template, resource_type: str) -> dict[str, Any]:
    return dict(_sole(template, resource_type)["Properties"])



def _artifact_bucket_properties(template: Template) -> dict[str, Any]:
    """Return Properties of the artifact bucket, excluding the access logs bucket."""
    return dict(_sole(template, BUCKET_TYPE, exclude_prefix="AccessLogs")["Properties"])


def _key_schema(partition_key: str, sort_key: str) -> list[dict[str, str]]:
    return [
        {"AttributeName": partition_key, "KeyType": "HASH"},
        {"AttributeName": sort_key, "KeyType": "RANGE"},
    ]


def test_the_table_key_schema_is_the_declared_key_schema(template: Template) -> None:
    properties = _properties(template, TABLE_TYPE)
    assert properties["KeySchema"] == _key_schema(
        t.PARTITION_KEY_ATTRIBUTE, t.SORT_KEY_ATTRIBUTE
    )
    # Exactly the declared set with the declared types, and nothing else: DynamoDB refuses an
    # attribute definition that no key schema uses, and a wrong type is a silently different table.
    assert {
        definition["AttributeName"]: definition["AttributeType"]
        for definition in properties["AttributeDefinitions"]
    } == {name: kind.value for name, kind in t.ATTRIBUTE_DEFINITIONS.items()}


def test_the_table_is_on_demand_with_point_in_time_recovery(template: Template) -> None:
    properties = _properties(template, TABLE_TYPE)
    assert properties["BillingMode"] == t.BILLING_MODE
    assert (
        properties["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"]
        is t.POINT_IN_TIME_RECOVERY_ENABLED
    )
    # No physical name: the deployed name is stack-derived, which is what the schema module says
    # and what lets two deployments coexist in one account.
    assert "TableName" not in properties


def test_ttl_is_enabled_on_the_declared_attribute(template: Template) -> None:
    properties = _properties(template, TABLE_TYPE)
    assert properties["TimeToLiveSpecification"] == {
        "AttributeName": t.TTL_ATTRIBUTE,
        "Enabled": True,
    }
    # A TTL attribute in a key schema would make expiry structural rather than best-effort.
    names = {
        definition["AttributeName"] for definition in properties["AttributeDefinitions"]
    }
    assert t.TTL_ATTRIBUTE not in names


def test_both_declared_indexes_synthesise_with_their_key_schemas(
    template: Template,
) -> None:
    indexes = _properties(template, TABLE_TYPE)["GlobalSecondaryIndexes"]
    assert [index["IndexName"] for index in indexes] == [
        declared.name for declared in t.INDEXES
    ]
    for index, declared in zip(indexes, t.INDEXES, strict=True):
        assert index["KeySchema"] == _key_schema(
            declared.partition_key, declared.sort_key
        ), declared.name


def test_the_reaper_index_projects_exactly_the_declared_attributes(
    template: Template,
) -> None:
    indexes = {
        index["IndexName"]: index
        for index in _properties(template, TABLE_TYPE)["GlobalSecondaryIndexes"]
    }

    reaper = indexes[t.DEADLINE_INDEX.name]["Projection"]
    assert reaper["ProjectionType"] == t.DEADLINE_INDEX.projection.value
    # Exactly the declared set, no more: every extra projected attribute is a copy of Session
    # content in an index the Reaper reads across Tenants.
    assert reaper["NonKeyAttributes"] == list(t.DEADLINE_INDEX.non_key_attributes)

    listing = indexes[t.TENANT_STATE_INDEX.name]["Projection"]
    assert listing["ProjectionType"] == t.TENANT_STATE_INDEX.projection.value
    assert "NonKeyAttributes" not in listing


def test_artifacts_are_encrypted_with_a_customer_managed_key(
    template: Template,
) -> None:
    rules = _artifact_bucket_properties(template)["BucketEncryption"][
        "ServerSideEncryptionConfiguration"
    ]
    assert len(rules) == 1
    default = rules[0]["ServerSideEncryptionByDefault"]
    # SSE-KMS, not SSE-S3 (R13.5), and the same algorithm every artifact write sends.
    assert default["SSEAlgorithm"] == SERVER_SIDE_ENCRYPTION
    assert rules[0]["BucketKeyEnabled"] is True

    # The key is one this stack creates, so it is customer managed rather than an AWS managed
    # alias: the reference resolves to the sole `AWS::KMS::Key` in this template.
    key_logical_id = next(iter(template.find_resources(KEY_TYPE)))
    assert default["KMSMasterKeyID"] == {"Fn::GetAtt": [key_logical_id, "Arn"]}
    assert _properties(template, KEY_TYPE)["EnableKeyRotation"] is True


def test_the_bucket_policy_denies_requests_without_tls(template: Template) -> None:
    document = _sole(template, BUCKET_POLICY_TYPE, exclude_prefix="AccessLogs")["Properties"]["PolicyDocument"]
    statements = document["Statement"]
    denials = [
        statement
        for statement in statements
        if statement["Effect"] == "Deny"
        and statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        == "false"
    ]
    assert len(denials) == 1, statements
    assert denials[0]["Principal"] == {"AWS": "*"}
    assert denials[0]["Action"] == "s3:*"


def test_a_lifecycle_rule_expires_artifacts_at_the_retention_period(
    template: Template,
) -> None:
    rules = _artifact_bucket_properties(template)["LifecycleConfiguration"]["Rules"]
    assert len(rules) == 1
    assert rules[0]["Id"] == ARTIFACT_EXPIRATION_RULE_ID
    assert rules[0]["Status"] == "Enabled"
    assert rules[0]["ExpirationInDays"] == DEFAULT_ARTIFACT_RETENTION_DAYS
    # Unprefixed: the rule is the deployment-wide backstop, so an object written outside the
    # artifact layout still expires.
    assert "Prefix" not in rules[0]


def test_the_retention_period_is_configurable(tmp_path: Path) -> None:
    template = _synthesise(tmp_path, artifact_retention_days=7)
    rules = _artifact_bucket_properties(template)["LifecycleConfiguration"]["Rules"]
    assert rules[0]["ExpirationInDays"] == 7


def test_a_retention_period_below_one_day_is_refused(tmp_path: Path) -> None:
    # Zero days is a bucket that deletes what was just written, not a shorter retention period.
    with pytest.raises(ValueError, match="at least one day"):
        _synthesise(tmp_path, artifact_retention_days=0)


@pytest.mark.parametrize("resource_type", [TABLE_TYPE, BUCKET_TYPE, KEY_TYPE])
def test_the_stateful_resources_carry_an_explicit_destroy_policy(
    template: Template, resource_type: str
) -> None:
    # R15.5: `cdk destroy --all` removes what the package created, so neither the service default
    # nor CDK's retain-by-default for a stateful resource may be left in place.
    # For S3 buckets, check all (main + access logs); for others, expect exactly one
    if resource_type == BUCKET_TYPE:
        resources = template.find_resources(resource_type)
        assert len(resources) >= 1
        for lid, resource in resources.items():
            assert resource["DeletionPolicy"] == "Delete", f"{lid} missing Delete"
            assert resource["UpdateReplacePolicy"] == "Delete", f"{lid} missing Delete"
    else:
        resource = _sole(template, resource_type)
        assert resource["DeletionPolicy"] == "Delete"
        assert resource["UpdateReplacePolicy"] == "Delete"


def test_the_stack_declares_only_the_state_store_resources(template: Template) -> None:
    # The core state-store resources must always be present.  CDK may add ancillary resources
    # (e.g. a Lambda + IAM Role + Custom Resource for auto_delete_objects) that are
    # implementation details of the construct library, so we assert the core set as a subset
    # rather than an exact match.
    types = {
        resource["Type"] for resource in template.to_json()["Resources"].values()
    }
    core_types = {KEY_TYPE, BUCKET_TYPE, BUCKET_POLICY_TYPE, TABLE_TYPE}
    assert core_types <= types, f"missing core resources: {core_types - types}"

    # Only CDK-managed ancillary types (Lambda helpers, IAM roles, custom resources) should
    # appear beyond the core set.  Anything else signals an unintended resource.
    cdk_ancillary_prefixes = (
        "AWS::IAM::",
        "AWS::Lambda::",
        "Custom::",
    )
    unexpected = types - core_types
    for rtype in unexpected:
        assert rtype.startswith(cdk_ancillary_prefixes), (
            f"unexpected resource type {rtype!r} is not a known CDK ancillary type"
        )
