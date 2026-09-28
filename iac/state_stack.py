# kiro-classification: public
"""`StateStack`: the State_Store (R15.2, R13.1, R13.5, R13.6).

The table schema is not declared here. :mod:`control_plane.state.table` declares it once and this
stack reads it, so the key schema the handlers address and the key schema CloudFormation creates
are one value read twice. Nothing below spells a key name, an index name, an attribute type or a
projection.

The S3 side is declared here rather than beside the table schema, because it has one consumer: no
runtime module spells the bucket, the key or the retention period, they are handed to
`ArtifactStoreConfig` at deploy time. It depends on no other stack.
"""

from __future__ import annotations

from typing import Any, Final

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from constructs import Construct

from control_plane.state import table as state_table

__all__ = [
    "ARTIFACT_EXPIRATION_RULE_ID",
    "DEFAULT_ARTIFACT_RETENTION_DAYS",
    "StateStack",
]

#: The lifecycle expiration period the bucket applies, in days (R13.6). It is the deployment-wide
#: backstop applied by S3 rather than the per-Session mechanism: `artifactRetentionDays` on a
#: Session record mirrors this number, and `ArtifactStore.verify_record_retention` keeps the mirror
#: honest. A per-Session period shorter than this one is not expressible in a bucket rule and is
#: not what R13.6 asks for.
DEFAULT_ARTIFACT_RETENTION_DAYS: Final = 30

#: The lifecycle rule's identifier, named so the offline suite asserts on the rule it means.
ARTIFACT_EXPIRATION_RULE_ID: Final = "expire-session-artifacts"

#: `control_plane.state.table` spells an attribute type the way the DynamoDB API does, `S` and `N`;
#: the CDK enum spells the same two types `STRING` and `NUMBER`. This maps between the two enums,
#: so neither spelling appears as a literal.
_ATTRIBUTE_TYPES: Final[dict[state_table.AttributeType, dynamodb.AttributeType]] = {
    state_table.AttributeType.STRING: dynamodb.AttributeType.STRING,
    state_table.AttributeType.NUMBER: dynamodb.AttributeType.NUMBER,
}

_PROJECTION_TYPES: Final[dict[state_table.ProjectionType, dynamodb.ProjectionType]] = {
    state_table.ProjectionType.ALL: dynamodb.ProjectionType.ALL,
    state_table.ProjectionType.KEYS_ONLY: dynamodb.ProjectionType.KEYS_ONLY,
    state_table.ProjectionType.INCLUDE: dynamodb.ProjectionType.INCLUDE,
}


def _attribute(name: str) -> dynamodb.Attribute:
    """A key attribute, typed from the declared attribute definitions and not from here."""
    declared = state_table.ATTRIBUTE_DEFINITIONS[name]
    return dynamodb.Attribute(name=name, type=_ATTRIBUTE_TYPES[declared])


class StateStack(cdk.Stack):
    """The DynamoDB table, the artifact bucket and the customer managed key that encrypts it."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        artifact_retention_days: int = DEFAULT_ARTIFACT_RETENTION_DAYS,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        if artifact_retention_days < 1:
            # Zero days is not a shorter retention period, it is a bucket that deletes what was
            # just written. The same floor `ArtifactStoreConfig` applies to the mirrored value.
            raise ValueError(
                f"artifact_retention_days must be at least one day: {artifact_retention_days}"
            )
        self.artifact_retention_days = artifact_retention_days
        self.artifact_key = self._artifact_key()
        self.bucket = self._bucket(self.artifact_key)
        self.table = self._table()

    def _table(self) -> dynamodb.Table:
        """The single table, its two indexes and its TTL attribute, all read from the schema."""
        # No `encryption_key`: the table is left on DynamoDB's service-default encryption
        # deliberately. R13.5 covers Session artifacts, which the bucket below encrypts with the
        # customer managed key. Whether that key should extend to this metadata table is open, and
        # not free: it would oblige tasks 12.6 and 12.11 to grant `kms:Decrypt` on it to every
        # reader of the table, so the decision belongs with those IAM policies rather than here.
        table = dynamodb.Table(
            self,
            # The construct id, not `table_name`: the deployed name is stack-derived, which is what
            # lets `cdk destroy --all` and a second deployment in one account both work.
            state_table.TABLE_LOGICAL_NAME,
            partition_key=_attribute(state_table.PARTITION_KEY_ATTRIBUTE),
            sort_key=_attribute(state_table.SORT_KEY_ATTRIBUTE),
            billing_mode=dynamodb.BillingMode(state_table.BILLING_MODE),
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=state_table.POINT_IN_TIME_RECOVERY_ENABLED
            ),
            time_to_live_attribute=state_table.TTL_ATTRIBUTE,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        for index in state_table.INDEXES:
            table.add_global_secondary_index(
                index_name=index.name,
                partition_key=_attribute(index.partition_key),
                sort_key=_attribute(index.sort_key),
                projection_type=_PROJECTION_TYPES[index.projection],
                # Empty under any projection but INCLUDE, and CDK refuses the pair.
                non_key_attributes=list(index.non_key_attributes) or None,
            )
        return table

    def _artifact_key(self) -> kms.Key:
        """The customer managed key artifacts are encrypted with (R13.5)."""
        return kms.Key(
            self,
            "ArtifactKey",
            description="State_Store Session artifact encryption (R13.5)",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def _bucket(self, key: kms.Key) -> s3.Bucket:
        """The artifact bucket: CMK encryption, a non-TLS deny and the retention rule."""
        # Access logging bucket (AwsSolutions-S1)
        access_logs = s3.Bucket(
            self,
            "AccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        return s3.Bucket(
            self,
            "SessionArtifacts",
            # SSE-KMS with the key above rather than SSE-S3, because R11.9 offers per-Tenant key
            # separation as an operator option and Governed_Isolation names the reader's own keys.
            encryption=s3.BucketEncryption.KMS,
            encryption_key=key,
            # One data key per request would bill a KMS call per artifact written.
            bucket_key_enabled=True,
            # Emits the bucket policy denying every request without `aws:SecureTransport`.
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="access-logs/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    id=ARTIFACT_EXPIRATION_RULE_ID,
                    enabled=True,
                    # No prefix: the rule is the deployment-wide backstop, and a rule scoped to
                    # the artifact layout would leave an object written outside it un-expired.
                    expiration=cdk.Duration.days(self.artifact_retention_days),
                )
            ],
            # R15.5: `cdk destroy --all` must remove every resource the package created. CDK
            # cannot delete a non-empty bucket without this flag, which deploys a Lambda-backed
            # custom resource that empties the bucket before CloudFormation deletes it.
            auto_delete_objects=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
