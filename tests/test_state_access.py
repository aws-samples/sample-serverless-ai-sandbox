# kiro-classification: public
"""The per-request tenant-confined data access role (R11.3, R6.9).

Layer 2 is an IAM policy and a cache, so what is checkable offline is exactly this: that the
policy pins the caller's one partition key and the caller's one artifact prefix and nothing
wider, and that the cache can never answer a request with another Tenant's credentials. The
`AccessDenied` these produce is checked against deployed resources by the integration suite; here
STS is a stub and no AWS call is made.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from control_plane.state import access
from control_plane.state.keys import claim_partition_key
from control_plane.state.table import DEADLINE_INDEX, TENANT_STATE_INDEX
from control_plane.tenancy import (
    MAX_TENANT_ID_LENGTH,
    AuthenticatedPrincipal,
    pk_for,
)

ROLE_ARN = "arn:aws:iam::123456789012:role/SessionDataAccessRole"
TABLE_ARN = "arn:aws:dynamodb:eu-west-1:123456789012:table/sessions"
BUCKET = "test-sandbox-artifacts-placeholder"

EPOCH = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


def principal(tenant_id: str) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        caller_identity=f"arn:aws:sts::123456789012:assumed-role/caller/{tenant_id}",
        tenant_id=tenant_id,
    )


def targets(**overrides: Any) -> access.DataAccessTargets:
    fields: dict[str, Any] = {
        "role_arn": ROLE_ARN,
        "table_arn": TABLE_ARN,
        "artifact_bucket": BUCKET,
    }
    fields.update(overrides)
    return access.DataAccessTargets(**fields)


@dataclass
class StubSts:
    """An STS that records what it was asked and hands back distinguishable credentials."""

    expires_at: datetime = EPOCH + timedelta(minutes=15)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        serial = len(self.calls)
        return {
            "Credentials": {
                "AccessKeyId": f"ASIAEXAMPLE{serial}",
                "SecretAccessKey": f"secret-{serial}",
                "SessionToken": f"token-{serial}",
                "Expiration": self.expires_at,
            }
        }

    def policies(self) -> list[dict[str, Any]]:
        return [json.loads(call["Policy"]) for call in self.calls]


class MovableClock:
    def __init__(self, now: datetime = EPOCH) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def broker(
    sts: StubSts, clock: MovableClock, **target_overrides: Any
) -> access.TenantDataAccessBroker:
    return access.TenantDataAccessBroker(
        targets=targets(**target_overrides), sts_client=sts, clock=clock
    )


def dynamodb_statement(document: Mapping[str, Any]) -> Mapping[str, Any]:
    (statement,) = [
        entry
        for entry in document["Statement"]
        if any(action.startswith("dynamodb:") for action in entry["Action"])
    ]
    return statement


def s3_statement(document: Mapping[str, Any]) -> Mapping[str, Any]:
    (statement,) = [
        entry
        for entry in document["Statement"]
        if any(action.startswith("s3:") for action in entry["Action"])
    ]
    return statement


# --- the policy ------------------------------------------------------------------------------


def test_leading_keys_is_pinned_to_the_partition_key_pk_for_produces() -> None:
    caller = principal("acme")
    statement = dynamodb_statement(access.session_policy_document(caller, targets()))

    condition = statement["Condition"]["ForAllValues:StringEquals"]
    # The value the condition pins has one producer, so the policy and the keys the handler
    # builds cannot disagree about what this Tenant is.
    assert condition[access.LEADING_KEYS_CONDITION_KEY] == [pk_for(caller)]


def test_the_dynamodb_resources_are_the_table_and_the_tenant_index_only() -> None:
    statement = dynamodb_statement(
        access.session_policy_document(principal("acme"), targets())
    )

    assert statement["Resource"] == [
        TABLE_ARN,
        f"{TABLE_ARN}/index/{TENANT_STATE_INDEX.name}",
    ]
    # `deadline-index` is the Reaper's cross-Tenant read path: a handler able to query it could
    # see every Tenant's rows, and no LeadingKeys condition would stop it.
    assert not any(
        DEADLINE_INDEX.name in resource for resource in statement["Resource"]
    )


def test_the_action_set_carries_the_transaction_and_delete_but_no_scan() -> None:
    statement = dynamodb_statement(
        access.session_policy_document(principal("acme"), targets())
    )

    actions = set(statement["Action"])
    # The Affinity_Key claim is a transaction and binding cleanup is a delete (R6.16, R6.18).
    assert {"dynamodb:TransactWriteItems", "dynamodb:DeleteItem"} <= actions
    # An unpartitioned read is not something a handler should be able to attempt.
    assert "dynamodb:Scan" not in actions


def test_the_artifact_resource_is_confined_to_one_tenant_prefix() -> None:
    statement = s3_statement(
        access.session_policy_document(principal("acme"), targets())
    )

    assert statement["Resource"] == f"arn:aws:s3:::{BUCKET}/tenants/acme/*"
    assert set(statement["Action"]) == {"s3:GetObject", "s3:PutObject"}


def test_the_pinned_leading_key_cannot_address_the_sandbox_claim_partition() -> None:
    statement = dynamodb_statement(
        access.session_policy_document(principal("acme"), targets())
    )
    pinned = statement["Condition"]["ForAllValues:StringEquals"][
        access.LEADING_KEYS_CONDITION_KEY
    ]

    # The claim item is the one key shape outside a Tenant partition, written by the
    # orchestrator's own role. A handler credential pinned to exactly one `T#` key cannot reach
    # it, so quarantine and claim state are not something a Control_Plane bug can rewrite.
    assert len(pinned) == 1
    assert claim_partition_key("lambda-microvm", "sbx-1") not in pinned


def test_two_tenants_receive_disjoint_policies() -> None:
    first = access.session_policy_document(principal("acme"), targets())
    second = access.session_policy_document(principal("globex"), targets())

    first_keys = dynamodb_statement(first)["Condition"]["ForAllValues:StringEquals"][
        access.LEADING_KEYS_CONDITION_KEY
    ]
    second_keys = dynamodb_statement(second)["Condition"]["ForAllValues:StringEquals"][
        access.LEADING_KEYS_CONDITION_KEY
    ]
    assert first_keys != second_keys
    assert s3_statement(first)["Resource"] != s3_statement(second)["Resource"]


def test_the_arn_partition_follows_the_table_rather_than_being_assumed() -> None:
    gov = targets(
        role_arn="arn:aws-us-gov:iam::123456789012:role/SessionDataAccessRole",
        table_arn="arn:aws-us-gov:dynamodb:us-gov-west-1:123456789012:table/sessions",
    )

    resource = s3_statement(access.session_policy_document(principal("acme"), gov))[
        "Resource"
    ]
    assert resource.startswith("arn:aws-us-gov:s3:::")


def test_the_serialised_policy_is_compact_and_within_the_sts_limit() -> None:
    document = access.session_policy_json(principal("acme"), targets())

    assert ", " not in document
    assert len(document) <= access.MAX_SESSION_POLICY_CHARACTERS


def test_the_largest_legal_deployment_still_fits_in_an_inline_session_policy() -> None:
    # The bounds that matter: the longest Tenant identifier the principal accepts, the longest
    # S3 bucket name and the longest DynamoDB table name. If this ever exceeded the STS limit the
    # design's Layer 2 would be unbuildable for some legal deployment rather than merely awkward.
    document = access.session_policy_json(
        principal("t" * MAX_TENANT_ID_LENGTH),
        targets(
            artifact_bucket="b" * 63,
            table_arn=f"arn:aws:dynamodb:eu-west-1:123456789012:table/{'s' * 255}",
        ),
    )

    assert len(document) <= access.MAX_SESSION_POLICY_CHARACTERS


def test_a_policy_over_the_sts_limit_is_refused_with_its_size() -> None:
    with pytest.raises(
        access.DataAccessConfigurationError,
        match=str(access.MAX_SESSION_POLICY_CHARACTERS),
    ):
        access.session_policy_json(
            principal("acme"),
            targets(
                table_arn=f"arn:aws:dynamodb:eu-west-1:123456789012:table/{'s' * 2000}"
            ),
        )


# --- the credentials and their cache ---------------------------------------------------------


def test_credentials_are_derived_once_per_tenant_and_then_cached() -> None:
    sts, clock = StubSts(), MovableClock()
    subject = broker(sts, clock)
    caller = principal("acme")

    first = subject.credentials_for(caller)
    second = subject.credentials_for(caller)

    assert first is second
    assert len(sts.calls) == 1
    assert sts.calls[0]["RoleArn"] == ROLE_ARN
    assert sts.calls[0]["DurationSeconds"] == access.DEFAULT_SESSION_DURATION_SECONDS


def test_a_cached_credential_is_never_handed_to_another_tenant() -> None:
    sts, clock = StubSts(), MovableClock()
    subject = broker(sts, clock)

    acme = subject.credentials_for(principal("acme"))
    globex = subject.credentials_for(principal("globex"))

    assert acme.access_key_id != globex.access_key_id
    assert (acme.tenant_id, globex.tenant_id) == ("acme", "globex")
    assert subject.cached_tenant_ids() == frozenset({"acme", "globex"})
    # Each derivation carried its own Tenant's policy, so neither credential can address the
    # other's partition even if it were somehow reused.
    pinned = [
        dynamodb_statement(document)["Condition"]["ForAllValues:StringEquals"][
            access.LEADING_KEYS_CONDITION_KEY
        ]
        for document in sts.policies()
    ]
    assert pinned[0] != pinned[1]


def test_credentials_are_re_derived_before_they_expire() -> None:
    sts, clock = StubSts(), MovableClock()
    subject = broker(sts, clock)
    caller = principal("acme")

    first = subject.credentials_for(caller)
    # Inside the refresh margin: a request must not begin with a credential about to expire.
    clock.now = sts.expires_at - access.CREDENTIAL_REFRESH_MARGIN
    sts.expires_at = clock.now + timedelta(minutes=15)
    second = subject.credentials_for(caller)

    assert second is not first
    assert len(sts.calls) == 2


def test_invalidate_forces_the_next_request_to_re_derive() -> None:
    sts, clock = StubSts(), MovableClock()
    subject = broker(sts, clock)
    caller = principal("acme")

    subject.credentials_for(caller)
    subject.invalidate("acme")
    subject.credentials_for(caller)

    assert len(sts.calls) == 2
    assert subject.cached_tenant_ids() == frozenset({"acme"})


def test_a_cache_entry_recording_the_wrong_tenant_is_refused_not_returned() -> None:
    sts, clock = StubSts(), MovableClock()
    subject = broker(sts, clock)
    misfiled = subject.credentials_for(principal("globex"))
    subject._cache["acme"] = misfiled

    with pytest.raises(access.TenantCredentialMismatch):
        subject.credentials_for(principal("acme"))


def test_credentials_expose_client_keyword_arguments() -> None:
    sts, clock = StubSts(), MovableClock()
    credentials = broker(sts, clock).credentials_for(principal("acme"))

    assert credentials.as_client_kwargs() == {
        "aws_access_key_id": credentials.access_key_id,
        "aws_secret_access_key": credentials.secret_access_key,
        "aws_session_token": credentials.session_token,
    }


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S"}},
        {
            "Credentials": {
                "AccessKeyId": "A",
                "SecretAccessKey": "S",
                "SessionToken": "T",
                # Naive: comparing it against an aware clock would raise, and assuming UTC would
                # be a guess about how long a credential lives.
                "Expiration": (EPOCH + timedelta(minutes=15)).replace(tzinfo=None),
            }
        },
    ],
)
def test_an_unusable_assume_role_response_is_rejected(response: dict[str, Any]) -> None:
    class BadSts:
        def assume_role(self, **kwargs: Any) -> Mapping[str, Any]:
            return response

    subject = access.TenantDataAccessBroker(
        targets=targets(), sts_client=BadSts(), clock=MovableClock()
    )
    with pytest.raises(access.DataAccessCredentialError):
        subject.credentials_for(principal("acme"))


# --- the role session name -------------------------------------------------------------------


@pytest.mark.parametrize(
    "tenant_id", ["acme", "tenant/with/slashes", "t" * 120, "a!b*c(d)"]
)
def test_a_role_session_name_is_iam_legal_whatever_the_tenant_identifier(
    tenant_id: str,
) -> None:
    name = access.role_session_name(tenant_id)

    assert 2 <= len(name) <= access.MAX_ROLE_SESSION_NAME_LENGTH
    assert access._DISALLOWED_IN_ROLE_SESSION_NAME.search(name) is None


def test_tenants_that_sanitise_alike_still_get_distinct_session_names() -> None:
    # Both become `a-b` before the digest, so without it CloudTrail could not tell them apart.
    assert access.role_session_name("a/b") != access.role_session_name("a!b")


# --- the deployment-written configuration ----------------------------------------------------


def test_targets_are_read_from_the_environment_the_stack_wrote() -> None:
    resolved = access.DataAccessTargets.from_environment(
        {
            access.ROLE_ARN_ENVIRONMENT_VARIABLE: ROLE_ARN,
            access.TABLE_ARN_ENVIRONMENT_VARIABLE: TABLE_ARN,
            access.ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE: BUCKET,
            access.DURATION_ENVIRONMENT_VARIABLE: "1800",
        }
    )

    assert resolved == targets(duration_seconds=1800)


def test_an_absent_target_fails_at_construction_naming_what_is_missing() -> None:
    with pytest.raises(
        access.DataAccessConfigurationError,
        match=access.ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE,
    ):
        access.DataAccessTargets.from_environment(
            {
                access.ROLE_ARN_ENVIRONMENT_VARIABLE: ROLE_ARN,
                access.TABLE_ARN_ENVIRONMENT_VARIABLE: TABLE_ARN,
            }
        )


def test_the_session_duration_defaults_to_the_floor_when_unset() -> None:
    resolved = access.DataAccessTargets.from_environment(
        {
            access.ROLE_ARN_ENVIRONMENT_VARIABLE: ROLE_ARN,
            access.TABLE_ARN_ENVIRONMENT_VARIABLE: TABLE_ARN,
            access.ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE: BUCKET,
        }
    )

    assert resolved.duration_seconds == access.DEFAULT_SESSION_DURATION_SECONDS


@pytest.mark.parametrize(
    "overrides",
    [
        {"role_arn": "SessionDataAccessRole"},
        {"role_arn": TABLE_ARN},
        {"table_arn": "arn:aws:s3:::sessions"},
        {"artifact_bucket": ""},
        {"artifact_bucket": f"{BUCKET}/tenants"},
        {"duration_seconds": 60},
        {"duration_seconds": 86400},
    ],
)
def test_malformed_targets_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(access.DataAccessConfigurationError):
        targets(**overrides)


def test_the_execution_environment_broker_is_built_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(access.ROLE_ARN_ENVIRONMENT_VARIABLE, ROLE_ARN)
    monkeypatch.setenv(access.TABLE_ARN_ENVIRONMENT_VARIABLE, TABLE_ARN)
    monkeypatch.setenv(access.ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE, BUCKET)
    access.broker_from_environment.cache_clear()
    try:
        # Constructing it builds no STS client, so a cold start pays for no AWS call it may not
        # need; the cache it holds is what a per-request broker would throw away.
        first = access.broker_from_environment()
        assert first is access.broker_from_environment()
        assert first.sts_client is None
        assert first.targets == targets()
    finally:
        access.broker_from_environment.cache_clear()
