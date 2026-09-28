# kiro-classification: public
"""The per-request tenant-confined data access role (R11.3, R6.9).

Layer 2 of the three layers that make cross-tenant access structurally impossible. A
Control_Plane handler does **not** use its own execution role to reach the State_Store. Per
request it assumes one `SessionDataAccessRole` with an inline session policy that pins
`dynamodb:LeadingKeys` to the caller's single partition key and confines S3 to that Tenant's
artifact prefix. Enforcement therefore sits in IAM, outside the code that could be wrong: a
handler that built the wrong partition key receives `AccessDenied` from DynamoDB rather than
another Tenant's item, which is what turns R11.3 from a rule someone must remember into a
property of the credentials in hand. R6.9's not-found response is Layer 3 and lives with the
handlers; this module is what makes that response the only observable outcome.

The policy is built from the authenticated principal alone, and neither half of it is spelled
here. :func:`pk_for` supplies the `dynamodb:LeadingKeys` value and
:func:`~control_plane.state.artifacts.tenant_artifact_prefix` supplies the S3 prefix, so on both
the DynamoDB and the S3 side the string the policy pins and the string a handler addresses have
one producer and cannot drift apart. That is the whole reason this module imports the artifact
store's layout rather than restating `tenants/<tenantId>/`: a second spelling would let the
granted prefix and the written key diverge while both modules' own tests still passed.

The cost of Layer 2 is one `sts:AssumeRole`. It is mitigated by
:class:`TenantDataAccessBroker`, which caches derived credentials in the execution environment
for their lifetime **keyed by Tenant identifier**, so a cached credential cannot be handed to a
different Tenant's request: a lookup for Tenant A can only ever find an entry filed under A, and
an entry whose recorded Tenant disagrees with the key it was filed under is refused rather than
returned. For a `single-tenant` deployment that reduces to one assume-role per cold start.

No AWS call is made at import time and the STS client is injected, so the offline suite exercises
every path here against a stub with no deployed resources and no network access (R15.9).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any, Final, Protocol

from control_plane.state.artifacts import tenant_artifact_prefix
from control_plane.state.table import TENANT_STATE_INDEX
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = [
    "CREDENTIAL_REFRESH_MARGIN",
    "DEFAULT_SESSION_DURATION_SECONDS",
    "DYNAMODB_ACTIONS",
    "LEADING_KEYS_CONDITION_KEY",
    "MAX_ROLE_SESSION_NAME_LENGTH",
    "MAX_SESSION_DURATION_SECONDS",
    "MAX_SESSION_POLICY_CHARACTERS",
    "MIN_SESSION_DURATION_SECONDS",
    "POLICY_VERSION",
    "S3_ACTIONS",
    "DataAccessConfigurationError",
    "DataAccessCredentialError",
    "DataAccessCredentials",
    "DataAccessTargets",
    "StsClient",
    "TenantCredentialMismatch",
    "TenantDataAccessBroker",
    "broker_from_environment",
    "role_session_name",
    "session_policy_document",
    "session_policy_json",
]

POLICY_VERSION: Final = "2012-10-17"

#: The condition key that confines every request to one partition. It compares the *leading* —
#: that is, partition — key of every item a request touches, which is why the Tenant identifier
#: is the first element of the key and nothing precedes it.
LEADING_KEYS_CONDITION_KEY: Final = "dynamodb:LeadingKeys"

#: `ForAllValues:` because a `Query` or a `TransactWriteItems` presents several key values at
#: once and every one of them must satisfy the condition. Without the set operator a single
#: matching value would satisfy a request that also touched another partition.
_LEADING_KEYS_OPERATOR: Final = "ForAllValues:StringEquals"

#: The action set a Control_Plane handler needs, and no more. `TransactWriteItems` is here
#: because the Affinity_Key claim is a transaction, and `DeleteItem` because binding cleanup is a
#: delete (R6.16, R6.18). `Scan` is absent: no handler read path is unpartitioned, and an action
#: the credentials do not carry cannot be reached by a bug.
DYNAMODB_ACTIONS: Final[tuple[str, ...]] = (
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:Query",
    "dynamodb:DeleteItem",
    "dynamodb:TransactWriteItems",
)

#: Artifact reads and writes. The Sandbox execution role is provisioned separately and is not
#: this role.
S3_ACTIONS: Final[tuple[str, ...]] = ("s3:GetObject", "s3:PutObject")

#: STS accepts at most 2,048 characters of inline session policy. Checked here so an over-long
#: bucket or Tenant identifier fails with something a reader can act on rather than as an STS
#: validation error at the first request after a deployment.
MAX_SESSION_POLICY_CHARACTERS: Final = 2048

MIN_SESSION_DURATION_SECONDS: Final = 900
MAX_SESSION_DURATION_SECONDS: Final = 3600

#: The floor, deliberately. A credential that outlives its usefulness is a credential to steal,
#: and the cache means a longer lifetime buys only a marginally lower assume-role rate.
DEFAULT_SESSION_DURATION_SECONDS: Final = MIN_SESSION_DURATION_SECONDS

#: Credentials are re-derived this far before expiry, so a request cannot begin with a credential
#: that expires while DynamoDB is answering it.
CREDENTIAL_REFRESH_MARGIN: Final = timedelta(seconds=60)

#: IAM's bound on a role session name, which appears in every CloudTrail record of this role.
MAX_ROLE_SESSION_NAME_LENGTH: Final = 64

#: Everything IAM's `[\w+=,.@-]` pattern excludes, ASCII-only because `\w` in Python matches
#: letters IAM would reject.
_DISALLOWED_IN_ROLE_SESSION_NAME: Final = re.compile(r"[^\w+=,.@-]", re.ASCII)

_TENANT_DIGEST_LENGTH: Final = 8

ROLE_ARN_ENVIRONMENT_VARIABLE: Final = "SESSION_DATA_ACCESS_ROLE_ARN"
TABLE_ARN_ENVIRONMENT_VARIABLE: Final = "STATE_STORE_TABLE_ARN"
ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE: Final = "STATE_STORE_ARTIFACT_BUCKET"
DURATION_ENVIRONMENT_VARIABLE: Final = "SESSION_DATA_ACCESS_DURATION_SECONDS"


class DataAccessConfigurationError(ValueError):
    """The deployment-written configuration this role is built from is absent or malformed.

    Raised at construction rather than at the first request, so a misconfigured deployment fails
    where an operator is looking instead of one `AccessDenied` at a time.
    """


class DataAccessCredentialError(RuntimeError):
    """STS returned something that is not a usable set of credentials."""


class TenantCredentialMismatch(RuntimeError):
    """A cached credential was filed under one Tenant and recorded another.

    Unreachable unless the cache itself is wrong, which is the point: the one bug that would
    matter here is a credential handed to the wrong Tenant, so it raises instead of returning.
    """


def _require_arn(name: str, value: str, expected_service: str) -> str:
    parts = value.split(":")
    if len(parts) < 6 or parts[0] != "arn" or not parts[1]:
        raise DataAccessConfigurationError(f"{name} is not an ARN: {value!r}")
    if parts[2] != expected_service:
        raise DataAccessConfigurationError(
            f"{name} is not an {expected_service} ARN: {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class DataAccessTargets:
    """What the session policy is written against, all of it deployment-derived.

    Every field comes from the stack through the handler's own environment. None of it can be
    influenced by a request, which is the same reason the Tenant identifier cannot be: a caller
    who could name the table or the bucket would have widened the policy that confines them.
    """

    role_arn: str
    table_arn: str
    artifact_bucket: str
    duration_seconds: int = DEFAULT_SESSION_DURATION_SECONDS

    def __post_init__(self) -> None:
        _require_arn("role_arn", self.role_arn, "iam")
        _require_arn("table_arn", self.table_arn, "dynamodb")
        if not self.artifact_bucket:
            raise DataAccessConfigurationError("artifact_bucket must not be empty")
        if "/" in self.artifact_bucket:
            raise DataAccessConfigurationError(
                f"artifact_bucket must be a bucket name, not a path: "
                f"{self.artifact_bucket!r}"
            )
        if not (
            MIN_SESSION_DURATION_SECONDS
            <= self.duration_seconds
            <= MAX_SESSION_DURATION_SECONDS
        ):
            raise DataAccessConfigurationError(
                f"duration_seconds must be between {MIN_SESSION_DURATION_SECONDS} and "
                f"{MAX_SESSION_DURATION_SECONDS}: {self.duration_seconds}"
            )

    @property
    def partition(self) -> str:
        """The ARN partition, taken from the table ARN rather than assumed to be `aws`.

        An S3 ARN carries no account or Region to derive it from, and a deployment in a partition
        this did not name would get a policy that grants nothing.
        """
        return self.table_arn.split(":")[1]

    @property
    def tenant_state_index_arn(self) -> str:
        """The one index a handler reads. `deadline-index` is deliberately absent.

        That index is the Reaper's cross-Tenant read path, so a handler credential able to query
        it would be a credential able to see every Tenant's rows.
        """
        return f"{self.table_arn}/index/{TENANT_STATE_INDEX.name}"

    def artifact_arn_for(self, tenant_id: str) -> str:
        """The S3 resource ARN confining this role to one Tenant's artifacts.

        The prefix comes from :func:`~control_plane.state.artifacts.tenant_artifact_prefix`, which
        is also what builds the object keys artifacts are actually written under. That shared
        producer is load-bearing: this pattern and those keys agreeing is *what* S3 tenant
        confinement is, and two independent spellings of `tenants/<tenantId>/` could drift apart
        while both modules' own tests stayed green — a silent failure of a security boundary. The
        policy pins only the Tenant root, because a policy naming the Session too would have to be
        rebuilt per Session and would confine nothing further.
        """
        return f"arn:{self.partition}:s3:::{self.artifact_bucket}/{tenant_artifact_prefix(tenant_id)}*"

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> DataAccessTargets:
        """Read the targets the stack wrote into the handler's environment.

        The environment is a parameter so the offline suite can state a deployment without one,
        not so that a caller may supply it: at runtime the default is the process environment,
        which no request can reach.
        """
        source = os.environ if environment is None else environment
        missing = [
            name
            for name in (
                ROLE_ARN_ENVIRONMENT_VARIABLE,
                TABLE_ARN_ENVIRONMENT_VARIABLE,
                ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE,
            )
            if not source.get(name)
        ]
        if missing:
            raise DataAccessConfigurationError(
                f"environment is missing {', '.join(missing)}"
            )

        raw_duration = source.get(DURATION_ENVIRONMENT_VARIABLE)
        if raw_duration is None or raw_duration == "":
            duration = DEFAULT_SESSION_DURATION_SECONDS
        else:
            try:
                duration = int(raw_duration)
            except ValueError as exc:
                raise DataAccessConfigurationError(
                    f"{DURATION_ENVIRONMENT_VARIABLE} is not an integer: {raw_duration!r}"
                ) from exc

        return cls(
            role_arn=source[ROLE_ARN_ENVIRONMENT_VARIABLE],
            table_arn=source[TABLE_ARN_ENVIRONMENT_VARIABLE],
            artifact_bucket=source[ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE],
            duration_seconds=duration,
        )


def role_session_name(tenant_id: str) -> str:
    """Derive an IAM-legal role session name that attributes the session to its Tenant.

    Derived rather than passed through for two reasons: a Tenant identifier may legally contain
    characters IAM's session-name pattern rejects, and two identifiers that sanitise to the same
    text would become indistinguishable in CloudTrail. The digest suffix keeps them distinct.
    Confinement does not rest on this name — the policy and the cache key both use the Tenant
    identifier itself — so this is an audit concern rather than a security one.
    """
    if not tenant_id:
        raise DataAccessConfigurationError("tenant_id must not be empty")
    digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[
        :_TENANT_DIGEST_LENGTH
    ]
    sanitised = _DISALLOWED_IN_ROLE_SESSION_NAME.sub("-", tenant_id)
    room = MAX_ROLE_SESSION_NAME_LENGTH - len(digest) - 1
    return f"{sanitised[:room]}-{digest}"


def session_policy_document(
    principal: AuthenticatedPrincipal, targets: DataAccessTargets
) -> dict[str, Any]:
    """Build the inline session policy confining one request to one Tenant.

    The principal is the only source of the Tenant identifier, and `pk_for` is the only producer
    of the value `dynamodb:LeadingKeys` pins. The policy the credentials carry and the keys the
    handler builds therefore cannot disagree about what "this Tenant" means.
    """
    return {
        "Version": POLICY_VERSION,
        "Statement": [
            {
                "Effect": "Allow",
                "Action": list(DYNAMODB_ACTIONS),
                "Resource": [targets.table_arn, targets.tenant_state_index_arn],
                "Condition": {
                    _LEADING_KEYS_OPERATOR: {
                        LEADING_KEYS_CONDITION_KEY: [pk_for(principal)]
                    }
                },
            },
            {
                "Effect": "Allow",
                "Action": list(S3_ACTIONS),
                "Resource": targets.artifact_arn_for(principal.tenant_id),
            },
        ],
    }


def session_policy_json(
    principal: AuthenticatedPrincipal, targets: DataAccessTargets
) -> str:
    """Serialise the session policy, compactly, and refuse one STS would reject."""
    document = json.dumps(
        session_policy_document(principal, targets), separators=(",", ":")
    )
    if len(document) > MAX_SESSION_POLICY_CHARACTERS:
        raise DataAccessConfigurationError(
            f"inline session policy is {len(document)} characters, over the STS limit of "
            f"{MAX_SESSION_POLICY_CHARACTERS}"
        )
    return document


@dataclass(frozen=True, slots=True)
class DataAccessCredentials:
    """One set of derived credentials, and the Tenant they were derived for.

    The Tenant identifier is carried on the credentials rather than only in the cache key, so a
    credential can be checked against the request that found it.
    """

    tenant_id: str
    access_key_id: str
    secret_access_key: str
    session_token: str
    expires_at: datetime

    def is_fresh(
        self, now: datetime, margin: timedelta = CREDENTIAL_REFRESH_MARGIN
    ) -> bool:
        """Whether these credentials will still be valid for a request beginning now."""
        return self.expires_at - margin > now

    def as_client_kwargs(self) -> dict[str, str]:
        """Keyword arguments for a boto3 client or session built from these credentials."""
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
        }


class StsClient(Protocol):
    """The one STS call this module makes.

    A structural type rather than the boto3 client itself: the offline suite substitutes a stub,
    and boto3 stays out of the import graph of every test that does not need it.
    """

    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _default_sts_client() -> StsClient:
    """Build the real STS client, imported here so importing this module needs no AWS."""
    import boto3  # type: ignore[import-untyped]

    client: StsClient = boto3.client("sts")
    return client


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _credentials_from_response(
    response: Mapping[str, Any], tenant_id: str
) -> DataAccessCredentials:
    credentials = response.get("Credentials")
    if not isinstance(credentials, Mapping):
        raise DataAccessCredentialError("AssumeRole response carried no Credentials")
    try:
        access_key_id = str(credentials["AccessKeyId"])
        secret_access_key = str(credentials["SecretAccessKey"])
        session_token = str(credentials["SessionToken"])
        expiration = credentials["Expiration"]
    except KeyError as exc:
        raise DataAccessCredentialError(
            f"AssumeRole credentials are missing {exc.args[0]}"
        ) from exc

    if isinstance(expiration, str):
        try:
            expires_at = datetime.fromisoformat(expiration)
        except ValueError as exc:
            raise DataAccessCredentialError(
                f"AssumeRole expiration is not a timestamp: {expiration!r}"
            ) from exc
    elif isinstance(expiration, datetime):
        expires_at = expiration
    else:
        raise DataAccessCredentialError(
            f"AssumeRole expiration is not a timestamp: {expiration!r}"
        )
    if expires_at.tzinfo is None:
        # A naive expiry compared against an aware clock raises, and silently treating it as UTC
        # would be a guess about a credential's lifetime.
        raise DataAccessCredentialError(
            f"AssumeRole expiration carries no timezone: {expiration!r}"
        )

    return DataAccessCredentials(
        tenant_id=tenant_id,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        expires_at=expires_at,
    )


@dataclass(slots=True)
class TenantDataAccessBroker:
    """Derives, and caches, the credentials one request uses to reach the State_Store.

    One instance per execution environment. The cache is keyed by Tenant identifier and by
    nothing else, so it can only ever answer a request with a credential derived for that
    request's Tenant; a stale entry is re-derived rather than shared, and an entry whose recorded
    Tenant disagrees with its key is refused.

    No lock: a Lambda execution environment handles one request at a time, and a duplicate
    assume-role under any other host would be a wasted call rather than a correctness problem.
    """

    targets: DataAccessTargets
    #: Left unset in a deployment and built on first use, so constructing the broker — which
    #: happens while an execution environment is still initialising — touches no AWS.
    sts_client: StsClient | None = None
    clock: Callable[[], datetime] = _utc_now
    refresh_margin: timedelta = CREDENTIAL_REFRESH_MARGIN
    _cache: dict[str, DataAccessCredentials] = field(default_factory=dict, repr=False)

    def credentials_for(
        self, principal: AuthenticatedPrincipal
    ) -> DataAccessCredentials:
        """Return credentials confined to this principal's Tenant, cached where still fresh."""
        tenant_id = principal.tenant_id
        cached = self._cache.get(tenant_id)
        if cached is not None:
            if cached.tenant_id != tenant_id:
                del self._cache[tenant_id]
                raise TenantCredentialMismatch(
                    f"credentials cached for {tenant_id!r} were derived for "
                    f"{cached.tenant_id!r}"
                )
            if cached.is_fresh(self.clock(), self.refresh_margin):
                return cached

        derived = self._assume(principal)
        self._cache[tenant_id] = derived
        return derived

    def invalidate(self, tenant_id: str) -> None:
        """Drop a Tenant's cached credentials, for a handler that saw them rejected."""
        self._cache.pop(tenant_id, None)

    def cached_tenant_ids(self) -> frozenset[str]:
        """The Tenants currently holding a cache entry. For assertions and metrics."""
        return frozenset(self._cache)

    def _client(self) -> StsClient:
        if self.sts_client is None:
            self.sts_client = _default_sts_client()
        return self.sts_client

    def _assume(self, principal: AuthenticatedPrincipal) -> DataAccessCredentials:
        response = self._client().assume_role(
            RoleArn=self.targets.role_arn,
            RoleSessionName=role_session_name(principal.tenant_id),
            Policy=session_policy_json(principal, self.targets),
            DurationSeconds=self.targets.duration_seconds,
        )
        return _credentials_from_response(response, principal.tenant_id)


@lru_cache(maxsize=1)
def broker_from_environment() -> TenantDataAccessBroker:
    """The broker of this execution environment, built once from the stack-written environment.

    Memoised because the cache it holds is the whole point: a broker rebuilt per request would
    assume the role per request, which is the cost the design set out to pay only once per
    Tenant per execution environment. `cache_clear()` exists for the offline suite.
    """
    return TenantDataAccessBroker(targets=DataAccessTargets.from_environment())
