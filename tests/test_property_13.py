# kiro-classification: public
"""Property 13: Tenant partition confinement, asserted over addresses rather than over a comparison.

Confinement is a claim about **addresses**. The code half of it is an absence — there is no branch
anywhere in the Control_Plane for "the Session exists but belongs to another Tenant" — and the
absence of a check is not evidence that the check is unnecessary. So nothing here asserts that a
Tenant identifier was compared, or that a comparison was skipped. Every read and every write issued
while handling a request is intercepted, its key recorded, and the partition component of every one
of those keys is required to equal `pk_for(the calling principal)`. The design's Layer 3 half is
asserted the same way: the response for another Tenant's Session identifier is compared byte for
byte against the response for an identifier that never existed, and against the response for one
that is not well formed at all.

`ci/lint_rules/tenant_partition_key.py` already discharges the **static** half of the same
guarantee: no module outside `control_plane/tenancy/partition.py` spells the prefix, imports it, or
defines a second `pk_for`. Restating that here would be redundant, so this property asserts the
**runtime** half instead — that the set of partition keys actually addressed while serving a request
is exactly the one-element image of `pk_for` under the calling principal, and that the set of
partition keys present in the State_Store is the image of `pk_for` over the Tenants that own them.
A source-level rule cannot say that; only a run can.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| Tenant pairs where one identifier is a prefix of the other | a key encoding that confined by `begins_with` rather than by equality; the pinned `dynamodb:LeadingKeys` value is asserted to be compared by an equality operator |
| non-ASCII and astral-plane Tenant identifiers | that confinement rests on the key structure and not on an alphabet somebody assumed |
| Tenant identifiers carrying the sort-key delimiter, whitespace, a non-printable, the empty string, or more than the bound | that such a value is refused at :class:`AuthenticatedPrincipal` and therefore never reaches a key at all — the confusable encoding is unreachable rather than handled |
| a Tenant identifier carrying `/` | the one asymmetry between the two stores: it is a safe DynamoDB partition key, because `LeadingKeys` compares by equality, and a refused S3 prefix, because a prefix pattern would overlap another Tenant's objects |
| both Deployment_Profiles | R11.17 and R11.18. Under `single-tenant` two distinct verified identities resolve to one Tenant, so the partition a request addresses is the deployment constant whatever the caller; under `multi-tenant` they resolve to two |
| the same Affinity_Key presented by both Tenants | R11.11 over addresses: one digest, two partitions, and neither Tenant's binding is ever addressed by the other |
| one Session identifier seated in **both** partitions, and one seated only in the other's | a Tenant naming an identifier that exists elsewhere. The sort key is identical; only the partition differs, which is the whole of what makes it unreachable |
| sequences of one to four requests, interleaving the two callers | that confinement holds at *every* point, including after a request has created a Session, claimed a binding and written an artifact |
| all five Session-naming routes, plus `CreateSession`, `ResolveSession` and an artifact write and read | the operations R6.9, R11.2 and R11.3 reach. Resolution alone is Property 35's domain; this property is quantified over the whole surface |

The five Session-naming routes are derived from `ROUTES_BY_OPERATION` rather than listed, so a route
that later declares `{id}` is drawn into this property without an edit here.

## What is asserted, at every step of every sequence

- **Every address is the caller's own** (R11.2, R11.3). Every key of every read and every write in
  the step carries `pk_for(the resolved principal)`, and the routed reads carry exactly the sort key
  derived from the identifier the caller named — so the assertion is over what was addressed, not
  over what was returned.
- **The other Tenant's item is never addressed** (R6.9). Not merely reported absent: the key it
  occupies does not appear among the addresses at all, including when the caller names a Session
  identifier that exists in both partitions and only the partition differs.
- **Byte-identical, and by identity** (R6.9). Another Tenant's identifier, an identifier that never
  existed, and a malformed identifier produce the same response bytes on the same route, and that
  response *is* :data:`NOT_FOUND_RESPONSE` rather than an equal rebuild of it.
- **The other Tenant's items are untouched.** Every item outside the caller's partition is
  byte-identical before and after the step, and so is every stored artifact object outside the
  caller's prefix.
- **The credentials in hand cannot name another partition** (R11.3). The inline session policy of
  the per-request data access role pins `dynamodb:LeadingKeys` to exactly `[pk_for(principal)]`
  under an equality operator, and confines S3 to that Tenant's prefix. This is what makes another
  Tenant's partition *unaddressable* rather than merely not-found, and it is asserted per request
  because the policy is built per request.
- **Nothing but `pk_for` produced a key.** Every partition key touched, and every partition key
  present in the store afterwards, is in the image of `pk_for`; and each stored row's own `tenantId`
  attribute agrees with the partition it sits in.

## Why the store double is imported rather than rewritten

`FakeStore` in `test_control_plane_resolution.py` records every key of every read and write in
`keys_touched`, which is exactly what makes this property assertable, and it implements the Session
row, binding and lookup seams over one dict keyed as DynamoDB is. A second copy would be a second
thing to keep faithful. `operations()` comes from the same module for the injected fixed clock, the
`RecordingMint` the sole-issuer lint rule allows, and the shared Session identifier counter. The
wait, the S3 seam, the operations wiring and the seating helpers are local, because task 6.16 is
writing over the same allocation and creation code concurrently; consolidating the seating helpers
that this file, Property 35 and Property 36 each hold is a later change.

## Non-vacuity

`test_every_bucket_is_reachable_and_the_property_holds_on_each` runs the checker over an enumerated
case per bucket and asserts every bucket is occupied, so no arm is dead — in particular that the
`404` arm is reached, that the `RefreshConnection` arm returns a credential, and that both profiles
run. `test_the_assertions_discriminate_two_plausible_leaks` asserts that the checker rejects a
lookup that falls back to another partition when the caller's own read misses, and rejects a
not-found response that names the identifier it refused; without those, "every address was the
caller's own" could hold of a suite that recorded no addresses.

## Budget

200 examples. Each runs up to four requests against an in-memory dict and an in-memory object store
with an injected clock, an injected mint and a stub orchestration: no subprocess, no filesystem, no
network and no wall-clock dependence. The design's floor of 100 would leave several of the eight
operation buckets crossed with five identifier buckets and two profiles unvisited on a given run.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from io import BytesIO
from typing import Any, Final
from unittest.mock import patch

from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.api.connection import ConnectionOperations
from control_plane.api.errors import NOT_FOUND_RESPONSE, HttpResponse
from control_plane.api.handlers import (
    ControlPlaneApi,
    NotImplementedOperations,
    OperationRequest,
    OperationResult,
)
from control_plane.api.request import TENANT_ATTRIBUTE_FIELD
from control_plane.api.resolution import AFFINITY_KEY_FIELD, ResolutionOperations
from control_plane.api.routes import (
    ROUTES_BY_OPERATION,
    SESSION_ID_PARAMETER,
    Operation,
)
from control_plane.providers.local_firecracker import LocalFirecrackerProvider
from control_plane.state.access import (
    LEADING_KEYS_CONDITION_KEY,
    DataAccessTargets,
    session_policy_document,
    session_policy_json,
)
from control_plane.state.artifacts import (
    ArtifactLayoutError,
    ArtifactStore,
    ArtifactStoreConfig,
    tenant_artifact_prefix,
)
from control_plane.state.keys import (
    SEPARATOR,
    affinity_key_digest,
    binding_sort_key,
    session_sort_key,
)
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.state.table import PARTITION_KEY_ATTRIBUTE
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    MAX_TENANT_ID_LENGTH,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    TenantIdentifierError,
    VerifiedCallerIdentity,
    pk_for,
    reset_resolver_cache,
    tenant_of,
)
from tests.test_control_plane_resolution import (
    NOW_MS,
    PUBLISHED,
    SANDBOX_HANDLE,
    SETTINGS,
    FakeStore,
    RecordingStarter,
    operations,
)

# --- The two stores this property addresses -------------------------------------------------------

#: The deployment-derived targets the per-request session policy is written against. Nothing here is
#: request-influenced, which is the same reason the Tenant identifier is not.
TARGETS: Final = DataAccessTargets(
    role_arn="arn:aws:iam::123456789012:role/SessionDataAccessRole",
    table_arn="arn:aws:dynamodb:us-east-1:123456789012:table/sessions",
    artifact_bucket="sandbox-artifacts-123456789012",
)

ARTIFACT_CONFIG: Final = ArtifactStoreConfig(
    bucket=TARGETS.artifact_bucket,
    kms_key_id="arn:aws:kms:us-east-1:123456789012:key/fake-key-for-tests",
    retention_days=SETTINGS.artifact_retention_days,
)

#: The artifact one step writes and reads back. A fixed relative path: which artifact is written is
#: not a dimension of this property, only which prefix it lands under.
ARTIFACT_ID: Final = "stdout.log"
ARTIFACT_GENERATION: Final = 1
ARTIFACT_BODY: Final = b"artifact bytes"

#: An object seated under the other Tenant's prefix before the sequence runs, so "no key outside the
#: caller's prefix is addressed" is a statement about an object that exists rather than about one
#: that does not.
FOREIGN_ARTIFACT_BODY: Final = b"another tenant's artifact bytes"

# --- The identifiers a step may name --------------------------------------------------------------

#: Seated in **both** Tenants' partitions under the identical sort key. Only the partition differs,
#: which is the sharpest form of one Tenant naming an identifier that exists elsewhere.
SHARED_SESSION: Final = "01JSHAREDIDENTIFIERAAAAAAA"

#: One per drawn Tenant, seated only in that Tenant's partition.
OWN_SESSIONS: Final = ("01JOWNOFTHEFIRSTAAAAAAAAAA", "01JOWNOFTHESECONDBBBBBBBBB")

#: Well formed and never created anywhere. The reference response R6.9 compares against.
NEVER_EXISTED: Final = "01JNEVEREXISTEDANYWHEREXXX"

#: Not well formed: it carries the key separator, so it is refused before the read is issued and is
#: answered with the same fixed response (`control_plane/api/lookup.py`).
MALFORMED: Final = f"01JMALFORMED{SEPARATOR}IDENTIFIER"

OWN: Final = "own"
SHARED: Final = "shared"
THEIRS: Final = "theirs"
NEVER: Final = "never"
MALFORMED_TARGET: Final = "malformed"

TARGETS_NAMING_A_SESSION: Final = (OWN, SHARED, THEIRS, NEVER, MALFORMED_TARGET)

#: The artifact step, which is a State_Store read and write that no HTTP route carries.
ARTIFACT_STEP: Final = "artifact"

#: Derived from the route table rather than listed, so a route that later declares `{id}` is drawn
#: into this property without an edit here.
NAMING_OPERATIONS: Final = tuple(
    operation
    for operation, route in ROUTES_BY_OPERATION.items()
    if route.names_a_session
)

#: The two routes that write. `ListSessions` is absent: it reaches the `tenant-state-index` rather
#: than an item key, and the index read path is Property 34's domain.
WRITING_OPERATIONS: Final = (Operation.CREATE_SESSION, Operation.RESOLVE_SESSION)

# --- Tenant identifiers ---------------------------------------------------------------------------

#: Bound on a drawn Tenant identifier. Well under `MAX_TENANT_ID_LENGTH`, so that two of them plus
#: the policy skeleton stay inside the STS inline-policy limit and the assertion that the policy is
#: expressible at all is about confinement rather than about a length nobody deploys.
DRAWN_TENANT_ID_LENGTH: Final = 32

#: Tenant identifier pairs worth drawing by name. Each pair is one a naive key encoding would
#: confuse: one identifier a prefix of the other, one differing only in case, one differing only
#: after a long common head, a non-ASCII pair, an astral-plane pair, and a pair whose identifiers
#: differ only by a character an ARN would carry.
CONFUSABLE_PAIRS: Final = (
    ("acme", "acme-eu"),
    ("acme", "acmeeu"),
    ("acme-eu", "acme-eu-2"),
    ("t", "t1"),
    ("acme", "ACME"),
    ("a" * 64, "a" * 64 + "b"),
    ("会社-tokyo", "会社-tokyo-2"),
    ("\U0001f600", "\U0001f600\U0001f600"),
    ("arn:aws:iam::123456789012:root", "arn:aws:iam::123456789013:root"),
    ("0", "00"),
)

#: Tenant identifiers that must never become a partition key. Each is refused by
#: `require_tenant_id`, so the confusable encoding it would produce is unreachable rather than
#: handled: the delimiter would let one Tenant's key be spelled as another key shape, and the rest
#: are values a policy document could not be reviewed against.
UNUSABLE_TENANT_IDS: Final = (
    f"acme{SEPARATOR}eu",
    SEPARATOR,
    f"{SEPARATOR}acme",
    "acme eu",
    "acme\teu",
    "acme\neu",
    "acme\u0000eu",
    "",
    "x" * (MAX_TENANT_ID_LENGTH + 1),
)

#: The one identifier that is a safe DynamoDB partition key and an unsafe S3 prefix. `LeadingKeys`
#: compares by equality, so `T#acme/eu` collides with nothing; the artifact layout confines by
#: prefix, and `tenants/acme/eu/` sits inside the `tenants/acme/*` granted to the Tenant `acme`.
PREFIX_OVERLAPPING_TENANT_ID: Final = "acme/eu"

#: Affinity_Keys both Tenants present. The delimiter-carrying and non-ASCII cases are here because
#: the digest is what makes a caller-supplied value safe as a sort key; the full domain of that is
#: Property 35's.
AFFINITY_KEYS: Final = (
    "thread-9f3",
    f"thread{SEPARATOR}9f3",
    "会話-9f3",
)


def caller_arn(tenant_id: str) -> str:
    """The ARN the `AWS_IAM` authorizer verified for a caller belonging to this Tenant."""
    return f"arn:aws:sts::123456789012:assumed-role/Caller/{tenant_id}"


def seat_principal(tenant_id: str) -> AuthenticatedPrincipal:
    """A principal for a Tenant that owns seated items, used only to address its partition.

    Built through :class:`AuthenticatedPrincipal` so that the partition a row is seated in comes
    from the sole producer of a partition key and not from a spelling this file invented.
    """
    return AuthenticatedPrincipal(
        caller_identity=caller_arn(tenant_id), tenant_id=tenant_id
    )


# --- The doubles ----------------------------------------------------------------------------------


@dataclass
class PublishingWait:
    """The creation wait, standing in for the orchestration publishing a credential.

    It writes directly rather than through the recorded seams, which is correct: the orchestration
    is a different principal with its own credentials, and its writes are not addresses this
    property attributes to the handler. It can only write at the row's own partition key, so it
    cannot fabricate a foreign address either.
    """

    store: FakeStore
    calls: list[str] = field(default_factory=list)

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        self.calls.append(record.session_id)
        row = self.store.items[(record.pk, record.sort_key)]
        row["lifecycleState"] = LifecycleState.RUNNING.value
        row["connection"] = PUBLISHED.to_map()
        row["connectionPublishedAt"] = NOW_MS
        row["sandboxHandle"] = dict(SANDBOX_HANDLE)
        return PUBLISHED


@dataclass
class RecordingS3:
    """The artifact store's S3 seam, recording the key of every object written and read.

    The S3 half of `keys_touched`: R11.3 scopes every State_Store read and write, and the artifact
    bucket is as much the State_Store as the table is.
    """

    objects: dict[str, bytes] = field(default_factory=dict)
    keys: list[str] = field(default_factory=list)

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = str(kwargs["Key"])
        self.keys.append(key)
        self.objects[key] = bytes(kwargs["Body"])
        return {}

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = str(kwargs["Key"])
        self.keys.append(key)
        return {"Body": BytesIO(self.objects[key])}


@dataclass(frozen=True, slots=True)
class WiredOperations:
    """The three operations that are implemented, with the other five still answering `501`.

    The unimplemented five are delegated to :class:`NotImplementedOperations` rather than restated,
    so this double asserts nothing about behaviour task 6.18 owns. What matters for this property is
    that the dispatcher resolves the named Session inside the caller's own partition *before* the
    operation runs, which happens on all five of those routes whatever they then answer.
    """

    resolution: ResolutionOperations
    connection: ConnectionOperations
    unimplemented: NotImplementedOperations = field(
        default_factory=NotImplementedOperations
    )
    seen: list[OperationRequest] = field(default_factory=list)

    def create_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.resolution.creation.create_session(request)

    def resolve_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.resolution.resolve_session(request)

    def refresh_connection(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.connection.refresh_connection(request)

    def get_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.unimplemented.get_session(request)

    def list_sessions(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.unimplemented.list_sessions(request)

    def suspend_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.unimplemented.suspend_session(request)

    def resume_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.unimplemented.resume_session(request)

    def terminate_session(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return self.unimplemented.terminate_session(request)


def invocation(
    method: str, path: str, *, tenant_id: str, body: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """An API Gateway HTTP API payload-format-2.0 invocation.

    The identity and the Tenant attribute live under `requestContext.authorizer`, which API Gateway
    populates from the route's authorizer and no caller can set. There is deliberately no way to
    express a Tenant anywhere else in this helper, which is why every drawn request in this property
    names a Tenant only where the deployment allows one to be named at all.
    """
    return {
        "version": "2.0",
        "rawPath": path,
        "requestContext": {
            "http": {"method": method},
            "authorizer": {
                "iam": {"userArn": caller_arn(tenant_id)},
                TENANT_ATTRIBUTE_FIELD: tenant_id,
            },
        },
        "body": None if body is None else json.dumps(body),
        "isBase64Encoded": False,
    }


@contextmanager
def deployment(profile: DeploymentProfile, fixed_tenant_id: str) -> Iterator[None]:
    """Serve the whole case under one Deployment_Profile.

    The profile and the Tenant constant are read from the handler environment the stack writes, so
    they are set there rather than injected: the resolver a handler holds is the one this property
    should be quantified over. Both variables are set under both profiles, which is itself part of
    R11.17 — under `multi-tenant` the constant is present and never read.
    """
    with patch.dict(
        os.environ,
        {
            DEPLOYMENT_PROFILE_VARIABLE: profile.value,
            TENANT_ID_VARIABLE: fixed_tenant_id,
        },
    ):
        reset_resolver_cache()
        try:
            yield
        finally:
            reset_resolver_cache()


# --- One drawn case -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Step:
    """One request in the sequence: who issued it, which operation, and what it named."""

    caller: int
    operation: Operation | None
    target: str

    @property
    def bucket(self) -> str:
        name = ARTIFACT_STEP if self.operation is None else self.operation.value
        return f"operation: {name}"


@dataclass(frozen=True, slots=True)
class ConfinementCase:
    """Two Tenants, one Affinity_Key, one profile, and a sequence of requests over one store."""

    profile: DeploymentProfile
    tenants: tuple[str, str]
    unusable: str
    affinity_key: str
    steps: tuple[Step, ...]

    @property
    def digest(self) -> str:
        """The sort-key component the Affinity_Key becomes in *both* Tenants' partitions."""
        return affinity_key_digest(self.affinity_key)

    def resolved_index(self, caller: int) -> int:
        """Which of the two Tenants this caller's request resolves to, restated from R11.17.

        Under `single-tenant` the Tenant of a Session is derived from no request content, so both
        verified identities resolve to the deployment constant, which this property fixes as the
        first drawn identifier. Under `multi-tenant` each identity resolves to its own. Restated
        here and checked against :func:`tenant_of` in :func:`build`, rather than read out of the
        resolver, because an expectation computed by the code under test would hold of any resolver.
        """
        return 0 if self.profile is DeploymentProfile.SINGLE_TENANT else caller

    def buckets(self) -> frozenset[str]:
        """The buckets this case occupies before any step has run."""
        first, second = self.tenants
        found = {
            f"profile: {self.profile.value}",
            f"unusable identifier: {'over the length bound' if len(self.unusable) > MAX_TENANT_ID_LENGTH else self.unusable!r}",
        }
        if second.startswith(first) or first.startswith(second):
            found.add("tenants: one identifier is a prefix of the other")
        if not (first.isascii() and second.isascii()):
            found.add("tenants: not ASCII")
        if first.lower() == second.lower():
            found.add("tenants: the pair differs only in case")
        if SEPARATOR in self.affinity_key:
            found.add("key: carries the sort-key delimiter")
        if not self.affinity_key.isascii():
            found.add("key: not ASCII")
        if len({step.caller for step in self.steps}) == 2:
            found.add("callers: both verified identities issued a request")
        if len(self.steps) > 1:
            found.add("sequence: more than one request")
        for step in self.steps:
            found.add(step.bucket)
            if step.operation in NAMING_OPERATIONS:
                found.add(f"target: {step.target}")
        return frozenset(found)


@st.composite
def tenant_pair(drawn: st.DrawFn) -> tuple[str, str]:
    """Two distinct Tenant identifiers, either a named confusable pair or a uniform draw.

    The named pairs are mixed with uniform draws over printable text because a uniform draw would
    essentially never produce a pair one of which is a prefix of the other, and the pool alone would
    never produce a codepoint nobody thought to name. The uniform alphabet excludes the delimiter,
    whitespace and non-printables, because `require_tenant_id` refuses those outright — they are
    drawn as :attr:`ConfinementCase.unusable` and asserted to be refused, rather than being drawn
    here where they would only ever raise.
    """
    usable = st.text(
        alphabet=st.characters(
            codec="utf-8",
            exclude_characters=f"{SEPARATOR}/\\",
            exclude_categories=("C", "Z"),
        ),
        min_size=1,
        max_size=DRAWN_TENANT_ID_LENGTH,
    )
    if drawn(st.booleans()):
        named: tuple[str, str] = drawn(st.sampled_from(CONFUSABLE_PAIRS))
        return named
    first = drawn(usable)
    second = drawn(usable)
    # Distinguished by extension rather than by a filter: two short uniform draws collide often
    # enough that filtering discards a third of the examples, and the extension lands the collision
    # in the prefix-pair case, which is the one worth reaching anyway.
    return (first, second if second != first else f"{second}-2")


@st.composite
def step(drawn: st.DrawFn) -> Step:
    """One request: a caller, an operation, and — where the route names a Session — a target."""
    operation: Operation | None = drawn(
        st.sampled_from((*NAMING_OPERATIONS, *WRITING_OPERATIONS, None))
    )
    return Step(
        caller=drawn(st.integers(min_value=0, max_value=1)),
        operation=operation,
        target=(
            drawn(st.sampled_from(TARGETS_NAMING_A_SESSION))
            if operation in NAMING_OPERATIONS
            else ""
        ),
    )


@st.composite
def confinement_case(drawn: st.DrawFn) -> ConfinementCase:
    """One profile, one Tenant pair, one Affinity_Key and one to four requests."""
    return ConfinementCase(
        profile=drawn(st.sampled_from(tuple(DeploymentProfile))),
        tenants=drawn(tenant_pair()),
        unusable=drawn(st.sampled_from(UNUSABLE_TENANT_IDS)),
        affinity_key=drawn(st.sampled_from(AFFINITY_KEYS)),
        steps=tuple(drawn(st.lists(step(), min_size=1, max_size=4))),
    )


# --- The fixture one case runs against ------------------------------------------------------------


@dataclass
class Fixture:
    """One store, one object store, one dispatcher, and the principals of one case."""

    case: ConfinementCase
    store: FakeStore
    starter: RecordingStarter
    api: ControlPlaneApi
    double: WiredOperations
    artifacts: ArtifactStore
    s3: RecordingS3
    #: A principal per drawn Tenant, addressing the partition that Tenant's seated items sit in.
    owners: tuple[AuthenticatedPrincipal, AuthenticatedPrincipal]
    #: A principal per caller, carrying the Tenant that caller's verified identity resolved to.
    callers: tuple[AuthenticatedPrincipal, AuthenticatedPrincipal]

    def owner_of(self, caller: int) -> AuthenticatedPrincipal:
        return self.owners[self.case.resolved_index(caller)]

    def foreign_owner_of(self, caller: int) -> AuthenticatedPrincipal:
        """The Tenant whose partition this caller does not address, whatever the profile."""
        return self.owners[1 - self.case.resolved_index(caller)]


def seat_session(
    fixture: Fixture, owner: AuthenticatedPrincipal, session_id: str
) -> None:
    """Seat a running Session from an earlier turn in one Tenant's partition.

    `RUNNING` with a Sandbox handle and a published credential, so that a `RefreshConnection` on it
    mints rather than reporting the Session unusable — the assertion that an own-partition read is
    answered is what keeps the not-found assertions from being vacuous.
    """
    fixture.store.place_session(
        SessionRecord(
            pk=pk_for(owner),
            session_id=session_id,
            tenant_id=owner.tenant_id,
            provider_name=LocalFirecrackerProvider.name,
            lifecycle_state=LifecycleState.RUNNING,
            created_at=NOW_MS,
            updated_at=NOW_MS,
            max_duration_seconds=3600,
            idle_seconds=300,
            suspended_seconds=600,
            auto_resume=True,
            memory_bytes=SETTINGS.memory_bytes,
            execution_role_arn=SETTINGS.execution_role_arn,
            reap_shard=3,
            reap_deadline=NOW_MS + 3_600_000,
            artifact_retention_days=SETTINGS.artifact_retention_days,
            generation=1,
            sandbox_handle=dict(SANDBOX_HANDLE),
            connection=PUBLISHED,
        )
    )


def build(case: ConfinementCase) -> Fixture:
    """Wire one case: the store, the dispatcher, the artifact store, and the seated prior state.

    Called inside :func:`deployment`, because the principals are resolved by the resolver that
    deployment holds rather than constructed from the drawn identifiers directly.
    """
    store = FakeStore()
    starter = RecordingStarter()
    base = operations(store, starter=starter, wait=PublishingWait(store))
    double = WiredOperations(
        resolution=base, connection=ConnectionOperations(issuer=base.issuer)
    )
    s3 = RecordingS3()

    callers: list[AuthenticatedPrincipal] = []
    for caller, tenant_id in enumerate(case.tenants):
        identity = VerifiedCallerIdentity(
            caller_identity=caller_arn(tenant_id), tenant_id=tenant_id
        )
        resolved = tenant_of(identity)
        # R11.17, R11.18: the resolution is the same call under both profiles, and what differs is
        # only which Tenant it returns. Checked against the restatement rather than the reverse.
        assert resolved == case.tenants[case.resolved_index(caller)]
        callers.append(
            AuthenticatedPrincipal(
                caller_identity=identity.caller_identity, tenant_id=resolved
            )
        )

    owners = (seat_principal(case.tenants[0]), seat_principal(case.tenants[1]))
    fixture = Fixture(
        case=case,
        store=store,
        starter=starter,
        api=ControlPlaneApi(operations=double, lookup=store),
        double=double,
        artifacts=ArtifactStore(client=s3, config=ARTIFACT_CONFIG),
        s3=s3,
        owners=owners,
        callers=(callers[0], callers[1]),
    )

    for index, owner in enumerate(owners):
        seat_session(fixture, owner, OWN_SESSIONS[index])
        # The same identifier in both partitions: identical sort key, different partition.
        seat_session(fixture, owner, SHARED_SESSION)
        s3.objects[f"{tenant_artifact_prefix(owner.tenant_id)}seated/{ARTIFACT_ID}"] = (
            FOREIGN_ARTIFACT_BODY
        )
    return fixture


def identifier_for(fixture: Fixture, step_taken: Step) -> str:
    """The Session identifier this step names."""
    if step_taken.target == OWN:
        return OWN_SESSIONS[fixture.case.resolved_index(step_taken.caller)]
    if step_taken.target == SHARED:
        return SHARED_SESSION
    if step_taken.target == THEIRS:
        return OWN_SESSIONS[1 - fixture.case.resolved_index(step_taken.caller)]
    return NEVER_EXISTED if step_taken.target == NEVER else MALFORMED


# --- What every request must satisfy --------------------------------------------------------------


def check_the_credentials_cannot_name_another_partition(
    principal: AuthenticatedPrincipal, foreign: AuthenticatedPrincipal
) -> None:
    """R11.3: the per-request policy pins one partition, by equality, and one S3 prefix.

    This is what makes another Tenant's partition unaddressable rather than merely not-found, so it
    is asserted per request: the policy is derived per request from the principal alone.

    The equality operator is the assertion that carries the confusable Tenant pairs. A condition
    that matched by prefix or by wildcard would grant the Tenant `acme` every key beginning `T#acme`
    — `T#acme-eu` among them — with the policy written exactly as designed.
    """
    document = session_policy_document(principal, TARGETS)
    table_statement, artifact_statement = document["Statement"]

    condition: Mapping[str, Any] = table_statement["Condition"]
    assert len(condition) == 1
    operator, pinned = next(iter(condition.items()))
    assert operator.endswith("StringEquals"), operator
    assert pinned == {LEADING_KEYS_CONDITION_KEY: [pk_for(principal)]}
    assert pk_for(foreign) not in pinned[LEADING_KEYS_CONDITION_KEY]

    granted = artifact_statement["Resource"]
    assert tenant_artifact_prefix(principal.tenant_id) in granted
    # The trailing separator is what defeats the prefix confusion: `tenants/acme/` is not a prefix
    # of `tenants/acme-eu/`, so a resource pattern built from one cannot reach the other's objects.
    assert tenant_artifact_prefix(foreign.tenant_id) not in granted

    # Expressible at all, which the drawn identifier lengths could otherwise silently break.
    assert session_policy_json(principal, TARGETS)


def check_addresses(
    fixture: Fixture,
    caller: int,
    *,
    expected: set[tuple[str, str]] | None = None,
) -> None:
    """Every key touched since the last clear is in the caller's own partition, and only there.

    `expected` pins the exact key set where the step's addresses are known — a routed read is one
    `GetItem` at the sort key derived from the identifier the caller named — because "the partition
    was right" is weaker than "this was the one item addressed".
    """
    own = pk_for(fixture.owner_of(caller))
    foreign = pk_for(fixture.foreign_owner_of(caller))
    touched = set(fixture.store.keys_touched)

    assert {partition for partition, _ in touched} <= {own}
    assert not any(partition == foreign for partition, _ in touched)
    if expected is not None:
        assert touched == expected

    prefix = tenant_artifact_prefix(fixture.owner_of(caller).tenant_id)
    assert all(key.startswith(prefix) for key in fixture.s3.keys)


@dataclass
class Snapshot:
    """Every item and object outside one caller's partition, as bytes, before a step runs."""

    items: dict[tuple[str, str], dict[str, Any]]
    objects: dict[str, bytes]

    @classmethod
    def outside(cls, fixture: Fixture, caller: int) -> Snapshot:
        own = pk_for(fixture.owner_of(caller))
        prefix = tenant_artifact_prefix(fixture.owner_of(caller).tenant_id)
        return cls(
            items={
                key: dict(item)
                for key, item in fixture.store.items.items()
                if key[0] != own
            },
            objects={
                key: value
                for key, value in fixture.s3.objects.items()
                if not key.startswith(prefix)
            },
        )

    def assert_unchanged(self, fixture: Fixture, caller: int) -> None:
        """R6.9's second half at the level of stored bytes, not of a response."""
        after = Snapshot.outside(fixture, caller)
        assert after.items == self.items
        assert after.objects == self.objects


def route_request(
    fixture: Fixture, caller: int, operation: Operation, identifier: str
) -> HttpResponse:
    """Issue one routed request naming an identifier, with the recorders cleared beforehand."""
    route = ROUTES_BY_OPERATION[operation]
    path = route.path_template.replace(f"{{{SESSION_ID_PARAMETER}}}", identifier)
    fixture.store.keys_touched.clear()
    fixture.s3.keys.clear()
    return fixture.api.handle(
        invocation(route.method, path, tenant_id=fixture.case.tenants[caller])
    )


def check_read_addresses(fixture: Fixture, caller: int, identifier: str) -> None:
    """One routed read: exactly one key, in the caller's partition, at the named sort key.

    An identifier that is not well formed is refused before the read is issued, so its address set
    is empty — and the response is the same fixed one, which is the point of answering it here
    rather than with a `400`.
    """
    if SEPARATOR in identifier:
        check_addresses(fixture, caller, expected=set())
        return
    own = pk_for(fixture.owner_of(caller))
    check_addresses(fixture, caller, expected={(own, session_sort_key(identifier))})


def check_naming_step(fixture: Fixture, step_taken: Step) -> None:
    """One request on a Session-naming route, and the not-found comparison R6.9 fixes."""
    caller = step_taken.caller
    operation = step_taken.operation
    assert operation is not None
    identifier = identifier_for(fixture, step_taken)
    own = pk_for(fixture.owner_of(caller))
    foreign_key = (
        pk_for(fixture.foreign_owner_of(caller)),
        session_sort_key(OWN_SESSIONS[1 - fixture.case.resolved_index(caller)]),
    )
    invoked_from = len(fixture.double.seen)

    response = route_request(fixture, caller, operation, identifier)
    check_read_addresses(fixture, caller, identifier)
    # Not merely reported absent: the other Tenant's item is never among the addresses, including
    # when the caller named the identifier that exists in both partitions.
    assert foreign_key not in set(fixture.store.keys_touched)

    if step_taken.target in {OWN, SHARED}:
        # The caller's own Session is answered, which is what keeps the comparisons below from
        # holding of a dispatcher that answered every request with the fixed not-found response.
        assert response is not NOT_FOUND_RESPONSE
        assert response.status != HTTPStatus.NOT_FOUND
        assert fixture.double.seen[-1].principal.tenant_id == (
            fixture.owner_of(caller).tenant_id
        )
        session = fixture.double.seen[-1].session
        assert session is not None
        assert session.session_id == identifier
        assert session.pk == own
        if operation is Operation.REFRESH_CONNECTION:
            assert response.status == HTTPStatus.OK
            assert json.loads(response.body)["sessionId"] == identifier
        return

    # R6.9. The three inputs that must be indistinguishable, on this route, at this point in the
    # sequence: another Tenant's Session, one that never existed, and one that is not well formed.
    others: list[HttpResponse] = []
    for other in (
        identifier_for(fixture, replace(step_taken, target=THEIRS)),
        NEVER_EXISTED,
        MALFORMED,
    ):
        others.append(route_request(fixture, caller, operation, other))
        check_read_addresses(fixture, caller, other)
        assert foreign_key not in set(fixture.store.keys_touched)

    rendered = {response.to_bytes(), *(other.to_bytes() for other in others)}
    assert rendered == {NOT_FOUND_RESPONSE.to_bytes()}
    # Returned by identity rather than rebuilt, so the two paths cannot differ in a header either.
    assert all(one is NOT_FOUND_RESPONSE for one in (response, *others))
    # No operation ran on any of them, so the identifier reached no code that could have echoed it:
    # the dispatcher resolves the Session before the operation, and none of these resolved.
    assert len(fixture.double.seen) == invoked_from


def check_writing_step(fixture: Fixture, step_taken: Step) -> None:
    """`CreateSession` or `ResolveSession`: the writes land in the caller's own partition."""
    caller = step_taken.caller
    operation = step_taken.operation
    assert operation is not None
    route = ROUTES_BY_OPERATION[operation]
    own = pk_for(fixture.owner_of(caller))
    body = (
        {AFFINITY_KEY_FIELD: fixture.case.affinity_key}
        if operation is Operation.RESOLVE_SESSION
        else {}
    )
    before = set(fixture.store.items)
    fixture.store.keys_touched.clear()
    fixture.s3.keys.clear()

    response = fixture.api.handle(
        invocation(
            route.method,
            route.path_template,
            tenant_id=fixture.case.tenants[caller],
            body=body,
        )
    )

    assert response.status in {
        HTTPStatus.OK,
        HTTPStatus.CREATED,
        HTTPStatus.ACCEPTED,
    }, response.to_bytes()
    check_addresses(fixture, caller)
    assert fixture.store.keys_touched
    # Every item this step added is in the caller's own partition, and nothing outside it moved.
    assert all(key[0] == own for key in set(fixture.store.items) - before)
    if operation is Operation.RESOLVE_SESSION:
        # The digest is the same in both partitions; the partition is what separates them (R11.11).
        assert (own, binding_sort_key(fixture.case.digest)) in fixture.store.items


def check_artifact_step(fixture: Fixture, step_taken: Step) -> None:
    """One artifact write and read: the object key is confined to the caller's Tenant prefix."""
    caller = step_taken.caller
    principal = fixture.callers[caller]
    fixture.store.keys_touched.clear()
    fixture.s3.keys.clear()

    entry = fixture.artifacts.put_artifact(
        principal,
        OWN_SESSIONS[fixture.case.resolved_index(caller)],
        ARTIFACT_GENERATION,
        ARTIFACT_ID,
        ARTIFACT_BODY,
    )
    read = fixture.artifacts.get_artifact(
        principal,
        OWN_SESSIONS[fixture.case.resolved_index(caller)],
        ARTIFACT_GENERATION,
        ARTIFACT_ID,
    )

    assert read == ARTIFACT_BODY
    # The index entry describing the object and the object key are addressed with the same Tenant:
    # the entry's partition key comes from `pk_for` and the object key from the artifact layout.
    assert entry.pk == pk_for(fixture.owner_of(caller))
    assert entry.s3_key.startswith(
        tenant_artifact_prefix(fixture.owner_of(caller).tenant_id)
    )
    check_addresses(fixture, caller, expected=set())
    assert fixture.s3.keys


def one_step(fixture: Fixture, step_taken: Step) -> None:
    """Run one request and assert the whole property of it, whatever kind of request it is."""
    outside = Snapshot.outside(fixture, step_taken.caller)
    check_the_credentials_cannot_name_another_partition(
        fixture.callers[step_taken.caller],
        fixture.foreign_owner_of(step_taken.caller),
    )

    if step_taken.operation is None:
        check_artifact_step(fixture, step_taken)
    elif step_taken.operation in NAMING_OPERATIONS:
        check_naming_step(fixture, step_taken)
    else:
        check_writing_step(fixture, step_taken)

    outside.assert_unchanged(fixture, step_taken.caller)


# --- What the whole sequence must satisfy ---------------------------------------------------------


def check_unusable_identifiers_never_become_a_key(case: ConfinementCase) -> None:
    """A Tenant identifier that could forge a different key shape never reaches a key at all.

    The delimiter case is the load-bearing one: `require_tenant_id` refuses it, so the confusable
    encoding is unreachable rather than handled downstream. The `/` case is the asymmetry between
    the two stores, and it is asserted in both directions because getting it wrong in either one is
    a cross-tenant read written exactly as designed.
    """
    try:
        AuthenticatedPrincipal(
            caller_identity=caller_arn("caller"), tenant_id=case.unusable
        )
    except TenantIdentifierError:
        pass
    else:  # pragma: no cover - a refusal that stopped happening is the failure
        raise AssertionError(
            f"{case.unusable!r} became a Tenant identifier, so it can reach a partition key"
        )

    overlapping = seat_principal(PREFIX_OVERLAPPING_TENANT_ID)
    # A safe partition key: `LeadingKeys` compares by equality, so this collides with nothing.
    assert pk_for(overlapping) != pk_for(seat_principal("acme"))
    # An unsafe S3 prefix, and refused rather than granted: `tenants/acme/eu/` would sit inside the
    # `tenants/acme/*` a different Tenant is granted.
    try:
        tenant_artifact_prefix(overlapping.tenant_id)
    except ArtifactLayoutError:
        pass
    else:  # pragma: no cover - the same refusal, on the store that confines by prefix
        raise AssertionError(
            f"{PREFIX_OVERLAPPING_TENANT_ID!r} produced an artifact prefix that overlaps another"
        )


def check_partitions(fixture: Fixture) -> None:
    """Nothing in the store sits at a partition key that `pk_for` did not produce.

    The runtime half of the sole-producer claim, which the lint rule cannot make: every partition
    key present belongs to one of the two Tenants that own items, and every Session row's own
    `tenantId` attribute agrees with the partition it sits in — so a row cannot have been written to
    a partition derived from anything other than its Tenant.
    """
    owned = {pk_for(owner) for owner in fixture.owners}
    assert {key[0] for key in fixture.store.items} <= owned

    for key, item in fixture.store.items.items():
        assert item[PARTITION_KEY_ATTRIBUTE] == key[0]
        if not key[1].startswith(f"S{SEPARATOR}"):
            continue
        record = SessionRecord.from_item(item)
        assert record.pk == pk_for(seat_principal(record.tenant_id))

    # R11.11: one Affinity_Key digest, at most one binding per partition, and the Session each
    # binding names has no row in the other partition — the address-level form of "and to no
    # Session of another Tenant".
    sort_key = binding_sort_key(fixture.case.digest)
    bound = {
        pk_for(owner): fixture.store.items[(pk_for(owner), sort_key)]["sessionId"]
        for owner in fixture.owners
        if (pk_for(owner), sort_key) in fixture.store.items
    }
    partitions = list(bound)
    if len(partitions) == 2:
        first, second = partitions
        assert bound[first] != bound[second]
        assert (second, session_sort_key(str(bound[first]))) not in fixture.store.items
        assert (first, session_sort_key(str(bound[second]))) not in fixture.store.items


def check_case(case: ConfinementCase) -> frozenset[str]:
    """Run one whole case under its profile and return the buckets it occupied."""
    check_unusable_identifiers_never_become_a_key(case)
    with deployment(case.profile, case.tenants[0]):
        fixture = build(case)
        if case.profile is DeploymentProfile.SINGLE_TENANT:
            # R11.17: the partition addressed is the deployment constant whatever the caller, even
            # though the two verified identities differ and each carried a Tenant attribute.
            assert pk_for(fixture.callers[0]) == pk_for(fixture.callers[1])
        else:
            assert pk_for(fixture.callers[0]) != pk_for(fixture.callers[1])
        for step_taken in case.steps:
            one_step(fixture, step_taken)
        check_partitions(fixture)
    return case.buckets()


# Feature: aws-serverless-agent-sandbox, Property 13: For all pairs of distinct Tenants and for all
# sets of Sessions belonging to them, every State_Store request issued while handling a request from
# one Tenant carries a partition key derived solely from that Tenant's authenticated identity; and a
# request naming a Session belonging to the other Tenant produces a response byte-identical to the
# response for a well-formed Session identifier that has never existed.
@given(case=confinement_case())
@settings(max_examples=200)
def test_every_state_store_address_is_the_calling_tenants_own(
    case: ConfinementCase,
) -> None:
    """**Validates: Requirements 6.9, 11.2, 11.3**"""
    for bucket in check_case(case):
        event(bucket)


# --- Non-vacuity, both deterministic --------------------------------------------------------------


#: The case every enumerated one below varies from: two Tenants one of which is a prefix of the
#: other, `multi-tenant`, and one request that reads the caller's own Session.
BASE_CASE: Final = ConfinementCase(
    profile=DeploymentProfile.MULTI_TENANT,
    tenants=("acme", "acme-eu"),
    unusable=f"acme{SEPARATOR}eu",
    affinity_key="thread-9f3",
    steps=(Step(caller=0, operation=Operation.GET_SESSION, target=OWN),),
)

#: One case per bucket, stated rather than drawn, so every arm of the checker runs on every run.
ENUMERATED_CASES: Final = (
    BASE_CASE,
    replace(BASE_CASE, profile=DeploymentProfile.SINGLE_TENANT),
    *(replace(BASE_CASE, unusable=value) for value in UNUSABLE_TENANT_IDS),
    *(replace(BASE_CASE, tenants=pair) for pair in CONFUSABLE_PAIRS),
    *(replace(BASE_CASE, affinity_key=key) for key in AFFINITY_KEYS),
    # Every Session-naming route crossed with every identifier a caller may name.
    *(
        replace(BASE_CASE, steps=(Step(caller=0, operation=operation, target=target),))
        for operation in NAMING_OPERATIONS
        for target in TARGETS_NAMING_A_SESSION
    ),
    # The same, under `single-tenant`, where both callers resolve to one Tenant.
    *(
        replace(
            BASE_CASE,
            profile=DeploymentProfile.SINGLE_TENANT,
            steps=(Step(caller=1, operation=operation, target=target),),
        )
        for operation in NAMING_OPERATIONS
        for target in TARGETS_NAMING_A_SESSION
    ),
    # The two writing routes and the artifact write, from each caller.
    *(
        replace(BASE_CASE, steps=(Step(caller=caller, operation=operation, target=""),))
        for caller in (0, 1)
        for operation in (*WRITING_OPERATIONS, None)
    ),
    # A sequence long enough that a later request resolves what an earlier one created, with both
    # callers presenting the byte-identical Affinity_Key.
    replace(
        BASE_CASE,
        steps=(
            Step(caller=0, operation=Operation.RESOLVE_SESSION, target=""),
            Step(caller=1, operation=Operation.RESOLVE_SESSION, target=""),
            Step(caller=0, operation=Operation.RESOLVE_SESSION, target=""),
            Step(caller=1, operation=Operation.GET_SESSION, target=THEIRS),
        ),
    ),
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain this property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    for case in ENUMERATED_CASES:
        covered |= check_case(case)

    for target in TARGETS_NAMING_A_SESSION:
        assert f"target: {target}" in covered
    for operation in (*NAMING_OPERATIONS, *WRITING_OPERATIONS):
        assert f"operation: {operation.value}" in covered
    assert f"operation: {ARTIFACT_STEP}" in covered
    for profile in DeploymentProfile:
        assert f"profile: {profile.value}" in covered
    assert "tenants: one identifier is a prefix of the other" in covered
    assert "tenants: not ASCII" in covered
    assert "tenants: the pair differs only in case" in covered
    assert "key: carries the sort-key delimiter" in covered
    assert "key: not ASCII" in covered
    assert "callers: both verified identities issued a request" in covered
    assert "sequence: more than one request" in covered


@dataclass
class LeakyLookup:
    """A lookup that falls back to the other partition when the caller's own read misses.

    The mistake this property exists to catch, and the one a not-found comparison alone would miss:
    it returns another Tenant's row, so the response is *not* a `404` and the address it read is not
    the caller's.
    """

    store: FakeStore
    elsewhere: str

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        found = self.store.read_session(partition_key=partition_key, sort_key=sort_key)
        if found is not None:
            return found
        return self.store.read_session(partition_key=self.elsewhere, sort_key=sort_key)


def test_the_assertions_discriminate_two_plausible_leaks() -> None:
    """Each wrong implementation is rejected by the assertion that exists to reject it.

    Without this, "every address was the caller's own" could hold of a checker that recorded no
    addresses, and "the two responses were identical" could hold of one comparing nothing.
    """
    case = replace(
        BASE_CASE,
        steps=(Step(caller=0, operation=Operation.GET_SESSION, target=THEIRS),),
    )
    with deployment(case.profile, case.tenants[0]):
        fixture = build(case)

        # 1. A lookup that falls back to the other Tenant's partition. The address assertion and the
        #    not-found comparison both reject it.
        leaked = replace(
            fixture,
            api=ControlPlaneApi(
                operations=fixture.double,
                lookup=LeakyLookup(
                    store=fixture.store, elsewhere=pk_for(fixture.owners[1])
                ),
            ),
        )
        try:
            one_step(leaked, case.steps[0])
        except AssertionError:
            pass
        else:  # pragma: no cover - the leak this property exists to catch
            raise AssertionError("a cross-partition fallback was not rejected")

        # 2. The honest implementation, on the same case, passes.
        one_step(fixture, case.steps[0])

    # 3. A not-found response that names the identifier it refused is not byte-identical to the
    #    fixed one, which is the comparison R6.9 rests on.
    echoed = HttpResponse(
        status=HTTPStatus.NOT_FOUND,
        body=b'{"error":"NotFound","message":"No such Session: '
        + OWN_SESSIONS[1].encode()
        + b'."}',
    )
    assert echoed.to_bytes() != NOT_FOUND_RESPONSE.to_bytes()
    assert echoed.status == NOT_FOUND_RESPONSE.status
