# kiro-classification: public
"""The artifact object layout and the client that writes through it (R13.5, R13.6).

The layout is Tenant first: `tenants/<tenantId>/sessions/<sessionId>/<generation>/<artifactId>`.
That ordering is the same choice the State_Store key structure makes, and for the same reason: the
per-request inline session policy confines S3 access with `arn:aws:s3:::BUCKET/tenants/TENANT_ID/*`
and the per-Session Sandbox execution role narrows it to `tenants/<tenantId>/sessions/<sessionId>/*`.
A resource pattern of that shape can only exist if the Tenant identifier is the first variable
element of the key and nothing precedes it.

The Tenant identifier reaches this module the way it reaches the partition key: from the
authenticated principal, and from nowhere else. :class:`ArtifactStore` therefore takes the principal
rather than a Tenant identifier, so an object key and the artifact index entry describing it cannot
name different Tenants — both derive from one object.

Two things this module owns and one it does not:

* **Encryption on write (R13.5).** Every write carries SSE-KMS with the configured customer managed
  key. The key identifier has no default and an empty value is refused, so there is no code path
  that writes an artifact under SSE-S3 or unencrypted.
* **The retention period mirrored onto the record (R13.6).** Deletion is a bucket lifecycle
  expiration rule, applied by S3 rather than by a sweeper this project would have to keep running.
  The number of days that rule uses is mirrored onto the Session record's `artifactRetentionDays`,
  and :meth:`ArtifactStore.verify_record_retention` is what keeps the mirror honest.
* **The bucket, the key, the lifecycle rule and the non-TLS deny policy** are provisioned by
  `StateStack`, not here. This module holds the layout and the client, and it is given an already
  constructed S3 client so that the per-request credentials from `SessionDataAccessRole` are the
  only credentials it can possibly use.

This module is imported directly rather than through :mod:`control_plane.state`. That package
describes the shape of the store and re-exports nothing that talks to it, and this module depends
on :mod:`control_plane.tenancy`, which already depends on the package's key module. Re-exporting it
from the package would make the two import each other during initialisation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from control_plane.state.records import ArtifactIndexEntry, SessionRecord
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = [
    "GENERATION_SEGMENT_MINIMUM",
    "KEY_SEPARATOR",
    "SERVER_SIDE_ENCRYPTION",
    "SESSIONS_SEGMENT",
    "TENANTS_SEGMENT",
    "ArtifactLayoutError",
    "ArtifactStore",
    "ArtifactStoreConfig",
    "ArtifactStoreError",
    "RetentionMirrorError",
    "S3Client",
    "artifact_object_key",
    "generation_artifact_prefix",
    "session_artifact_prefix",
    "tenant_artifact_prefix",
]

#: S3 key path separator. Also the character a key component may not contain, because a component
#: carrying it would silently become two.
KEY_SEPARATOR: Final = "/"

#: The two literal segments of the layout, spelled here and nowhere else. Named rather than inlined
#: so the prefix builders and the IaC resource patterns cannot drift apart by a rename, and read
#: through the prefix functions below rather than re-joined by each consumer:
#: :mod:`control_plane.state.access` builds the session policy's S3 resource from
#: :func:`tenant_artifact_prefix`, so the pattern it grants and the keys written here are one
#: string with one producer.
TENANTS_SEGMENT: Final = "tenants"
SESSIONS_SEGMENT: Final = "sessions"

#: The S3 `ServerSideEncryption` value for a customer managed KMS key (R13.5).
SERVER_SIDE_ENCRYPTION: Final = "aws:kms"

#: A Session's generation starts at 1 and increments on each continuation, so 0 is not a generation
#: that ever existed.
GENERATION_SEGMENT_MINIMUM: Final = 1

#: Path segments that would move a key out of the prefix it was built for.
_TRAVERSAL_SEGMENTS: Final = frozenset({".", ".."})

#: Characters refused inside a single key component. `/` would add a path level, `#` is the
#: State_Store key separator and would let the artifact index entry's sort key be forged, and `\`
#: is refused because a backslash is an ordinary character to S3 but reads as a separator to a
#: person reviewing a prefix.
_FORBIDDEN_CHARACTERS: Final = frozenset({KEY_SEPARATOR, "#", "\\"})


class ArtifactStoreError(ValueError):
    """A defect in the artifact store's inputs or configuration."""


class ArtifactLayoutError(ArtifactStoreError):
    """A component cannot safely become part of an artifact object key."""


class RetentionMirrorError(ArtifactStoreError):
    """A Session record's retention period disagrees with the bucket lifecycle rule (R13.6)."""


def _require_component(name: str, value: str) -> str:
    """Reject a component that would change the shape or the reach of a key.

    The `/` rejection is the load-bearing one, and it is about more than tidiness. Prefix
    confinement relies on no Tenant's prefix being a prefix of another's. A Tenant identifier of
    `acme/eu` would produce `tenants/acme/eu/...`, which sits inside the `tenants/acme/*` resource
    granted to the Tenant `acme` — one Tenant reading another's artifacts with both policies
    written exactly as designed. The same argument applies to a Session identifier inside the
    Sandbox execution role's `sessions/<sessionId>/*`.
    """
    if not value:
        raise ArtifactLayoutError(f"{name} must not be empty")
    for character in _FORBIDDEN_CHARACTERS:
        if character in value:
            raise ArtifactLayoutError(
                f"{name} must not contain {character!r}: {value!r}"
            )
    if any(not character.isprintable() for character in value):
        raise ArtifactLayoutError(f"{name} must be printable: {value!r}")
    if value in _TRAVERSAL_SEGMENTS:
        raise ArtifactLayoutError(f"{name} must not be a traversal segment: {value!r}")
    return value


def _require_artifact_id(artifact_id: str) -> str:
    """Reject an artifact identifier that is not a safe relative path.

    An artifact identifier is the path of the artifact within the Session's artifact tree, so it
    may carry `/`. It is the same string that becomes the tail of the index entry's sort key
    (`S#<sessionId>#A#<artifactId>`), which is why one identifier serves both: the record and the
    object it points at cannot disagree about which artifact they describe.

    Every segment is validated individually, so `..` cannot walk out of the Session prefix and an
    empty segment cannot collapse a path level.
    """
    if not artifact_id:
        raise ArtifactLayoutError("artifact_id must not be empty")
    if artifact_id.startswith(KEY_SEPARATOR) or artifact_id.endswith(KEY_SEPARATOR):
        raise ArtifactLayoutError(
            f"artifact_id must be a relative path: {artifact_id!r}"
        )
    for segment in artifact_id.split(KEY_SEPARATOR):
        _require_component("artifact_id segment", segment)
    return artifact_id


def _require_generation(generation: int) -> int:
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise ArtifactLayoutError(f"generation must be an integer: {generation!r}")
    if generation < GENERATION_SEGMENT_MINIMUM:
        raise ArtifactLayoutError(
            f"generation must be at least {GENERATION_SEGMENT_MINIMUM}: {generation}"
        )
    return generation


def tenant_artifact_prefix(tenant_id: str) -> str:
    """`tenants/<tenantId>/` — everything one Tenant may reach.

    The sole producer of that string. :mod:`control_plane.state.access` calls this to build the
    per-request inline session policy's `s3:GetObject` and `s3:PutObject` resource pattern, and
    :meth:`ArtifactStore.put_artifact` builds every object key on top of it. Tenant confinement in
    S3 *is* those two agreeing, so they are the same function call rather than two spellings that
    happen to match today.

    The validation below therefore guards the policy as well as the key: a Tenant identifier that
    would overlap another Tenant's prefix is refused before a policy granting it can be built.
    """
    return f"{TENANTS_SEGMENT}{KEY_SEPARATOR}{_require_component('tenant_id', tenant_id)}{KEY_SEPARATOR}"


def session_artifact_prefix(tenant_id: str, session_id: str) -> str:
    """`tenants/<tenantId>/sessions/<sessionId>/` — one Session's artifacts.

    The per-Session Sandbox execution role is confined to this prefix, so a Sandbox cannot read
    another Session's artifacts even within its own Tenant (R11.6).
    """
    return (
        f"{tenant_artifact_prefix(tenant_id)}{SESSIONS_SEGMENT}{KEY_SEPARATOR}"
        f"{_require_component('session_id', session_id)}{KEY_SEPARATOR}"
    )


def generation_artifact_prefix(tenant_id: str, session_id: str, generation: int) -> str:
    """`tenants/<tenantId>/sessions/<sessionId>/<generation>/` — one generation's artifacts.

    The generation level is what keeps a duration-ceiling handoff from overwriting the artifacts of
    the generation it replaced: the replacement Sandbox writes under a prefix the previous one
    never had.
    """
    return (
        f"{session_artifact_prefix(tenant_id, session_id)}"
        f"{_require_generation(generation)}{KEY_SEPARATOR}"
    )


def artifact_object_key(
    tenant_id: str, session_id: str, generation: int, artifact_id: str
) -> str:
    """The full object key of one artifact."""
    return (
        f"{generation_artifact_prefix(tenant_id, session_id, generation)}"
        f"{_require_artifact_id(artifact_id)}"
    )


class S3Client(Protocol):
    """The two S3 operations the artifact store uses.

    A structural type rather than a boto3 client, for two reasons. The credentials an artifact
    write runs under are the per-request ones derived from `SessionDataAccessRole`, so the client
    is constructed by the caller that holds them and handed in; and the offline suite, which has no
    deployed bucket and no network, can satisfy this interface directly.
    """

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ArtifactStoreConfig:
    """The deployed bucket, its customer managed key and its retention period.

    `kms_key_id` has no default. R13.5 is discharged by there being no way to construct this object
    without naming a key, rather than by a check at each write.
    """

    bucket: str
    kms_key_id: str
    retention_days: int

    def __post_init__(self) -> None:
        _require_component("bucket", self.bucket)
        if not self.kms_key_id:
            raise ArtifactStoreError(
                "kms_key_id must name the customer managed key artifacts are encrypted with (R13.5)"
            )
        if isinstance(self.retention_days, bool) or not isinstance(
            self.retention_days, int
        ):
            raise ArtifactStoreError(
                f"retention_days must be an integer: {self.retention_days!r}"
            )
        if self.retention_days < 1:
            # R13.6 asks for a retention period that artifacts can exceed. Zero days is not a
            # shorter retention period, it is a bucket that deletes what was just written.
            raise ArtifactStoreError(
                f"retention_days must be at least one day: {self.retention_days}"
            )


@dataclass(frozen=True, slots=True)
class ArtifactStore:
    """Reads and writes Session artifacts under the Tenant-first layout.

    Every method takes the authenticated principal, so the Tenant portion of every key it touches
    comes from the same object the partition key comes from.
    """

    client: S3Client
    config: ArtifactStoreConfig

    @property
    def retention_days(self) -> int:
        """The lifecycle expiration period, in days, to mirror onto a new Session record."""
        return self.config.retention_days

    def object_key(
        self,
        principal: AuthenticatedPrincipal,
        session_id: str,
        generation: int,
        artifact_id: str,
    ) -> str:
        """The object key one artifact of this principal's Session occupies."""
        return artifact_object_key(
            principal.tenant_id, session_id, generation, artifact_id
        )

    def put_artifact(
        self,
        principal: AuthenticatedPrincipal,
        session_id: str,
        generation: int,
        artifact_id: str,
        body: bytes,
        *,
        truncated: bool = False,
    ) -> ArtifactIndexEntry:
        """Write one artifact encrypted with the customer managed key, and describe it (R13.5).

        Returns the index entry for the object rather than writing it: the State_Store write and
        the S3 write are separate operations under separate failure modes, and the caller in the
        `/terminate` hook path decides how to order them.

        `truncated` is carried through from the caller, which sets it when the artifact write hit
        its bounded deadline. The marker belongs on the record beside the size, so a partial
        artifact is distinguishable from a complete small one.
        """
        key = self.object_key(principal, session_id, generation, artifact_id)
        self.client.put_object(
            Bucket=self.config.bucket,
            Key=key,
            Body=body,
            ServerSideEncryption=SERVER_SIDE_ENCRYPTION,
            SSEKMSKeyId=self.config.kms_key_id,
        )
        return ArtifactIndexEntry(
            pk=pk_for(principal),
            session_id=session_id,
            artifact_id=artifact_id,
            s3_key=key,
            size_bytes=len(body),
            truncated=truncated,
        )

    def get_artifact(
        self,
        principal: AuthenticatedPrincipal,
        session_id: str,
        generation: int,
        artifact_id: str,
    ) -> bytes:
        """Read one artifact back.

        No decryption parameter is passed: SSE-KMS decrypts on read for a caller whose credentials
        allow the key, and a caller whose credentials do not gets `AccessDenied` from S3 rather
        than a partial success this code would have to interpret.
        """
        key = self.object_key(principal, session_id, generation, artifact_id)
        response = self.client.get_object(Bucket=self.config.bucket, Key=key)
        body = response.get("Body")
        if body is None:
            raise ArtifactStoreError(f"no body returned for {key}")
        read = body.read()
        if not isinstance(read, bytes):
            raise ArtifactStoreError(f"body for {key} is not bytes")
        return read

    def verify_record_retention(self, record: SessionRecord) -> None:
        """Check that a Session record mirrors the bucket's retention period (R13.6).

        The lifecycle rule is what actually deletes an artifact, so the number on the record is a
        mirror and never the source of truth. A mirror that has silently stopped matching is worse
        than no mirror at all: an operator reading the Session row would be told a retention period
        the bucket is not applying.
        """
        if record.artifact_retention_days != self.config.retention_days:
            raise RetentionMirrorError(
                f"session {record.session_id} records artifactRetentionDays="
                f"{record.artifact_retention_days} but the bucket lifecycle rule expires "
                f"artifacts after {self.config.retention_days} days"
            )
