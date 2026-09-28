# kiro-classification: public
"""The artifact object layout, encryption on write and the retention mirror (R13.5, R13.6).

No AWS call and no network: the store is handed a stub satisfying its two-operation interface,
which is the same reason the interface is two operations wide.
"""

from __future__ import annotations

import io
from typing import Any

import pytest

from control_plane.state.access import (
    S3_ACTIONS,
    DataAccessTargets,
    session_policy_document,
)
from control_plane.state.artifacts import (
    SERVER_SIDE_ENCRYPTION,
    ArtifactLayoutError,
    ArtifactStore,
    ArtifactStoreConfig,
    ArtifactStoreError,
    RetentionMirrorError,
    artifact_object_key,
    generation_artifact_prefix,
    session_artifact_prefix,
    tenant_artifact_prefix,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for
from tests.test_state_records import a_session

TENANT_ID = "tenant-a"
SESSION_ID = "01JD7Q2M9K4X8V3B0T5C6Y7E1F"
BUCKET = "state-store-artifacts"
KEY_ID = "arn:aws:kms:eu-west-1:111122223333:key/8e6a1c2f-0f3a-4a2d-9f1b-0d5c7e9a1b2c"
RETENTION_DAYS = 30

PRINCIPAL = AuthenticatedPrincipal(
    caller_identity="arn:aws:sts::123456789012:assumed-role/Caller/session",
    tenant_id=TENANT_ID,
)


class RecordingS3:
    """An in-memory stand-in for the two S3 operations the store uses.

    It records the full parameter set of every write, because what R13.5 asks to be checked is the
    parameters the store sends rather than a value it stores.
    """

    def __init__(self) -> None:
        self.writes: list[dict[str, Any]] = []
        self.objects: dict[tuple[str, str], bytes] = {}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.writes.append(dict(kwargs))
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]
        return {"ETag": '"stub"'}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        body = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        return {"Body": io.BytesIO(body)}


def a_store(client: RecordingS3 | None = None, **overrides: Any) -> ArtifactStore:
    fields: dict[str, Any] = {
        "bucket": BUCKET,
        "kms_key_id": KEY_ID,
        "retention_days": RETENTION_DAYS,
    }
    fields.update(overrides)
    return ArtifactStore(
        client=client if client is not None else RecordingS3(),
        config=ArtifactStoreConfig(**fields),
    )


def test_the_layout_is_tenant_first() -> None:
    # The prefix the per-request inline session policy pins, and the two prefixes nested inside it.
    assert tenant_artifact_prefix(TENANT_ID) == "tenants/tenant-a/"
    assert session_artifact_prefix(TENANT_ID, SESSION_ID) == (
        f"tenants/tenant-a/sessions/{SESSION_ID}/"
    )
    assert generation_artifact_prefix(TENANT_ID, SESSION_ID, 2) == (
        f"tenants/tenant-a/sessions/{SESSION_ID}/2/"
    )
    assert artifact_object_key(TENANT_ID, SESSION_ID, 2, "stdout.log") == (
        f"tenants/tenant-a/sessions/{SESSION_ID}/2/stdout.log"
    )


def test_each_prefix_contains_the_next() -> None:
    # Nesting is what makes the Sandbox execution role a narrowing of the handler's grant rather
    # than a second, independently correct pattern.
    key = artifact_object_key(TENANT_ID, SESSION_ID, 1, "out/result.json")
    session_prefix = session_artifact_prefix(TENANT_ID, SESSION_ID)
    assert session_prefix.startswith(tenant_artifact_prefix(TENANT_ID))
    assert key.startswith(generation_artifact_prefix(TENANT_ID, SESSION_ID, 1))
    assert key.startswith(session_prefix)


def test_one_generation_cannot_overwrite_another() -> None:
    first = artifact_object_key(TENANT_ID, SESSION_ID, 1, "state.tar")
    second = artifact_object_key(TENANT_ID, SESSION_ID, 2, "state.tar")
    assert first != second


def test_an_artifact_identifier_may_be_a_relative_path() -> None:
    # The design writes a continuation handoff under `<generation>/gpu-in/`, so a tree is expected.
    assert artifact_object_key(TENANT_ID, SESSION_ID, 1, "gpu-in/input.bin").endswith(
        "/1/gpu-in/input.bin"
    )


@pytest.mark.parametrize(
    "artifact_id",
    [
        "",
        "..",
        ".",
        "../../etc/passwd",
        "out/../../../other-session/state.tar",
        "out/./state.tar",
        "/absolute",
        "trailing/",
        "double//segment",
        "with#hash",
        "back\\slash",
        "control\x00byte",
    ],
)
def test_an_artifact_identifier_cannot_leave_its_prefix(artifact_id: str) -> None:
    with pytest.raises(ArtifactLayoutError):
        artifact_object_key(TENANT_ID, SESSION_ID, 1, artifact_id)


@pytest.mark.parametrize("tenant_id", ["", "acme/eu", "acme#eu", "acme\\eu", "."])
def test_a_tenant_identifier_cannot_widen_or_overlap_a_prefix(tenant_id: str) -> None:
    # `acme/eu` is the one that matters: it would sit inside the `tenants/acme/*` resource granted
    # to the Tenant `acme`, which is one Tenant reading another's artifacts with both policies
    # written exactly as designed.
    with pytest.raises(ArtifactLayoutError):
        tenant_artifact_prefix(tenant_id)


@pytest.mark.parametrize("session_id", ["", "a/b", "a#b", ".."])
def test_a_session_identifier_cannot_widen_or_overlap_a_prefix(session_id: str) -> None:
    with pytest.raises(ArtifactLayoutError):
        session_artifact_prefix(TENANT_ID, session_id)


@pytest.mark.parametrize("generation", [0, -1, True])
def test_a_generation_below_one_is_refused(generation: int) -> None:
    # A Session's generation starts at 1, so 0 names a generation that never existed.
    with pytest.raises(ArtifactLayoutError):
        generation_artifact_prefix(TENANT_ID, SESSION_ID, generation)


def test_a_write_carries_the_customer_managed_key() -> None:
    client = RecordingS3()
    store = a_store(client)

    store.put_artifact(PRINCIPAL, SESSION_ID, 1, "stdout.log", b"hello")

    (write,) = client.writes
    assert write["ServerSideEncryption"] == SERVER_SIDE_ENCRYPTION == "aws:kms"
    assert write["SSEKMSKeyId"] == KEY_ID
    assert write["Bucket"] == BUCKET
    assert write["Key"] == artifact_object_key(TENANT_ID, SESSION_ID, 1, "stdout.log")


def test_a_store_cannot_be_configured_without_a_customer_managed_key() -> None:
    # R13.5 holds because there is no unencrypted write path to reach, not because a write checks.
    with pytest.raises(ArtifactStoreError):
        a_store(kms_key_id="")


@pytest.mark.parametrize("retention_days", [0, -1, True, 1.5])
def test_a_store_cannot_be_configured_without_a_retention_period(
    retention_days: Any,
) -> None:
    with pytest.raises(ArtifactStoreError):
        a_store(retention_days=retention_days)


def test_the_index_entry_describes_the_object_that_was_written() -> None:
    store = a_store()

    entry = store.put_artifact(PRINCIPAL, SESSION_ID, 3, "out/result.json", b"12345")

    # The partition key comes from the sole producer, and the object key from the same principal,
    # so the record and the object cannot name different Tenants.
    assert entry.pk == pk_for(PRINCIPAL)
    assert entry.s3_key == artifact_object_key(
        TENANT_ID, SESSION_ID, 3, "out/result.json"
    )
    assert entry.session_id == SESSION_ID
    assert entry.artifact_id == "out/result.json"
    assert entry.size_bytes == 5
    assert entry.truncated is False
    # One identifier serves the sort key and the object key.
    assert entry.sort_key.endswith("#A#out/result.json")
    assert entry.s3_key.endswith("/out/result.json")


def test_a_truncated_write_is_recorded_as_truncated() -> None:
    entry = a_store().put_artifact(
        PRINCIPAL, SESSION_ID, 1, "stdout.log", b"part", truncated=True
    )
    assert entry.truncated is True
    assert entry.size_bytes == 4


def test_an_artifact_reads_back_byte_for_byte() -> None:
    client = RecordingS3()
    store = a_store(client)
    body = b"\x00\xff not utf-8 \x80"

    store.put_artifact(PRINCIPAL, SESSION_ID, 1, "state.tar", body)

    assert store.get_artifact(PRINCIPAL, SESSION_ID, 1, "state.tar") == body


def test_a_read_and_a_write_address_the_same_key() -> None:
    client = RecordingS3()
    store = a_store(client)
    store.put_artifact(PRINCIPAL, SESSION_ID, 1, "state.tar", b"x")

    with pytest.raises(KeyError):
        # A different generation is a different object, so the stub has nothing under that key.
        store.get_artifact(PRINCIPAL, SESSION_ID, 2, "state.tar")


def test_another_tenants_key_is_never_constructed_from_this_principal() -> None:
    store = a_store()
    entry = store.put_artifact(PRINCIPAL, SESSION_ID, 1, "stdout.log", b"x")
    assert entry.s3_key.startswith(tenant_artifact_prefix(TENANT_ID))
    assert "tenant-b" not in entry.s3_key


def _granted_artifact_prefix(principal: AuthenticatedPrincipal) -> str:
    """The S3 key prefix the per-request session policy actually grants, read back out of it.

    Read out of the built policy rather than out of the function that built it, so this reflects
    what STS would receive.
    """
    targets = DataAccessTargets(
        role_arn="arn:aws:iam::123456789012:role/SessionDataAccessRole",
        table_arn="arn:aws:dynamodb:eu-west-1:123456789012:table/sessions",
        artifact_bucket=BUCKET,
    )
    (statement,) = [
        statement
        for statement in session_policy_document(principal, targets)["Statement"]
        if set(statement["Action"]) == set(S3_ACTIONS)
    ]
    resource = statement["Resource"]
    arn_prefix = f"arn:aws:s3:::{BUCKET}/"
    assert resource.startswith(arn_prefix), resource
    assert resource.endswith("*"), resource
    return resource[len(arn_prefix) : -1]


def test_the_granted_prefix_and_a_written_object_key_agree() -> None:
    # S3 tenant confinement is exactly this agreement, and it used to rest on two independent
    # spellings of `tenants/<tenantId>/` — one in the policy builder, one in the key builder — that
    # could have drifted apart while both modules' own tests stayed green. They now share one
    # producer; this asserts the end-to-end result, so a reintroduced second spelling fails here.
    client = RecordingS3()
    store = a_store(client)

    store.put_artifact(PRINCIPAL, SESSION_ID, 1, "out/result.json", b"x")

    (write,) = client.writes
    assert write["Key"].startswith(_granted_artifact_prefix(PRINCIPAL))


def test_the_granted_prefix_does_not_reach_another_tenants_object_key() -> None:
    # The other half of confinement: the pattern must not match, not merely match its own Tenant.
    other = AuthenticatedPrincipal(
        caller_identity=PRINCIPAL.caller_identity, tenant_id="tenant-b"
    )
    granted = _granted_artifact_prefix(PRINCIPAL)

    other_key = artifact_object_key(other.tenant_id, SESSION_ID, 1, "out/result.json")

    assert not other_key.startswith(granted)
    assert other_key.startswith(_granted_artifact_prefix(other))


def test_a_tenant_identifier_that_would_overlap_another_prefix_is_refused_a_policy() -> (
    None
):
    # `acme/eu` produces `tenants/acme/eu/`, which sits inside the `tenants/acme/*` resource
    # granted to the Tenant `acme`. The principal type permits the identifier — it forbids only the
    # State_Store separator — so the refusal has to come from the shared prefix producer, which is
    # now the one the policy is built from too.
    overlapping = AuthenticatedPrincipal(
        caller_identity=PRINCIPAL.caller_identity, tenant_id="acme/eu"
    )
    with pytest.raises(ArtifactLayoutError):
        _granted_artifact_prefix(overlapping)


def test_the_retention_period_is_the_value_a_record_mirrors() -> None:
    store = a_store()
    assert store.retention_days == RETENTION_DAYS
    store.verify_record_retention(a_session(artifact_retention_days=RETENTION_DAYS))


def test_a_record_that_stopped_mirroring_the_lifecycle_rule_is_a_defect() -> None:
    store = a_store()
    with pytest.raises(RetentionMirrorError) as raised:
        store.verify_record_retention(a_session(artifact_retention_days=7))
    # The message names both numbers, because the useful question is which one is wrong.
    assert "7" in str(raised.value) and str(RETENTION_DAYS) in str(raised.value)
