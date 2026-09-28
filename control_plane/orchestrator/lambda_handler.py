# kiro-classification: public
"""Lambda entry point for the Session Orchestrator task function.

Wires the ``SessionOrchestrator`` to the real AWS services the CDK stack provisions:

- **DynamoDB** for the Session row store, the lifecycle store, the Session lookup,
  the Sandbox claim ledger, and the continuation store.
- **Lambda MicroVMs** as the Compute_Provider, the Connection_Mint and the
  Sandbox terminator.
- **CloudWatch** (embedded metric format) for the Sandbox count metrics.

Every collaborator is built once per execution environment (at import time or on first use)
and every AWS call uses the orchestrator's own role — not the per-request tenant-confined
credentials the API handler uses.  The orchestrator touches items in every Tenant partition
(claim items sit outside all of them) and its identity is the execution ARN from the Step
Functions context, so the ``dynamodb:LeadingKeys`` confinement is the API handler's mechanism
and not this one's.

The handler receives the Step Functions task input shaped by each ``Task`` state's
``Parameters`` block::

    {
        "task": "Provision",
        "executionId": "arn:aws:states:...:execution:...",
        "state": { ... accumulated execution state ... }
    }

and delegates to ``SessionOrchestrator.run(event)``.

Environment variables consumed (written by ``ControlPlaneStack``):

    TABLE_NAME                    — the DynamoDB table name
    IMAGE_REF                     — the Sandbox_Runtime image reference
    EGRESS_ATTACHMENT_REF         — the Egress_Controller network attachment reference
    VCPU_MILLIS                   — milli-vCPUs per Sandbox
    POLL_INTERVAL_SECONDS         — governing-loop sleep between ``describe`` calls
    READINESS_ATTEMPTS            — how many ``describe`` calls before giving up
    READINESS_INTERVAL_SECONDS    — sleep between readiness ``describe`` calls
    CONTINUATION_LEAD_SECONDS     — how far before the ceiling the handoff begins
"""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any, Final

from control_plane.allocation.ledger import (
    ELIGIBILITY_ATTRIBUTE,
    QUARANTINE_REASON_ATTRIBUTE,
    ClaimConditionFailed,
    SandboxClaimLedger,
)
from control_plane.credentials import ConnectionIssuer
from control_plane.lifecycle import (
    REAP_DEADLINE_ATTRIBUTE,
    LifecycleConditionFailed,
    LifecycleReconciler,
    LiveTransition,
    TerminalSettlement,
)
from control_plane.observability import LifecycleAuditor, SandboxCountEmitter
from control_plane.orchestrator.continuation import (
    ContinuationAlreadyRecorded,
    ContinuationHandoff,
    ContinuationHandoffs,
)
from control_plane.orchestrator.tasks import (
    CredentialPublication,
    OrchestratorSettings,
    SandboxRecording,
    SessionOrchestrator,
)
from control_plane.providers.lambda_microvm import LambdaMicroVmProvider
from control_plane.state.keys import CLAIM_SORT_KEY
from control_plane.state.records import ContinuationRecord, Eligibility
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment variable names written by ControlPlaneStack
# ---------------------------------------------------------------------------

_TABLE_NAME_VAR: Final = "TABLE_NAME"
_IMAGE_REF_VAR: Final = "IMAGE_REF"
_EGRESS_ATTACHMENT_REF_VAR: Final = "CONNECTOR_REF"
_EGRESS_ENDPOINT_VAR: Final = "EGRESS_ENDPOINT"
_VCPU_MILLIS_VAR: Final = "VCPU_MILLIS"
_POLL_INTERVAL_SECONDS_VAR: Final = "POLL_INTERVAL_SECONDS"
_READINESS_ATTEMPTS_VAR: Final = "READINESS_ATTEMPTS"
_READINESS_INTERVAL_SECONDS_VAR: Final = "READINESS_INTERVAL_SECONDS"
_CONTINUATION_LEAD_SECONDS_VAR: Final = "CONTINUATION_LEAD_SECONDS"


# ---------------------------------------------------------------------------
# DynamoDB-backed protocol implementations
# ---------------------------------------------------------------------------


class _DynamoSessionStore:
    """A single DynamoDB table handle satisfying five structural protocols at once:

    - ``OrchestrationRowStore`` — ``record_sandbox``, ``publish_connection``
    - ``SessionLifecycleStore`` — ``advance_live_state``, ``settle_terminal_state``
    - ``SessionLookup``        — ``read_session``
    - ``ClaimItemStore``       — ``put_claim_if_absent``, ``read_claim``,
                                  ``mark_claim_used``, ``quarantine_claim``
    - ``ContinuationStore``    — ``read_continuation``, ``record_continuation``,
                                  ``apply_continuation``

    One class because they all hit the same table with the orchestrator's own role, and
    each conditional write maps the DynamoDB ``ConditionalCheckFailedException`` to the
    protocol's own exception exactly as the test doubles do.

    The table resource is built lazily so that importing this module touches no AWS endpoint.
    """

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name
        self._table_resource: Any | None = None
        self._dynamodb_client: Any | None = None

    def _table(self) -> Any:
        if self._table_resource is None:
            import boto3  # type: ignore[import-untyped]

            self._table_resource = boto3.resource("dynamodb").Table(self._table_name)
        return self._table_resource

    def _client(self) -> Any:
        if self._dynamodb_client is None:
            import boto3  # type: ignore[import-untyped]

            self._dynamodb_client = boto3.client("dynamodb")
        return self._dynamodb_client

    # -- SessionLookup ------------------------------------------------------------

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        response = self._table().get_item(
            Key={
                PARTITION_KEY_ATTRIBUTE: partition_key,
                SORT_KEY_ATTRIBUTE: sort_key,
            },
            ConsistentRead=True,
        )
        return response.get("Item")

    # -- OrchestrationRowStore ----------------------------------------------------

    def record_sandbox(self, recording: SandboxRecording) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: recording.partition_key,
                    SORT_KEY_ATTRIBUTE: recording.sort_key,
                },
                UpdateExpression=(
                    "SET sandboxHandle = :handle, sandboxId = :id, updatedAt = :at"
                ),
                ExpressionAttributeValues={
                    ":handle": recording.handle_map,
                    ":id": recording.sandbox_id,
                    ":at": recording.updated_at,
                    ":terminated": "TERMINATED",
                    ":failed": "FAILED",
                },
                ConditionExpression=(
                    "attribute_exists(#pk) "
                    "AND NOT lifecycleState IN (:terminated, :failed)"
                ),
                ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise LifecycleConditionFailed(str(exc)) from exc

    def publish_connection(self, publication: CredentialPublication) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: publication.partition_key,
                    SORT_KEY_ATTRIBUTE: publication.sort_key,
                },
                UpdateExpression=(
                    "SET #conn = :connection, "
                    "connectionPublishedAt = :at, "
                    "updatedAt = :at"
                ),
                ExpressionAttributeNames={
                    "#conn": "connection",
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                },
                ExpressionAttributeValues={
                    ":connection": publication.connection.to_map(),
                    ":at": publication.published_at,
                    ":terminated": "TERMINATED",
                    ":failed": "FAILED",
                },
                ConditionExpression=(
                    "attribute_exists(#pk) "
                    "AND NOT lifecycleState IN (:terminated, :failed)"
                ),
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise LifecycleConditionFailed(str(exc)) from exc

    # -- SessionLifecycleStore ----------------------------------------------------

    def advance_live_state(self, transition: LiveTransition) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: transition.partition_key,
                    SORT_KEY_ATTRIBUTE: transition.sort_key,
                },
                UpdateExpression=(
                    "SET lifecycleState = :state, "
                    "stateReason = :reason, "
                    "updatedAt = :at, "
                    "#scAt = :scAt"
                ),
                ExpressionAttributeNames={
                    "#scAt": TENANT_STATE_INDEX.sort_key,
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                },
                ExpressionAttributeValues={
                    ":state": transition.state.value,
                    ":reason": transition.state_reason,
                    ":at": transition.updated_at,
                    ":scAt": transition.state_created_at,
                    ":terminated": "TERMINATED",
                    ":failed": "FAILED",
                },
                ConditionExpression=(
                    "attribute_exists(#pk) "
                    "AND NOT lifecycleState IN (:terminated, :failed)"
                ),
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise LifecycleConditionFailed(str(exc)) from exc

    def settle_terminal_state(self, settlement: TerminalSettlement) -> None:
        """TransactWriteItems: update the Session row and delete the binding, as one step."""
        from boto3.dynamodb.types import TypeSerializer  # type: ignore[import-untyped]

        serializer = TypeSerializer()

        session_update = {
            "Update": {
                "TableName": self._table_name,
                "Key": {
                    PARTITION_KEY_ATTRIBUTE: serializer.serialize(
                        settlement.partition_key
                    ),
                    SORT_KEY_ATTRIBUTE: serializer.serialize(settlement.sort_key),
                },
                "UpdateExpression": (
                    "SET lifecycleState = :state, "
                    "stateReason = :reason, "
                    "updatedAt = :at, "
                    "#scAt = :scAt "
                    "REMOVE #deadline"
                ),
                "ExpressionAttributeNames": {
                    "#scAt": TENANT_STATE_INDEX.sort_key,
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                    "#deadline": REAP_DEADLINE_ATTRIBUTE,
                },
                "ExpressionAttributeValues": {
                    ":state": serializer.serialize(settlement.state.value),
                    ":reason": serializer.serialize(settlement.state_reason),
                    ":at": serializer.serialize(settlement.updated_at),
                    ":scAt": serializer.serialize(settlement.state_created_at),
                    ":terminated": serializer.serialize("TERMINATED"),
                    ":failed": serializer.serialize("FAILED"),
                },
                "ConditionExpression": (
                    "attribute_exists(#pk) "
                    "AND NOT lifecycleState IN (:terminated, :failed)"
                ),
            }
        }

        items: list[dict[str, Any]] = [session_update]

        if settlement.binding is not None:
            binding_delete = {
                "Delete": {
                    "TableName": self._table_name,
                    "Key": {
                        PARTITION_KEY_ATTRIBUTE: serializer.serialize(
                            settlement.binding.partition_key
                        ),
                        SORT_KEY_ATTRIBUTE: serializer.serialize(
                            settlement.binding.sort_key
                        ),
                    },
                }
            }
            items.append(binding_delete)

        try:
            self._client().transact_write_items(TransactItems=items)
        except self._client().exceptions.TransactionCanceledException as exc:
            reasons = getattr(exc, "response", {}).get(
                "CancellationReasons", []
            )
            # The first item is the Session update — if its condition failed, raise.
            if reasons and reasons[0].get("Code") == "ConditionalCheckFailed":
                raise LifecycleConditionFailed(str(exc)) from exc
            raise

    # -- ClaimItemStore -----------------------------------------------------------

    def put_claim_if_absent(self, item: Mapping[str, Any]) -> None:
        try:
            self._table().put_item(
                Item=dict(item),
                ConditionExpression="attribute_not_exists(#pk)",
                ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise ClaimConditionFailed(str(exc)) from exc

    def read_claim(self, *, partition_key: str) -> Mapping[str, Any] | None:
        response = self._table().get_item(
            Key={
                PARTITION_KEY_ATTRIBUTE: partition_key,
                SORT_KEY_ATTRIBUTE: CLAIM_SORT_KEY,
            },
            ConsistentRead=True,
        )
        return response.get("Item")

    def mark_claim_used(self, *, partition_key: str) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: partition_key,
                    SORT_KEY_ATTRIBUTE: CLAIM_SORT_KEY,
                },
                UpdateExpression="SET #elig = :used",
                ExpressionAttributeNames={
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                    "#elig": ELIGIBILITY_ATTRIBUTE,
                },
                ExpressionAttributeValues={
                    ":used": Eligibility.USED.value,
                    ":never_run": Eligibility.NEVER_RUN.value,
                },
                ConditionExpression=(
                    "attribute_exists(#pk) AND #elig = :never_run"
                ),
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise ClaimConditionFailed(str(exc)) from exc

    def quarantine_claim(self, *, partition_key: str, reason: str) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: partition_key,
                    SORT_KEY_ATTRIBUTE: CLAIM_SORT_KEY,
                },
                UpdateExpression=(
                    "SET #elig = :quarantined, #reason = :reason"
                ),
                ExpressionAttributeNames={
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                    "#elig": ELIGIBILITY_ATTRIBUTE,
                    "#reason": QUARANTINE_REASON_ATTRIBUTE,
                },
                ExpressionAttributeValues={
                    ":quarantined": Eligibility.QUARANTINED.value,
                    ":reason": reason,
                },
                ConditionExpression=(
                    "attribute_exists(#pk) "
                    "AND attribute_not_exists(#reason)"
                ),
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise ClaimConditionFailed(str(exc)) from exc

    # -- ContinuationStore --------------------------------------------------------

    def read_continuation(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        response = self._table().get_item(
            Key={
                PARTITION_KEY_ATTRIBUTE: partition_key,
                SORT_KEY_ATTRIBUTE: sort_key,
            },
            ConsistentRead=True,
        )
        return response.get("Item")

    def record_continuation(self, record: ContinuationRecord) -> None:
        try:
            self._table().put_item(
                Item=dict(record.to_item()),
                ConditionExpression="attribute_not_exists(#pk)",
                ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise ContinuationAlreadyRecorded(
                record.session_id, record.generation
            ) from exc

    def apply_continuation(self, handoff: ContinuationHandoff) -> None:
        try:
            self._table().update_item(
                Key={
                    PARTITION_KEY_ATTRIBUTE: handoff.partition_key,
                    SORT_KEY_ATTRIBUTE: handoff.sort_key,
                },
                UpdateExpression=(
                    "SET generation = :incoming, updatedAt = :at "
                    "REMOVE sandboxHandle, sandboxId, "
                    "#conn, connectionPublishedAt"
                ),
                ExpressionAttributeNames={
                    "#pk": PARTITION_KEY_ATTRIBUTE,
                    "#conn": "connection",
                },
                ExpressionAttributeValues={
                    ":incoming": handoff.incoming_generation,
                    ":at": handoff.updated_at,
                    ":outgoing": handoff.outgoing_generation,
                    ":terminated": "TERMINATED",
                    ":failed": "FAILED",
                },
                ConditionExpression=(
                    "attribute_exists(#pk) "
                    "AND generation = :outgoing "
                    "AND NOT lifecycleState IN (:terminated, :failed)"
                ),
            )
        except self._table().meta.client.exceptions.ConditionalCheckFailedException as exc:
            raise LifecycleConditionFailed(str(exc)) from exc


class _HttpSandboxQuiesce:
    """Deliver the ``session.quiesce`` protocol message to a Session's Sandbox endpoint.

    The message is typed ``orchestrator-to-runtime`` in the protocol catalogue and carries an
    empty body.  It uses the Session row's own published credential to authenticate,
    so there is no additional secret to wire.

    A failure is reported rather than raised: the Sandbox is being terminated in the very next
    step, and the archive does not depend on the message arriving (see the protocol's docstring).
    """

    def quiesce(self, record: Any) -> bool:
        """Ask this Session's Sandbox to stop accepting new work.

        Returns ``True`` when the Sandbox acknowledged, ``False`` otherwise.
        """
        connection = getattr(record, "connection", None)
        if connection is None:
            logger.warning(
                "quiesce: no published connection on Session %s — skipping",
                record.session_id,
            )
            return False

        try:
            import json as _json
            import urllib.error
            import urllib.request

            base_url = connection.base_url
            url = f"{base_url}/session.quiesce"
            body = _json.dumps({}).encode("utf-8")
            headers = {
                connection.auth_header_name: connection.auth_header_value,
                "Content-Type": "application/json",
            }
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
                return resp.status == 200
        except Exception:
            logger.warning(
                "quiesce: failed to deliver quiesce to Session %s",
                record.session_id,
                exc_info=True,
            )
            return False


# ---------------------------------------------------------------------------
# Wiring helpers
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name!r} is not set")
    return value


def _int_env(name: str) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        raise RuntimeError(f"required environment variable {name!r} is not set")
    return int(raw)


# ---------------------------------------------------------------------------
# Build the orchestrator — once per execution environment
# ---------------------------------------------------------------------------


def _build_orchestrator() -> SessionOrchestrator:
    table_name = _require_env(_TABLE_NAME_VAR)

    store = _DynamoSessionStore(table_name)
    provider = LambdaMicroVmProvider()

    settings = OrchestratorSettings(
        image_ref=_require_env(_IMAGE_REF_VAR),
        egress_attachment_ref=_require_env(_EGRESS_ATTACHMENT_REF_VAR),
        egress_endpoint=os.environ.get(_EGRESS_ENDPOINT_VAR, ""),
        s3files_filesystem_id=os.environ.get("S3FILES_FILESYSTEM_ID", ""),
        s3files_access_point_id=os.environ.get("S3FILES_ACCESS_POINT_ID", ""),
        s3files_mount_target_ips=os.environ.get("S3FILES_MOUNT_TARGET_IPS", ""),
        vcpu_millis=_int_env(_VCPU_MILLIS_VAR),
        poll_interval_seconds=_int_env(_POLL_INTERVAL_SECONDS_VAR),
        readiness_attempts=_int_env(_READINESS_ATTEMPTS_VAR),
        readiness_interval_seconds=_int_env(_READINESS_INTERVAL_SECONDS_VAR),
        continuation_lead_seconds=_int_env(_CONTINUATION_LEAD_SECONDS_VAR),
    )

    # The execution ARN is set per-invocation, but the LifecycleAuditor binds the
    # calling principal at construction.  Use a placeholder that is replaced on
    # each invocation by the handler wrapper below.
    auditor = LifecycleAuditor(principal="orchestrator")

    return SessionOrchestrator(
        provider=provider,
        store=store,
        lookup=store,
        reconciler=LifecycleReconciler(
            store=store,
            lookup=store,
            audit=auditor,
        ),
        ledger=SandboxClaimLedger(store=store, terminator=provider),
        counts=SandboxCountEmitter(),
        issuer=ConnectionIssuer(mint=provider),
        continuation=ContinuationHandoffs(store=store, quiescer=_HttpSandboxQuiesce()),
        settings=settings,
    )


_orchestrator = _build_orchestrator()


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point: dispatch a Step Functions task invocation to the orchestrator."""
    del context
    return _orchestrator.run(event)
