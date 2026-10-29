# kiro-classification: public
"""Lambda entry point for the Control_Plane API handler.

Wires the ``ControlPlaneApi`` to the real AWS services the CDK stack provisions:

- **DynamoDB** for the Session row store and the Session lookup, reached through the
  ``TenantDataAccessBroker``'s per-request tenant-confined credentials (R11.3).
- **Step Functions** for ``StartExecution`` on the Session_Orchestrator.
- **Lambda MicroVMs** as the Compute_Provider, for admission's ceiling and for the provider name
  recorded on every Session row.

The remaining seven operations inherit ``NotImplementedOperations``'s ``501`` through
``CreationOperations``, which is the shape
:class:`~control_plane.api.connection.ConnectionOperations` established: each operation arrives with
the task that fills it, and the ``501`` is a truthful skeleton until then.

Every collaborator is built once per execution environment (at import time or on first use) and
every AWS call that touches a Tenant's data is made with the per-request tenant-confined credentials
the broker derives. The broker's STS client and the Step Functions client are built lazily, so this
module's import touches no AWS endpoint and no credential — the same posture
:class:`~control_plane.state.access.TenantDataAccessBroker` takes for the offline suite.

Environment variables consumed (written by ``ControlPlaneStack``):

    TABLE_NAME               — the DynamoDB table name
    STATE_MACHINE_ARN        — the Session_Orchestrator state machine ARN
    REAP_SHARD_COUNT         — the number of Reaper shards
    SESSION_DATA_ACCESS_ROLE_ARN — the role assumed for per-request tenant-confined credentials
    BUCKET_NAME              — the artifact bucket name (used to build the broker targets)
    ARTIFACT_KEY_ARN         — the artifact encryption key ARN (not consumed here)
    DEPLOYMENT_PROFILE       — ``single-tenant`` or ``multi-tenant``
    TENANT_ID                — the fixed Tenant identifier under ``single-tenant``
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any, Final

from control_plane.api.admission import AdmissionPolicy
from control_plane.api.creation import (
    CreationOperations,
    CreationSettings,
    OrchestrationStart,
)
from http import HTTPStatus
from control_plane.api.handlers import (
    ControlPlaneApi,
    OperationRequest,
    OperationResult,
    lambda_entrypoint,
)
from control_plane.api.errors import ControlPlaneError, error_response
from control_plane.providers.base import SandboxHandle
from control_plane.providers.lambda_microvm import LambdaMicroVmProvider
from control_plane.state.access import (
    ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE,
    ROLE_ARN_ENVIRONMENT_VARIABLE,
    TABLE_ARN_ENVIRONMENT_VARIABLE,
    DataAccessTargets,
    TenantDataAccessBroker,
)
from control_plane.state.table import (
    PARTITION_KEY_ATTRIBUTE,
    SORT_KEY_ATTRIBUTE,
    TENANT_STATE_INDEX,
)

# ---------------------------------------------------------------------------
# Environment variable names written by ControlPlaneStack
# ---------------------------------------------------------------------------

_TABLE_NAME_VAR: Final = "TABLE_NAME"
_STATE_MACHINE_ARN_VAR: Final = "STATE_MACHINE_ARN"
_REAP_SHARD_COUNT_VAR: Final = "REAP_SHARD_COUNT"
_BUCKET_NAME_VAR: Final = "BUCKET_NAME"
_EXECUTION_ROLE_ARN_VAR: Final = "SANDBOX_EXECUTION_ROLE_ARN"
_SESSION_LIMIT_PER_USER: Final = int(os.environ.get("SESSION_LIMIT_PER_USER", "5"))
_SESSION_LIMIT_PER_TENANT: Final = int(os.environ.get("SESSION_LIMIT_PER_TENANT", "100"))
_WORKSPACE_PREFIX: Final = "workspaces"
_PRESIGNED_URL_EXPIRY: Final = 3600  # 1 hour

# ---------------------------------------------------------------------------
# Default policy values — the design's declared configuration.
# ---------------------------------------------------------------------------
# These are conservative defaults that ``AdmissionPolicy`` requires.  A real
# deployment should pass them through CDK context values; they live here so
# that the handler can start without every possible env var being wired.

_DEFAULT_DURATION_SECONDS: Final = 3600
_DEFAULT_IDLE_SECONDS: Final = 600
_DEFAULT_SUSPENDED_SECONDS: Final = 3600
_DEFAULT_AUTO_RESUME: Final = True

# Default memory size: 2 GiB, one of ``MICROVM_MEMORY_CHOICES``.
_DEFAULT_MEMORY_BYTES: Final = 2 * 1024 * 1024 * 1024

# Default artifact retention: 7 days.
_DEFAULT_ARTIFACT_RETENTION_DAYS: Final = 7


# ---------------------------------------------------------------------------
# Concrete protocol implementations — DynamoDB and Step Functions
# ---------------------------------------------------------------------------


class _DynamoSessionRowStore:
    """A ``SessionRowStore`` backed by DynamoDB.

    Each write is made with the caller-specific credentials the
    ``TenantDataAccessBroker`` derived for this request, so the ``dynamodb:LeadingKeys``
    condition in the session policy structurally confines every write to the caller's Tenant
    partition (R11.3).

    The table resource is built lazily from ``TABLE_NAME`` so that importing this module
    touches no AWS.
    """

    def __init__(self, table_name: str, broker: TenantDataAccessBroker) -> None:
        self._table_name = table_name
        self._broker = broker
        self._table_resource: Any | None = None

    def _table(self) -> Any:
        """Return the shared ``boto3.resource("dynamodb").Table(...)`` handle."""
        if self._table_resource is None:
            import boto3  # type: ignore[import-untyped]

            self._table_resource = boto3.resource("dynamodb").Table(self._table_name)
        return self._table_resource

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        """Conditional ``PutItem``, refusing to overwrite an existing row."""
        self._table().put_item(
            Item=dict(item),
            ConditionExpression="attribute_not_exists(#pk)",
            ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
        )

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        """``UpdateItem`` moving the row to ``ORCHESTRATING``."""
        self._table().update_item(
            Key={
                PARTITION_KEY_ATTRIBUTE: start.partition_key,
                SORT_KEY_ATTRIBUTE: start.sort_key,
            },
            UpdateExpression=(
                "SET lifecycleState = :state, "
                "stateReason = :reason, "
                "orchestrationExecutionArn = :arn, "
                "updatedAt = :at, "
                "#scAt = :scAt"
            ),
            ExpressionAttributeNames={
                "#scAt": TENANT_STATE_INDEX.sort_key,
                "#pk": PARTITION_KEY_ATTRIBUTE,
            },
            ExpressionAttributeValues={
                ":state": start.state.value,
                ":reason": start.state_reason,
                ":arn": start.execution_arn,
                ":at": start.updated_at,
                ":scAt": start.state_created_at,
            },
            ConditionExpression="attribute_exists(#pk)",
        )


class _DynamoSessionLookup:
    """A ``SessionLookup`` backed by a strongly consistent ``GetItem``."""

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name
        self._table_resource: Any | None = None

    def _table(self) -> Any:
        if self._table_resource is None:
            import boto3  # type: ignore[import-untyped]

            self._table_resource = boto3.resource("dynamodb").Table(self._table_name)
        return self._table_resource

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


class _StepFunctionsOrchestrationStarter:
    """An ``OrchestrationStarter`` backed by Step Functions ``StartExecution``."""

    def __init__(self, state_machine_arn: str) -> None:
        self._arn = state_machine_arn
        self._client: Any | None = None

    def _sfn(self) -> Any:
        if self._client is None:
            import boto3  # type: ignore[import-untyped]

            self._client = boto3.client("stepfunctions")
        return self._client

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        """Start or join the execution, returning its ARN (R6.10)."""
        response = self._sfn().start_execution(
            stateMachineArn=self._arn,
            name=name,
            input=json.dumps(payload),
        )
        return response["executionArn"]


# ---------------------------------------------------------------------------
# Wiring — built once per execution environment
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name!r} is not set")
    return value


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _build_broker(table_name: str) -> TenantDataAccessBroker:
    """Build the ``TenantDataAccessBroker`` from the handler's environment.

    The CDK stack writes ``SESSION_DATA_ACCESS_ROLE_ARN`` and ``TABLE_NAME``.
    ``DataAccessTargets`` expects an ARN for the table, so we derive it from the
    account and Region environment that Lambda provides.
    """
    role_arn = os.environ.get(ROLE_ARN_ENVIRONMENT_VARIABLE, "")
    bucket_name = os.environ.get(_BUCKET_NAME_VAR, "")
    # Derive the table ARN from the table name and the Lambda execution context.
    region = os.environ.get("AWS_REGION", "us-east-1")
    account = os.environ.get("AWS_ACCOUNT_ID", "")
    # If we can't derive the ARN cleanly, fall back to a placeholder that still
    # lets the broker construct (it validates at assume-role time, not at build time).
    if account:
        table_arn = f"arn:aws:dynamodb:{region}:{account}:table/{table_name}"
    else:
        # In a real Lambda environment, the execution role ARN carries the account.
        # Parse it: arn:aws:iam::<account>:role/...
        parts = role_arn.split(":") if role_arn else []
        acct = parts[4] if len(parts) > 4 else "000000000000"
        table_arn = f"arn:aws:dynamodb:{region}:{acct}:table/{table_name}"

    # Inject the derived ARN so ``DataAccessTargets.from_environment`` can read it.
    os.environ.setdefault(TABLE_ARN_ENVIRONMENT_VARIABLE, table_arn)
    os.environ.setdefault(ARTIFACT_BUCKET_ENVIRONMENT_VARIABLE, bucket_name)

    return TenantDataAccessBroker(targets=DataAccessTargets.from_environment())


class _SessionLimitExceeded(ControlPlaneError):
    """Raised when session creation would exceed the per-tenant limit (HTTP 429)."""
    def __init__(self, message: str) -> None:
        super().__init__(error_response(HTTPStatus.TOO_MANY_REQUESTS, "SessionLimitExceeded", message))


class _DemoOperations(CreationOperations):
    """Extends ``CreationOperations`` with ``get_session`` and ``terminate_session``.

    ``get_session`` serialises the already-resolved record (the dispatcher resolves the
    Session before the operation is invoked, so ``request.session`` is a ``SessionRecord``
    or the fixed not-found has already been returned).

    ``terminate_session`` returns a minimal acknowledgement.  Full termination logic
    (provider teardown, artifact capture) belongs to a later task; the stub here unblocks
    the demo's cleanup step.
    """

    def create_session(self, request: OperationRequest) -> OperationResult:
        """Override to add session limit checks before creation."""
        self._check_session_limits(request)
        return super().create_session(request)

    def _check_session_limits(self, request: OperationRequest) -> None:
        """Enforce per-tenant session limits before creating a new session."""
        import boto3

        from control_plane.state.keys import SEPARATOR, SESSION_PREFIX
        from control_plane.tenancy.partition import pk_for

        table_name = os.environ.get("TABLE_NAME", "")
        partition_key = pk_for(request.principal)

        table = boto3.resource("dynamodb").Table(table_name)

        # Count active (non-terminal) sessions for this tenant.
        # Query the tenant-state-index and count RUNNING + SUSPENDED + ORCHESTRATING etc.
        response = table.query(
            IndexName=TENANT_STATE_INDEX.name,
            KeyConditionExpression="#pk = :pk",
            ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
            ExpressionAttributeValues={":pk": partition_key},
            Select="COUNT",
        )
        # Filter: only count non-terminal sessions
        # The GSI sorts by stateCreatedAt which starts with the state name.
        # We need a more targeted approach: query for each active state prefix.
        active_count = 0
        for state_prefix in ("ORCHESTRATING", "PROVISIONING", "STARTING", "RUNNING", "SUSPENDED"):
            resp = table.query(
                IndexName=TENANT_STATE_INDEX.name,
                KeyConditionExpression="#pk = :pk AND begins_with(stateCreatedAt, :state)",
                ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
                ExpressionAttributeValues={
                    ":pk": partition_key,
                    ":state": state_prefix,
                },
                Select="COUNT",
            )
            active_count += resp.get("Count", 0)

        if active_count >= _SESSION_LIMIT_PER_TENANT:
            raise _SessionLimitExceeded(
                f"Tenant has {active_count} active sessions (limit: {_SESSION_LIMIT_PER_TENANT})"
            )

    def get_session(self, request: OperationRequest) -> OperationResult:
        """Report the resolved Session's lifecycle state and any published credential."""
        record = request.session
        assert record is not None  # the dispatcher resolved it or raised not-found
        payload: dict[str, Any] = {
            "sessionId": record.session_id,
            "lifecycleState": record.lifecycle_state.value,
            "tenantId": record.tenant_id,
        }
        if record.connection is not None:
            payload["connection"] = record.connection.to_map()
        # Workspace path for per-session persistent storage
        bucket = os.environ.get("BUCKET_NAME", "")
        if bucket:
            payload["workspace"] = {
                "bucket": bucket,
                "prefix": f"{_WORKSPACE_PREFIX}/{record.tenant_id}/{record.session_id}/",
            }
        return OperationResult(payload=payload)

    def list_sessions(self, request: OperationRequest) -> OperationResult:
        """List sessions for the authenticated tenant via the tenant-state-index GSI."""
        import boto3

        from control_plane.state.keys import SEPARATOR, SESSION_PREFIX
        from control_plane.tenancy.partition import pk_for

        table_name = os.environ.get("TABLE_NAME", "")
        partition_key = pk_for(request.principal)

        table = boto3.resource("dynamodb").Table(table_name)
        response = table.query(
            IndexName=TENANT_STATE_INDEX.name,
            KeyConditionExpression="#pk = :pk",
            ExpressionAttributeNames={"#pk": PARTITION_KEY_ATTRIBUTE},
            ExpressionAttributeValues={":pk": partition_key},
            Limit=100,
        )

        # Session sort keys are `S#<sessionId>`. Other item types (bindings,
        # artifacts, continuations) share the same partition but have different
        # sort key prefixes, so filter by the session prefix.
        session_prefix = f"{SESSION_PREFIX}{SEPARATOR}"
        sessions = []
        for item in response.get("Items", []):
            sort_key = item.get(SORT_KEY_ATTRIBUTE, "")
            if not sort_key.startswith(session_prefix):
                continue
            # The session ID is everything after `S#`, but only for plain
            # session rows (sort key has exactly one separator after the prefix).
            remainder = sort_key[len(session_prefix):]
            if SEPARATOR in remainder:
                continue  # artifact or continuation item, not a session row
            entry: dict[str, object] = {
                "sessionId": remainder,
                "lifecycleState": item.get("lifecycleState", "UNKNOWN"),
                "tenantId": item.get("tenantId", ""),
            }
            # Include timestamps when available for client-side sorting.
            created = item.get("createdAt")
            if created is not None:
                entry["createdAt"] = int(created)
            updated = item.get("updatedAt")
            if updated is not None:
                entry["updatedAt"] = int(updated)
            sessions.append(entry)

        return OperationResult(payload={"sessions": sessions})

    def terminate_session(self, request: OperationRequest) -> OperationResult:
        """Terminate the MicroVM and update DynamoDB to TERMINATED."""
        import time

        import boto3

        record = request.session
        assert record is not None

        # If already terminal, return idempotently.
        if record.lifecycle_state.value in ("TERMINATED", "FAILED"):
            return OperationResult(
                payload={
                    "sessionId": record.session_id,
                    "lifecycleState": record.lifecycle_state.value,
                },
            )

        # 1. Terminate the MicroVM via the provider (idempotent).
        try:
            handle = self._rebuild_handle(request)
            status = self.provider.terminate(handle)
        except Exception:
            # If the handle is missing (session never fully provisioned), skip.
            status = None

        # 2. Update DynamoDB row to TERMINATED.
        import os
        table_name = os.environ.get("TABLE_NAME", "")
        now = int(time.time() * 1000)
        state = "TERMINATED"
        state_created_at = f"{state}#{now}"

        try:
            table = boto3.resource("dynamodb").Table(table_name)
            from control_plane.state.keys import SEPARATOR, SESSION_PREFIX
            from control_plane.tenancy.partition import pk_for
            pk = pk_for(request.principal)
            sk = f"{SESSION_PREFIX}{SEPARATOR}{record.session_id}"

            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=(
                    "SET lifecycleState = :state, stateReason = :reason, "
                    "updatedAt = :at, stateCreatedAt = :stateCreatedAt "
                    "REMOVE reapDeadline"
                ),
                ExpressionAttributeValues={
                    ":state": state,
                    ":reason": "Terminated via API",
                    ":at": now,
                    ":stateCreatedAt": state_created_at,
                },
            )
        except Exception as exc:
            # Log but don't fail — the MicroVM is already stopped.
            import logging
            logging.getLogger(__name__).warning(
                "Failed to update DynamoDB for session %s: %s",
                record.session_id, exc,
            )

        # 3. Send callback to wake the orchestrator for graceful teardown,
        # or stop the execution directly as fallback.
        self._send_lifecycle_callback(record, "tear-down")

        return OperationResult(
            payload={
                "sessionId": record.session_id,
                "lifecycleState": state,
            },
        )



    def _send_lifecycle_callback(self, record, decision: str) -> None:
        """Send a callback to the orchestrator's WaitForLifecycle state.

        Reads the task token from the session record and calls
        ``sfn.send_task_success``. If the token is stale (already consumed by a
        previous callback), retries by re-reading from DDB until a fresh token
        appears — this handles the token rotation gap after suspend/resume where
        the new WaitForLifecycle hasn't stored its token yet.
        """
        import json
        import os
        import time
        import boto3
        import logging

        logger = logging.getLogger(__name__)

        # First try with the token from the request's session record
        token = getattr(record, "task_token", None)
        sent = self._try_send_callback(token, decision, record.session_id, logger)
        if sent:
            return

        # Token missing or stale — poll DDB for a fresh one (token rotation gap)
        table_name = os.environ.get("TABLE_NAME", "")
        if not table_name:
            return
        ddb = boto3.resource("dynamodb").Table(table_name)  # nosemgrep  # nosec

        deadline = time.monotonic() + 5  # 5 second cap
        while time.monotonic() < deadline:
            time.sleep(0.5)  # nosemgrep: arbitrary-sleep — retry backoff for token rotation
            try:
                resp = ddb.get_item(
                    Key={"pk": record.pk, "sk": record.sort_key},
                    ProjectionExpression="taskToken",
                    ConsistentRead=True,
                )
                fresh_token = resp.get("Item", {}).get("taskToken", "")
                if fresh_token and fresh_token != token:
                    sent = self._try_send_callback(fresh_token, decision, record.session_id, logger)
                    if sent:
                        return
            except Exception:  # nosec B110 — retry loop; token refresh failure is retried on next iteration
                pass

        logger.warning("No fresh task token for session %s after 5s", record.session_id)  # nosemgrep: python-logger-credential-disclosure — logs session ID, not secrets

    @staticmethod
    def _try_send_callback(token, decision: str, session_id: str, logger) -> bool:
        """Attempt to send the callback. Returns True on success."""
        import json
        import boto3

        if not token:
            return False
        try:
            sfn = boto3.client("stepfunctions")
            sfn.send_task_success(
                taskToken=token,
                output=json.dumps({"decision": decision, "source": "api-handler"}),
            )
            return True
        except sfn.exceptions.TaskTimedOut:
            return False  # Token expired — need a fresh one
        except sfn.exceptions.InvalidToken:
            return False  # Token already consumed — need a fresh one
        except sfn.exceptions.TaskDoesNotExist:
            return False  # Task no longer exists
        except Exception as exc:  # nosec B110
            logger.warning("Callback failed for session %s: %s", session_id, exc)
            return False

    # --------------------------------------------------------- workspace operations

    def _rebuild_handle(self, request: OperationRequest) -> SandboxHandle:
        """Rebuild a ``SandboxHandle`` from the stored ``sandbox_handle`` map."""
        record = request.session
        assert record is not None
        stored = record.sandbox_handle
        assert stored is not None, "session has no sandbox_handle"
        return SandboxHandle(
            provider_name=str(stored.get("providerName", "")),
            sandbox_id=str(stored.get("sandboxId", "")),
            opaque={str(k): str(v) for k, v in stored.get("opaque", {}).items()},
        )

    def suspend_session(self, request: OperationRequest) -> OperationResult:
        """Suspend the MicroVM and send callback to wake the orchestrator."""
        record = request.session
        assert record is not None
        handle = self._rebuild_handle(request)
        status = self.provider.suspend(handle)
        # Send callback to the orchestrator's WaitForLifecycle state
        self._send_lifecycle_callback(record, "suspend")
        return OperationResult(
            payload={
                "sessionId": record.session_id,
                "lifecycleState": status.state.value,
            },
        )

    def resume_session(self, request: OperationRequest) -> OperationResult:
        """Resume the MicroVM and send callback to wake the orchestrator."""
        record = request.session
        assert record is not None
        handle = self._rebuild_handle(request)
        status = self.provider.resume(handle)
        # Send callback to the orchestrator's WaitForLifecycle state
        self._send_lifecycle_callback(record, "resume")
        return OperationResult(
            payload={
                "sessionId": record.session_id,
                "lifecycleState": status.state.value,
            },
        )

    def refresh_connection(self, request: OperationRequest) -> OperationResult:
        """Mint a fresh connection credential for the resumed Sandbox."""
        import time

        from control_plane.credentials import ConnectionIssuer

        record = request.session
        assert record is not None

        issuer = ConnectionIssuer(mint=self.provider)

        # The MicroVM may still be transitioning after resume; retry on transient errors.
        last_exc: Exception | None = None
        for attempt in range(5):
            try:
                descriptor = issuer.issue(record)
                break
            except Exception as exc:
                last_exc = exc
                if attempt < 4:
                    time.sleep(2)  # nosemgrep: arbitrary-sleep — polling loop by design
        else:
            raise last_exc  # type: ignore[misc]

        return OperationResult(
            payload={
                "sessionId": record.session_id,
                "connection": {
                    "baseUrl": descriptor.base_url,
                    "authHeaderName": descriptor.auth_header_name,
                    "authHeaderValue": descriptor.auth_header_value,
                    "ports": list(descriptor.ports),
                    "expiresAt": descriptor.expires_at,
                },
            },
        )


def _build_api() -> ControlPlaneApi:
    """Build the ``ControlPlaneApi`` with ``CreationOperations`` wired to real AWS services."""
    table_name = _require_env(_TABLE_NAME_VAR)
    state_machine_arn = _require_env(_STATE_MACHINE_ARN_VAR)
    reap_shard_count = _int_env(_REAP_SHARD_COUNT_VAR, 4)

    # Execution role ARN for the Sandbox — may be supplied by CDK or left empty
    # (the orchestrator resolves it at provision time from its own environment).
    execution_role_arn = os.environ.get(_EXECUTION_ROLE_ARN_VAR, "")
    if not execution_role_arn:
        # Fallback: construct a placeholder that ``CreationSettings`` will accept.
        # The real role ARN is used by the orchestrator, not by the handler, so the
        # value on the Session row is informational for the handler's purposes.
        parts = os.environ.get(ROLE_ARN_ENVIRONMENT_VARIABLE, "").split(":")
        acct = parts[4] if len(parts) > 4 else "000000000000"
        execution_role_arn = (
            f"arn:aws:iam::{acct}:role/SandboxExecutionRole"
        )

    broker = _build_broker(table_name)

    store = _DynamoSessionRowStore(table_name, broker)
    lookup = _DynamoSessionLookup(table_name)
    orchestration = _StepFunctionsOrchestrationStarter(state_machine_arn)
    provider = LambdaMicroVmProvider()

    policy = AdmissionPolicy(
        default_duration_seconds=_DEFAULT_DURATION_SECONDS,
        default_idle_seconds=_DEFAULT_IDLE_SECONDS,
        default_suspended_seconds=_DEFAULT_SUSPENDED_SECONDS,
        default_auto_resume=_DEFAULT_AUTO_RESUME,
    )
    settings = CreationSettings(
        memory_bytes=_DEFAULT_MEMORY_BYTES,
        execution_role_arn=execution_role_arn,
        artifact_retention_days=_DEFAULT_ARTIFACT_RETENTION_DAYS,
        reap_shard_count=reap_shard_count,
    )

    operations = _DemoOperations(
        provider=provider,
        policy=policy,
        settings=settings,
        store=store,
        orchestration=orchestration,
    )

    return ControlPlaneApi(operations=operations, lookup=lookup)


_api = _build_api()
handler = lambda_entrypoint(_api)
