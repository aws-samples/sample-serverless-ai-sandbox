# kiro-classification: public
"""State sync: batch-describe active sessions and mirror platform state to DynamoDB.

Runs as part of the Reaper sweep to detect sessions that the platform auto-suspended.
Without polling, DDB may show RUNNING for sessions the platform has suspended. This
module describes the actual provider state and updates DDB to match.

If a session's ``suspended_seconds`` has expired, sends the task token callback to
wake the orchestrator for teardown.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Final

import boto3

logger = logging.getLogger(__name__)

_MILLISECONDS_PER_SECOND: Final = 1000


def sync_active_sessions() -> dict[str, Any]:
    """Query RUNNING sessions from DDB, describe each via the provider, update stale state.

    Returns a summary of what was synced.
    """
    table_name = os.environ.get("TABLE_NAME", "")
    if not table_name:
        return {"synced": 0, "error": "TABLE_NAME not set"}

    ddb = boto3.resource("dynamodb").Table(table_name)  # nosemgrep  # nosec
    sfn = boto3.client("stepfunctions")

    # Query sessions in RUNNING state using the lifecycle-state-index GSI
    # (or scan with filter — depends on index availability)
    try:
        response = ddb.scan(  # nosemgrep  # nosec
            FilterExpression="lifecycleState = :state",
            ExpressionAttributeValues={":state": "RUNNING"},
            ProjectionExpression="pk, sk, sessionId, tenantId, lifecycleState, "
                                "sandboxHandle, taskToken, suspendedSeconds, createdAt, "
                                "maxDurationSeconds, updatedAt",
        )
        items = response.get("Items", [])
    except Exception as exc:
        logger.warning("State sync scan failed: %s", exc)
        return {"synced": 0, "error": str(exc)[:200]}

    synced = 0
    callbacks_sent = 0
    now_ms = int(time.time() * 1000)

    for item in items:
        session_id = item.get("sessionId", "?")
        try:
            # Describe the sandbox via the Lambda MicroVM provider
            handle = item.get("sandboxHandle")
            if not handle:
                continue

            provider_name = handle.get("providerName", "")
            sandbox_id = handle.get("sandboxId", "")
            if not provider_name or not sandbox_id:
                continue

            # Call the Lambda MicroVM describe API
            lambda_client = boto3.client("lambda")
            opaque = handle.get("opaque", {})
            microvm_id = opaque.get("microvmId", sandbox_id)

            try:
                desc_resp = lambda_client.get_function(FunctionName=microvm_id)
                state = desc_resp.get("Configuration", {}).get("State", "Unknown")
            except Exception:  # nosec B112 — describe call may fail for deleted MicroVMs; skip and continue sweep
                continue

            # Map Lambda state to our lifecycle state
            platform_suspended = state in ("Inactive", "Suspended")

            if platform_suspended:
                # The platform suspended this session but DDB still says RUNNING
                pk = item.get("pk", "")
                sk = item.get("sk", "")

                # Update DDB to SUSPENDED
                try:
                    ddb.update_item(
                        Key={"pk": pk, "sk": sk},
                        UpdateExpression="SET lifecycleState = :state, updatedAt = :now",
                        ConditionExpression="lifecycleState = :running",
                        ExpressionAttributeValues={
                            ":state": "SUSPENDED",
                            ":now": now_ms,
                            ":running": "RUNNING",
                        },
                    )
                    synced += 1
                    logger.info("State sync: session %s RUNNING→SUSPENDED", session_id)
                except Exception:  # nosec B110 — DDB condition failure means another process updated; safe to ignore
                    pass

                # Check if suspended_seconds has expired
                suspended_seconds = int(item.get("suspendedSeconds", 3600))
                updated_at = int(item.get("updatedAt", now_ms))
                suspended_duration = (now_ms - updated_at) // _MILLISECONDS_PER_SECOND

                if suspended_duration >= suspended_seconds:
                    # Send tear-down callback
                    task_token = item.get("taskToken", "")
                    if task_token:
                        try:
                            sfn.send_task_success(
                                taskToken=task_token,
                                output=json.dumps({
                                    "decision": "tear-down",
                                    "source": "reaper-state-sync",
                                    "reason": "suspended-too-long",
                                }),
                            )
                            callbacks_sent += 1
                            logger.info(
                                "State sync: session %s suspended too long (%ds > %ds), sent tear-down",
                                session_id, suspended_duration, suspended_seconds,
                            )
                        except Exception as exc:
                            logger.warning(
                                "Failed to send tear-down callback for session %s: %s",
                                session_id, exc,
                            )

        except Exception as exc:
            logger.warning("State sync error for session %s: %s", session_id, exc)

    return {
        "synced": synced,
        "callbacks_sent": callbacks_sent,
        "sessions_checked": len(items),
    }
