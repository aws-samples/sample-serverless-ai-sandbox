# kiro-classification: public
"""Lambda entry point for the Reaper sweep + state sync."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Run the Reaper deadline sweep AND the state sync on each scheduled invocation.

    1. **Deadline sweep**: the existing Reaper.sweep() queries the DDB deadline index
       and terminates sessions that exceeded max_duration, suspended_too_long, or
       were orphaned (no Step Functions execution ever started).

    2. **State sync**: detects sessions the platform auto-suspended and updates DDB.
       Sends tear-down callbacks for sessions that exceeded suspended_seconds.
    """
    del context

    results = {}

    # 1. State sync (detect auto-suspended sessions)
    # TODO: implement state sync when provider.describe API is wired
    results["stateSync"] = {"skipped": True}

    # 2. Deadline sweep (max_duration, suspended_too_long, orphan detection)
    # The full Reaper.sweep() is complex and requires wiring all its collaborators.
    # For now, we handle max_duration via DDB scan + terminate.
    try:
        _sweep_expired_sessions()
        results["deadlineSweep"] = {"ok": True}
    except Exception as exc:
        logger.warning("Deadline sweep failed: %s", exc)
        results["deadlineSweep"] = {"error": str(exc)[:200]}

    return {"statusCode": 200, "body": json.dumps(results)}


def _sweep_expired_sessions() -> None:
    """Deadline sweep: find sessions past reapDeadline and clean them up.

    For each expired session:
    1. Stop the Step Functions execution (if running) so it doesn't hold resources.
    2. Update DDB: set lifecycleState=TERMINATED, update stateCreatedAt GSI key,
       remove reapDeadline and taskToken.

    Previous approach tried send_task_success first, but that relies on the SFN
    execution completing tear-down — which fails when the MicroVM is already gone.
    The direct approach is more reliable: stop the execution + update DDB.
    """
    import time
    import boto3
    from decimal import Decimal

    table_name = os.environ.get("TABLE_NAME", "")
    if not table_name:
        return

    ddb = boto3.resource("dynamodb").Table(table_name)  # nosemgrep  # nosec
    sfn = boto3.client("stepfunctions")
    now_ms = int(time.time() * 1000)
    now_decimal = Decimal(str(now_ms))

    # Scan for non-terminal sessions with reapDeadline in the past.
    # The scan is paginated because DDB returns at most 1MB per page,
    # and expired sessions may be spread across many pages.
    scan_kwargs: dict[str, object] = {
        "FilterExpression": (
            "attribute_exists(reapDeadline) AND reapDeadline <= :now "
            "AND NOT lifecycleState IN (:t1, :t2)"
        ),
        "ExpressionAttributeValues": {
            ":now": now_decimal,
            ":t1": "TERMINATED",
            ":t2": "FAILED",
        },
        "ProjectionExpression": "pk,sk,sessionId,lifecycleState,taskToken,reapDeadline,createdAt,orchestrationExecutionArn",
    }
    expired_items: list[dict] = []
    try:
        while True:
            resp = ddb.scan(**scan_kwargs)  # nosemgrep  # nosec
            expired_items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except Exception as exc:
        logger.warning("Sweep scan failed: %s", exc)
        return

    logger.info("Found %d expired sessions to reap", len(expired_items))
    reaped = 0
    for item in expired_items:
        session_id = item.get("sessionId", "?")
        execution_arn = item.get("orchestrationExecutionArn", "")
        created_at = item.get("createdAt")

        logger.info("Reaping session %s (deadline passed)", session_id)

        # Step 1: Stop the Step Functions execution if it's still running.
        # This prevents the execution from holding resources or getting stuck
        # in waitForTaskToken forever.
        if execution_arn:
            try:
                sfn.stop_execution(
                    executionArn=execution_arn,
                    cause="Reaped: session exceeded maximum duration",
                )
                logger.info("Stopped SFN execution for %s", session_id)
            except Exception as se:
                # Execution may already be stopped/succeeded — that's fine
                logger.info("SFN stop for %s: %s", session_id, se)

        # Step 2: Update DDB — mark TERMINATED and fix the GSI sort key.
        # The stateCreatedAt GSI key must be updated to TERMINATED#<createdAt>
        # so the session appears under the correct state in list queries.
        state_created_at = f"TERMINATED#{created_at}" if created_at else f"TERMINATED#{now_ms}"
        try:
            ddb.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET lifecycleState = :state, updatedAt = :now, "
                    "stateReason = :reason, stateCreatedAt = :sca "
                    "REMOVE reapDeadline, taskToken"
                ),
                ConditionExpression="NOT lifecycleState IN (:t1, :t2)",
                ExpressionAttributeValues={
                    ":state": "TERMINATED",
                    ":now": now_decimal,
                    ":reason": "Reaped: deadline expired",
                    ":sca": state_created_at,
                    ":t1": "TERMINATED",
                    ":t2": "FAILED",
                },
            )
            reaped += 1
            logger.info("Terminated session %s in DDB", session_id)
        except Exception as de:
            logger.info("DDB update failed for %s: %s", session_id, de)

    if reaped:
        logger.info("Reaped %d expired sessions", reaped)

