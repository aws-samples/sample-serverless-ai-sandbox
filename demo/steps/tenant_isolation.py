# kiro-classification: public
"""Multi-tenant isolation demo step (N2: R11.17, R11.18, R11.19, R17.10-12).

Proves that the engine isolates tenants at the data level by exercising the deployed
multi-tenant API through the Lambda authorizer with bearer tokens. Two tenants each create
a session, then attempt to access each other's — isolation means the cross-tenant read returns
404 and each tenant's list contains only their own sessions.

The step registers conditionally: it only runs when ``--deployment-profile multi-tenant`` is
passed to the demo CLI.

Two client modes are supported:

* **Bearer token** (default for multi-tenant) — sends ``Authorization: Bearer <token>`` to the
  API Gateway endpoint, exercising the full authorizer path.
* **Direct Lambda invocation** (fallback) — calls the handler directly via ``boto3``, bypassing
  API Gateway. Useful when the API is deployed with ``AWS_IAM`` and the demo operator wants to
  test isolation logic without a separate authorizer.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urljoin

import boto3  # type: ignore[import-untyped]

from demo.driver import DemoContext, DemoStep, StepRegistry

__all__ = ["register_tenant_isolation_steps"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STACK_NAME: Final = "ControlPlaneStack"
_HANDLER_LOGICAL_ID: Final = "ApiHandler"
_TENANT_A: Final = "tenant-a"
_TENANT_B: Final = "tenant-b"
_TOKEN_A: Final = "demo-token-tenant-a"
_TOKEN_B: Final = "demo-token-tenant-b"
_CALLER_ARN_A: Final = "arn:aws:iam::111111111111:user/demo-tenant-a"
_CALLER_ARN_B: Final = "arn:aws:iam::222222222222:user/demo-tenant-b"

# How long to wait for the Lambda update to propagate (seconds).
_UPDATE_POLL_INTERVAL: Final = 3
_UPDATE_MAX_WAIT: Final = 120


# ---------------------------------------------------------------------------
# Bearer-token HTTP client for multi-tenant API
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BearerTokenClient:
    """A minimal HTTP client that authenticates with ``Authorization: Bearer <token>``.

    Unlike :class:`~demo.client.ControlPlaneClient`, this client does NOT sign requests
    with SigV4. It sends the bearer token that the Lambda authorizer validates.
    """

    api_url: str
    token: str

    def create_session(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /sessions``."""
        return self._request("POST", "/sessions", body=body)

    def get_session(self, session_id: str) -> dict[str, Any]:
        """``GET /sessions/{id}``."""
        return self._request("GET", f"/sessions/{session_id}")

    def list_sessions(self) -> dict[str, Any]:
        """``GET /sessions``."""
        return self._request("GET", "/sessions")

    def terminate_session(self, session_id: str) -> dict[str, Any]:
        """``POST /sessions/{id}/terminate``."""
        return self._request("POST", f"/sessions/{session_id}/terminate")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a bearer-authenticated request and return the parsed JSON response."""
        url = urljoin(self.api_url.rstrip("/") + "/", path.lstrip("/"))
        data = json.dumps(body).encode() if body is not None else None
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req) as response: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_body = exc.read().decode(errors="replace")
            # Return status and body for assertion rather than raising, so the caller
            # can check cross-tenant 404 responses.
            try:
                parsed = json.loads(response_body)
            except json.JSONDecodeError:
                parsed = {"error": response_body}
            return {"_statusCode": status, **parsed}


# ---------------------------------------------------------------------------
# Direct Lambda invocation helpers (fallback path)
# ---------------------------------------------------------------------------


def _find_api_handler_function_name(region: str) -> str:
    """Resolve the physical Lambda function name from the CloudFormation stack."""
    cfn = boto3.client("cloudformation", region_name=region)
    paginator = cfn.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=_STACK_NAME):
        for summary in page["StackResourceSummaries"]:
            if (
                summary["LogicalResourceId"].startswith(_HANDLER_LOGICAL_ID)
                and summary["ResourceType"] == "AWS::Lambda::Function"
            ):
                return summary["PhysicalResourceId"]
    raise RuntimeError(
        f"Could not find {_HANDLER_LOGICAL_ID!r} in stack {_STACK_NAME!r}"
    )


def _get_function_env(
    lambda_client: Any, function_name: str
) -> dict[str, str]:
    """Return the current environment variables of a Lambda function."""
    config = lambda_client.get_function_configuration(FunctionName=function_name)
    return dict(config.get("Environment", {}).get("Variables", {}))


def _update_function_env(
    lambda_client: Any, function_name: str, env: dict[str, str]
) -> None:
    """Update the Lambda function's environment and wait for the update to complete."""
    lambda_client.update_function_configuration(
        FunctionName=function_name,
        Environment={"Variables": env},
    )
    deadline = time.monotonic() + _UPDATE_MAX_WAIT
    while time.monotonic() < deadline:
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        state = config.get("LastUpdateStatus", "")
        if state == "Successful":
            return
        if state == "Failed":
            reason = config.get("LastUpdateStatusReason", "unknown")
            raise RuntimeError(
                f"Lambda configuration update failed: {reason}"
            )
        time.sleep(_UPDATE_POLL_INTERVAL)
    raise RuntimeError(
        f"Lambda configuration update did not complete within {_UPDATE_MAX_WAIT}s"
    )


def _invoke_handler(
    lambda_client: Any,
    function_name: str,
    *,
    method: str,
    path: str,
    tenant_id: str,
    caller_arn: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Invoke the API handler Lambda directly with a synthetic API Gateway event."""
    event: dict[str, Any] = {
        "version": "2.0",
        "rawPath": path,
        "requestContext": {
            "http": {"method": method},
            "authorizer": {
                "iam": {"userArn": caller_arn},
                "tenantId": tenant_id,
            },
        },
        "body": None if body is None else json.dumps(body),
        "isBase64Encoded": False,
    }
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode(),
    )
    payload = json.loads(response["Payload"].read())
    status = payload.get("statusCode", 500)
    raw_body = payload.get("body", "{}")
    parsed = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
    return {"statusCode": status, "body": parsed, "raw": payload}


# ---------------------------------------------------------------------------
# Bearer-token demo step (primary path for multi-tenant deployments)
# ---------------------------------------------------------------------------


def _step_tenant_isolation(ctx: DemoContext) -> dict[str, Any]:
    """Prove multi-tenant isolation using bearer tokens through the API Gateway.

    1. Create a session as Tenant A (token A) and Tenant B (token B).
    2. Try to get Tenant A's session with Tenant B's token -> expect 404.
    3. Try to get Tenant B's session with Tenant A's token -> expect 404.
    4. List sessions for each tenant -> each sees only their own.
    5. Terminate both sessions.
    """
    api_url = ctx.client.api_url

    client_a = BearerTokenClient(api_url=api_url, token=_TOKEN_A)
    client_b = BearerTokenClient(api_url=api_url, token=_TOKEN_B)

    session_a_id: str | None = None
    session_b_id: str | None = None

    session_body: dict[str, Any] = {
        "maxDurationSeconds": 3600,
        "idleSeconds": 300,
        "suspendedSeconds": 600,
        "autoResume": True,
    }

    try:
        # --- Create session as Tenant A ------------------------------------------
        print(f"  Creating session as {_TENANT_A} (bearer token)...")
        create_a = client_a.create_session(session_body)
        assert "_statusCode" not in create_a or create_a["_statusCode"] in (200, 201, 202), (
            f"CreateSession for {_TENANT_A} failed: {create_a}"
        )
        session_a_id = create_a.get("sessionId")
        assert session_a_id, f"No sessionId in Tenant A response: {create_a}"
        print(f"  Tenant A session: {session_a_id}")

        # --- Create session as Tenant B ------------------------------------------
        print(f"  Creating session as {_TENANT_B} (bearer token)...")
        create_b = client_b.create_session(session_body)
        assert "_statusCode" not in create_b or create_b["_statusCode"] in (200, 201, 202), (
            f"CreateSession for {_TENANT_B} failed: {create_b}"
        )
        session_b_id = create_b.get("sessionId")
        assert session_b_id, f"No sessionId in Tenant B response: {create_b}"
        print(f"  Tenant B session: {session_b_id}")

        # --- Cross-tenant GetSession: Tenant B tries Tenant A's session ----------
        print("\n  Cross-tenant test: Tenant B reading Tenant A's session...")
        cross_ba = client_b.get_session(session_a_id)
        cross_ba_status = cross_ba.get("_statusCode", 200)
        assert cross_ba_status == 404, (
            f"ISOLATION BREACH: Tenant B could see Tenant A's session! "
            f"Expected 404, got {cross_ba_status}: {cross_ba}"
        )
        print("  OK: Tenant B cannot see Tenant A's session (404)")

        # --- Cross-tenant GetSession: Tenant A tries Tenant B's session ----------
        print("  Cross-tenant test: Tenant A reading Tenant B's session...")
        cross_ab = client_a.get_session(session_b_id)
        cross_ab_status = cross_ab.get("_statusCode", 200)
        assert cross_ab_status == 404, (
            f"ISOLATION BREACH: Tenant A could see Tenant B's session! "
            f"Expected 404, got {cross_ab_status}: {cross_ab}"
        )
        print("  OK: Tenant A cannot see Tenant B's session (404)")

        # --- ListSessions: each tenant sees only their own -----------------------
        print("\n  List isolation: Tenant A listing sessions...")
        list_a = client_a.list_sessions()
        sessions_a = list_a.get("sessions", [])
        session_ids_a = {s.get("sessionId") for s in sessions_a}
        assert session_a_id in session_ids_a, (
            f"Tenant A's session {session_a_id} not in their list: {session_ids_a}"
        )
        assert session_b_id not in session_ids_a, (
            f"ISOLATION BREACH: Tenant B's session {session_b_id} visible to Tenant A!"
        )
        print(f"  OK: Tenant A sees {len(sessions_a)} session(s), none from Tenant B")

        print("  List isolation: Tenant B listing sessions...")
        list_b = client_b.list_sessions()
        sessions_b = list_b.get("sessions", [])
        session_ids_b = {s.get("sessionId") for s in sessions_b}
        assert session_b_id in session_ids_b, (
            f"Tenant B's session {session_b_id} not in their list: {session_ids_b}"
        )
        assert session_a_id not in session_ids_b, (
            f"ISOLATION BREACH: Tenant A's session {session_a_id} visible to Tenant B!"
        )
        print(f"  OK: Tenant B sees {len(sessions_b)} session(s), none from Tenant A")

        isolation_result = "PASSED"

    except Exception:
        isolation_result = "FAILED"
        raise

    finally:
        # --- Cleanup: terminate both sessions ------------------------------------
        print("\n  Cleaning up...")
        for label, sid, client in [
            (_TENANT_A, session_a_id, client_a),
            (_TENANT_B, session_b_id, client_b),
        ]:
            if sid:
                try:
                    client.terminate_session(sid)
                    print(f"  Terminated {label} session {sid}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  Warning: could not terminate {label} session {sid}: {exc}")

    return {
        "isolation_result": isolation_result,
        "tenant_a": _TENANT_A,
        "tenant_b": _TENANT_B,
        "session_a": session_a_id or "not created",
        "session_b": session_b_id or "not created",
        "cross_tenant_a_to_b": "404 (correct)",
        "cross_tenant_b_to_a": "404 (correct)",
        "list_isolation_a": f"{len(sessions_a)} session(s), no cross-tenant",
        "list_isolation_b": f"{len(sessions_b)} session(s), no cross-tenant",
    }


# ---------------------------------------------------------------------------
# Direct invocation demo step (fallback for single-tenant -> multi-tenant switch)
# ---------------------------------------------------------------------------


def _step_tenant_isolation_direct(ctx: DemoContext) -> dict[str, Any]:
    """Prove multi-tenant isolation via direct Lambda invocation.

    Temporarily switches the API handler to multi-tenant mode, creates sessions as
    two distinct tenants, asserts cross-tenant isolation, then restores the original
    configuration.
    """
    region = ctx.region
    lambda_client = boto3.client("lambda", region_name=region)

    print("  Resolving API handler Lambda function...")
    function_name = _find_api_handler_function_name(region)
    print(f"  Function: {function_name}")

    print("  Saving original Lambda environment...")
    original_env = _get_function_env(lambda_client, function_name)
    original_profile = original_env.get("DEPLOYMENT_PROFILE", "single-tenant")
    original_tenant_id = original_env.get("TENANT_ID", "operator")
    print(f"  Original profile: {original_profile}, tenant: {original_tenant_id}")

    multi_tenant_env = {
        **original_env,
        "DEPLOYMENT_PROFILE": "multi-tenant",
        "TENANT_ID": "",
    }
    print("  Switching to multi-tenant mode...")
    _update_function_env(lambda_client, function_name, multi_tenant_env)
    print("  Multi-tenant mode active.")

    session_a_id: str | None = None
    session_b_id: str | None = None
    sessions_a: list[Any] = []
    sessions_b: list[Any] = []

    try:
        # --- Create sessions -----------------------------------------------------
        print(f"\n  Creating session as {_TENANT_A}...")
        create_a = _invoke_handler(
            lambda_client, function_name,
            method="POST", path="/sessions",
            tenant_id=_TENANT_A, caller_arn=_CALLER_ARN_A,
            body={"maxDurationSeconds": 3600, "idleSeconds": 300,
                  "suspendedSeconds": 600, "autoResume": True},
        )
        assert create_a["statusCode"] in (200, 201, 202), (
            f"CreateSession for {_TENANT_A} failed: {create_a}"
        )
        session_a_id = create_a["body"].get("sessionId")
        print(f"  Tenant A session: {session_a_id}")

        print(f"\n  Creating session as {_TENANT_B}...")
        create_b = _invoke_handler(
            lambda_client, function_name,
            method="POST", path="/sessions",
            tenant_id=_TENANT_B, caller_arn=_CALLER_ARN_B,
            body={"maxDurationSeconds": 3600, "idleSeconds": 300,
                  "suspendedSeconds": 600, "autoResume": True},
        )
        assert create_b["statusCode"] in (200, 201, 202), (
            f"CreateSession for {_TENANT_B} failed: {create_b}"
        )
        session_b_id = create_b["body"].get("sessionId")
        print(f"  Tenant B session: {session_b_id}")

        # --- Cross-tenant reads --------------------------------------------------
        print("\n  Cross-tenant test: Tenant B reading Tenant A's session...")
        cross_ba = _invoke_handler(
            lambda_client, function_name,
            method="GET", path=f"/sessions/{session_a_id}",
            tenant_id=_TENANT_B, caller_arn=_CALLER_ARN_B,
        )
        assert cross_ba["statusCode"] == 404, (
            f"ISOLATION BREACH: Tenant B could see Tenant A's session! "
            f"Expected 404, got {cross_ba['statusCode']}"
        )
        print("  OK: Tenant B cannot see Tenant A's session (404)")

        print("  Cross-tenant test: Tenant A reading Tenant B's session...")
        cross_ab = _invoke_handler(
            lambda_client, function_name,
            method="GET", path=f"/sessions/{session_b_id}",
            tenant_id=_TENANT_A, caller_arn=_CALLER_ARN_A,
        )
        assert cross_ab["statusCode"] == 404, (
            f"ISOLATION BREACH: Tenant A could see Tenant B's session! "
            f"Expected 404, got {cross_ab['statusCode']}"
        )
        print("  OK: Tenant A cannot see Tenant B's session (404)")

        # --- List isolation ------------------------------------------------------
        print("\n  List isolation: Tenant A listing sessions...")
        list_a = _invoke_handler(
            lambda_client, function_name,
            method="GET", path="/sessions",
            tenant_id=_TENANT_A, caller_arn=_CALLER_ARN_A,
        )
        assert list_a["statusCode"] == 200
        sessions_a = list_a["body"].get("sessions", [])
        session_ids_a = {s["sessionId"] for s in sessions_a}
        assert session_a_id in session_ids_a
        assert session_b_id not in session_ids_a, "ISOLATION BREACH: cross-tenant list leak"
        print(f"  OK: Tenant A sees {len(sessions_a)} session(s), none from Tenant B")

        print("  List isolation: Tenant B listing sessions...")
        list_b = _invoke_handler(
            lambda_client, function_name,
            method="GET", path="/sessions",
            tenant_id=_TENANT_B, caller_arn=_CALLER_ARN_B,
        )
        assert list_b["statusCode"] == 200
        sessions_b = list_b["body"].get("sessions", [])
        session_ids_b = {s["sessionId"] for s in sessions_b}
        assert session_b_id in session_ids_b
        assert session_a_id not in session_ids_b, "ISOLATION BREACH: cross-tenant list leak"
        print(f"  OK: Tenant B sees {len(sessions_b)} session(s), none from Tenant A")

        isolation_result = "PASSED"

    except Exception:
        isolation_result = "FAILED"
        raise

    finally:
        print("\n  Cleaning up...")
        for label, sid, tenant, arn in [
            (_TENANT_A, session_a_id, _TENANT_A, _CALLER_ARN_A),
            (_TENANT_B, session_b_id, _TENANT_B, _CALLER_ARN_B),
        ]:
            if sid:
                try:
                    _invoke_handler(
                        lambda_client, function_name,
                        method="POST", path=f"/sessions/{sid}/terminate",
                        tenant_id=tenant, caller_arn=arn,
                    )
                    print(f"  Terminated {label} session {sid}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  Warning: could not terminate {label} session {sid}: {exc}")

        print("  Restoring original Lambda environment...")
        restore_env = {
            **original_env,
            "DEPLOYMENT_PROFILE": original_profile,
            "TENANT_ID": original_tenant_id,
        }
        try:
            _update_function_env(lambda_client, function_name, restore_env)
            print(f"  Restored: profile={original_profile}, tenant={original_tenant_id}")
        except Exception as exc:  # noqa: BLE001
            print(f"  WARNING: Failed to restore Lambda environment: {exc}")
            print(
                f"  Manual restore may be needed: DEPLOYMENT_PROFILE={original_profile}, "
                f"TENANT_ID={original_tenant_id}"
            )

    return {
        "isolation_result": isolation_result,
        "tenant_a": _TENANT_A,
        "tenant_b": _TENANT_B,
        "session_a": session_a_id or "not created",
        "session_b": session_b_id or "not created",
        "cross_tenant_a_to_b": "404 (correct)",
        "cross_tenant_b_to_a": "404 (correct)",
        "list_isolation_a": f"{len(sessions_a)} session(s), no cross-tenant",
        "list_isolation_b": f"{len(sessions_b)} session(s), no cross-tenant",
    }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_tenant_isolation_steps(
    registry: StepRegistry, *, deployment_profile: str = "single-tenant"
) -> None:
    """Register tenant isolation steps on *registry*.

    Only registers when ``deployment_profile`` is ``"multi-tenant"``. Under single-tenant the
    step is a no-op since there is only one tenant partition.

    When multi-tenant is active, registers the bearer-token step (``tenant-isolation``) which
    exercises the full API Gateway + Lambda authorizer path.

    The direct-invocation step (``tenant-isolation-direct``) is always available as a fallback
    and can be registered manually if needed.
    """
    if deployment_profile != "multi-tenant":
        return

    registry.register(
        DemoStep(
            name="tenant-isolation",
            callable=_step_tenant_isolation,
            dependencies=("create-session",),
        )
    )
