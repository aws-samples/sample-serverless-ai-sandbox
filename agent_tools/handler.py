# kiro-classification: public
"""MCP Agent Tool Interface -- Model Context Protocol server over streamable HTTP.

Exposes sandbox operations as MCP tools that agent frameworks (Strands, LangChain, etc.)
can call without managing session IDs or credentials directly.

Deployed as a Lambda function behind API Gateway's ``POST /tool`` route (R20.1).

Design invariants (R20.3, R20.4):
- No tool argument carries authority (no tenant_id, session_id, affinity_key).
- No tool result carries a secret or a handle (credentials and identifiers are excluded).
- The Affinity_Key is derived from the interface's own session context, never from the model.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Any, Final

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Environment variables (set by AgentToolStack CDK)
# ---------------------------------------------------------------------------
_TABLE_NAME: Final = os.environ.get("TABLE_NAME", "")
_API_HANDLER_FUNCTION_NAME: Final = os.environ.get("API_HANDLER_FUNCTION_NAME", "")

# ---------------------------------------------------------------------------
# In-memory session cache (per Lambda execution environment)
# ---------------------------------------------------------------------------
_session_cache: dict[str, dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Tool definitions (R20.2)
# ---------------------------------------------------------------------------
TOOLS: Final[list[dict[str, Any]]] = [
    {
        "name": "execute_command",
        "description": (
            "Execute a shell command inside the sandbox environment. "
            "Returns exit code, stdout, and stderr."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory (default: /tmp)",
                    "default": "/tmp",  # nosec B108
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 60)",
                    "default": 60,
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a file from the sandbox filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file in the sandbox filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file",
                },
                "content": {
                    "type": "string",
                    "description": "File content to write",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_files",
        "description": "List files and directories at the given path in the sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (default: /tmp)",
                    "default": "/tmp",  # nosec B108
                },
            },
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file from the sandbox filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to delete",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "get_session_info",
        "description": (
            "Get information about the current sandbox session, "
            "including lifecycle state and readiness."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for MCP tool calls via API Gateway HTTP API."""
    body = event.get("body", "{}")
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()

    try:
        request = json.loads(body) if isinstance(body, str) else body
    except json.JSONDecodeError:
        return _jsonrpc_error(None, -32700, "Parse error")

    method: str = request.get("method", "")
    request_id = request.get("id")
    params: dict[str, Any] = request.get("params", {})

    # Extract session context from headers for Affinity_Key derivation (R20.3).
    headers = event.get("headers", {})
    # PCSR Finding 4: extract caller identity from API Gateway IAM context.
    # POST /tool uses AWS_IAM auth, so requestContext.authorizer.iam.userArn is the caller.
    request_context = event.get("requestContext", {})
    caller_arn = (
        request_context.get("authorizer", {}).get("iam", {}).get("userArn", "")
        or request_context.get("authorizer", {}).get("principalId", "")
        or "unknown"
    )
    # PCSR Finding 4: bind session key to caller identity so different IAM principals
    # cannot share sessions even with the same key header.
    raw_session_key = (
        headers.get("x-session-key", "")
        or headers.get("x-mcp-session-id", "")
        or headers.get("mcp-session-id", "")
    )
    if raw_session_key:
        import hashlib
        session_key = hashlib.sha256(f"{caller_arn}:{raw_session_key}".encode()).hexdigest()[:32]
    else:
        session_key = ""

    try:
        if method == "initialize":
            result = _handle_initialize(params)
        elif method == "tools/list":
            result = _handle_tools_list()
        elif method == "tools/call":
            result = _handle_tool_call(params, session_key, caller_arn)
        elif method == "ping":
            result = {}
        else:
            return _jsonrpc_error(request_id, -32601, f"Method not found: {method}")

        return _jsonrpc_response(request_id, result)
    except Exception as exc:
        logger.exception("Error handling MCP request")
        return _jsonrpc_error(request_id, -32603, str(exc))


# ---------------------------------------------------------------------------
# MCP method handlers
# ---------------------------------------------------------------------------


def _handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    """Handle MCP ``initialize`` -- return server capabilities."""
    return {
        "protocolVersion": "2025-03-26",
        "capabilities": {
            "tools": {"listChanged": False},
        },
        "serverInfo": {
            "name": "aws-serverless-agent-sandbox",
            "version": "1.0.0",
        },
    }


def _handle_tools_list() -> dict[str, Any]:
    """Handle ``tools/list`` -- return all available tools."""
    return {"tools": TOOLS}


def _handle_tool_call(params: dict[str, Any], session_key: str, caller_arn: str = "") -> dict[str, Any]:
    """Handle ``tools/call`` -- route to the appropriate tool implementation."""
    tool_name: str = params.get("name", "")
    arguments: dict[str, Any] = params.get("arguments", {})

    # Ensure we have a sandbox session.
    session = _get_or_create_session(session_key, caller_arn)

    # Build a SandboxClient from the session's connection descriptor.
    from demo.sandbox import SandboxClient

    sandbox = SandboxClient.from_connection(session["connection"])

    # Route to the tool implementation.
    router: dict[str, Any] = {
        "execute_command": _tool_execute_command,
        "read_file": _tool_read_file,
        "write_file": _tool_write_file,
        "list_files": _tool_list_files,
        "delete_file": _tool_delete_file,
    }

    if tool_name == "get_session_info":
        return _tool_get_session_info(session)

    tool_fn = router.get(tool_name)
    if tool_fn is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return tool_fn(sandbox, arguments)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _tool_execute_command(sandbox: Any, args: dict[str, Any]) -> dict[str, Any]:
    """Run a shell command inside the Sandbox."""
    command: str = args.get("command", "")
    cwd: str = args.get("cwd", "/tmp")  # nosec B108
    timeout: int = args.get("timeout_seconds", 60)

    result = sandbox.execute(
            # SECURITY: sandbox MicroVM isolation is the control, not input sanitization
        ["sh", "-c", command],
        cwd=cwd,
        timeout_seconds=timeout,
    )

    # Extract stdout, stderr, exit code from the protocol response.
    stdout = result.get("field_2", "")
    stderr = result.get("field_3", "")
    exit_code = result.get("field_1", -1)

    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "exit_code": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                    }
                ),
            }
        ],
    }


def _tool_read_file(sandbox: Any, args: dict[str, Any]) -> dict[str, Any]:
    """Read a file from the Sandbox filesystem."""
    path: str = args.get("path", "")
    content = sandbox.read_file(path)
    return {
        "content": [
            {"type": "text", "text": content.decode(errors="replace")}
        ],
    }


def _tool_write_file(sandbox: Any, args: dict[str, Any]) -> dict[str, Any]:
    """Write content to a file in the Sandbox filesystem."""
    path: str = args.get("path", "")
    content: str = args.get("content", "")
    sandbox.write_file(path, content.encode())
    return {
        "content": [
            {"type": "text", "text": f"Written {len(content)} bytes to {path}"}
        ],
    }


def _tool_list_files(sandbox: Any, args: dict[str, Any]) -> dict[str, Any]:
    """List files and directories in the Sandbox."""
    path: str = args.get("path", "/tmp")  # nosec B108
    result = sandbox.execute(["ls", "-la", path], timeout_seconds=10)
    output = result.get("field_2", "")
    return {
        "content": [{"type": "text", "text": output}],
    }


def _tool_delete_file(sandbox: Any, args: dict[str, Any]) -> dict[str, Any]:
    """Delete a file from the Sandbox filesystem."""
    path: str = args.get("path", "")
    sandbox.execute(["rm", "-f", path], timeout_seconds=10)
    return {
        "content": [{"type": "text", "text": f"Deleted {path}"}],
    }


def _tool_get_session_info(session: dict[str, Any]) -> dict[str, Any]:
    """Return sanitised session info -- no credentials or identifiers per R20.4."""
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "lifecycle_state": session.get("lifecycleState", ""),
                        "ready": session.get("connection") is not None,
                    }
                ),
            }
        ],
    }


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


def _get_or_create_session(session_key: str, caller_arn: str = "") -> dict[str, Any]:
    """Get an existing session from cache or create a new one via the Control Plane.

    Session provisioning (MicroVM creation) can take 20-40s, which exceeds the API
    Gateway 30s integration timeout. The strategy:
    1. Check the in-memory cache first (hot path, <1ms).
    2. If a session_id is cached but has no connection yet, poll for it.
    3. Otherwise, create a new session and poll within the remaining Lambda budget.
    """
    # Check in-memory cache first.
    if session_key and session_key in _session_cache:
        cached = _session_cache[session_key]
        if cached.get("connection"):
            return cached
        # We have a session_id from a previous create but no connection yet — poll.
        session_id = cached.get("sessionId", "")
        if session_id:
            connection = _poll_for_connection(session_id, max_seconds=25)
            if connection:
                cached["connection"] = connection
                return cached
            raise RuntimeError(
                "Sandbox is still provisioning. Please retry in a few seconds."
            )

    # Create a new session via the Control Plane API.
    session = _create_session(caller_arn)

    if session_key:
        _session_cache[session_key] = session

    return session


#: Maximum time (seconds) the handler will spend polling for a connection descriptor
#: within a single invocation, leaving headroom for the API Gateway 30s timeout.
_POLL_BUDGET_SECONDS: Final = 25


def _create_session(caller_arn: str = "") -> dict[str, Any]:
    """Create a new sandbox session via direct Lambda invocation of the API handler.

    PCSR Finding 4: passes the real caller ARN as the principal identity.
    """
    import boto3

    lambda_client = boto3.client(
        "lambda", region_name=os.environ.get("AWS_REGION", "us-east-1")
    )

    # Build a synthetic API Gateway v2 event for CreateSession.
    # PCSR Finding 4: use the real caller ARN instead of a hardcoded tenant.
    event = {
        "version": "2.0",
        "rawPath": "/sessions",
        "requestContext": {
            "http": {"method": "POST"},
            "authorizer": {
                "iam": {
                    "userArn": caller_arn or "arn:aws:iam::internal:role/AgentToolFunction",
                },
                "tenantId": os.environ.get("TENANT_ID", "operator"),
            },
        },
        "body": json.dumps(
            {
                "maxDurationSeconds": 3600,
                "idleSeconds": 300,
                "suspendedSeconds": 600,
                "autoResume": True,
            }
        ),
        "isBase64Encoded": False,
    }

    response = lambda_client.invoke(
        FunctionName=_API_HANDLER_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode(),
    )

    payload = json.loads(response["Payload"].read())
    status = payload.get("statusCode", 500)
    if status >= 400:
        raise RuntimeError(
            f"CreateSession failed: HTTP {status}: {payload.get('body', '')}"
        )

    body_str = payload.get("body", "{}")
    result: dict[str, Any] = (
        json.loads(body_str) if isinstance(body_str, str) else body_str
    )

    connection = result.get("connection")

    # If no connection yet (async creation), poll GetSession.
    if not connection:
        session_id = result.get("sessionId", "")
        connection = _poll_for_connection(session_id, max_seconds=_POLL_BUDGET_SECONDS)
        if connection:
            result["connection"] = connection
        else:
            raise RuntimeError(
                "Sandbox is still provisioning. Please retry in a few seconds."
            )

    return result


def _poll_for_connection(
    session_id: str, *, max_seconds: int = 25
) -> dict[str, Any] | None:
    """Poll ``GetSession`` via direct Lambda invocation within a time budget."""
    import boto3

    lambda_client = boto3.client(
        "lambda", region_name=os.environ.get("AWS_REGION", "us-east-1")
    )
    deadline = time.monotonic() + max_seconds

    while time.monotonic() < deadline:
        try:
            event = {
                "version": "2.0",
                "rawPath": f"/sessions/{session_id}",
                "requestContext": {
                    "http": {"method": "GET"},
                    "authorizer": {
                        "iam": {
                            "userArn": "arn:aws:iam::internal:role/AgentToolFunction",
                        },
                        "tenantId": os.environ.get("TENANT_ID", "operator"),
                    },
                },
                "body": None,
                "isBase64Encoded": False,
            }

            response = lambda_client.invoke(
                FunctionName=_API_HANDLER_FUNCTION_NAME,
                InvocationType="RequestResponse",
                Payload=json.dumps(event).encode(),
            )

            payload = json.loads(response["Payload"].read())
            if payload.get("statusCode", 500) == 200:
                body = json.loads(payload.get("body", "{}"))
                connection = body.get("connection")
                if connection:
                    return connection  # type: ignore[no-any-return]
        except Exception:  # nosec B110
            pass
        time.sleep(2)  # nosemgrep: arbitrary-sleep — polling loop by design

    return None


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 helpers
# ---------------------------------------------------------------------------


def _jsonrpc_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC success response wrapped in an API Gateway proxy response."""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result,
            }
        ),
    }


def _jsonrpc_error(
    request_id: Any, code: int, message: str
) -> dict[str, Any]:
    """Build a JSON-RPC error response (still HTTP 200 per the spec)."""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        ),
    }
