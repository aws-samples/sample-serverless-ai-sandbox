# kiro-classification: public
"""Agent workload steps (R16.1, R16.2, R16.3, R16.4).

1. Create a Session via ``POST /sessions`` (SigV4-signed).
2. Execute a basic command inside the Sandbox.
3. Invoke Amazon Bedrock from inside the Sandbox via the Egress_Controller proxy (R16.2) —
   the MicroVM writes a Python script and executes it, sending a forward proxy request
   through the NLB to the proxy fleet that re-signs with the proxy task role's credentials.
4. Execute model-generated code inside the Sandbox and return its output (R16.3).
5. Stream intermediate output before completion (R16.4).
"""

from __future__ import annotations

import textwrap
import time
from typing import Any

from demo.driver import DemoContext, DemoStep, StepCallable, StepRegistry
from demo.sandbox import SandboxClient

__all__ = ["register_workload_steps"]

#: A small Python script that calls Bedrock from inside the Sandbox.  The MicroVM reaches
#: Bedrock through the Egress_Controller proxy (NLB → Fargate fleet → SigV4 re-sign → upstream).
#:
#: The proxy is a Tier 1 HTTP forward proxy: the MicroVM sends a plaintext HTTP request whose
#: URL names the Bedrock Runtime host, and the proxy strips the Sandbox's credentials, re-signs
#: with its own IAM role (R12.5, R16.2), and forwards the request over TLS to the upstream.
#:
#: We connect to the NLB on plain TCP and send an absolute-form request line
#: (``POST http://bedrock-runtime.<region>.amazonaws.com/... HTTP/1.1``) so that the proxy
#: handles it as a forward proxy request, not a CONNECT tunnel.
#:
#: The execution role carries an explicit deny on ``bedrock:InvokeModel*`` and
#: ``bedrock:Converse*``, so a direct call (bypassing the proxy) fails with AccessDenied.
#: The proxy's task role holds the allow.
_BEDROCK_SCRIPT: str = textwrap.dedent("""\
    import http.client, json, os, sys

    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    proxy_endpoint = os.environ.get("EGRESS_PROXY_ENDPOINT", "")
    bedrock_host = f"bedrock-runtime.{region}.amazonaws.com"

    if not proxy_endpoint:
        print("EGRESS_PROXY_ENDPOINT not set", file=sys.stderr)
        sys.exit(1)

    body = json.dumps({
        "modelId": "amazon.nova-micro-v1:0",
        "messages": [{"role": "user", "content": [{"text": "Respond with exactly: Hello from Bedrock"}]}],
        "inferenceConfig": {"maxTokens": 64, "temperature": 0.0},
    }).encode()

    # Connect to the proxy NLB on plain TCP (port 443, no TLS on this leg).
    # SECURITY NOTE: The MicroVM-to-proxy leg uses plain HTTP because the forward
    # proxy design requires absolute-form URLs for SigV4 re-signing. The internal
    # network segment (connector subnet -> NLB) is isolated with zero external routes.
    # For end-to-end TLS, use a CONNECT tunnel instead of forward proxy.
    conn = http.client.HTTPConnection(proxy_endpoint, 443, timeout=30)
    # Absolute-form URL tells the proxy this is a forward request, not a tunnel.
    conn.request(
        "POST",
        f"http://{bedrock_host}/model/amazon.nova-micro-v1:0/converse",
        body=body,
        headers={
            "Host": bedrock_host,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    resp = conn.getresponse()
    resp_body = resp.read()
    conn.close()

    if resp.status != 200:
        print(f"HTTP {resp.status}: {resp_body.decode('utf-8', errors='replace')[:500]}", file=sys.stderr)
        sys.exit(1)

    result = json.loads(resp_body)
    text = result["output"]["message"]["content"][0]["text"].strip()
    print(text)
""")

#: Code that the demo pretends a model generated, then runs inside the Sandbox (R16.3).
_MODEL_GENERATED_CODE: str = textwrap.dedent("""\
    import math, json
    result = {"pi": round(math.pi, 8), "sqrt2": round(math.sqrt(2), 8)}
    print(json.dumps(result))
""")


def _make_create_session(*, persistence: bool = False) -> StepCallable:
    """Return a create-session step, optionally with persistence enabled."""

    def _step_create_session(ctx: DemoContext) -> dict[str, Any]:
        """Create a Session and store its identifier and connection on the context."""
        body: dict[str, Any] = {
            "maxDurationSeconds": 3600,
            "idleSeconds": 300,
            "suspendedSeconds": 600,
            "autoResume": True,
            "memoryBytes": 536_870_912,  # 512 MiB
        }
        if persistence:
            body["persistence"] = True
        response = ctx.client.create_session(body)
        ctx.session_id = response["sessionId"]
        ctx.connection = response.get("connection")

        # If no connection yet (async creation returns 202), poll GetSession until
        # the orchestrator publishes the connection credential onto the Session row.
        if ctx.connection is None:
            for _attempt in range(60):  # poll for up to 120 seconds
                time.sleep(2)  # nosemgrep: arbitrary-sleep — polling loop by design
                session = ctx.client.get_session(ctx.session_id)
                ctx.connection = session.get("connection")
                if ctx.connection is not None:
                    break
            if ctx.connection is None:
                raise RuntimeError(
                    "Session created but connection credential never appeared after 120s"
                )

        # Build the Sandbox client from the connection descriptor.
        ctx.sandbox_client = SandboxClient.from_connection(ctx.connection)

        return {
            "sessionId": ctx.session_id,
            "lifecycleState": response.get("lifecycleState", "unknown"),
            "persistence": persistence,
        }

    return _step_create_session


def _step_basic_command(ctx: DemoContext) -> dict[str, Any]:
    """Execute a basic command — ``echo "Hello from Sandbox"``."""
    assert ctx.sandbox_client is not None
    result = ctx.sandbox_client.execute(["echo", "Hello from Sandbox"])
    return {"output": result}


def _step_bedrock_invocation(ctx: DemoContext) -> dict[str, Any]:
    """Invoke Amazon Bedrock from inside the Sandbox (R16.2).

    Writes a Python script to the Sandbox filesystem, then executes it.  The MicroVM reaches
    Bedrock through the Egress_Controller proxy: ``EGRESS_PROXY_ENDPOINT`` tells boto3 to route
    through the NLB, where the proxy strips the Sandbox's credentials and re-signs with its own
    IAM role.
    """
    assert ctx.sandbox_client is not None

    ctx.sandbox_client.write_file("/tmp/bedrock_demo.py", _BEDROCK_SCRIPT.encode())  # nosec B108

    env: dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",  # nosec B108
        "AWS_DEFAULT_REGION": ctx.region,
    }
    if ctx.egress_endpoint:
        env["EGRESS_PROXY_ENDPOINT"] = ctx.egress_endpoint

    result = ctx.sandbox_client.execute(
        ["python3", "/tmp/bedrock_demo.py"],  # nosec B108
        timeout_seconds=30,
        env=env,
    )
    return {"bedrock_output": result}


def _step_model_generated_code(ctx: DemoContext) -> dict[str, Any]:
    """Execute model-generated code inside the Sandbox and return its output (R16.3)."""
    assert ctx.sandbox_client is not None

    # Write the "model-generated" script.
    ctx.sandbox_client.write_file("/tmp/model_code.py", _MODEL_GENERATED_CODE.encode())  # nosec B108

    # Execute it.
    result = ctx.sandbox_client.execute(
        ["python3", "/tmp/model_code.py"],  # nosec B108
        timeout_seconds=15,
    )
    return {"model_code_output": result}


def _step_streaming_output(ctx: DemoContext) -> dict[str, Any]:
    """Stream intermediate output before the workload completes (R16.4).

    Uses a shell loop that prints lines with small delays, showing that output is
    available before the overall command finishes.
    """
    assert ctx.sandbox_client is not None

    # A command that produces several lines with sleeps in between.
    result = ctx.sandbox_client.execute(
        [
            "sh", "-c",
            'for i in 1 2 3 4 5; do echo "streaming line $i"; sleep 0.2; done',
        ],
        timeout_seconds=15,
    )
    return {"streamed_output": result}


def register_workload_steps(registry: StepRegistry, *, persistence: bool = False) -> None:
    """Register all workload steps on *registry*."""
    registry.register(DemoStep(
        name="create-session",
        callable=_make_create_session(persistence=persistence),
    ))
    registry.register(DemoStep(
        name="basic-command",
        callable=_step_basic_command,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="bedrock-invocation",
        callable=_step_bedrock_invocation,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="model-generated-code",
        callable=_step_model_generated_code,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="streaming-output",
        callable=_step_streaming_output,
        dependencies=("create-session",),
    ))
