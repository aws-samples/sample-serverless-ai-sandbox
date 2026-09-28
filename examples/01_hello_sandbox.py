#!/usr/bin/env python3
"""Hello Sandbox — create a session, run a command, see the output."""

import os
from agent_sandbox import SandboxClient

API_URL = os.environ.get("API_URL", "")
if not API_URL:
    print("Set API_URL environment variable. Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com")
    exit(1)
REGION = os.environ.get("AWS_REGION", "us-east-1")
TOKEN = os.environ.get("SANDBOX_TOKEN")

client = SandboxClient(api_url=API_URL, region=REGION, token=TOKEN)

print("Creating sandbox session...")
with client.create_session() as session:
    session.wait_ready(timeout=60)
    print(f"Session {session.session_id[:12]}... is RUNNING\n")

    # Run a command
    result = session.execute("echo 'Hello from an isolated Firecracker MicroVM!'")
    print(f"stdout: {result.stdout}")

    # Check the environment
    result = session.execute("uname -a && python3 --version && git --version")
    print(f"Environment:\n{result.stdout}")

    # Run Python inside the sandbox
    result = session.execute(
        'python3 -c "import json; print(json.dumps({\'pi\': 3.14159, \'sandbox\': True}, indent=2))"'
    )
    print(f"Python output:\n{result.stdout}")

print("Session terminated.")
