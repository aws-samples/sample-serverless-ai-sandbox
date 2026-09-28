#!/usr/bin/env python3
"""Suspend/resume — pause a sandbox and resume it with full memory + disk state."""

import os
import time
from agent_sandbox import SandboxClient

API_URL = os.environ.get("API_URL", "")
if not API_URL:
    print("Set API_URL environment variable. Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com")
    exit(1)
REGION = os.environ.get("AWS_REGION", "us-east-1")
TOKEN = os.environ.get("SANDBOX_TOKEN")

client = SandboxClient(api_url=API_URL, region=REGION, token=TOKEN)

print("Creating sandbox session...")
session = client.create_session(max_duration_seconds=600)
session.wait_ready(timeout=60)
print(f"Session {session.session_id[:12]}... is RUNNING\n")

# Create state
session.execute("echo 'I was here before suspend' > /tmp/memory_test.txt")
session.execute("HOME=/tmp pip install --quiet --target /tmp/pylibs cowsay")
result = session.execute("PYTHONPATH=/tmp/pylibs python3 -c \"import cowsay; cowsay.cow('Before suspend!')\"")
print(f"Before suspend:\n{result.stdout}")

# Suspend
print("Suspending...")
session.suspend()
time.sleep(5)
print("Sandbox is frozen. Memory + disk state preserved.\n")

# Resume
print("Resuming...")
session.resume()
session.wait_ready(timeout=60)
print("Sandbox resumed!\n")

# Verify state survived
result = session.execute("cat /tmp/memory_test.txt")
print(f"File survived: {result.stdout.strip()}")

result = session.execute("PYTHONPATH=/tmp/pylibs python3 -c \"import cowsay; cowsay.cow('After resume!')\"")
print(f"Package survived:\n{result.stdout}")

session.terminate()
print("Session terminated.")
