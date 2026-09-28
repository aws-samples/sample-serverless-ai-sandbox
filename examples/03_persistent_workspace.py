#!/usr/bin/env python3
"""Persistent workspace — files survive session termination via S3 Files."""

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

AFFINITY_KEY = "demo-persistent-workspace"

# Session 1: Write files
print("--- Session 1: Writing files to persistent workspace ---")
session1 = client.create_session(persistence=True, affinity_key=AFFINITY_KEY)
session1.wait_ready(timeout=60)
print(f"Session 1: {session1.session_id[:12]}...")

result = session1.execute("mountpoint /mnt/workspace && echo 'NFS mounted'")
print(result.stdout.strip())

session1.execute("echo 'Created by Session 1 at '$(date) > /mnt/workspace/hello.txt")
session1.execute("echo '{\"counter\": 1, \"source\": \"session-1\"}' > /mnt/workspace/state.json")
result = session1.execute("ls -la /mnt/workspace/")
print(f"Workspace contents:\n{result.stdout}")

# Terminate session 1
session1.terminate()
print("Session 1 terminated.\n")
time.sleep(3)

# Session 2: Read files from the same workspace
print("--- Session 2: Reading files from persistent workspace ---")
session2 = client.create_session(persistence=True, affinity_key=AFFINITY_KEY)
session2.wait_ready(timeout=60)
print(f"Session 2: {session2.session_id[:12]}...")

result = session2.execute("echo 'Files from Session 1:' && cat /mnt/workspace/hello.txt && cat /mnt/workspace/state.json")
print(result.stdout)

# Add more data
session2.execute("echo 'Updated by Session 2 at '$(date) >> /mnt/workspace/hello.txt")
result = session2.execute("cat /mnt/workspace/hello.txt")
print(f"Updated file:\n{result.stdout}")

session2.terminate()
print("Session 2 terminated. Files persist in S3 for the next session.")
