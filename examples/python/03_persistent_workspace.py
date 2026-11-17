#!/usr/bin/env python3
# kiro-classification: public
"""Persistent workspace — files survive session termination via S3 Files.

Two sessions share the same workspace using an affinity key. Session 1 writes
files to /mnt/workspace (backed by S3 Files). Session 2 reads them back,
proving the data persisted across session boundaries.

Prerequisites:
    - S3 Files infrastructure set up (see docs/persistence-setup.md)
    - CDK deployed with s3filesFilesystemId, s3filesAccessPointId, s3filesMountTargetIps

Usage:
    export API_URL="https://xxx.execute-api.us-east-1.amazonaws.com"
    export AWS_REGION="us-east-1"
    python examples/03_persistent_workspace.py
"""

import os
import time
from agent_sandbox import SandboxClient

API_URL = os.environ.get("API_URL", "")
if not API_URL:
    print("Set API_URL environment variable.")
    print("Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com")
    exit(1)
REGION = os.environ.get("AWS_REGION", "us-east-1")
TOKEN = os.environ.get("SANDBOX_TOKEN")

client = SandboxClient(api_url=API_URL, region=REGION, token=TOKEN)

# Both sessions share this key — same key = same workspace in S3
AFFINITY_KEY = "demo-persistent-workspace"

# ─────────────────────────────────────────────────────────────
# Session 1: Write files to the persistent workspace
# ─────────────────────────────────────────────────────────────
print("=" * 55)
print("Session 1: Writing files to persistent workspace")
print("=" * 55)

# Context manager: session.terminate() is called automatically when the block exits
with client.create_session(persistence=True, affinity_key=AFFINITY_KEY) as session1:
    session1.wait_ready(timeout=60)
    print(f"  Session ID: {session1.session_id[:12]}...")

    # Verify the workspace is mounted
    r = session1.execute("mountpoint /mnt/workspace && echo 'S3 Files mount active'")
    print(f"  Mount: {r.stdout.strip()}")

    # The workspace is backed by S3 at:
    #   s3://<bucket>/workspaces/<tenantId>/<principalId>/<sessionId>/
    # Files written here persist after the session terminates.
    workspace = session1.session_data.get("workspace", {})
    bucket = workspace.get("bucket", "(not available)")
    print(f"  S3 bucket: {bucket}")

    # Write two files
    session1.execute("echo 'Created by Session 1 at '$(date) > /mnt/workspace/hello.txt")
    session1.execute("echo '{\"counter\": 1, \"source\": \"session-1\"}' > /mnt/workspace/state.json")
    print(f"\n  Files created in /mnt/workspace/:")
    r = session1.execute("ls -la /mnt/workspace/")
    for line in r.stdout.strip().split("\n")[1:]:  # skip "total" line
        print(f"    {line}")

print("\n  Session 1 terminated — files persist in S3.\n")

# Brief pause for S3 sync
time.sleep(3)

# ─────────────────────────────────────────────────────────────
# Session 2: Read files from the same workspace
# ─────────────────────────────────────────────────────────────
print("=" * 55)
print("Session 2: Reading files from persistent workspace")
print("=" * 55)

# Context manager: session.terminate() is called automatically when the block exits
with client.create_session(persistence=True, affinity_key=AFFINITY_KEY) as session2:
    session2.wait_ready(timeout=60)
    print(f"  Session ID: {session2.session_id[:12]}... (different session, same workspace)")

    # List what survived from Session 1
    print(f"\n  Files found in /mnt/workspace/:")
    r = session2.execute("ls -la /mnt/workspace/")
    for line in r.stdout.strip().split("\n")[1:]:
        print(f"    {line}")

    # Read them back
    print(f"\n  Reading files written by Session 1:")
    r = session2.execute("cat /mnt/workspace/hello.txt")
    print(f"    hello.txt:  {r.stdout.strip()}")
    r = session2.execute("cat /mnt/workspace/state.json")
    print(f"    state.json: {r.stdout.strip()}")

    # Append to prove Session 2 can also write
    session2.execute("echo 'Updated by Session 2 at '$(date) >> /mnt/workspace/hello.txt")
    print(f"\n  Session 2 appended to hello.txt:")
    r = session2.execute("cat /mnt/workspace/hello.txt")
    for line in r.stdout.strip().split("\n"):
        print(f"    {line}")

print("\n  Session 2 terminated — files still persist for the next session.")
