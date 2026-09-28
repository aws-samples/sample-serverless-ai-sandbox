#!/usr/bin/env python3
"""Multi-tenant isolation — two tenants, isolated data partitions."""

import os
from agent_sandbox import SandboxClient

API_URL = os.environ.get("API_URL", "")
if not API_URL:
    print("Set API_URL environment variable. Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com")
    exit(1)
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Two different tenants
tenant_a = SandboxClient(api_url=API_URL, region=REGION, token="demo-token-tenant-a")
tenant_b = SandboxClient(api_url=API_URL, region=REGION, token="demo-token-tenant-b")

print("=== Tenant A ===")
sessions_a = tenant_a.list_sessions()
print(f"Tenant A sees {len(sessions_a)} session(s)")

print("\n=== Tenant B ===")
sessions_b = tenant_b.list_sessions()
print(f"Tenant B sees {len(sessions_b)} session(s)")

print("\n=== Creating a session as Tenant A ===")
with tenant_a.create_session() as session:
    session.wait_ready(timeout=60)
    print(f"Tenant A session: {session.session_id[:12]}...")

    result = session.execute("echo 'Hello from Tenant A sandbox'")
    print(f"Output: {result.stdout.strip()}")

    # Tenant A sees their session
    sessions_a = tenant_a.list_sessions()
    print(f"Tenant A now sees {len(sessions_a)} session(s)")

    # Tenant B cannot see Tenant A's sessions
    sessions_b = tenant_b.list_sessions()
    print(f"Tenant B still sees {len(sessions_b)} session(s) (isolation!)")

print("\nTenant A session terminated.")
tenant_a.close()
tenant_b.close()
