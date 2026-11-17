#!/usr/bin/env python3
"""Data analysis in a sandbox — upload CSV, run pandas, download results."""

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
with client.create_session(max_duration_seconds=600) as session:
    session.wait_ready(timeout=60)
    print(f"Session ready: {session.session_id[:12]}...\n")

    # Upload a CSV file
    csv_data = "name,age,city\nAlice,30,Seattle\nBob,25,Portland\nCharlie,35,San Francisco\nDiana,28,Denver"
    session.write_file("/tmp/people.csv", csv_data)
    print("Uploaded people.csv")

    # Install pandas (into /tmp since rootfs is read-only)
    print("Installing pandas...")
    result = session.execute(
        "HOME=/tmp pip install --quiet --target /tmp/pylibs pandas",
        timeout_seconds=120,
    )

    # Run analysis
    analysis_script = '''
import sys; sys.path.insert(0, "/tmp/pylibs")
import pandas as pd

df = pd.read_csv("/tmp/people.csv")
print("=== Data ===")
print(df.to_string(index=False))
print(f"\\n=== Stats ===")
print(f"Average age: {df['age'].mean():.1f}")
print(f"Oldest: {df.loc[df['age'].idxmax(), 'name']} ({df['age'].max()})")
print(f"Youngest: {df.loc[df['age'].idxmin(), 'name']} ({df['age'].min()})")
print(f"Cities: {', '.join(df['city'].unique())}")
'''
    session.write_file("/tmp/analyze.py", analysis_script)
    result = session.execute("PYTHONPATH=/tmp/pylibs python3 /tmp/analyze.py")
    print(f"\n{result.stdout}")

print("Session terminated.")
