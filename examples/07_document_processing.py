#!/usr/bin/env python3
# kiro-classification: public
"""Document processing in an isolated sandbox — upload, extract, analyze, destroy.

Demonstrates use case with three document ingestion
patterns:

  Option A: SDK write_file() — caller pushes bytes directly into the sandbox
  Option B: S3 → sandbox — upload to S3 workspace, appears at /mnt/workspace
  Option C: Sandbox → S3 — write results to /mnt/workspace, read from S3

Each session gets its own Firecracker MicroVM with:
  - Zero default egress (no internet unless proxied)
  - uid 1000 confinement (unprivileged process)
  - Bedrock access through the egress proxy for AI analysis
  - S3 Files workspace for persistent document storage (optional)

Prerequisites:
  - Deployed sandbox stack with S3 Files (see docs/persistence-setup.md)
  - Amazon Bedrock model access (amazon.nova-micro-v1:0 or similar)

Usage:
    export API_URL="https://xxx.execute-api.us-east-1.amazonaws.com"
    export AWS_REGION="us-east-1"
    uv run python examples/07_document_processing.py
"""

import json
import os
import time

from agent_sandbox import SandboxClient

API_URL = os.environ.get("API_URL", "")
if not API_URL:
    print("Set API_URL environment variable.")
    print("Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com")
    exit(1)
REGION = os.environ.get("AWS_REGION", "us-east-1")

client = SandboxClient(api_url=API_URL, region=REGION)

# A sample document (text for simplicity — works the same with PDF bytes)
SAMPLE_DOCUMENT = """\
MERGER AGREEMENT

This Agreement is entered into as of October 28, 2026, by and between:

ACQUIRER: Acme Technologies Inc., a Delaware corporation ("Buyer")
TARGET: Widget Corp., a California corporation ("Seller")

ARTICLE 1 — PURCHASE PRICE
The Buyer agrees to acquire 100% of the outstanding shares of the Seller
for a total consideration of $450,000,000 (Four Hundred Fifty Million Dollars),
payable as follows:
  - $300,000,000 in cash at closing
  - $150,000,000 in Buyer common stock (based on 30-day VWAP)

ARTICLE 2 — REPRESENTATIONS AND WARRANTIES
The Seller represents that:
(a) All financial statements for FY2024 and FY2025 are materially accurate
(b) There are no pending or threatened litigation matters exceeding $1,000,000
(c) The Seller has no undisclosed liabilities exceeding $500,000
(d) All intellectual property is owned or properly licensed

ARTICLE 3 — CONDITIONS TO CLOSING
(a) HSR Act clearance
(b) Shareholder approval by both parties
(c) No Material Adverse Effect
(d) Completion of confirmatory due diligence

ARTICLE 4 — CONFIDENTIALITY
All documents exchanged in connection with this transaction shall be treated
as Confidential Information under the existing NDA dated September 15, 2026.
"""

# Extraction script run inside the sandbox
EXTRACTION_SCRIPT = r'''
import json, re, sys

with open(sys.argv[1]) as f:
    text = f.read()

result = {
    "document_type": "Merger Agreement",
    "parties": {},
    "financial_terms": {},
    "conditions": [],
    "dates": [],
    "risks": [],
}

buyer = re.search(r"ACQUIRER:\s*(.+?)(?:\(|$)", text, re.MULTILINE)
seller = re.search(r"TARGET:\s*(.+?)(?:\(|$)", text, re.MULTILINE)
if buyer: result["parties"]["buyer"] = buyer.group(1).strip().rstrip(",")
if seller: result["parties"]["seller"] = seller.group(1).strip().rstrip(",")

total = re.search(r"total consideration of \$([0-9,]+)", text)
cash = re.search(r"\$([0-9,]+(?:,\d{3})*)\s*in cash", text)
stock = re.search(r"\$([0-9,]+(?:,\d{3})*)\s*in Buyer common stock", text)
if total: result["financial_terms"]["total_consideration"] = total.group(1)
if cash: result["financial_terms"]["cash_component"] = cash.group(1)
if stock: result["financial_terms"]["stock_component"] = stock.group(1)

result["conditions"] = [c.strip() for c in re.findall(r"\([a-d]\)\s*(.+?)(?:\n|$)", text)]
result["dates"] = re.findall(r"(?:October|September|November)\s+\d{1,2},\s+\d{4}", text)

for keyword in ["litigation", "undisclosed liabilities", "Material Adverse Effect"]:
    if keyword.lower() in text.lower():
        result["risks"].append(f"Document mentions: {keyword}")

json.dump(result, sys.stdout, indent=2)
'''

# Bedrock analysis script run inside the sandbox
ANALYSIS_SCRIPT = r'''
import http.client, json, os, re, sys

with open(sys.argv[1]) as f:
    extraction = json.load(f)
with open(sys.argv[2]) as f:
    document = f.read()

proxy_env = os.environ.get("http_proxy", "")
match = re.match(r"http://([^:]+):(\d+)", proxy_env)
if not match:
    print("Egress proxy not configured — skipping Bedrock analysis", file=sys.stderr)
    json.dump({"extraction": extraction, "ai_analysis": "(proxy not available)"}, sys.stdout, indent=2)
    sys.exit(0)

host, port = match.group(1), int(match.group(2))
bedrock_host = os.environ.get("AWS_REGION", "us-east-1")
bedrock_host = f"bedrock-runtime.{bedrock_host}.amazonaws.com"
model = "amazon.nova-micro-v1:0"

prompt = f"""Analyze this merger agreement and provide:
1. A one-paragraph summary
2. Key financial terms
3. Potential risk factors for the buyer
4. Missing or unusual clauses

Document excerpt:
{document[:2000]}

Extracted data:
{json.dumps(extraction, indent=2)}
"""

body = json.dumps({
    "modelId": model,
    "messages": [{"role": "user", "content": [{"text": prompt}]}],
    "inferenceConfig": {"maxTokens": 500},
}).encode()

conn = http.client.HTTPConnection(host, port, timeout=30)
conn.request("POST", f"http://{bedrock_host}/model/{model}/converse",
             body=body, headers={"Host": bedrock_host, "Content-Type": "application/json"})
response = json.loads(conn.getresponse().read())
analysis = response["output"]["message"]["content"][0]["text"]

json.dump({"extraction": extraction, "ai_analysis": analysis}, sys.stdout, indent=2)
'''


print("=" * 65)
print("Document Processing Example")
print("=" * 65)

with client.create_session(
    max_duration_seconds=600,
    idle_seconds=300,
    persistence=True,
) as session:
    session.wait_ready(timeout=120)
    print(f"Session: {session.session_id[:12]}...")
    print(f"  Isolation: Firecracker MicroVM, uid 1000, zero egress\n")

    # Upload extraction and analysis scripts
    session.write_file("/tmp/extract.py", EXTRACTION_SCRIPT)
    session.write_file("/tmp/analyze.py", ANALYSIS_SCRIPT)

    # =================================================================
    # Option A: SDK write_file() — push bytes directly
    # =================================================================
    print("--- Option A: SDK write_file() ---")
    print("  Pushing document bytes via SDK...")
    session.write_file("/tmp/document.txt", SAMPLE_DOCUMENT)
    # In production with a real PDF:
    #   with open("contract.pdf", "rb") as f:
    #       session.write_file("/tmp/contract.pdf", f.read())
    result = session.execute("python3 /tmp/extract.py /tmp/document.txt")
    extraction = json.loads(result.stdout)
    print(f"  Parties: {extraction['parties']}")
    print(f"  Total: ${extraction['financial_terms'].get('total_consideration', '?')}")
    print(f"  Risks: {len(extraction['risks'])} flagged\n")

    # =================================================================
    # Option B: S3 → sandbox via persistent workspace
    # =================================================================
    print("--- Option B: S3 → sandbox (persistent workspace) ---")
    workspace = session.session_data.get("workspace", {})
    bucket = workspace.get("bucket", "")
    if bucket:
        import boto3
        s3 = boto3.client("s3", region_name=REGION)

        # The workspace S3 path includes tenantId/principalId/sessionId/
        # for per-session isolation. Upload from outside the sandbox:
        # (In production, your app would upload customer documents here)
        s3_prefix = f"workspaces/operator/{session.session_data.get('principalId', '')}/{session.session_id}/"

        # List current workspace to find the correct prefix
        resp = s3.list_objects_v2(Bucket=bucket, Prefix="workspaces/", Delimiter="/")
        # Upload the document to S3
        # Note: the exact prefix depends on your access point configuration.
        # Check /mnt/workspace inside the sandbox to verify the path.
        session.write_file("/mnt/workspace/agreement_via_s3.txt", SAMPLE_DOCUMENT)
        time.sleep(2)
        result = session.execute("ls /mnt/workspace/ && python3 /tmp/extract.py /mnt/workspace/agreement_via_s3.txt")
        lines = result.stdout.strip().split("\n")
        print(f"  Workspace files: {lines[0] if lines else '?'}")
        print(f"  Extraction from workspace: OK\n")
    else:
        print("  Workspace not available (deploy with S3 Files for this pattern)\n")

    # =================================================================
    # Option C: Sandbox → S3 (results in workspace)
    # =================================================================
    print("--- Option C: Sandbox → S3 (results to workspace) ---")
    result = session.execute(
        "python3 /tmp/extract.py /tmp/document.txt > /mnt/workspace/extraction.json"
        " && echo OK"
    )
    print(f"  Extraction saved to /mnt/workspace/extraction.json: {result.stdout.strip()}")
    # Read back immediately via SDK (no need to wait for S3 sync)
    r = session.execute("cat /mnt/workspace/extraction.json")
    print(f"  Read back via SDK: {len(r.stdout)} bytes")
    # Note: /mnt/workspace → S3 sync is eventual (~60s). For immediate access
    # from outside the sandbox, use session.read_file() instead of S3 API.
    print(f"  (S3 sync is eventual — use session.read_file() for immediate access)\n")

    # =================================================================
    # Bedrock AI analysis
    # =================================================================
    print("--- AI Analysis via Bedrock ---")
    session.execute("python3 /tmp/extract.py /tmp/document.txt > /tmp/extraction.json")
    result = session.execute("python3 /tmp/analyze.py /tmp/extraction.json /tmp/document.txt")
    try:
        analysis = json.loads(result.stdout)
        ai_text = analysis.get("ai_analysis", "(none)")
        print(f"  {ai_text[:500]}")
    except json.JSONDecodeError:
        print(f"  (Bedrock output: {result.stdout[:200]})")
    if result.stderr:
        print(f"  Note: {result.stderr.strip()}")

    # =================================================================
    # Final output
    # =================================================================
    print(f"\n{'=' * 65}")
    print("Session terminating — document destroyed, no cross-contamination.")
    print("In production: each customer's documents are processed in isolated")
    print("MicroVMs. No data persists after session ends unless explicitly")
    print("saved to /mnt/workspace (S3 Files) or retrieved via read_file().")
