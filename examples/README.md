# Examples

Quick demos of the AWS Serverless Agent Sandbox SDK. No web console needed.

## Setup

```bash
# From the repo root
uv sync
export API_URL="https://<your-api-id>.execute-api.<region>.amazonaws.com"
export AWS_REGION="us-east-1"
# For multi-tenant: export SANDBOX_TOKEN="demo-token-tenant-a"
```

## Run

```bash
uv run python examples/01_hello_sandbox.py
uv run python examples/02_data_analysis.py
uv run python examples/03_persistent_workspace.py
uv run python examples/04_suspend_resume.py
uv run python examples/05_multi_tenant.py
uv run python examples/06_software_factory.py
uv run python examples/07_document_processing.py
```

## Examples

| # | Name | What it shows |
|---|------|---------------|
| 01 | Hello Sandbox | Create a session, run a command, see stdout |
| 02 | Data Analysis | Upload CSV, install pandas, run analysis |
| 03 | Persistent Workspace | `/mnt/workspace` backed by S3 Files, data survives termination |
| 04 | Suspend / Resume | Suspend a session (memory + disk snapshot), resume later |
| 05 | Multi-Tenant | Bearer token auth, tenant isolation |
| 06 | Software Factory | AI coding agent (opencode) with Node.js, Bedrock, Git — requires `software-factory` image |
| 07 | Document Processing | Due diligence clean room: upload documents, extract, analyze with Bedrock |

### Example 06: Software Factory

Runs an AI coding agent (opencode) inside a governed sandbox with Node.js 22,
Bedrock model access through the egress proxy, and Git clone support.

Requires the `software-factory` MicroVM image (see [templates/software-factory/](../templates/software-factory/)).
Use the `image_ref` parameter if the deployment default is a different image:

```python
session = client.create_session(
    image_ref="arn:aws:lambda:us-east-1:123456789012:microvm-image:sandbox-software-factory-v7"
)
```

### Example 07: Document Processing

Demonstrates a workflow where documents are processed inside isolated MicroVMs. Each document gets its own sandbox — no
cross-contamination between sessions.

Three ways to get documents into the sandbox:

**Option A: SDK `write_file()` (simplest)**
The caller reads the document from any source (local disk, S3, API) and pushes
the bytes into the sandbox. Works with any file type and size.

```python
with open("contract.pdf", "rb") as f:
    session.write_file("/tmp/contract.pdf", f.read())
```

**Option B: S3 → sandbox via persistent workspace**
Upload documents to the session's S3 workspace prefix from outside. They appear
inside the sandbox at `/mnt/workspace/` within seconds. Requires `persistence=True`
and [S3 Files setup](../docs/persistence-setup.md).

```python
# From your app (outside the sandbox):
s3.put_object(Bucket=workspace_bucket, Key=f"{workspace_prefix}contract.pdf", Body=pdf_bytes)

# Inside the sandbox, the file appears at:
#   /mnt/workspace/contract.pdf
```

The workspace S3 path includes the tenant and principal for isolation:
`workspaces/{tenantId}/{principalId}/{sessionId}/`

**Option C: Sandbox → S3 via persistent workspace**
Files written inside `/mnt/workspace/` sync to S3 automatically (eventual, ~60s).
Your app can read the results from S3 after the session completes.

```python
# Inside the sandbox:
session.execute("python3 extract.py > /mnt/workspace/results.json")

# From your app (after session or with a delay):
obj = s3.get_object(Bucket=bucket, Key=f"{prefix}results.json")
```

> **Note**: S3 → sandbox sync is near-instant. Sandbox → S3 sync is eventual (~60s).
> For immediate result retrieval, use `session.read_file()` instead of waiting for
> S3 sync.
