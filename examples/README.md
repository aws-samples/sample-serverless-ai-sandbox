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
```
