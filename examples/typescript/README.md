# TypeScript examples

Live examples that mirror `examples/python/`, using the TypeScript SDK (`sdk/typescript`).

## Run

```bash
export API_URL=https://<your-api-id>.execute-api.us-east-1.amazonaws.com
export AWS_REGION=us-east-1
# Multi-tenant deployment: set a bearer token. Single-tenant: leave SANDBOX_TOKEN unset (uses SigV4).
export SANDBOX_TOKEN=demo-token-tenant-a

# from the TS SDK dir (so its node_modules resolve):
cd sdk/typescript
npx tsx ../../examples/typescript/01_hello_sandbox.ts
```

Each example takes `API_URL`, `AWS_REGION`, and an optional `SANDBOX_TOKEN`
(unset → SigV4/single-tenant; set → bearer/multi-tenant), matching the Python examples.

| File | Mirrors |
|------|---------|
| 01_hello_sandbox.ts | python/01 |
| 02_data_analysis.ts | python/02 |
| 03_persistent_workspace.ts | python/03 |
| 04_suspend_resume.ts | python/04 |
| 05_multi_tenant.ts | python/05 |
| 06_software_factory.ts | python/06 |
| 07_document_processing.ts | python/07 |
| 08_per_session_image.ts | python/08 |

## Example 06 (software factory)

Example 06 needs the `software-factory` MicroVM image, so pass it with `--image`
(or `SANDBOX_IMAGE`). It also requires `github.com` on the egress allowlist and
Amazon Bedrock model access:

```bash
cd sdk/typescript
npx tsx ../../examples/typescript/06_software_factory.ts \
  --image arn:aws:lambda:us-east-1:ACCOUNT:microvm-image:sandbox-software-factory-v7
```

