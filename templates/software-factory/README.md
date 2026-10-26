# Software Factory Template

A MicroVM image for AI-driven coding workflows. Adds Node.js 22, opencode (AI coding
agent), AWS CDK, and ripgrep to the base sandbox runtime. Designed to replace managed
sandbox services (like Modal) for customers who need self-hosted, governed code execution.

## What's included

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.13 | Base runtime, data processing |
| Node.js | 22 | JavaScript/TypeScript execution, CDK |
| npm | 10.8+ | Package management |
| opencode | 1.18.35 | AI coding agent CLI (75+ model providers) |
| AWS CDK | Latest | Infrastructure-as-code synthesis and deployment |
| ripgrep | 14.1.1 | Fast code search (used by opencode internally) |
| Git | 2.50+ | Version control |
| Bedrock adapter | 1.0 | Bridges Node.js AI SDK to the egress proxy |

## Building the image

1. Ensure the base sandbox is deployed (all stacks).

2. Update the `_DOCKERFILE` string in `scripts/build-image.py` with this template's
   Dockerfile contents, then build:

   ```bash
   uv run python scripts/build-image.py --region us-east-1 --name sandbox-software-factory
   ```

3. Deploy with the new image:

   ```bash
   npx cdk deploy ControlPlaneStack \
     -c imageVersion=<software-factory-image-arn> \
     -c proxyImageUri=<existing-proxy-uri> \
     --require-approval never
   ```

## Configuring Bedrock access

The sandbox has zero internet routes and an IAM deny on direct Bedrock calls. Model
inference goes through the egress proxy, which re-signs requests with its own role.

Node.js native `fetch` does not respect `http_proxy` environment variables, so a local
adapter bridges the AI SDK to the proxy. The adapter is baked into the image at
`/opt/bedrock-adapter.js`.

### How the adapter works

1. Listens on `127.0.0.1:9090`
2. Receives AI SDK Bedrock requests
3. Strips auth headers (the sandbox credentials are IAM-denied for Bedrock)
4. Forwards via raw TCP to the egress proxy with the correct Bedrock `Host` header
5. The proxy re-signs with its own Bedrock-allowed IAM role
6. Response flows back: Bedrock -> proxy -> adapter -> AI SDKJ
### Starting the adapter

Start it as a background process before running opencode:

```bash
node /opt/bedrock-adapter.js &
export AWS_ENDPOINT_URL_BEDROCK_RUNTIME=http://127.0.0.1:9090
```

### opencode configuration

Create `opencode.json` in your project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "amazon-bedrock": {
      "options": {
        "region": "us-east-1"
      }
    }
  },
  "model": "amazon-bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0",
  "permission": {
    "*": "allow"
  }
}
```

### Running opencode in headless serve mode

```bash
node /opt/bedrock-adapter.js &

AWS_ENDPOINT_URL_BEDROCK_RUNTIME=http://127.0.0.1:9090 \
AWS_REGION=us-east-1 \
OPENCODE_SERVER_PASSWORD=<random-password> \
opencode serve --hostname 127.0.0.1 --port 4096
```

The `@opencode-ai/sdk` can then drive the session via the local endpoint.

## Egress allowlist

The software factory needs these domains in the egress policy:

| Domain | Purpose |
|--------|---------|
| `bedrock-runtime.*.amazonaws.com` | Model inference (Tier 1, SigV4 re-signing) |
| `github.com` | Git clone and push |
| `pypi.org`, `files.pythonhosted.org` | Python packages |
| `registry.npmjs.org` | npm packages |

`github.com` is **not** in the default allowlist. Add it to the EgressConfig DynamoDB
table as a Tier 3 destination set. See `docs/egress-allowlist-guide.md` for details.

## Tested capabilities

All verified on a live deployment (October 2026):

| Capability | Status | Notes |
|-----------|--------|-------|
| Node.js execution | OK | v22.23.4 |
| opencode CLI | OK | v1.18.35 |
| opencode serve (headless) | OK | Auth works, /api/session returns 200 |
| Bedrock via adapter then proxy | OK | AI SDK generateText returns model response |
| Git clone through proxy | OK | Public repos via github.com allowlist |
| ripgrep search | OK | Code search works |
| CDK CLI | OK | v2.1146.1 |
| Suspend/resume | OK | Files and Node.js processes survive |
| 60s sustained session | OK | Multi-turn workloads complete |
| Python execution | OK | v3.13 |
| uid 1000 confinement | OK | Same security model as default image |
| Persistent workspace | OK | S3 Files mount works (same runtime) |

## Known limitations

- **opencode /config returns 500 on startup** -- opencode tries to list models
  before the adapter is reachable. The /api/session endpoint (used by the SDK)
  works correctly.

- **Node.js 18 is also present** -- AL2023 nodejs22 package pulls nodejs (v18)
  as a dependency. The symlink ensures v22 is the default.

- **npm install at runtime needs HOME=/tmp** -- /root is not writable by uid 1000.

- **baseURL in opencode Bedrock config is ignored** -- Known issue
  (anomalyco/opencode#2446). Use AWS_ENDPOINT_URL_BEDROCK_RUNTIME env var instead,
  which is why the adapter exists.
