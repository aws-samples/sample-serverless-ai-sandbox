# Egress Allowlist Guide

## Overview

By default, sandboxes have **no internet access**. MicroVMs sit in subnets with zero
routes. All outbound traffic must go through the egress proxy, which checks every
connection against a policy stored in DynamoDB.

The default policy allows only Amazon Bedrock endpoints (for model invocation via
SigV4 re-signing). Everything else is denied until you add it to the allowlist.

## Policy Schema

The policy has two sections:

- **`bedrock.hosts`** — Tier 1: destinations where the proxy strips the sandbox's
  credentials and re-signs with SigV4 using its own IAM role. The sandbox never sees
  model access credentials.
- **`allowed`** — Tier 3: destinations the proxy will CONNECT-tunnel to. The sandbox
  does its own TLS; the proxy just pipes bytes.

```json
{
  "policyVersion": 1,
  "defaultAction": "deny",
  "bedrock": {
    "tier": 1,
    "hosts": [
      "bedrock-runtime.us-east-1.amazonaws.com",
      "bedrock-mantle.us-east-1.api.aws"
    ]
  },
  "allowed": [
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "registry.npmjs.org"
  ]
}
```

Anything not in `bedrock.hosts` or `allowed` gets HTTP 403.

## Policy Storage

The policy lives in DynamoDB in the `EgressConfig` table (created by `EgressStack`).

**Table name**: find it in CDK outputs or:
```bash
aws dynamodb list-tables --query "TableNames[?contains(@, 'EgressConfig')]" --output text
```

**Item key**: `pk = "EGRESS_POLICY"`

The proxy reads this item every 30 seconds (cache TTL). Changes take effect within
30 seconds — no proxy restart or image rebuild needed.

## Updating the Policy

```bash
aws dynamodb put-item \
  --table-name <EgressConfig table name> \
  --item '{
    "pk": {"S": "EGRESS_POLICY"},
    "policy": {"S": "{\"policyVersion\":2,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"allowed\":[\"pypi.org\",\"files.pythonhosted.org\",\"github.com\",\"registry.npmjs.org\"]}"}
  }' \
  --region us-east-1
```

## Common Configurations

### Bedrock only (default)
No internet access. Sandboxes can only call Bedrock models.
```json
{"bedrock": {"tier": 1, "hosts": ["bedrock-runtime.us-east-1.amazonaws.com", "bedrock-mantle.us-east-1.api.aws"]}, "allowed": []}
```

### Development (Bedrock + package registries + GitHub)
```json
{
  "bedrock": {"tier": 1, "hosts": ["bedrock-runtime.us-east-1.amazonaws.com", "bedrock-mantle.us-east-1.api.aws"]},
  "allowed": ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com", "api.github.com"]
}
```

### Locked down (Bedrock + one specific API)
```json
{
  "bedrock": {"tier": 1, "hosts": ["bedrock-runtime.us-east-1.amazonaws.com", "bedrock-mantle.us-east-1.api.aws"]},
  "allowed": ["api.example.com"]
}
```

## How Sandbox Code Reaches the Proxy

Code inside the sandbox must use the proxy explicitly. The proxy NLB is reachable
from the connector subnet on port 443.

**Method 1: HTTPS_PROXY environment variable** (recommended)

Set in the session configuration so all HTTP libraries use it automatically:

```bash
export HTTPS_PROXY=https://<NLB_DNS>:443
curl https://pypi.org/simple/   # goes through the proxy automatically
pip install pandas==2.2.3               # also goes through the proxy
```

**Method 2: Explicit proxy flag**

```bash
curl --proxy https://<NLB_DNS>:443 https://github.com
```

**Without proxy configuration**, direct connections time out — the connector subnet
has zero routes and no default gateway.

## What Happens on Deny

- Proxy returns HTTP 403 Forbidden
- The denial is logged in the proxy's CloudWatch Logs
- The sandbox is NOT terminated — it can retry with a different destination
- The denial does not count against session limits


## Bedrock Web Search

Agents inside sandboxes can search the web via [Web Search on Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/web-search.html)
without any additional egress configuration. The search happens entirely inside
Bedrock's infrastructure — no search engine URLs need to be in the allowlist.

The default policy includes `bedrock-mantle.us-east-1.api.aws` in the Bedrock hosts.
The proxy re-signs requests to this endpoint with SigV4, same as `bedrock-runtime`.

**How it works from inside a sandbox:**

The sandbox sends a forward proxy request to the proxy NLB targeting
`bedrock-mantle.us-east-1.api.aws`. The proxy strips the sandbox's credentials,
re-signs with SigV4 using its IAM role, and forwards to Bedrock. Bedrock handles
the web search and returns grounded results with citations.

**Supported models**: OpenAI GPT-5.6 family (Terra, Sol, Luna) via the Responses API.

**Note**: Web search queries take longer than simple model calls (10-30s for search +
model response). Set socket timeouts to at least 45 seconds when using web search.

**Zero-egress**: search queries stay within AWS. With `external_web_access: false`,
retrieval uses only the Amazon Bedrock web index and cache — no data leaves the
AWS boundary.

## Per-Tenant Egress Policies

Today the egress policy applies uniformly to all sandboxes regardless of tenant.
Per-tenant differentiation (Tenant A can reach GitHub, Tenant B cannot) is designed
but not feasible with the current architecture. See [per-tenant-egress-design.md](per-tenant-egress-design.md) for the analysis
for the planned approach.
