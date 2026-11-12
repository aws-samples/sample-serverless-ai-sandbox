<!-- kiro-classification: public -->

# Per-Tenant / Per-Group Egress Policies

> **Status**: Implemented and tested at scale (1,000 sessions, 5 tenants, 200 users).
> Works in both single-tenant and multi-tenant deployment profiles.

## Overview

The egress proxy can apply **different egress rules per session** based on the user's
role, tenant, or policy group. A developer session might reach GitHub, PyPI, and npm
while an analyst session only reaches PyPI.

Each MicroVM is identified by its unique IPv6 /128 address. The proxy sees this address
on every request via Proxy Protocol v2 and applies the matching policy — no Network
Firewall, no per-tenant connectors, zero additional infrastructure cost.

## How It Works

```
Session Creation (API Handler):
  User authenticates → API reads policy group from:
    • IAM tag SandboxEgressPolicy (single-tenant, SigV4)
    • Lambda authorizer context policyGroup (multi-tenant, bearer token)
    • Cognito JWT claim custom:egress_policy (multi-tenant, JWT)
  → Writes policyGroup to session record in DynamoDB

Provisioning (Orchestrator):
  → Generates opaque registrationToken (UUID4)
  → Resolves NLB IPv6 address (AAAA record)
  → Writes registrationToken to session record
  → Provisions MicroVM on DualStack connector → VM gets unique /128

Registration (MicroVM boot, before user code runs):
  → Sets http_proxy=http://[<proxyIPv6>]:443
  → Sends CONNECT with X-Registration-Token header through the proxy
  → NLB forwards to proxy with Proxy Protocol v2 (carries /128)
  → Proxy reads token → queries DDB → maps /128 → policyGroup

Every subsequent request (pip install, curl, git, Bedrock, etc.):
  → All traffic routes through IPv6 proxy
  → NLB → PP2 → Proxy looks up /128 → policyGroup → applies policy
  → Allowed → tunnel upstream (IPv4 NAT)
  → Denied → 403 Forbidden
```

### Why IPv6?

On a DualStack connector, each MicroVM gets a unique /128 from the VPC subnet CIDR.
This address is:

- **Unique per VM** — no sharing, even on the same connector
- **Unforgeable** — assigned by the hypervisor. A root guest binding a sibling's
  address gets silently dropped by the network layer
- **Visible via PP2** — the NLB includes the source /128 in the Proxy Protocol v2
  header on every connection, so the proxy knows which VM is making each request
- **Zero cost** — no additional infrastructure (no Network Firewall, no extra NAT)

## Single-Tenant Setup (SigV4)

### 1. Tag IAM users or roles

Add the `SandboxEgressPolicy` tag to IAM users or roles that create sessions:

```bash
# Tag a user
aws iam tag-user --user-name alice \
  --tags Key=SandboxEgressPolicy,Value=developer

# Tag a role
aws iam tag-role --role-name DataAnalystRole \
  --tags Key=SandboxEgressPolicy,Value=analyst

# No tag = "default" policy group
```

### 2. How resolution works

The API handler calls `iam:ListUserTags` or `iam:ListRoleTags` at session creation
(~50ms overhead). It handles user ARNs, role ARNs, and assumed-role ARNs.

| Caller ARN pattern | Tag source |
|--------------------|------------|
| `arn:aws:iam::ACCOUNT:user/alice` | `iam:ListUserTags` on the user |
| `arn:aws:iam::ACCOUNT:role/MyRole` | `iam:ListRoleTags` on the role |
| `arn:aws:sts::ACCOUNT:assumed-role/MyRole/session` | `iam:ListRoleTags` on the role |
| Tag missing or IAM call fails | Falls back to `"default"` |

### 3. Test it

```bash
# Create a session as the tagged user — check proxy logs for policy group
aws sts get-caller-identity  # confirm you're the tagged user
curl --aws-sigv4 "aws:amz:us-east-1:execute-api" \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  -X POST https://xxx.execute-api.us-east-1.amazonaws.com/sessions \
  -d '{"maxDurationSeconds": 3600}'
```

## Multi-Tenant Setup

### Lambda Authorizer (Bearer Tokens)

The Lambda authorizer maps tokens to tenant + policy group. Update `TENANT_TOKEN_MAP`:

```json
{
  "token-developer": {"tenantId": "acme-corp", "policyGroup": "developer"},
  "token-analyst":   {"tenantId": "acme-corp", "policyGroup": "analyst"},
  "token-restricted": {"tenantId": "acme-corp", "policyGroup": "restricted"},
  "token-tenant-b":  "tenant-b"
}
```

Tokens with a string value (e.g., `"tenant-b"`) get no explicit policyGroup — they
use the tenant default or global default.

Tokens with an object value get `tenantId` and `policyGroup` from the object. The
authorizer returns `policyGroup` in the API Gateway authorizer context.

### Cognito JWT

Add `custom:egress_policy` to the user pool schema and set it per user:

```bash
# Create user pool with egress_policy attribute
aws cognito-idp create-user-pool \
  --pool-name sandbox-users \
  --schema \
    Name=tenantId,AttributeDataType=String,Mutable=true \
    Name=egress_policy,AttributeDataType=String,Mutable=true

# Create a developer user
aws cognito-idp admin-create-user \
  --user-pool-id <pool-id> \
  --username dev@example.com \
  --user-attributes \
    Name=custom:tenantId,Value=acme-corp \
    Name=custom:egress_policy,Value=developer

# Create an analyst user (restricted egress)
aws cognito-idp admin-create-user \
  --user-pool-id <pool-id> \
  --username analyst@example.com \
  --user-attributes \
    Name=custom:tenantId,Value=acme-corp \
    Name=custom:egress_policy,Value=analyst
```

The API handler reads `custom:egress_policy` from JWT claims automatically.
See [Cognito Integration Guide](cognito-auth.md) for the full migration.

## Policy Configuration

Policies are stored in the **DynamoDB egress config table** (`EgressConfig`).
Each row has a `pk` key and a `policy` attribute containing the policy JSON.

### Policy format

```json
{
  "policyVersion": 1,
  "defaultAction": "deny",
  "bedrock": {
    "tier": 1,
    "hosts": [
      "bedrock-runtime.us-east-1.amazonaws.com",
      "bedrock-runtime.us-west-2.amazonaws.com"
    ]
  },
  "packages": {
    "tier": 3,
    "hosts": ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]
  },
  "github": {
    "tier": 3,
    "hosts": ["github.com", "api.github.com"]
  }
}
```

- **Tier 1** (SigV4 re-signing): For AWS services — the proxy strips sandbox credentials
  and re-signs with its own IAM role
- **Tier 3** (CONNECT tunnel): For external hosts — the proxy creates a TCP tunnel,
  your TLS session goes end-to-end

### Row types

| `pk` pattern | Purpose | Example |
|---|---|---|
| `EGRESS_POLICY` | Global default — applies when no group or tenant policy matches | Bedrock + system packages |
| `EGRESS_POLICY#GROUP#<name>` | Group-specific policy | `EGRESS_POLICY#GROUP#developer` |
| `EGRESS_POLICY#TENANT#<name>` | Tenant default — applies to all sessions from a tenant without a matching group | `EGRESS_POLICY#TENANT#acme-corp` |

### Fallback chain

For every request, the proxy resolves the policy in this order:

```
1. EGRESS_POLICY#GROUP#<policyGroup>   ← group-specific (if exists)
2. EGRESS_POLICY#TENANT#<tenantId>     ← tenant default (if exists)
3. EGRESS_POLICY                        ← global default (always exists)
```

**Examples:**
- Developer with group policy → uses `EGRESS_POLICY#GROUP#developer`
- User with no group, tenant has a default → uses `EGRESS_POLICY#TENANT#acme-corp`
- User with no group, tenant has no default → uses `EGRESS_POLICY` (global)
- User with a group that has no matching row → falls back to tenant, then global

### Adding policies

```bash
# Find your egress config table name
TABLE=$(aws cloudformation describe-stacks --stack-name EgressStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey,`EgressConfig`)].OutputValue' \
  --output text)

# Developer group: Bedrock + PyPI + npm + GitHub
aws dynamodb put-item --table-name "$TABLE" --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#developer"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\",\"bedrock-runtime.us-west-2.amazonaws.com\",\"bedrock-mantle.us-east-1.api.aws\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\",\"registry.npmjs.org\",\"registry.yarnpkg.com\"]},\"github\":{\"tier\":3,\"hosts\":[\"github.com\",\"api.github.com\"]},\"system\":{\"tier\":3,\"hosts\":[\"cdn.amazonlinux.com\"]}}"}
}'

# Analyst group: Bedrock + PyPI only (no GitHub, no npm)
aws dynamodb put-item --table-name "$TABLE" --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#analyst"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\"]}}"}
}'

# Restricted group: Bedrock only (no external packages)
aws dynamodb put-item --table-name "$TABLE" --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#restricted"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]}}"}
}'

# Tenant default for acme-corp: Bedrock + PyPI
aws dynamodb put-item --table-name "$TABLE" --item '{
  "pk": {"S": "EGRESS_POLICY#TENANT#acme-corp"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\"]}}"}
}'
```

### Policy hot-swap

Update a DDB row and the proxy picks it up within **30 seconds** (cache TTL).
No redeployment needed. Sessions in progress get the updated policy on their
next request after the cache expires.

## Bedrock Model Permissions

The proxy's IAM role (ProxyTaskRole) re-signs Bedrock requests. The CDK grants:

```
bedrock:InvokeModel, bedrock:Converse, bedrock:ConverseStream
  on arn:aws:bedrock:us-east-1::foundation-model/*
```

**Cross-region inference profiles** (e.g., `us.moonshotai.kimi-k3.1`,
`us.anthropic.claude-fable-5-2`) resolve to foundation models in other regions.
If you use cross-region models, add an inline policy to the proxy task role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel", "bedrock:Converse", "bedrock:ConverseStream"],
    "Resource": [
      "arn:aws:bedrock:*::foundation-model/*",
      "arn:aws:bedrock:*:ACCOUNT_ID:inference-profile/*"
    ]
  }]
}
```

**Data retention**: Some models (Claude Fable 5.x) require `aws_review` data
retention mode. Set it at the account level:

```python
import boto3
boto3.client('bedrock').put_account_data_retention(mode='aws_review')
```

## Security Properties

- **IPv6 is unforgeable**: The /128 is assigned by the hypervisor. A guest cannot
  impersonate another VM's address — binding attempts get `EADDRNOTAVAIL` or
  silently drop
- **Registration token is opaque**: The MicroVM never sees the tenantId, sessionId,
  or policyGroup. Only a UUID4 that the proxy resolves server-side
- **Token replay overwrites**: Re-registering with the same token from a different
  /128 overwrites the mapping. This is the expected behavior for the same session
  (e.g., after resume)
- **Header injection blocked**: The proxy uses the PP2 source /128 exclusively.
  Any `X-Policy-Group` or similar header from the client is ignored
- **Unknown /128**: An unregistered IPv6 address gets the global default policy
  (deny-by-default)

## Key Files

| File | Purpose |
|------|---------|
| `control_plane/api/creation.py` | `_resolve_policy_group()` — reads IAM tag or authorizer context |
| `control_plane/api/request.py` | `extract_policy_group()` — reads from Lambda/JWT/flat context |
| `control_plane/authorizer/handler.py` | Lambda authorizer — maps tokens to tenantId + policyGroup |
| `egress/server.py` | Proxy — PP2 parser, registration handler, per-group interceptor |
| `runtime/__main__.py` | MicroVM — `_register_ipv6_with_proxy()`, IPv6 proxy env setup |
| `iac/egress_stack.py` | CDK — NLB dualstack, IPv6 target group, PP2, proxy permissions |
| `iac/network_stack.py` | CDK — DualStack connector, IPv6 CIDRs on subnets |
