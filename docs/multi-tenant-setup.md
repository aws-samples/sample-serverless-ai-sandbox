<!-- kiro-classification: public -->

# Multi-Tenant Setup Guide

This guide covers onboarding tenants and configuring per-group egress policies
in a multi-tenant deployment (`-c deploymentProfile=multi-tenant`).

## Prerequisites

- Deployed with `-c deploymentProfile=multi-tenant`

## Two Auth Options

Multi-tenant supports two authorization mechanisms. Both resolve `tenantId`,
`principalId`, and `policyGroup` per request:

| | Lambda Authorizer (default) | Cognito JWT |
|---|---|---|
| **Setup** | Edit env var on Lambda | Create Cognito User Pool + app client |
| **Token source** | Static tokens in `TENANT_TOKEN_MAP` | Cognito issues JWTs |
| **User management** | Manual (add/remove tokens) | Cognito hosted UI, federation, MFA |
| **Policy group** | `policyGroup` field in token map | `custom:egress_policy` JWT claim |
| **Per-request cost** | Lambda invocation (~$0.20/1M) | Zero (API Gateway validates natively) |
| **Best for** | Development, demos, small teams | Production, self-service, >10 users |

**Lambda authorizer** is deployed by default with `-c deploymentProfile=multi-tenant`.
The rest of this guide covers both options.

**Cognito JWT** is the recommended production path. See the
[Cognito Integration Guide](cognito-auth.md) for the full migration — user pool
creation, `custom:tenantId` + `custom:egress_policy` attributes, JWT authorizer
CDK swap, and SDK auth changes. Tested at scale: 200 users, 5 tenants, JWT
authorizer with per-user egress policies.

## How Tenant Resolution Works

Every API request includes a token in the `Authorization` header. The authorizer
(Lambda or Cognito JWT) validates it and returns:

- `tenantId` — which DynamoDB partition the session belongs to
- `principalId` — the authenticated caller identity (for workspace scoping)
- `policyGroup` — which egress policy applies (optional, falls back to default)

## Step 1: Add a Tenant Token

The token map is a JSON object on the Lambda authorizer's `TENANT_TOKEN_MAP`
environment variable. Each key is a bearer token, each value is either a string
(tenant ID only) or an object with `tenantId`, `principalId`, and `policyGroup`.

### Simple (tenant ID only, default egress policy)

```json
{
  "my-secret-token": "acme-corp"
}
```

Sessions created with this token get tenant `acme-corp`, principal `tenant:acme-corp`,
and the global default egress policy.

### With policy group

```json
{
  "dev-token": {"tenantId": "acme-corp", "policyGroup": "developer"},
  "analyst-token": {"tenantId": "acme-corp", "policyGroup": "analyst"},
  "admin-token": {"tenantId": "acme-corp", "principalId": "admin@acme.com", "policyGroup": "developer"}
}
```

- `policyGroup` determines which egress rules apply (see Step 2)
- `principalId` is optional — defaults to `tenant:<tenantId>`. Set it to distinguish
  users within a tenant for workspace isolation.

### How to update the token map

**Option A: AWS Console**
Lambda → Functions → find `ControlPlaneStack-TenantAuthorizer*` → Configuration →
Environment Variables → edit `TENANT_TOKEN_MAP`.

**Option B: AWS CLI**
```bash
FUNC=$(aws cloudformation list-stack-resources --stack-name ControlPlaneStack \
  --query 'StackResourceSummaries[?contains(LogicalResourceId,`TenantAuthorizer`) && ResourceType==`AWS::Lambda::Function`].PhysicalResourceId' \
  --output text --region us-east-1)

aws lambda update-function-configuration \
  --function-name "$FUNC" \
  --environment "Variables={TENANT_TOKEN_MAP='{\"token-a\":{\"tenantId\":\"acme\",\"policyGroup\":\"developer\"},\"token-b\":\"beta-corp\"}'}" \
  --region us-east-1
```

**Option C: CDK (permanent)**
Edit `iac/control_plane_stack.py`, update the `TENANT_TOKEN_MAP` dict in
`_lambda_authorizer()`, and redeploy.

> **Production**: For production deployments, replace the Lambda authorizer with
> Cognito JWT — see [Cognito Integration Guide](cognito-auth.md). With Cognito,
> tenants are managed as users in the user pool, not as tokens in an env var.

## Step 2: Add Egress Policies (Optional)

By default, all sessions use the global egress policy (`EGRESS_POLICY` row in
the EgressConfig DynamoDB table). To give different groups different egress rules,
add group-specific rows.

Find the table name:
```bash
TABLE=$(aws cloudformation list-stack-resources --stack-name EgressStack \
  --query 'StackResourceSummaries[?contains(LogicalResourceId,`EgressConfig`)].PhysicalResourceId' \
  --output text --region us-east-1)
```

### Add a group policy

```bash
# Developer: Bedrock + PyPI + npm + GitHub
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#developer"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\",\"bedrock-mantle.us-east-1.api.aws\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\",\"registry.npmjs.org\"]},\"scm\":{\"tier\":3,\"hosts\":[\"github.com\",\"api.github.com\"]}}"}
}'

# Analyst: Bedrock + PyPI only
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#analyst"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\"]}}"}
}'
```

### Add a tenant default

Applies to all sessions from a tenant that don't match a group policy:

```bash
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#TENANT#acme-corp"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\"]}}"}
}'
```

### Policy fallback chain

The proxy resolves the policy in this order:
```
1. EGRESS_POLICY#GROUP#<policyGroup>    ← group-specific
2. EGRESS_POLICY#TENANT#<tenantId>      ← tenant default
3. EGRESS_POLICY                         ← global default
```

Policy changes take effect within **30 seconds** (cache TTL). No redeploy needed.

See [Per-Tenant Egress Design](per-tenant-egress-design.md) for the full policy
format, architecture details, and security properties.

## Step 3: Test

```bash
# Create a session with the new tenant token
curl -X POST https://<api-url>/sessions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"maxDurationSeconds": 3600}'

# Or with the Python SDK
from agent_sandbox import SandboxClient
client = SandboxClient(api_url="https://...", region="us-east-1", token="dev-token")
session = client.create_session()
```

## Demo Tokens (Default)

The CDK deploys two demo tokens:

| Token | Tenant | Policy Group | Egress |
|-------|--------|-------------|--------|
| `demo-token-tenant-a` | `tenant-a` | `developer` | Bedrock + PyPI + npm + GitHub (if group policy seeded) |
| `demo-token-tenant-b` | `tenant-b` | _(default)_ | Global default policy |

> **Important**: The `developer` group policy is NOT seeded by CDK. After a fresh
> deploy, `demo-token-tenant-a` uses the global default until you add the
> `EGRESS_POLICY#GROUP#developer` row (see Step 2).
