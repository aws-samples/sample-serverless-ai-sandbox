<!-- kiro-classification: public -->

# Single-Tenant Setup Guide

This guide covers configuring per-user egress policies in a single-tenant
deployment (the default — no `-c deploymentProfile` flag needed).

## How It Works

In single-tenant mode, all API routes use `AWS_IAM` (SigV4) authentication.
Every session belongs to the `operator` tenant. There's no Lambda authorizer
and no bearer tokens.

Even though there's one tenant, different IAM users or roles can have
**different egress policies**. The API handler reads the `SandboxEgressPolicy`
IAM tag from the caller's user or role at session creation time.

## Step 1: Tag IAM Users or Roles

Add the `SandboxEgressPolicy` tag to the IAM users or roles that create sessions:

```bash
# Tag a user
aws iam tag-user --user-name alice \
  --tags Key=SandboxEgressPolicy,Value=developer

# Tag a role
aws iam tag-role --role-name DataAnalystRole \
  --tags Key=SandboxEgressPolicy,Value=analyst

# Tag an assumed role (tag the role, not the session)
aws iam tag-role --role-name CIBuildRole \
  --tags Key=SandboxEgressPolicy,Value=restricted
```

Users/roles without the tag get the `"default"` policy group.

### How tag resolution works

| Caller ARN pattern | Tag source |
|--------------------|------------|
| `arn:aws:iam::ACCOUNT:user/alice` | `iam:ListUserTags` on the user |
| `arn:aws:iam::ACCOUNT:role/MyRole` | `iam:ListRoleTags` on the role |
| `arn:aws:sts::ACCOUNT:assumed-role/MyRole/session` | `iam:ListRoleTags` on the role (extracted from the ARN) |
| Tag missing or IAM call fails | Falls back to `"default"` |

The tag lookup adds ~50ms to session creation. The API handler Lambda has
`iam:ListUserTags` and `iam:ListRoleTags` permissions (granted by CDK).

## Step 2: Add Egress Policies

Find the egress config table:
```bash
TABLE=$(aws cloudformation list-stack-resources --stack-name EgressStack \
  --query 'StackResourceSummaries[?contains(LogicalResourceId,`EgressConfig`)].PhysicalResourceId' \
  --output text --region us-east-1)
```

The CDK seeds a global default (`EGRESS_POLICY`) that allows Bedrock and
package registries. Add group-specific policies for different users:

```bash
# Developer: Bedrock + PyPI + npm + GitHub
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#developer"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\",\"bedrock-mantle.us-east-1.api.aws\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\",\"registry.npmjs.org\"]},\"scm\":{\"tier\":3,\"hosts\":[\"github.com\",\"api.github.com\"]}}"}
}'

# Analyst: Bedrock + PyPI only (no GitHub, no npm)
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#analyst"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]},\"packages\":{\"tier\":3,\"hosts\":[\"pypi.org\",\"files.pythonhosted.org\"]}}"}
}'

# Restricted: Bedrock only (no external packages or repos)
aws dynamodb put-item --table-name "$TABLE" --region us-east-1 --item '{
  "pk": {"S": "EGRESS_POLICY#GROUP#restricted"},
  "policy": {"S": "{\"policyVersion\":1,\"defaultAction\":\"deny\",\"bedrock\":{\"tier\":1,\"hosts\":[\"bedrock-runtime.us-east-1.amazonaws.com\"]}}"}
}'
```

### Policy fallback chain

Since single-tenant has only one tenant (`operator`), the chain is:

```
1. EGRESS_POLICY#GROUP#<tag value>      ← from IAM tag
2. EGRESS_POLICY#TENANT#operator        ← operator default (if you set one)
3. EGRESS_POLICY                         ← global default (CDK-seeded)
```

Policy changes take effect within **30 seconds** (cache TTL). No redeploy needed.

## Step 3: Test

```bash
# As the tagged user
export AWS_PROFILE=alice  # or set credentials for the tagged user/role
python3 -c "
from agent_sandbox import SandboxClient
client = SandboxClient(api_url='https://<api-url>', region='us-east-1')
with client.create_session() as s:
    s.wait_ready()
    # Developer → GitHub should work
    r = s.execute('curl -s -o /dev/null -w \"%{http_code}\" --max-time 5 https://github.com')
    print(f'GitHub: HTTP {r.stdout.strip()}')
"
```

## Examples

The examples work on single-tenant without any extra configuration:

```bash
export API_URL="https://<api-url>"
export AWS_REGION="us-east-1"
# Do NOT set SANDBOX_TOKEN — that's for multi-tenant only
# If it's set from a previous session: unset SANDBOX_TOKEN

python3 examples/01_hello_sandbox.py
```

> **Common gotcha**: If you previously tested with multi-tenant and have
> `SANDBOX_TOKEN` set in your shell, single-tenant will reject all requests
> with 403. Run `unset SANDBOX_TOKEN` first.

## Reference

- [Per-Tenant Egress Design](per-tenant-egress-design.md) — architecture, policy
  format, fallback chain, security properties
- [Egress Allowlist Guide](egress-allowlist-guide.md) — global policy configuration
