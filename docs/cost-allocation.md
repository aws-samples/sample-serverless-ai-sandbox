# Cost Allocation & Tenant Segregation

## Overview

Every sandbox carries `tenantId` and `sessionId` tags at the MicroVM level. Every CDK
resource carries `Project`, `ManagedBy`, and `DeploymentProfile` tags. Together these
enable cost attribution at three levels: project-wide, per-tenant, and per-session.

## Tag Hierarchy

### Infrastructure Tags (CDK-managed, all resources)

| Tag | Value | Purpose |
|-----|-------|---------|
| `Project` | `AgentSandbox` | Identify all sandbox resources in a shared account |
| `ManagedBy` | `CDK` | Distinguish from manually created resources |
| `DeploymentProfile` | `single-tenant` or `multi-tenant` | Identify deployment mode |

These are applied to **every resource** across all stacks via `cdk.Tags.of(app).add(...)`.

### Sandbox Tags (per MicroVM, per session)

| Tag | Value | Purpose |
|-----|-------|---------|
| `tenantId` | e.g. `tenant-a`, `operator` | Attribute compute cost to the tenant |
| `sessionId` | e.g. `7N9RV9RZMW1DSXCKAHBQAA3276` | Attribute compute cost to the session |

These are set by `sandbox_tags()` in `control_plane/allocation/tags.py` and applied to
every MicroVM at creation time. They cannot be overridden or omitted — a sandbox without
both tags is refused by the claim ledger before it can be associated with a session.

## Activating Cost Allocation Tags

AWS does not use tags for billing by default. You must activate them:

1. Go to **AWS Billing → Cost Allocation Tags**
2. Find the tags: `Project`, `tenantId`, `sessionId`, `DeploymentProfile`
3. Click **Activate** for each
4. Tags take up to 24 hours to appear in Cost Explorer

After activation, you can filter and group costs by any combination of these tags.

## Cost Explorer Queries

### Total sandbox cost
```
Filter: Tag: Project = AgentSandbox
Group by: Service
```

### Cost per tenant (multi-tenant)
```
Filter: Tag: Project = AgentSandbox
Group by: Tag: tenantId
```

This shows how much each tenant is consuming. In multi-tenant mode, this is
the primary cost segregation mechanism — each tenant's MicroVM compute is
tagged with their `tenantId`.

### Cost per session
```
Filter: Tag: tenantId = tenant-a
Group by: Tag: sessionId
```

This shows individual session costs within a tenant. Useful for identifying
expensive sessions or unexpected usage patterns.

### Shared infrastructure vs. per-session
```
Filter: Tag: Project = AgentSandbox
Group by: Tag: sessionId
```

Resources without a `sessionId` tag are shared infrastructure (VPC, NLB, Fargate proxy,
DynamoDB table). Resources with a `sessionId` are per-session compute (MicroVMs).

## DynamoDB Cost Attribution

DynamoDB costs are shared across all tenants in a single table. Per-tenant DynamoDB cost
attribution is not possible with tags alone because all tenants share one table. However:

- **DynamoDB on-demand pricing** scales with actual read/write volume per tenant
- The `tenantId` partition key means a tenant's operations only touch their own partition
- For precise per-tenant DynamoDB costs, monitor `ConsumedReadCapacityUnits` and
  `ConsumedWriteCapacityUnits` per partition using CloudWatch Contributor Insights

To enable Contributor Insights:
```bash
aws dynamodb update-contributor-insights \
  --table-name StateStack-sessions... \
  --contributor-insights-action ENABLE \
  --region us-east-1
```

This shows the top partition keys by consumed capacity — effectively a per-tenant
usage breakdown.

## S3 Artifact Cost Attribution

Artifacts are stored under tenant-prefixed paths:
```
s3://<your-artifact-bucket>/tenant=<tenantId>/session=<sessionId>/...
```

Use S3 Storage Lens or S3 Inventory to break down storage costs by prefix (tenant).
For automated cost attribution, enable S3 Object Tags and set `tenantId` on each
artifact at write time.

## Billing Alarms

Set up CloudWatch alarms to catch unexpected cost increases:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name AgentSandbox-DailyCost \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=Currency,Value=USD \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:billing-alerts
```

## Tenant Cost Reporting

For multi-tenant deployments, generate per-tenant cost reports:

1. **Cost Explorer API**: Query `GetCostAndUsage` with `TagValues` filter for `tenantId`
2. **AWS Cost and Usage Report (CUR)**: Enable CUR with resource-level data and
   cost allocation tags. Parse the CSV/Parquet for `tenantId` grouping.
3. **Custom dashboard**: Query CloudWatch metrics (`SandboxesRunning` has a `TenantId`
   dimension if configured) and correlate with billing data.

## What's Tagged

| Resource | Tags Applied | By |
|----------|-------------|-----|
| All CDK resources | `Project`, `ManagedBy`, `DeploymentProfile` | CDK app tags |
| Lambda MicroVMs | `tenantId`, `sessionId` | `sandbox_tags()` at provisioning |
| DynamoDB items | `tenantId` in partition key (not a tag) | Data model |
| S3 artifacts | `tenantId` in path prefix | Artifact store |
| VPC, subnets, NLB | `Project`, `egressGeneration` | CDK stack tags |

## Egress Cost per Tenant (Planned)

With per-tenant egress policies (see [per-tenant-egress-design.md](per-tenant-egress-design.md)),
the proxy will know which tenant each connection belongs to. This enables:

- **Per-tenant egress byte counting**: the proxy can meter bytes transferred per tenant
  and publish as a CloudWatch metric with a `TenantId` dimension
- **Per-tenant Bedrock usage**: Tier 1 re-signing requests can be logged with the tenant,
  enabling per-tenant model invocation cost attribution
- **Per-tenant NAT Gateway cost**: egress bytes through the NAT can be attributed to the
  tenant whose MicroVM generated the traffic

This closes the "Bedrock invocations billed to proxy role, not per-tenant" gap listed below.

## What's NOT Tagged (Limitations)

| Resource | Why |
|----------|-----|
| API Gateway requests | APIGW doesn't support per-request tagging |
| Bedrock invocations | Billed to the proxy role, not per-tenant |
| NAT Gateway data transfer | Per-byte, no per-session attribution |
| CloudWatch logs | Log group level only, not per-session |

For Bedrock per-tenant cost attribution, enable **Bedrock model invocation logging** and
parse the logs to correlate invocations with the session (and therefore tenant) that
triggered them via the proxy.
