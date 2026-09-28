# Compliance Posture

This document lists every AWS service the reference architecture uses and its
compliance program coverage. Compliance status changes over time — verify against
the [AWS Services in Scope](https://aws.amazon.com/compliance/services-in-scope/)
page before making claims in customer-facing material.

**Last verified: September 2026**

## Services Used

| Service | Purpose in this architecture | HIPAA | SOC | ISO 27001 | PCI DSS | FedRAMP |
|---------|------------------------------|-------|-----|-----------|---------|---------|
| AWS Lambda | API handler, orchestrator task, reaper, authorizer, MCP tools | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS Lambda MicroVMs | Sandbox compute (Firecracker VMs) | ⚠️ Unconfirmed | ⚠️ Unconfirmed | ⚠️ Unconfirmed | ⚠️ Unconfirmed | ⚠️ Unconfirmed |
| Amazon DynamoDB | Session state, config, egress policy | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS Step Functions | Session orchestrator (lifecycle state machine) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon S3 | Artifact storage | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS KMS | Encryption keys for artifacts and secrets | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon API Gateway | HTTP API for the control plane | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS Fargate | Egress proxy fleet | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon ECS | Proxy fleet orchestration | ✅ | ✅ | ✅ | ✅ | ✅ |
| Elastic Load Balancing (NLB) | Internal load balancer for proxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon VPC | Egress VPC, subnets, security groups, NAT GW | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon CloudWatch | Logs, metrics, dashboard | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS IAM | Roles, policies, authentication | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS Secrets Manager | Upstream API credentials (Tier 2 egress) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon EventBridge | Reaper scheduler | ✅ | ✅ | ✅ | ✅ | ✅ |
| AWS STS | Temporary credentials for tenant scoping | ✅ | ✅ | ✅ | ✅ | ✅ |
| Amazon Bedrock | Model invocation (via proxy) | ✅ | ✅ | ✅ | ✅ | Partial |
| AWS ACM Private CA | TLS certificates for proxy | ✅ | ✅ | ✅ | ✅ | ✅ |

## Key Finding: Lambda MicroVMs Compliance Status

**Lambda MicroVMs is a new service (GA June 2026).** As of September 2026, it does
not yet appear on the AWS Services in Scope page for any compliance program. This
means:

- Lambda MicroVMs is **not yet confirmed** as HIPAA eligible, SOC audited, or PCI
  compliant
- The underlying Lambda service IS in scope for all major programs
- MicroVMs use Firecracker isolation (the same technology as Lambda functions)
- The service runs in the customer's own account and Region

**Recommendation**: for compliance-sensitive workloads, confirm Lambda MicroVMs'
compliance status with your AWS account team before deploying. The service is expected
to be added to compliance programs as it matures, but no timeline is published.

## Shared Responsibility

Under the AWS shared responsibility model, the operator is responsible for:

| Operator Responsibility | How this architecture addresses it |
|------------------------|-----------------------------------|
| Data classification | Operator classifies data entering sandboxes |
| Access control | Lambda authorizer + IAM roles + DDB tenant partitions |
| Encryption configuration | KMS encryption on S3 and DDB (deployed by CDK) |
| Network security | Zero-route subnets + egress proxy (deployed by CDK) |
| Logging and monitoring | CloudWatch Logs + VPC Flow Logs (deployed by CDK) |
| Incident response | Operator responsibility — CloudTrail recommended |
| Patching | MicroVM images use Amazon Linux 2023 (AWS-managed base) |
| Compliance validation | Operator verifies service scope for their programs |

## Data Residency

Lambda MicroVMs is available in:
- US East (N. Virginia) — `us-east-1`
- US East (Ohio) — `us-east-2`
- US West (Oregon) — `us-west-2`
- Asia Pacific (Tokyo) — `ap-northeast-1`
- Europe (Ireland) — `eu-west-1`

All session data (DynamoDB, S3 artifacts, CloudWatch logs) stays in the deployment
Region. No data crosses Region boundaries. The egress proxy runs in the same VPC and
Region as the MicroVMs.

For data residency requirements naming a Region where Lambda MicroVMs is unavailable,
this architecture cannot be deployed. See the
[Supported Regions](../README.md#supported-regions) section of the README.

## Compliance Programs Reference

| Program | Verification URL |
|---------|-----------------|
| HIPAA | [HIPAA Eligible Services](https://aws.amazon.com/compliance/hipaa-eligible-services-reference/) |
| SOC 1/2/3 | [Services in Scope — SOC](https://aws.amazon.com/compliance/services-in-scope/SOC/) |
| ISO 27001 | [Services in Scope — ISO](https://aws.amazon.com/compliance/services-in-scope/ISO/) |
| PCI DSS | [Services in Scope — PCI](https://aws.amazon.com/compliance/services-in-scope/PCI/) |
| FedRAMP | [Services in Scope — FedRAMP](https://aws.amazon.com/compliance/services-in-scope/FedRAMP/) |
| Full list | [AWS Services in Scope](https://aws.amazon.com/compliance/services-in-scope/) |
