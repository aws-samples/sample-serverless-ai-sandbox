<!-- kiro-classification: public -->
# Documentation Index

## Getting Started

| Document | Description |
|----------|-------------|
| [Agent Sandbox Guide](agent-sandbox-guide.md) | Practical guide for AI agents running inside the sandbox — Bedrock access, package installation, egress rules, persistence, common pitfalls. |
| [Outbound Requests](outbound-requests.md) | How egress works from inside the sandbox — proxy tiers, environment variables, default allowlist, troubleshooting. |
| [Custom Templates](custom-templates.md) | Customize the MicroVM image with additional tools and packages. |

## Architecture & Security

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Deployed components, lifecycle flow, networking, how the stacks connect. |
| [Security Posture](security-posture.md) | Deployed security controls and recommended hardening (WAF, CloudTrail, KMS). |
| [Compliance Posture](compliance-posture.md) | Service-by-compliance-program table, HIPAA/SOC/ISO/PCI/FedRAMP, shared responsibility, data residency. |

## Egress & Multi-tenancy

| Document | Description |
|----------|-------------|
| [Per-Tenant Egress Design](per-tenant-egress-design.md) | Per-group/per-tenant/per-user egress policies — IPv6 identification, IAM tags, Lambda authorizer, Cognito JWT, DDB policy configuration, fallback chain. |
| [Egress Allowlist Guide](egress-allowlist-guide.md) | Configure which destinations sandboxes can reach — policy schema, update commands, common configurations. |
| [Cognito Integration Guide](cognito-auth.md) | Migrate from Lambda authorizer to Cognito JWT for production multi-tenant deployments. Includes `custom:egress_policy` attribute for per-user policies. |

## Storage

| Document | Description |
|----------|-------------|
| [Persistence Setup](persistence-setup.md) | Set up S3 Files persistent workspace — NFS mount at `/mnt/workspace` that survives suspend/resume/termination. |
| [Persistent Storage Design](persistent-storage-design.md) | Design rationale for the S3 Files persistence layer — access point isolation, affinity keys, tenant scoping. |

## SDKs

| Document | Description |
|----------|-------------|
| [Python SDK](python-sdk.md) | Full API reference: SandboxClient, SandboxSession, SandboxConnection, all methods and data classes. |
| [TypeScript SDK](typescript-sdk.md) | TypeScript API reference with camelCase equivalents of the Python SDK. |

## Cost

| Document | Description |
|----------|-------------|
| [Cost Model](cost-model.md) | Per-component pricing breakdown and monthly estimates. |
| [Cost Allocation](cost-allocation.md) | Per-tenant cost attribution with AWS tags. |

## Migration

| Document | Description |
|----------|-------------|
| [E2B Migration Map](e2b-migration-map.md) | Operation-by-operation mapping from E2B Python/TypeScript SDK to this platform. |

## Internal / Development

| Document | Description |
|----------|-------------|
| [Callback Orchestrator Design](callback-orchestrator-design.md) | Step Functions orchestrator internals — task token pattern, state transitions. |
| [Lessons Learned](lessons-learned.md) | Architecture and implementation decisions with rationale. |
