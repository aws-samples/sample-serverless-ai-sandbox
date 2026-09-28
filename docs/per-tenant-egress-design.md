<!-- kiro-classification: public -->

# Per-Tenant Egress Policies

> **Status**: Per-tenant egress differentiation is not feasible with the current
> proxy-based architecture. The connector-per-tenant approach was rejected (ENI
> sharing makes source IP unreliable). The IPv6 per-VM approach below is documented
> for reference but requires AWS Network Firewall and is not on the active roadmap.

## Current Approach: One Policy for All

Today the egress proxy applies a single policy to all sandboxes regardless of tenant.
The operator defines which destinations are allowed (stored in DynamoDB, 30s cache TTL),
and every MicroVM gets the same rules.

**This is correct for most deployments.** The operator controls the network boundary,
not the tenants. Multi-tenancy is enforced at the data layer (DynamoDB partitions,
IAM conditions) and at the API layer (Lambda authorizer). Egress policy is an
operator concern, not a per-tenant one.

**When this isn't enough:** a platform operator hosting mutually untrusted tenants
may need Tenant A to reach GitHub while Tenant B cannot. The approach below addresses
that.

### Why not connector-per-tenant?

We evaluated a design where each tenant gets a dedicated Lambda network connector,
and the proxy identifies the tenant by the connector ENI's source IPv4. This was
rejected because:

- **ENI sharing across connectors**: A principal engineer from the MicroVM service
  team confirmed that MicroVMs on the same connector share the connector ENI's IPv4.
  Furthermore, connectors in the same subnet and security group may reuse each other's
  ENIs, making source IP an unreliable tenant identifier.
- **1,000 connector limit** per account (non-adjustable).
- **10-minute provisioning** per connector (async), which complicates dynamic
  tenant onboarding.

---

## IPv6 per-VM Identification (Advanced Option)

On a DualStack network connector, the Lambda MicroVM service assigns each VM a
unique IPv6 /128 address. This is the most precise identification — per-VM, not
just per-tenant — and the identity is unforgeable at the hypervisor level.

### How it works

Each MicroVM gets a /128 from the connector's delegated /80 prefix. This address:

- Is **unique per MicroVM** — no sharing, even on the same connector
- Is **unforgeable** — assigned by the hypervisor. A root guest with ALL capabilities
  can bind a sibling's address locally, but egress under it silently drops. Tested
  and verified on real MicroVMs.
- Appears in **VPC flow logs** (`pkt-srcaddr`) and Network Firewall logs
- Costs **1 NAU unit** for the entire /80, regardless of VM count

### Policy enforcement

Enforcement uses **AWS Network Firewall** with per-source /128 Suricata rules —
protocol-agnostic (HTTP, SSH, arbitrary TCP). Cost: ~$320/month for the firewall
endpoint plus ~$32/month for the NAT Gateway (needed for IPv4-only destinations
via DNS64/NAT64).

### Limitations

- **29% of common agent destinations are IPv4-only (based on internal testing of top-100 agent destinations, 2026-09)** (GitHub among them). DNS64/NAT64
  can close this gap while preserving attribution, at the cost of a NAT Gateway
  (~$32/month + per-GB processing).
- **Network Firewall rule changes take 60–80 seconds** to propagate (vs seconds for
  the proxy's DDB-backed policy). Not suitable for dynamic policy changes.
- **Network Firewall cannot inject credentials** — the Fargate proxy is still needed
  for Bedrock SigV4 re-signing and Tier 2 token injection regardless.
- **Operational traps**: `ACTION_ORDER` in Network Firewall silently defeats narrow
  drop rules. Discovered during testing — requires careful rule ordering.

### When to use this

For operators who need per-VM (not just per-tenant) policy differentiation, or who
need protocol-agnostic enforcement at the network layer for compliance reasons. The
cost (~$350/month) and complexity are justified when the uniform policy approach
doesn't provide sufficient granularity.

---

## Comparison

| | One Policy (current) | IPv6 + Network Firewall |
|---|---|---|
| **Granularity** | All sandboxes | Per VM |
| **Identity** | None needed | MicroVM IPv6 /128 |
| **Forgeable?** | N/A | No (hypervisor-level) |
| **New infra** | None | Network Firewall + NAT Gateway |
| **Monthly cost** | $0 | ~$350 |
| **Tenant limit** | Unlimited | Unlimited |
| **Policy change speed** | 30s (DDB cache) | 60–80s (NFW propagation) |
| **Protocol coverage** | HTTP/CONNECT | All TCP including SSH |
| **Credential injection** | Yes (proxy) | No (proxy still needed) |

## Decision

Ship with one policy for all. Document IPv6/NFW as the advanced option for operators
needing per-VM network-layer enforcement. The proxy-based approach is the right
trade-off for cost, simplicity, and the credential injection requirement.
