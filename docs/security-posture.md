<!-- kiro-classification: public -->

# Security Posture — AWS Serverless Agent Sandbox

## Isolation Model

### Compute isolation

Each sandbox is a **Firecracker MicroVM** — a hardware-isolated virtual machine, not a
shared container. The MicroVM has its own kernel, memory space, and filesystem. A
compromised sandbox cannot access another sandbox's memory or processes even if they
run on the same physical host.

The MicroVM image uses `additionalOsCapabilities: ["ALL"]` to grant Linux capabilities
required for S3 Files NFS mounting. User code runs with a significantly reduced
capability set enforced by the runtime (see Capability Confinement below).

### Network isolation

The sandbox subnets have **zero routes to the internet** — no NAT gateway, no internet
gateway, no VPC endpoint routes to AWS services. The only outbound path is through
the Fargate proxy NLB on port 443.

This is fail-closed by design:
- Direct connections to any external IP: **timeout** (no route exists)
- AWS API calls (`.amazonaws.com` is in `NO_PROXY`): **timeout** (boto3 tries direct, no route)
- AWS API calls via proxy: **rejected** (proxy allowlist does not include `.amazonaws.com`)
- Proxy down: **no outbound access at all**

### Egress control

All outbound traffic goes through a **forward proxy** running on Fargate. The proxy
enforces a per-domain allowlist stored in DynamoDB:

- **Tier 1 (SigV4 re-signing)**: Bedrock endpoints. The proxy re-signs requests with
  its own IAM role. The sandbox never holds Bedrock credentials.
- **Tier 2 (Token injection)**: Third-party APIs. The proxy injects API keys from
  Secrets Manager. The sandbox never sees the key.
- **Tier 3 (CONNECT tunnel)**: Allowed destinations (package registries, etc.).

Policy changes are immediate — update the DynamoDB item, no redeployment needed.

### User code isolation (uid 1000)

User code runs as **uid 1000 (sandbox)**, not root. The runtime process (PID 1) switches
the user identity and drops capabilities in every child process before `execve`, using
`setgid(1000)` + `setuid(1000)` + `PR_SET_NO_NEW_PRIVS`.

The `setuid` to a non-root user causes the kernel to automatically clear **all effective
and permitted capabilities** — user code has zero Linux capabilities. Combined with
`NO_NEW_PRIVS`, capabilities cannot be regained through `execve`, SUID binaries, or
file capabilities.

This prevents:
- Overwriting root-owned system binaries (the attack that bypassed v53's confinement)
- Any form of privilege escalation via `setuid(0)`, `su`, `sudo`, SUID binaries, or file capabilities
- Capability restoration through `execve` (NNP blocks it)

PID 1 (the runtime) retains root and full capabilities for NFS mount/re-mount.
It cannot be inspected by user code (`/proc/1/*` returns EACCES for uid 1000).

The bounding set additionally has these caps irrevocably removed:

| Capability | Dropped from | Why |
|-----------|-------------|-----|
| CAP_SYS_ADMIN | effective + permitted | Prevents mount, namespace creation, sysctl writes |
| CAP_BPF | effective + permitted | Prevents kernel BPF program loading |
| CAP_MKNOD | effective + permitted | Prevents block device node creation |
| CAP_PERFMON | effective + permitted | Prevents kernel performance tracing |
| CAP_SYS_PTRACE | effective + permitted + bounding | Prevents reading other processes' memory |
| CAP_SETUID | effective + permitted | Prevents UID spoofing |
| CAP_SETGID | effective + permitted | Prevents GID spoofing |
| CAP_NET_RAW | effective + permitted | Prevents raw packet crafting |
| CAP_NET_ADMIN | bounding set | Prevents iptables/routing modifications |
| CAP_SYS_MODULE | bounding set | Prevents kernel module loading |
| CAP_SYS_RAWIO | bounding set | Prevents raw I/O port access |
| CAP_SYS_BOOT | bounding set | Prevents reboot |
| CAP_SYS_TIME | bounding set | Prevents clock manipulation |
| CAP_SYS_RESOURCE | bounding set | Prevents resource limit overrides |
| CAP_SETPCAP | bounding set | Prevents capability set manipulation |

`PR_SET_NO_NEW_PRIVS` prevents root `execve` from restoring capabilities. Once dropped,
caps cannot be regained by any process in the user code tree.

PID 1 (the runtime) retains full capabilities for NFS mount/re-mount on resume. It
cannot be ptrace'd (CAP_SYS_PTRACE is dropped from the bounding set).

### Core pattern lockdown

`/proc/sys/kernel/core_pattern` is protected by a **read-only bind mount** applied by
PID 1 before user code runs. This prevents the classic container escape where an
attacker writes a pipe handler (`|/path/to/evil`) and triggers a crash to execute code
in the init mount namespace.

Without CAP_SYS_ADMIN, user code cannot:
- Write to core_pattern (EROFS from the bind mount)
- Unmount the bind mount (requires CAP_SYS_ADMIN)
- Remount it read-write (requires CAP_SYS_ADMIN)
- Mount a fresh procfs (requires CAP_SYS_ADMIN)
- Create a new mount namespace (requires CAP_SYS_ADMIN)

### Data isolation

- **DynamoDB**: Per-tenant partition key (`T#<tenantId>`) with `LeadingKeys` conditions
- **S3 artifacts**: Tenant-scoped prefix (`workspaces/<tenantId>/`)
- **S3 Files workspaces**: Per-session access point scoped to
  `/<tenantId>/<principalId>/<sessionId>/`. NFS-level isolation — the mount physically
  cannot see outside its access point root directory.

### Credential exposure model

IMDS (169.254.169.254) is reachable from inside the sandbox. The execution role's
temporary credentials can be read by user code. This is an **accepted residual risk**
with the following mitigations:

**Why IMDS is not blocked**: The efs-proxy (S3 Files NFS tunnel) shares the network
namespace with user code and needs IMDS to refresh credentials on suspend/resume. The
kernel lacks `xt_cgroup` for selective per-process IMDS blocking. Blanket iptables
blocking breaks resume.

**Why the credentials are not dangerous**:

1. **Network-unreachable for AWS API use**: `.amazonaws.com` is in `NO_PROXY`, so boto3
   tries direct connections that timeout (zero-route subnets). The proxy also rejects
   `.amazonaws.com` domains. Stolen credentials cannot be used for AWS API calls from
   inside the sandbox.

2. **Narrowly scoped permissions**: The execution role allows only:
   - `s3:GetObject` / `s3:PutObject` within the tenant's artifact prefix
   - `s3files:Client*` on the specific filesystem

3. **Everything else is explicitly denied**:
   - `DenyBedrockDirect` — all Bedrock actions on `*`
   - `DenyEgressSecrets` — Secrets Manager for proxy secrets
   - `DenyEgressKey` — KMS for proxy encryption key
   - `DenyProxyRole` — STS AssumeRole for the proxy's task role

4. **Exfiltration path is narrow**: Credentials could theoretically be encoded into
   requests to allowed proxy domains (pypi.org, npmjs.org). From outside, the creds
   allow only tenant-scoped S3 read/write — the same data the sandbox already has
   access to via the NFS mount.

### Authentication

| Mode | Auth type | Tenant resolution | Notes |
|------|-----------|-------------------|-------|
| Multi-tenant (default) | Lambda authorizer + bearer token | Token → tenantId mapping | Development/testing |
| IAM (single-tenant) | SigV4 | Default "operator" tenant | Zero overhead |
| Cognito (documented) | JWT authorizer | JWT `sub` claim → tenantId | See [migration guide](cognito-auth.md) |

## Deployed Controls

| Control | Stack | Details |
|---------|-------|---------|
| VPC Flow Logs | NetworkStack | All traffic, CloudWatch Logs destination |
| Zero-route connector subnets | NetworkStack | No IGW, no NAT, no VPC endpoint routes |
| KMS encryption on artifacts | StateStack | AWS-managed key on S3 bucket |
| DynamoDB encryption | StateStack | AWS-managed key (default) |
| Lambda authorizer | ControlPlaneStack | Token validation + tenant isolation |
| Session limits | ControlPlaneStack | Per-tenant limit (default 100) |
| Egress policy enforcement | EgressStack | DDB-backed allowlist, 30s cache |
| DenyBedrockDirect IAM | ControlPlaneStack | Explicit deny on bedrock:Invoke*/Converse* |
| DenyEgressSecrets IAM | ControlPlaneStack | Deny secretsmanager for proxy secrets |
| DenyProxyRole IAM | ControlPlaneStack | Deny sts:AssumeRole for proxy role |
| core_pattern read-only bind | Runtime | Prevents pipe handler escape |
| User isolation (uid 1000) | Runtime (confine.py) | setuid(1000) + NNP, zero capabilities |
| Bounding set drops | Runtime | 8 caps irrevocably removed |
| Per-user workspace AP | Orchestrator | Access point scoped to `/<tenant>/<principal>/` |
| Proxy env auto-injection | Runtime | `https_proxy` for governed egress |
| Kernel hardening | Image | `modules_disabled=1`, `kexec_load_disabled=1`, `mem.devmem=0` |

## Red-Team Audit Results

### Methodology

Autonomous AI agents (Kimi K3 and Claude Sonnet 5 via Strands Agents SDK) were given
full sandbox access with instructions to try every possible escape, privilege escalation,
and data exfiltration technique. Multiple audit rounds were conducted across image
versions v41 through v53, with each round's findings driving the next version's hardening.

### Audit rounds

**Round 1 (Sonnet 5, v41)**: Initial reconnaissance. Found IMDS credential exposure and
full Linux capabilities. Led to iptables blocking and bounding set cap drops (v41).

**Round 2 (Kimi K3, v41)**: Deep kernel-level audit. Discovered the `core_pattern` pipe
handler escape (code execution in init mount namespace via `CAP_SYS_ADMIN` + writable
`/proc/sys/kernel/core_pattern`). Also found CAP_MKNOD allows block device node creation,
EFS TLS certs readable, direct mTLS to S3 Files backend. Led to bind mount + capset
confinement (v50).

**Round 3 (Kimi K3, v50)**: Post-fix verification. Confirmed core_pattern escape blocked
(EROFS), all bypass paths closed (umount, remount, fresh procfs, unshare, mknod all
denied). Found that S3 Files NFS access point jail holds against LOOKUPP traversal.
No escapes achieved.

**Round 4 (Kimi K3, v53)**: 45-minute audit. Found confinement bypass: user code as
root could overwrite system binaries, trigger `/suspend`+`/resume` via unauthenticated
port 8080, and PID 1's `subprocess.run` would exec the attacker binary with full
capabilities. Led to uid 1000 user isolation (v54).

**Round 5 (Kimi K3, v54)**: Final 30-minute audit on uid-1000 hardened image. Confirmed
v53 bypass is closed (binary overwrite denied, all privesc paths blocked). Found NFS
access point root POSIX identity (accepted: NNP blocks setuid, no cross-tenant access)
and unauthenticated terminate DoS (accepted: self-harm only). No escapes achieved.

### Accepted findings

These findings were identified during red-team audits, evaluated for risk, and accepted
with documented mitigations:

**IMDS credential readability** (accepted)
IMDS credentials are readable but scoped to tenant-prefix S3 only. AWS API endpoints
are network-unreachable from inside the sandbox (zero-route subnets + `NO_PROXY`
includes `.amazonaws.com`). Credentials cannot be used for AWS API calls from inside the
sandbox. Exfiltration yields creds with limited blast radius (same data accessible via
the NFS mount). Operator can further restrict with `aws:SourceVpce` IAM conditions.

**EFS/S3 Files TLS certificates readable** (accepted)
The stunnel configuration and TLS client certificate/key are readable by root user code.
However, the S3 Files access point jail holds — LOOKUPP traversal is blocked at the NFS
protocol level, and the pseudo-root returns zero entries. The credentials provide access
to the same data already available through the NFS mount. No cross-tenant access is
possible.

**DNS resolution of arbitrary domains** (accepted — operator mitigates)
The VPC DNS resolver resolves all domains, enabling low-bandwidth DNS tunneling.
This is operator-mitigated by deploying Route 53 Resolver DNS Firewall with a domain
allowlist. The allowlist is deployment-specific and not included in the CDK by default.

**Unauthenticated in-VM control plane (port 8080)** (by design)
The runtime's CBOR protocol on `127.0.0.1:8080` is unauthenticated. This is by design —
the external gateway (port 8443) handles authentication. The internal port only serves
operations that spawn confined children (exec, pty) or access `/tmp` (file operations).
No operation exposes PID 1's privileged capabilities to callers.

**Full capability bounding set** (platform limitation)
`additionalOsCapabilities: ["ALL"]` is required for NFS mount and cannot be individually
configured. The retained capabilities in the bounding set are not exploitable by user code
because `setuid(1000)` clears all effective and permitted caps, and `NO_NEW_PRIVS` prevents
restoration via `execve` on SUID or file-capability binaries. Verified: all SUID binaries
on the filesystem (mount, su, newuidmap, etc.) are inert under NNP.

**NFS access point root POSIX identity** (accepted — no local privesc)
The S3 Files access point enforces a root POSIX identity (`uid=0, gid=0`) for all NFS
operations, regardless of the client's uid. Files created on `/mnt/workspace` are owned
by root. This enables `chmod`, `chown` (including setuid bits) on workspace files. However:
- Setuid bits are inert: `NO_NEW_PRIVS=1` prevents any privilege gain from setuid binaries
- Cross-tenant access is blocked: the access point jail holds (LOOKUPP traversal denied)
- The workspace contains only the tenant's own data
- `mknod` is blocked by the NFS server (EFS restriction)

**Unauthenticated lifecycle hooks** (accepted — DoS only)
The runtime's lifecycle endpoints (`/suspend`, `/resume`, `/terminate`) on port 8080 are
unauthenticated by design. User code can terminate its own session. This is self-harm
only — it affects the attacker's own sandbox and does not impact other tenants or the
control plane. No privilege escalation is possible because system binaries are root-owned
and untouchable by uid 1000.

## Recommended — Operator Enables

These controls are not deployed by default because they require deployment-specific
configuration or have cost/compatibility implications the operator should decide on.

| Control | Why | Why not default |
|---------|-----|-----------------|
| Seccomp BPF filter | Reduces kernel attack surface by blocking unused syscalls (ptrace, bpf, io_uring, etc.) | Requires profiling which syscalls each tenant's workloads use. A too-restrictive filter breaks legitimate code (e.g., Python data science vs Node.js web scraping use different syscalls). |
| Route 53 DNS Firewall | Closes the DNS exfiltration channel by restricting which domains the VPC resolver answers | The domain allowlist is deployment-specific — what domains should resolve depends entirely on what the operator's tenants need. No universal default exists. |
| `aws:SourceVpce` IAM condition | Makes exfiltrated IMDS credentials unusable from outside the VPC | Requires an S3 VPC endpoint to be associated with the sandbox subnets. The condition would break S3 access if the operator's network topology differs from the reference deployment. |
| S3 Gateway VPC Endpoint | Enables the `aws:SourceVpce` condition above and provides direct S3 access from sandbox subnets | The sandbox subnets are intentionally zero-route. Adding an S3 route changes the network isolation model — the operator should explicitly decide which subnets get S3 access. |
| GuardDuty | Detects credential exfiltration via `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | Account-level service with billing implications across the entire account, not just this stack. If already enabled, re-deploying conflicts. If not enabled, it's an account-wide decision. |
| WAF on API Gateway | Rate limiting, IP filtering, request inspection | Requires deployment-specific configuration: rate limits, allowed IP ranges, and rule tuning vary between dev sandboxes (permissive) and production (restrictive). |
| CloudTrail data events | Full audit trail for S3 and DynamoDB operations | Costs money per event. S3 and DynamoDB data events can generate millions of records with significant storage costs. The operator should weigh the audit trail against cost for their compliance requirements. |
| Customer-managed KMS key | Key rotation control and cross-account access patterns | AWS-managed keys are sufficient for most deployments. Customer-managed keys add operational burden (key policy management, deletion protection) that is only justified for specific compliance requirements (HIPAA, PCI). |

## Compliance Positioning

### HIPAA

The architecture uses HIPAA-eligible services (Lambda, DynamoDB, S3, Fargate, KMS,
CloudWatch, Step Functions). Key controls:

- **Access control** (§164.312(a)): Per-tenant DDB partitions, Lambda authorizer,
  session data access roles, capability confinement
- **Audit controls** (§164.312(b)): VPC flow logs, CloudWatch logs, proxy audit logging
- **Integrity controls** (§164.312(c)): KMS encryption at rest, TLS in transit
- **Transmission security** (§164.312(e)): Zero-route subnets, governed proxy egress
- **PHI isolation**: VM-level isolation, per-user workspace access points,
  credential scoping to tenant prefix only

**Note**: HIPAA compliance requires a BAA with AWS and operational controls beyond
what this architecture deploys.

### PCI DSS

- **Network segmentation** (Req 1): VPC isolation, zero-route connector subnets
- **Encryption** (Req 3-4): KMS at rest, TLS in transit, proxy re-signing
- **Access control** (Req 7): Per-tenant partitions, least-privilege roles, capability confinement
- **Monitoring** (Req 10): VPC flow logs, CloudWatch, proxy logs

### SOC 2

- **Security**: VM isolation, capability confinement, egress control, authentication
- **Availability**: Suspend/resume, auto-resume, Step Functions orchestration
- **Confidentiality**: Per-user workspace isolation, credential scoping, core_pattern lockdown
