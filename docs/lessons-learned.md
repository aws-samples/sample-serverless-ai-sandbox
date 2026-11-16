<!-- kiro-classification: public -->

# Lessons Learned — AWS Serverless Agent Sandbox

Hard-won engineering lessons from building the reference architecture. Each entry
documents a problem that took significant time to diagnose, the root cause, and
the fix. Intended to save time for anyone extending or redeploying this system.

---

## 1. S3 Files NFS mount inside Lambda MicroVMs

**Problem**: Mounting S3 Files (`mount -t s3files`) from inside a MicroVM failed
with `mount.nfs4: Operation not permitted`. The error gives no hint about the
actual cause.

**Root cause**: Lambda MicroVMs run with a restricted Linux capability set. The
capability bitmask (`00000000a80425fb`) does not include `CAP_SYS_ADMIN` (bit 21),
which the `mount` syscall requires.

**Fix**: The MicroVM Image API accepts `additionalOsCapabilities: ["ALL"]` in the
`POST /microvm-images` body. This grants all Linux capabilities including
`CAP_SYS_ADMIN`. The serverlessland reference pattern (`lambda-microvm-s3files`)
uses this. See `scripts/build-image.py`, `_create_image()`.

**Time to diagnose**: ~2 days. The capability bitmask had to be decoded manually
to identify the missing bit.

---

## 2. MicroVM image build — opaque `CREATE_FAILED`

**Problem**: MicroVM image builds failed with `CREATE_FAILED` and no error details.
The API response had `stateReason: unknown`. We rebuilt the image 17 times before
finding all the issues.

**Root causes** (three separate issues):

a) **`curl-minimal` vs `curl` conflict on AL2023**: The managed base image includes
   `curl-minimal`. Installing `git` (which depends on full `curl`) via `dnf` fails
   with a package conflict. The error only appears in CloudWatch build logs at
   `/aws/lambda-microvms/{image-name}`, not in the API response.
   **Fix**: `dnf -y --allowerasing install ...`

b) **Hooks port mismatch**: The image API's `hooks.port` must match the port the
   application listens on for lifecycle hooks (`/aws/lambda-microvms/runtime/v1/ready`).
   If the app serves hooks on port 9000 but `hooks.port` is 8080, the `/ready` check
   fails and the build fails silently.
   **Fix**: Ensure hooks.port matches the app's listening port.

c) **No internet during build (for `FROM` image pull)**: The Dockerfile's `FROM` image
   is pulled during the build. The build environment has internet access by default
   (via `INTERNET_EGRESS` connector), but the `FROM` image must be accessible from
   ECR Public. `public.ecr.aws/amazonlinux/amazonlinux:2023` works.

**Key insight**: Always check CloudWatch logs at `/aws/lambda-microvms/{image-name}`
for build failures. The API response is useless.

---

## 3. Per-tenant egress identification via source IP — IPv4 doesn't work, IPv6 does

**Problem (IPv4)**: We designed a per-tenant egress policy where the proxy identifies
the tenant by the MicroVM's source IP. The plan: each MicroVM registers its VPC IP at
`/run` time, the proxy maps source IP → tenant → policy.

**Root cause**: MicroVMs do NOT have unique IPv4 addresses. All MicroVMs on one
network connector share the connector ENI's IPv4. The proxy's
`socket.getpeername()` returns the same IP for every MicroVM on the connector.
Confirmed by the MicroVM service team.

**Solution (IPv6)**: On a DualStack connector, each MicroVM gets a unique IPv6 /128
from the VPC subnet CIDR — unforgeable, assigned by the hypervisor. At boot, the
MicroVM registers its /128 with the proxy using an opaque token (UUID4) sent via a
CONNECT header during PID 1 initialization. The NLB forwards the real /128 via Proxy
Protocol v2 on every connection, so the proxy identifies each VM per-request without
Network Firewall or any additional infrastructure.

**What didn't work (IPv4)**:
- Source IP registration at `/run` hook — IPs were identical across VMs
- One connector per tenant — 1,000 limit, 10-min async creation

**What works (IPv6)**:
- DualStack connector + PP2 + opaque registration token
- Proxy maps /128 → policyGroup per request (30s DDB cache)
- Fallback chain: group → tenant default → global default
- Zero additional cost vs IPv4-only deployment

**Decision**: Per-group egress via IPv6 identification is the default. See
[per-tenant-egress-design.md](per-tenant-egress-design.md) for the full design.

---

## 4. `findmnt -T` vs `mountpoint` for checking mounts

**Problem**: The S3 Files auto-mount function checked if `/mnt/workspace` was already
mounted using `findmnt -T /mnt/workspace`. The mount was never attempted because
`findmnt` returned success (exit 0) even when the path was just a regular directory.

**Root cause**: `findmnt -T <path>` returns the filesystem that CONTAINS the given
path, not whether the path IS a mountpoint. Since `/mnt/workspace` existed as a
directory on the root filesystem, `findmnt` returned the root FS info with exit 0.

**Fix**: Use `mountpoint -q <path>` instead, which specifically checks if the path
is a mountpoint. Exit 0 = is a mountpoint, exit 32 = is not.

**Time to diagnose**: 5 image rebuilds. The function created the directory, found
params correctly, but silently returned before running the mount command.

---

## 5. `https_proxy` breaks AWS SDK credential retrieval (IMDS)

**Problem**: After setting `https_proxy` env var (for `dnf`/`pip`/`curl` to route
through the egress proxy), `boto3` calls to Bedrock failed with
`NoCredentialsError: Unable to locate credentials`.

**Root cause**: `boto3` retrieves credentials from IMDSv2 at `169.254.169.254`.
With `https_proxy` set, the SDK tried to reach IMDS through the proxy. The proxy
doesn't handle link-local addresses and the connection failed.

**Fix**: Set `NO_PROXY=169.254.169.254,169.254.170.2,127.0.0.1,localhost,.amazonaws.com,.api.aws`.
This excludes IMDS, credential endpoints, and all AWS service endpoints (which go
through VPC endpoints, not the internet proxy) from the proxy.

---

## 6. `DenyBedrockDirect` IAM policy requires positive allow

**Problem**: After removing the `DenyBedrockDirect` IAM statement to allow Bedrock
calls from inside the MicroVM, calls still failed with `AccessDeniedException` —
but now the error said "no identity-based policy allows" instead of "explicit deny."

**Root cause**: Removing a deny is not the same as adding an allow. The execution
role had no positive `Allow` statement for `bedrock:InvokeModel`. Without the deny,
IAM's default-deny applies.

**Fix**: Add an explicit `Allow` statement for `bedrock:InvokeModel`,
`bedrock:Converse`, etc. on the execution role.

---

## 7. MicroVM image build is NOT CodeBuild

**Problem**: Could not find image build logs in CodeBuild. Assumed the MicroVM
image build used CodeBuild like the Fargate proxy image.

**Reality**: Lambda MicroVM image builds use a Lambda-native build service. The
build is triggered by `POST /microvm-images` (SigV4-signed). Build logs go to
CloudWatch at `/aws/lambda-microvms/{image-name}`. The script
`scripts/build-image.py` drives the REST API directly.

The CodeBuild project (`ImageBuild30B7C98D-*`) is for the egress proxy Fargate
image only.

---

## 8. S3 Files sync role trust principal

**Problem**: Created the S3 Files sync role with trust principal
`s3files.amazonaws.com`. File system creation failed.

**Root cause**: The correct trust principal is `elasticfilesystem.amazonaws.com`,
not `s3files.amazonaws.com`. S3 Files is built on EFS infrastructure internally.

**Fix**: Trust policy `Principal.Service: elasticfilesystem.amazonaws.com`.

---

## 9. S3 Files API — `bucket` parameter requires ARN, not name

**Problem**: `boto3 s3files.create_file_system(bucket="my-bucket-name")` failed
with a validation error about regex pattern.

**Root cause**: The `bucket` parameter expects an S3 bucket ARN
(`arn:aws:s3:::bucket-name`), not the bucket name string.

**Fix**: `bucket="arn:aws:s3:::my-bucket-name"`.

---

## 10. runHookPayload is double-serialized by the platform

**Problem**: The runtime's `/run` hook received the payload but couldn't find the
S3 Files mount parameters in it, even though the orchestrator correctly injected
them.

**Root cause**: The Lambda MicroVM platform wraps the runHookPayload in an envelope:
```json
{"microvmId": "...", "runHookPayload": "{\"egressEndpoint\":\"...\",\"s3filesFileSystemId\":\"...\"}"}
```
The `runHookPayload` value is a **JSON string** (double-serialized), not a JSON
object. The runtime must `json.loads()` it twice — once for the envelope, once for
the inner payload.

**Fix**: Unwrap with:
```python
envelope = json.loads(payload)
inner = json.loads(envelope["runHookPayload"])  # double-deserialize
fs_id = inner.get("s3filesFileSystemId")
```

---

## 11. MCP tools without a session key provision a new MicroVM per call

**Problem**: Calling the MCP tools endpoint (`POST /tool`) without the
`x-session-key` header caused every tool call to provision a separate MicroVM.
A sequence of `write_file` then `read_file` hit different sandboxes, so the
read returned an empty error — the file didn't exist on that VM.

**Root cause**: The MCP handler uses the `x-session-key` header (or
`x-mcp-session-id`) to look up a cached session. Without it, `session_key` is
empty, the cache is never consulted, and `_create_session()` provisions a new
MicroVM on every invocation. The in-memory Lambda cache only works within the
same execution environment, and even then only if the key is present.

**Fix**: Always include `x-session-key: <stable-identifier>` (conversation ID,
user session ID, etc.) on every MCP tool call. With the header present, the
handler caches the session and subsequent calls reuse the same sandbox. All six
tools then work correctly against the same MicroVM.


---

## 12. Uid-based network filtering on a Firecracker guest: iptables-owner and nftables both fail
**Problem**: Code running as an unprivileged user could open a raw TCP connection to an NFS
mount target that a root helper process (efs-proxy) legitimately uses from the same network
namespace. A security-group rule could not close it, because the helper needs the same path.
**Root cause**: The guest kernel has `modules_disabled=1`. `iptables -m owner --uid-owner`
fails silently (no `xt_owner`). `nft ... meta skuid` fails with `Operation not supported`
(`nf_tables` is not compiled in; the `nft` binary was also missing from the image). There is no
`xt_cgroup` either.
**Fix**: Policy routing is built into the kernel. At boot, as root and before dropping
`CAP_NET_ADMIN` from the bounding set, add
`ip rule add uidrange 1000-1000 to <mount-target-ip>/32 blackhole`. A direct connect from that
uid now fails with `EINVAL`; the helper (root) is unaffected. Verify from inside the guest.
**Key insight**: On a locked-down guest kernel, check which netfilter features exist before
designing around them. FIB rules may be the only uid-based filter.

---

## 13. Disable unprivileged user namespaces in the guest
**Problem**: An unprivileged user could `unshare(CLONE_NEWUSER)` and receive a full capability
set inside the new namespace without holding any capability.
**Root cause**: Creating a user namespace needs no privilege, so dropping capabilities does not
stop it. Those capabilities cannot act on host-owned objects, but they make overlayfs,
nf_tables and io_uring local-privilege-escalation code reachable.
**Fix**: At boot, as root, write `0` to `/proc/sys/user/max_user_namespaces`. `unshare`,
`clone` and `clone3` with `CLONE_NEWUSER` then return `ENOSPC`, and the user cannot raise it.

---

## 14. Container escape tricks work inside a guest too: `core_pattern`
**Problem**: With root in the guest and `CAP_SYS_ADMIN`, writing a pipe handler to
`/proc/sys/kernel/core_pattern` and crashing a process runs the handler as root in the guest's
init mount namespace, exposing platform agents and credentials there. Reasoning that a
Firecracker guest "cannot escape" missed that the guest has its own namespaces to escape into.
**Root cause**: `core_pattern` writes are gated by uid, not by capability, so dropping
`CAP_SYS_ADMIN` alone is not enough. A read-only bind mount alone is not enough either (root
with `CAP_SYS_ADMIN` can unmount it).
**Fix**: Both together: a read-only bind mount of `core_pattern` and confinement of every user
process (no-new-privs plus a `capset` that drops `SYS_ADMIN`, `BPF`, `MKNOD`, `PERFMON`,
`PTRACE`, `SETUID`, `SETGID`, `NET_RAW`) applied as `preexec_fn`. Pitfalls:
`ctypes.util.find_library` inside a `preexec_fn` deadlocks in the forked child; import the
confinement from a module, not `__main__`; check idempotency with a read, not a write. Bisect
by shipping one control per image.

---

## 15. Do not let a privileged PID 1 execute binaries that untrusted root can replace
**Problem**: User code running as root overwrote `/usr/bin/mountpoint`, called the
(unauthenticated) lifecycle hooks, and PID 1 then ran the replaced binary with full capabilities.
**Root cause**: PID 1 shelled out to binaries on a filesystem the untrusted code could write.
Wrapping each internal call in confinement is a stopgap (`mount` itself needs the privileges),
and a read-only rootfs breaks package installs.
**Fix**: Run user code as a non-root uid (create the user in the image; setuid in the
confinement step, which also clears all capabilities). Keep PID 1 as the only privileged
process, chown the writable paths at start. Lifecycle hooks on the loopback port are
unauthenticated by design (the platform proxy is the authenticated boundary); document this.

---

## 16. Blocking IMDS with iptables is bypassable and can break suspend/resume
**Problem**: Guest user code could read the execution role's credentials from the instance
metadata service. An iptables DROP on 169.254.169.254 blocked the SDK too; root with
`CAP_NET_ADMIN` could delete the rule; and after dropping that capability, resume of an
NFS-backed workspace returned 502.
**Root cause**: The NFS helper re-authenticates through IMDS after a snapshot restore, and the
block applies to every process in the network namespace. (Bisected by commenting out the block
in the current image; testing an old image would have proved nothing.)
**Fix**: Do not block IMDS. Keep the role minimal with explicit denies, drop capabilities, keep
the connector subnets at zero routes so stolen credentials have nowhere to go, and document the
residual risk. An `aws:SourceVpce` condition would also block legitimate calls.

---

## 17. Adding IPv6 to a CDK L2 VPC: `AssignIpv6AddressOnCreation` on a fresh deploy (CDK #28843)
**Problem**: A fresh deploy failed with "Target group requires ipv6 addresses, but subnet only
supports ipv4". The subnets had IPv6 CIDR blocks but Fargate ENIs got no IPv6 address.
**Root cause**: `AssignIpv6AddressOnCreation` was never set by the stack. It had been set once
by hand on the long-lived VPC, and a code comment warning about it was deleted as stale.
CloudFormation needs `Ipv6CidrBlock` and `AssignIpv6AddressOnCreation` on the same subnet
resource, which conflicts with a separate `CfnSubnetCidrBlock`.
**Fix** (four attempts): (1) the flag plus `add_dependency` on the CIDR resource: circular
dependency. (2) The flag without the dependency: "Ipv6CidrBlock or Ipv6IpamPoolId cannot be
empty". (3) Property override of both on the `CfnSubnet`: the known race
`Fn::Select cannot select nonexistent value at index 0` (CDK #28843). (4) Working: an
`AwsCustomResource` that calls `ec2:ModifySubnetAttribute(AssignIpv6AddressOnCreation=true)`
after the CIDR association exists, with `on_delete` setting it back to false. On teardown the
flag must be unset before the IPv6 CIDR can be disassociated.

---

## 18. Identifying a VM at a proxy over IPv6: NLB, `preserve_client_ip` and Proxy Protocol v2
**Problem**: The proxy needs each VM's unique IPv6 /128, but it logged the load balancer's own
IPv4 address for IPv6 clients.
**Root cause**: `preserve_client_ip` does not carry an IPv6 client address to an IPv4 target.
Target-group `IpAddressType` must be `ipv6` (not `dualstack`) and is immutable. Manual
configuration of target group attributes was reset by every IaC deploy, so an early manual
success did not reflect the template. PP2 left on an IPv4 target group breaks TCP health checks.
**Fix**: Dual-stack NLB, target group `ipv6`, `proxy_protocol_v2` enabled, and the proxy parses
the PP2 header. The VM must reach the proxy over IPv6 (set the proxy to an IPv6 literal, see
entry 19). Only a dual-stack connector yields a VPC-routable /128 (a single-stack connector's
/128 comes from a different pool and is not routable to the VPC).

---

## 19. Dual-stack Fargate proxy checklist
**Problem**: A cluster of independent faults, each initially mistaken for another.
**Fixes**:
1. `net.ipv6.ip_unprivileged_port_start` does not exist (only `net.ipv4.*`, which covers all
   protocols). Adding it crashed the task and masqueraded as a health-check failure.
2. Bind both `0.0.0.0` and `::` (a lone `::` failed health checks on Fargate).
3. Read the PP2 header with a ~2 s timeout (health checks send zero bytes) and always prepend
   the bytes read back to the stream, or the CONNECT line is lost.
4. Docker HEALTHCHECK must use `127.0.0.1`, not `::1`.
5. Force upstream connections to `AF_INET`: the task has IPv6, `getaddrinfo` returns AAAA first
   and there is no IPv6 route out, so connects hang for exactly the connect timeout.
6. `curl` needs `--proxy-header` (not `-H`) to send a header on the CONNECT itself.
7. A failing health check can be an old task still serving: wait for the roll.
8. Proxy URLs with an IPv6 literal (`http://[2600:...]:443`) break regexes like
   `http://([^:]+):(\d+)`. Use `urllib.parse.urlparse` everywhere, including docs and examples
   (grep every copy).

---

## 20. Never derive policy identity from anything the guest sends
**Problem**: Several designs let the proxy learn which tenant a VM belongs to from a header, a
self-reported IP or tenant fields passed into the guest. All are spoofable or unreliable.
Entry 3 covers the /128 plus token bootstrap; this entry covers the surrounding rules.
**Fix**: No tenant data enters the box: the orchestrator stores the opaque token with the
session record and sends only the token. The policy group is derived server-side (authorizer
context or IAM tag), never caller-supplied. Unregistered sources fall back to the default
policy, never to open. A /128-to-group mapping held only in process memory fails with more than
one proxy task; write it to the shared store. Validate with distinct real principals, not a
toggled tag on one user.

---

## 21. MicroVM image identity: full ARN, immutable names, one image per runtime change
**Problem**: Deploys failed with `Malformed ARN` or `No active version found`.
**Root cause**: The build script printed `name:1`; the API needs the full image ARN as
`imageIdentifier`. Names cannot be reused (409; delete and wait, or version the names). The
runtime is baked into the image, so every runtime change is a new image, and the deployed image
must match the name used for the deploy.
**Fix**: Print the ARN, keep a naming convention, and keep a known-good image for rollback.

---

## 22. MicroVM runtime gotchas
- Application stdout and stderr are not forwarded without an execution role that allows
  CloudWatch Logs writes, so a failing `/run` hook shows nothing. Write debug JSON to a file and
  read it back, or add the role.
- `execute(env=...)` replaces the entire environment (PATH disappears: `python3` not found,
  exit 127).
- The protocol file operations are scoped to `/tmp`; workspace files go through `execute`.
- The first command pays platform cold start (the app side was about 50 ms). Warm-pool starts
  take seconds and cold starts can take minutes. Measure a baseline before changing
  infrastructure, and change one thing at a time.
- `idlePolicy.maxIdleDurationSeconds` has a minimum of 60.
- An orchestrator step that polls can keep waking a suspended VM; confirm suspend at the
  compute, database and workflow layers.
