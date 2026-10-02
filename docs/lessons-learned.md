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

## 3. Per-tenant egress identification via source IP — doesn't work

**Problem**: We designed a per-tenant egress policy where the proxy identifies the
tenant by the MicroVM's source IP. The plan: each MicroVM registers its VPC IP at
`/run` time, the proxy maps source IP → tenant → policy.

**Root cause**: MicroVMs do NOT have unique IPv4 addresses. All MicroVMs on one
network connector share the connector ENI's IPv4. The proxy's
`socket.getpeername()` returns the same IP for every MicroVM on the connector.
Confirmed by the MicroVM service team.

**What we tried**: Source IP registration at `/run` hook, DynamoDB lookup in the
proxy. The registration worked but the IPs were identical.

**Correct approaches**:
- **One connector per tenant**: Each tenant gets its own connector with its own ENI
  and IPv4. Limit: 1,000 connectors/account. Creation is async (~10 min).
- **IPv6 /128**: DualStack connector gives each MicroVM a unique /128. Requires
  Network Firewall (~$320/month). Overkill for a reference architecture.
- **One policy for all**: Current approach. Simplest. Sufficient for most use cases.

**Decision**: Ship with one policy for all. Document connector-per-tenant and IPv6
as advanced options.

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

