<!-- kiro-classification: public -->

# Persistent Workspace Setup Guide

Sessions with `persistence: true` mount a workspace at `/mnt/workspace` backed by S3 Files.
## Prerequisites

### 1. Enable S3 bucket versioning

S3 Files requires versioning on the artifact bucket. The CDK creates the bucket
but does not enable versioning by default.

Find the bucket from StateStack outputs and enable versioning:

aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled

Without this, filesystem creation fails with: Your bucket must have versioning enabled.

### 2. Verify S3 Files Service Role

The setup script creates S3FilesServiceRole. Verify the IAM policy is attached:

aws iam list-attached-role-policies --role-name S3FilesServiceRole

If empty, attach it:

aws iam attach-role-policy --role-name S3FilesServiceRole --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess (note: overly broad for production — replace with scoped policy)

If the role has no policies, filesystem creation stays in creating for ~3 minutes
then transitions to error with an empty statusReason field.

## Setup

Run: uv run python scripts/setup-s3files.py --region us-east-1

Creates: filesystem, mount targets, security group, access point.
Prints CDK context flags to copy-paste.

### Post-setup: Connector Security Group

The connector SG only allows TCP 443. Add NFS (TCP 2049) egress to mount target SG:

aws ec2 authorize-security-group-egress --group-id CONN_SG --protocol tcp --port-2049 --source-group MT_SG

Without this, mounts fail with Connection to the mount target IP address timeout.

## Deploy with Persistence

Re-deploy ControlPlaneStack with the S3 Files context flags printed by the setup script:

npx cdk deploy ControlPlaneStack -c s3filesFilesystemId=fs-xxxx -c s3filesAccessPointId=fsap-xxxx -c s3filesMountTargetIps=10.0.x.x,10.0.y.y

This adds s3files:Client* permission to the execution role and sets orchestrator env vars.

## Verify

Create a session with persistence=True and check:

mountpoint -q /mnt/workspace && echo Mounted

If mount fails, check: cat /tmp/_debug_mount.json

## File Ownership (posixUser)

The S3 Files access point is configured with `posixUser: {uid: 0, gid: 0}` (root).
This means all files created via NFS are owned by `root:root`, regardless of who
writes them inside the sandbox.

The sandbox process runs as **uid 1000** (non-root). The practical effect:

| Operation | Works? | Why |
|-----------|--------|-----|
| Create new file | ✅ | Directory has sticky bit (`drwxrwxrwt`), allows creation |
| Read file | ✅ | Files are world-readable (`644`) |
| Overwrite own file | ❌ | File is owned by root, uid 1000 has no write permission |
| Delete own file | ❌ | File is owned by root, uid 1000 cannot remove it |

**This is intentional for append-only workloads**: agents can write findings, logs,
and artifacts to `/mnt/workspace/` but cannot tamper with or delete files they've
already written. Each output should be a new file (e.g., `finding_001.txt`,
`finding_002.txt`). Use `/tmp` for scratch work that needs modification.

**To allow full read-write-delete access**, change the `posixUser` to match the
sandbox user in both:

1. `scripts/setup-s3files.py` — the default access point:
   ```python
   posixUser={"uid": 1000, "gid": 1000}
   ```

2. `control_plane/orchestrator/tasks.py` — per-session access points:
   ```python
   posixUser={"uid": 1000, "gid": 1000}
   ```

Existing access points are immutable — this only affects newly created ones.
Redeploy and create new sessions to take effect.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| Connection timeout | SG missing NFS egress rule or propagation delay (5 min) | Add SG rule, wait |
| access denied while mounting | Missing s3files:Client* on execution role | Redeploy with context flags |
| Operation not permitted | Missing additionalOsCapabilities: ALL | Rebuild image |
| Bucket has filesystem attached | Active filesystem | Delete APs, MTs, FS first |
| Filesystem error, empty reason | Role has no IAM policies | Attach AmazonS3FullAccess (note: overly broad for production — replace with scoped policy) |
| Versioning not enabled | Bucket versioning off | Enable versioning |

## Teardown Order

1. Delete all access points
2. Delete all mount targets, wait 30s
3. Delete filesystem, wait 60s
4. Delete S3 bucket
5. Then cdk destroy remaining stacks

