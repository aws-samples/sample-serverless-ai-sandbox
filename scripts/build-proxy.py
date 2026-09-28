# kiro-classification: public
# ruff: noqa: N999
"""Build the Egress_Controller proxy image via CodeBuild and push it to ECR.

Docker Desktop is not required: CodeBuild builds the image from the repository's
``egress/Dockerfile`` and pushes it to an ECR repository in the target Region.

Usage::

    uv run python scripts/build-proxy.py --region us-east-1

The script:
1. Creates or reuses an ECR repository named ``sandbox-egress-proxy``.
2. Zips the build context (``egress/`` and ``control_plane/allocation/``) and uploads it
   to the CDK bootstrap bucket in S3.
3. Creates or reuses a CodeBuild project named ``sandbox-proxy-build`` that builds the
   Dockerfile and pushes the resulting image to ECR.
4. Starts a build and polls until complete.
5. Prints the image URI for use with ``cdk deploy -c proxyImageUri=…``.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Final

import boto3  # type: ignore[import-untyped]
import botocore.exceptions  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: ECR repository name for the proxy image.
_ECR_REPO_NAME: Final = "sandbox-egress-proxy"

#: CodeBuild project name.
_CODEBUILD_PROJECT_NAME: Final = "sandbox-proxy-build"

#: CodeBuild image with Docker support.
_CODEBUILD_IMAGE: Final = "aws/codebuild/standard:7.0"

#: S3 key prefix for the uploaded build context.
_S3_KEY_PREFIX: Final = "proxy-build"

#: CDK bootstrap bucket naming convention.
_CDK_BOOTSTRAP_BUCKET_TEMPLATE: Final = "cdk-hnb659fds-assets-{account}-{region}"

#: Poll interval in seconds when waiting for the CodeBuild build.
_POLL_INTERVAL_SECONDS: Final = 15

#: Maximum poll iterations before giving up.
_MAX_POLL_ITERATIONS: Final = 80

#: The buildspec inlined into the CodeBuild project.
_BUILDSPEC: Final = """\
version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
  build:
    commands:
      - docker build -t $REPO_URI:latest -f egress/Dockerfile .
      - docker push $REPO_URI:latest
"""

# ---------------------------------------------------------------------------
# Repository root — one level above ``scripts/``.
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _die(msg: str) -> None:
    """Print an error and exit with status 1."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _get_account_id() -> str:
    """Return the caller's AWS account ID via STS."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Step 1: ECR repository
# ---------------------------------------------------------------------------


def _ensure_ecr_repository(region: str) -> str:
    """Create or reuse the ECR repository and return its URI."""
    ecr = boto3.client("ecr", region_name=region)
    try:
        resp = ecr.describe_repositories(repositoryNames=[_ECR_REPO_NAME])
        uri: str = resp["repositories"][0]["repositoryUri"]
        print(f"Reusing ECR repository: {uri}")
        return uri
    except ecr.exceptions.RepositoryNotFoundException:
        pass

    print(f"Creating ECR repository {_ECR_REPO_NAME} …")
    resp = ecr.create_repository(
        repositoryName=_ECR_REPO_NAME,
        imageScanningConfiguration={"scanOnPush": True},
        imageTagMutability="MUTABLE",
    )
    uri = resp["repository"]["repositoryUri"]
    print(f"Created ECR repository: {uri}")
    return uri


# ---------------------------------------------------------------------------
# Step 2: zip and upload
# ---------------------------------------------------------------------------


def _build_zip() -> bytes:
    """Create an in-memory zip of the build context.

    Includes ``egress/`` (with its Dockerfile) and ``control_plane/allocation/``
    (needed for the ``DenialReason`` import at runtime).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for pkg in ("egress", os.path.join("control_plane", "allocation")):
            pkg_dir = _REPO_ROOT / pkg
            if not pkg_dir.is_dir():
                _die(f"Required directory not found: {pkg_dir}")
            for root_path, _dirs, files in os.walk(pkg_dir):
                root = Path(root_path)
                for fname in files:
                    full = root / fname
                    if "__pycache__" in full.parts or full.suffix == ".pyc":
                        continue
                    arcname = str(full.relative_to(_REPO_ROOT))
                    zf.write(full, arcname)

        # Include the control_plane/__init__.py so the package is importable.
        cp_init = _REPO_ROOT / "control_plane" / "__init__.py"
        if cp_init.is_file():
            zf.write(cp_init, str(cp_init.relative_to(_REPO_ROOT)))

    return buf.getvalue()


def _resolve_bucket(bucket: str | None, account: str, region: str) -> str:
    """Return the bucket to use, falling back to the CDK bootstrap bucket."""
    if bucket:
        return bucket

    cdk_bucket = _CDK_BOOTSTRAP_BUCKET_TEMPLATE.format(account=account, region=region)
    s3 = boto3.client("s3", region_name=region)
    try:
        s3.head_bucket(Bucket=cdk_bucket)
        print(f"Using CDK bootstrap bucket: {cdk_bucket}")
        return cdk_bucket
    except botocore.exceptions.ClientError:
        _die(
            f"CDK bootstrap bucket {cdk_bucket} not found. Either bootstrap CDK "
            f"(npx cdk bootstrap aws://{account}/{region}) or pass --bucket."
        )
    return ""  # unreachable, satisfies mypy


def _upload_zip(zip_bytes: bytes, bucket: str, region: str) -> str:
    """Upload the zip to S3 and return the key."""
    key = f"{_S3_KEY_PREFIX}/proxy-context-{int(time.time())}.zip"
    s3 = boto3.client("s3", region_name=region)
    print(f"Uploading build context to s3://{bucket}/{key} …")
    s3.put_object(Bucket=bucket, Key=key, Body=zip_bytes)
    return key


# ---------------------------------------------------------------------------
# Step 3: CodeBuild project
# ---------------------------------------------------------------------------


def _ensure_codebuild_project(
    region: str,
    repo_uri: str,
    bucket: str,
    service_role_arn: str,
) -> str:
    """Create or reuse the CodeBuild project. Returns the project name."""
    cb = boto3.client("codebuild", region_name=region)
    try:
        cb.batch_get_projects(names=[_CODEBUILD_PROJECT_NAME])
        existing = cb.batch_get_projects(names=[_CODEBUILD_PROJECT_NAME])
        if existing["projects"]:
            print(f"Reusing CodeBuild project: {_CODEBUILD_PROJECT_NAME}")
            # Update the project to ensure the environment and source are current.
            cb.update_project(
                name=_CODEBUILD_PROJECT_NAME,
                source={"type": "S3", "location": f"{bucket}/", "buildspec": _BUILDSPEC},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": _CODEBUILD_IMAGE,
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "privilegedMode": True,
                    "environmentVariables": [
                        {"name": "REPO_URI", "value": repo_uri, "type": "PLAINTEXT"},
                    ],
                },
                serviceRole=service_role_arn,
            )
            return _CODEBUILD_PROJECT_NAME
    except cb.exceptions.ResourceNotFoundException:
        pass

    print(f"Creating CodeBuild project {_CODEBUILD_PROJECT_NAME} …")
    cb.create_project(
        name=_CODEBUILD_PROJECT_NAME,
        description="Builds the egress proxy Docker image and pushes to ECR",
        source={"type": "S3", "location": f"{bucket}/", "buildspec": _BUILDSPEC},
        environment={
            "type": "LINUX_CONTAINER",
            "image": _CODEBUILD_IMAGE,
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": True,
            "environmentVariables": [
                {"name": "REPO_URI", "value": repo_uri, "type": "PLAINTEXT"},
            ],
        },
        serviceRole=service_role_arn,
        artifacts={"type": "NO_ARTIFACTS"},
    )
    return _CODEBUILD_PROJECT_NAME


# ---------------------------------------------------------------------------
# Step 3b: CodeBuild service role
# ---------------------------------------------------------------------------


def _ensure_codebuild_role(account: str, region: str, bucket: str) -> str:
    """Create or reuse the IAM service role for CodeBuild. Returns its ARN."""
    import json

    role_name = "sandbox-proxy-codebuild"
    iam_client = boto3.client("iam")

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codebuild.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )

    inline_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:GetAuthorizationToken",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                        "ecr:PutImage",
                        "ecr:InitiateLayerUpload",
                        "ecr:UploadLayerPart",
                        "ecr:CompleteLayerUpload",
                    ],
                    "Resource": f"arn:aws:ecr:{region}:{account}:repository/{_ECR_REPO_NAME}",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetBucketLocation",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",  # CreateLogGroup requires Resource: * by API design
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )

    try:
        resp = iam_client.get_role(RoleName=role_name)
        arn: str = resp["Role"]["Arn"]
        print(f"Reusing existing CodeBuild role: {arn}")
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="proxy-build-access",
            PolicyDocument=inline_policy,
        )
        return arn
    except iam_client.exceptions.NoSuchEntityException:
        pass

    print("Creating IAM CodeBuild role …")
    resp = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description="Service role for the egress proxy CodeBuild project",
    )
    arn = resp["Role"]["Arn"]

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="proxy-build-access",
        PolicyDocument=inline_policy,
    )

    print("Waiting for IAM role propagation …")
    time.sleep(10)  # nosemgrep: arbitrary-sleep — polling loop by design

    return arn


# ---------------------------------------------------------------------------
# Step 4: start a build and poll
# ---------------------------------------------------------------------------


def _start_and_poll_build(
    project_name: str,
    region: str,
    bucket: str,
    key: str,
) -> None:
    """Start a CodeBuild build and poll until it completes."""
    cb = boto3.client("codebuild", region_name=region)

    print("Starting CodeBuild build …")
    resp = cb.start_build(
        projectName=project_name,
        sourceLocationOverride=f"{bucket}/{key}",
        sourceTypeOverride="S3",
    )
    build_id: str = resp["build"]["id"]
    print(f"Build started: {build_id}")

    for i in range(_MAX_POLL_ITERATIONS):
        time.sleep(_POLL_INTERVAL_SECONDS)
        builds = cb.batch_get_builds(ids=[build_id])
        build = builds["builds"][0]
        phase = build.get("currentPhase", "UNKNOWN")
        status = build.get("buildStatus", "IN_PROGRESS")
        print(f"  [{i + 1}] Phase: {phase}  Status: {status}")

        if status == "SUCCEEDED":
            return
        if status in ("FAILED", "FAULT", "TIMED_OUT", "STOPPED"):
            phases = build.get("phases", [])
            for p in phases:
                if p.get("phaseStatus") not in (None, "SUCCEEDED"):
                    contexts = p.get("contexts", [])
                    for ctx in contexts:
                        print(f"    {p['phaseType']}: {ctx.get('message', '')}", file=sys.stderr)
            _die(f"Build {build_id} ended with status: {status}")

    _die(f"Timed out after {_MAX_POLL_ITERATIONS * _POLL_INTERVAL_SECONDS}s waiting for build")


# ---------------------------------------------------------------------------
# Step 5: print result
# ---------------------------------------------------------------------------


def _print_result(repo_uri: str) -> None:
    """Print the success banner."""
    image_uri = f"{repo_uri}:latest"
    print()
    print("Proxy image built and pushed.")
    print(f"Image URI: {image_uri}")
    print()
    print("To deploy:")
    print(
        f"  npx cdk deploy --all"
        f" -c imageVersion=sandbox-runtime:1"
        f" -c proxyImageUri={image_uri}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the egress proxy Docker image via CodeBuild and push to ECR.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--region",
        required=True,
        help="AWS Region to build in (e.g. us-east-1)",
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="S3 bucket for the build context (uses CDK bootstrap bucket if omitted)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    args = _parse_args(argv)
    region: str = args.region

    # 1. ECR repository.
    repo_uri = _ensure_ecr_repository(region)

    # 2. Package and upload.
    print("Packaging build context …")
    zip_bytes = _build_zip()
    print(f"  Zip size: {len(zip_bytes):,} bytes")

    account = _get_account_id()
    bucket = _resolve_bucket(args.bucket, account, region)
    key = _upload_zip(zip_bytes, bucket, region)

    # 3. CodeBuild project.
    role_arn = _ensure_codebuild_role(account, region, bucket)
    project_name = _ensure_codebuild_project(region, repo_uri, bucket, role_arn)

    # 4. Build and poll.
    _start_and_poll_build(project_name, region, bucket, key)

    # 5. Done.
    _print_result(repo_uri)


if __name__ == "__main__":
    main()
