# kiro-classification: public
# ruff: noqa: N999
"""Build the Sandbox_Runtime MicroVM image via the raw REST API.

The ``lambda-microvms`` service model is not yet available in boto3, so this script drives the
three MicroVM image API calls directly with SigV4 signing (service name: ``lambda``).  boto3 is
used only for S3 uploads and STS/IAM calls, which have full SDK support.

Usage::

    python scripts/build-image.py --region us-east-1

The script packages ``runtime/``, ``protocol/``, ``pyproject.toml`` and ``uv.lock`` together
with a generated Dockerfile, uploads the zip to S3, discovers (or accepts) a base image,
creates (or reuses) a build role, kicks off the image build and polls until completion.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
import botocore.auth  # type: ignore[import-untyped]
import botocore.awsrequest  # type: ignore[import-untyped]
import botocore.exceptions  # type: ignore[import-untyped]
import botocore.session  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The API date prefix for the Lambda MicroVMs REST surface.
_API_DATE: str = "2025-09-09"

#: SigV4 service name — all MicroVM endpoints sit under the ``lambda`` service.
_SERVICE_NAME: str = "lambda"

#: The Dockerfile baked into the zip.  It uses ``uv export`` to produce a flat requirements
#: file, installs with pip, and copies the two Python packages.
_DOCKERFILE: str = """\
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
WORKDIR /var/task
RUN dnf -y --allowerasing install amazon-efs-utils nfs-utils python3.13 git jq iptables iproute \\
    && dnf clean all && rm -rf /var/cache/dnf
RUN python3.13 -m ensurepip --upgrade \\
    && python3.13 -m pip install --no-cache-dir --upgrade pip
RUN ln -sf /usr/bin/python3.13 /usr/local/bin/python3 \\
    && ln -sf /usr/bin/python3.13 /usr/local/bin/python
COPY pyproject.toml uv.lock ./
RUN python3.13 -m pip install --no-cache-dir uv \\
    && uv export --frozen --no-dev --no-emit-workspace --extra runtime --format requirements-txt > requirements.txt \\
    && python3.13 -m pip install --no-cache-dir -r requirements.txt \\
    && python3.13 -m pip install --no-cache-dir boto3
COPY runtime runtime
COPY protocol protocol
CMD ["python3.13", "-m", "runtime"]
"""

#: Name of the CDK bootstrap bucket (conventional).
_CDK_BOOTSTRAP_BUCKET_TEMPLATE: str = "cdk-hnb659fds-assets-{account}-{region}"

#: IAM trust policy allowing Lambda to assume the build role.
_BUILD_ROLE_TRUST_POLICY: str = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

#: Note: logs:* actions use Resource: * because CreateLogGroup requires it by API design.
#: Inline policy granting S3 read on the zip and CloudWatch Logs for build output.
_BUILD_ROLE_POLICY_TEMPLATE: str = """\
{{
    "Version": "2012-10-17",
    "Statement": [
        {{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::{bucket}/{key}"
        }},
        {{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }}
    ]
}}
"""

#: Poll interval in seconds.
_POLL_INTERVAL_SECONDS: int = 30

#: Maximum number of poll iterations before giving up.
_MAX_POLL_ITERATIONS: int = 60

# ---------------------------------------------------------------------------
# Repository root — one level above ``scripts/``.
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# SigV4-signed HTTP helper (same pattern as demo/client.py)
# ---------------------------------------------------------------------------


def _signed_request(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    region: str = "us-east-1",
) -> dict[str, Any]:
    """Send a SigV4-signed request to the Lambda MicroVM REST API."""
    data = json.dumps(body).encode() if body is not None else None
    headers: dict[str, str] = {"Content-Type": "application/json"} if data else {}

    aws_request = botocore.awsrequest.AWSRequest(
        method=method, url=url, data=data, headers=headers
    )

    session = botocore.session.get_session()
    credentials = session.get_credentials()
    if credentials is None:
        _die("No AWS credentials found — set AWS_PROFILE or credential env vars")
    signer = botocore.auth.SigV4Auth(
        credentials.get_frozen_credentials(), _SERVICE_NAME, region
    )
    signer.add_auth(aws_request)

    stdlib_request = urllib.request.Request(
        url,
        data=data,
        headers=dict(aws_request.headers),
        method=method,
    )

    try:
        with urllib.request.urlopen(stdlib_request) as resp: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
            return json.loads(resp.read())  # type: ignore[no-any-return]
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode(errors="replace")
        _die(f"HTTP {exc.code} for {method} {url}:\n{response_body}")
    return {}  # unreachable, satisfies mypy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _die(msg: str) -> None:
    """Print an error and exit with status 1."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _lambda_url(region: str, path: str) -> str:
    """Build a full URL against the Lambda MicroVM REST surface."""
    return f"https://lambda.{region}.amazonaws.com/{_API_DATE}/{path.lstrip('/')}"


def _get_account_id() -> str:
    """Return the caller's AWS account ID via STS."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Step 1: package the runtime into a zip
# ---------------------------------------------------------------------------


def _build_zip() -> bytes:
    """Create an in-memory zip of runtime/, protocol/, pyproject.toml, uv.lock and Dockerfile."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add the Dockerfile at the root of the zip.
        zf.writestr("Dockerfile", _DOCKERFILE)

        # Add pyproject.toml and uv.lock.
        for name in ("pyproject.toml", "uv.lock"):
            src = _REPO_ROOT / name
            if src.is_file():
                zf.write(src, name)
            else:
                _die(f"Required file not found: {src}")

        # Walk runtime/ and protocol/.
        for pkg in ("runtime", "protocol"):
            pkg_dir = _REPO_ROOT / pkg
            if not pkg_dir.is_dir():
                _die(f"Required directory not found: {pkg_dir}")
            for root_path, _dirs, files in os.walk(pkg_dir):
                root = Path(root_path)
                for fname in files:
                    full = root / fname
                    # Skip __pycache__ and .pyc files.
                    if "__pycache__" in full.parts or full.suffix == ".pyc":
                        continue
                    arcname = str(full.relative_to(_REPO_ROOT))
                    zf.write(full, arcname)

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Step 2: upload the zip to S3
# ---------------------------------------------------------------------------


def _upload_zip(zip_bytes: bytes, bucket: str, region: str) -> str:
    """Upload *zip_bytes* to *bucket* and return the S3 key."""
    key = f"microvm-images/sandbox-runtime-{int(time.time())}.zip"
    s3 = boto3.client("s3", region_name=region)
    print(f"Uploading code artifact to s3://{bucket}/{key} …")
    s3.put_object(Bucket=bucket, Key=key, Body=zip_bytes)
    return key


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
            f"CDK bootstrap bucket {cdk_bucket} not found.  Either bootstrap CDK "
            f"(npx cdk bootstrap aws://{account}/{region}) or pass --bucket."
        )
    return ""  # unreachable, satisfies mypy


# ---------------------------------------------------------------------------
# Step 3: discover the base image
# ---------------------------------------------------------------------------


def _discover_base_image(region: str) -> str:
    """Call the managed-microvm-images endpoint and return the first image ARN."""
    url = _lambda_url(region, "managed-microvm-images")
    print("Discovering managed base images …")
    resp = _signed_request("GET", url, region=region)
    images = resp.get("items", [])
    if not images:
        _die("No managed base images found.  Pass --base-image-arn explicitly.")
    arn: str = images[0].get("imageArn", "")
    print(f"Base image: {arn}")
    return arn


# ---------------------------------------------------------------------------
# Step 4: create or reuse a build role
# ---------------------------------------------------------------------------


def _ensure_build_role(bucket: str, key: str) -> str:
    """Create a temporary IAM role for the image build and return its ARN."""
    role_name = "sandbox-runtime-image-build"
    iam = boto3.client("iam")

    # Check if the role already exists.
    try:
        resp = iam.get_role(RoleName=role_name)
        arn: str = resp["Role"]["Arn"]
        print(f"Reusing existing build role: {arn}")
        # Update the inline policy so it covers the current bucket/key.
        policy_doc = _BUILD_ROLE_POLICY_TEMPLATE.format(bucket=bucket, key=key)
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="build-access",
            PolicyDocument=policy_doc,
        )
        return arn
    except iam.exceptions.NoSuchEntityException:
        pass

    print("Creating IAM build role …")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_BUILD_ROLE_TRUST_POLICY,
        Description="Temporary role for MicroVM image builds",
    )
    arn = resp["Role"]["Arn"]

    policy_doc = _BUILD_ROLE_POLICY_TEMPLATE.format(bucket=bucket, key=key)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="build-access",
        PolicyDocument=policy_doc,
    )

    # IAM role propagation can take a few seconds.
    print("Waiting for IAM role propagation …")
    time.sleep(10)  # nosemgrep: arbitrary-sleep — polling loop by design

    return arn


# ---------------------------------------------------------------------------
# Step 5: create the image
# ---------------------------------------------------------------------------


def _create_image(
    *,
    name: str,
    region: str,
    bucket: str,
    key: str,
    base_image_arn: str,
    build_role_arn: str,
) -> dict[str, Any]:
    """POST to the microvm-images endpoint to start a build."""
    url = _lambda_url(region, "microvm-images")
    body: dict[str, Any] = {
        "name": name,
        "baseImageArn": base_image_arn,
        "buildRoleArn": build_role_arn,
        "codeArtifact": {"uri": f"s3://{bucket}/{key}"},
        "hooks": {
            "port": 8080,
            "microvmHooks": {
                "run": "ENABLED",
                "runTimeoutInSeconds": 60,
                "resume": "ENABLED",
                "resumeTimeoutInSeconds": 30,
                "suspend": "ENABLED",
                "suspendTimeoutInSeconds": 30,
                "terminate": "ENABLED",
                "terminateTimeoutInSeconds": 30,
            },
            "microvmImageHooks": {
                "ready": "ENABLED",
                "readyTimeoutInSeconds": 120,
            },
        },
        "resources": [{"minimumMemoryInMiB": 2048}],
        # Required for NFS mount (CAP_SYS_ADMIN) — matches the serverlessland reference pattern.
        "additionalOsCapabilities": ["ALL"],
        "tags": {"TenantId": "operator"},
    }
    print(f"Creating image '{name}' …")
    return _signed_request("POST", url, body=body, region=region)


# ---------------------------------------------------------------------------
# Step 6: poll for completion
# ---------------------------------------------------------------------------


def _poll_image(image_identifier: str, region: str) -> dict[str, Any]:
    """Poll GET microvm-images/{imageIdentifier} until terminal state."""
    encoded = urllib.parse.quote(image_identifier, safe="")
    url = _lambda_url(region, f"microvm-images/{encoded}")
    for i in range(_MAX_POLL_ITERATIONS):
        resp = _signed_request("GET", url, region=region)
        state = resp.get("state", resp.get("State", "UNKNOWN"))
        print(f"  [{i + 1}] State: {state}")
        if state == "CREATED":
            return resp
        if state == "CREATE_FAILED":
            import pprint  # noqa: PLC0415
            print("=== FULL FAILURE RESPONSE ===")
            pprint.pprint(resp)
            print("=== END FAILURE RESPONSE ===")
            reason = resp.get("stateReason", resp.get("StateReason", "unknown"))
            _die(f"Image build failed: {reason}")
        time.sleep(_POLL_INTERVAL_SECONDS)  # nosemgrep: arbitrary-sleep — polling loop by design

    _die(f"Timed out after {_MAX_POLL_ITERATIONS * _POLL_INTERVAL_SECONDS}s waiting for image build")
    return {}  # unreachable, satisfies mypy


# ---------------------------------------------------------------------------
# Step 7: print the result
# ---------------------------------------------------------------------------


def _print_result(resp: dict[str, Any], name: str) -> None:
    """Print the success banner with the image ARN for deployment.

    The MicroVM API requires the full ARN as ``imageIdentifier`` when creating
    MicroVMs. The ``imageVersion`` from the build response (e.g. ``name:1``) is
    NOT accepted — only the ARN works.
    """
    arn = resp.get("imageArn", resp.get("ImageArn", ""))
    version = resp.get("imageVersion", resp.get("ImageVersion", f"{name}:1"))

    print()
    print("=== MicroVM Image Build ===")
    print(f"Image name: {name}")
    print(f"Image ARN: {arn}")
    print(f"Image version: {version}")
    print("State: CREATED")
    print()
    print("To deploy:")
    # Use the ARN, not the version string — the MicroVM create API requires it.
    print(f"  npx cdk deploy --all -c imageVersion={arn}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Sandbox Runtime MicroVM image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--region",
        required=True,
        help="AWS Region (must be a MicroVM launch region)",
    )
    parser.add_argument(
        "--name",
        default="sandbox-runtime",
        help="Image name (default: sandbox-runtime)",
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="S3 bucket for the code artifact (uses CDK bootstrap bucket if omitted)",
    )
    parser.add_argument(
        "--base-image-arn",
        default=None,
        dest="base_image_arn",
        help="Base image ARN (discovers one if omitted)",
    )
    parser.add_argument(
        "--build-role-arn",
        default=None,
        dest="build_role_arn",
        help="IAM build role ARN (creates a temp one if omitted)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    args = _parse_args(argv)
    region: str = args.region
    name: str = args.name

    # 1. Package.
    print("Packaging runtime …")
    zip_bytes = _build_zip()
    print(f"  Zip size: {len(zip_bytes):,} bytes")

    # 2. Resolve bucket and upload.
    account = _get_account_id()
    bucket = _resolve_bucket(args.bucket, account, region)
    key = _upload_zip(zip_bytes, bucket, region)

    # 3. Discover or accept base image.
    base_image_arn: str = args.base_image_arn or _discover_base_image(region)

    # 4. Create or reuse build role.
    build_role_arn: str = args.build_role_arn or _ensure_build_role(bucket, key)

    # 5. Create the image.
    create_resp = _create_image(
        name=name,
        region=region,
        bucket=bucket,
        key=key,
        base_image_arn=base_image_arn,
        build_role_arn=build_role_arn,
    )

    # 6. Poll for completion.
    image_arn = create_resp.get("imageArn", "")
    if not image_arn:
        _die("Create response missing imageArn")
    print(f"Polling every {_POLL_INTERVAL_SECONDS}s for build completion …")
    result = _poll_image(image_arn, region)

    # 7. Print the result.
    _print_result(result, name)


if __name__ == "__main__":
    main()
