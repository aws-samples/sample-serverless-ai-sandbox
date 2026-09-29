# Custom MicroVM Templates
<!-- kiro-classification: public -->

Custom templates let you build MicroVM images with pre-installed packages, tools, and
configurations so that sandboxes start ready for your specific workloads.

## What templates are

A template is a custom MicroVM image built on top of the AWS-managed `al2023-1` base image.
The base image provides Amazon Linux 2023 with the Lambda MicroVM runtime. Your template adds
a Dockerfile that installs packages, copies application code, and configures the environment.

The default template in this repository installs:
- Python 3.13 (from the `python:3.13-slim` base)
- The Sandbox Runtime (`runtime/` and `protocol/` packages)
- System tools: `git`, `curl`, `jq`
- `boto3` for AWS SDK access

## How to build a custom template

### 1. Modify the Dockerfile

Edit `scripts/build-image.py` and change the `_DOCKERFILE` string. The current default is:

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /var/task

# Install system tools commonly needed by sandbox workloads
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.5.0
RUN uv export --frozen --no-dev --no-emit-workspace --extra runtime --format requirements-txt > requirements.txt \
    && pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir boto3==1.35.0
COPY runtime runtime
COPY protocol protocol
CMD ["python", "-m", "runtime"]
```

Add your packages after the system tools line. For example, to add Node.js:

```dockerfile
# Install Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*
```

### 2. Build the image

```bash
uv run python scripts/build-image.py --region us-east-1 --name my-custom-template
```

This will:
1. Package the runtime, protocol, pyproject.toml, uv.lock, and Dockerfile into a zip
2. Upload the zip to the CDK bootstrap S3 bucket
3. Discover the managed base image
4. Create (or reuse) an IAM build role
5. Start the MicroVM image build (takes 3-5 minutes)
6. Poll until the build completes

The output includes the image version string you need for deployment.

### 3. Deploy with the new image

```bash
npx cdk deploy ControlPlaneStack \
  -c "imageVersion=my-custom-template:1" \
  -c proxyImageUri=<your-proxy-image-uri> \
  --require-approval never
```

The `imageVersion` CDK context parameter tells the `ControlPlaneStack` which MicroVM image
to use when provisioning new sandboxes.

## Examples

### Adding Node.js and npm

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /var/task

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq && \
    rm -rf /var/lib/apt/lists/*

# Add Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.5.0
RUN uv export --frozen --no-dev --no-emit-workspace --extra runtime --format requirements-txt > requirements.txt \
    && pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir boto3==1.35.0
COPY runtime runtime
COPY protocol protocol
CMD ["python", "-m", "runtime"]
```

### Adding Java (for JVM-based workloads)

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /var/task

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# ... rest of Dockerfile unchanged
```

### Adding R (for data science workloads)

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /var/task

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq r-base && \
    rm -rf /var/lib/apt/lists/*

# ... rest of Dockerfile unchanged
```

### Adding data science Python packages

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /var/task

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.5.0
RUN uv export --frozen --no-dev --no-emit-workspace --extra runtime --format requirements-txt > requirements.txt \
    && pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir boto3==1.35.0
# Pre-install commonly used data science packages
RUN pip install --no-cache-dir numpy==2.1.3 pandas==2.2.3 matplotlib==3.9.3 scikit-learn==1.6.0
COPY runtime runtime
COPY protocol protocol
CMD ["python", "-m", "runtime"]
```

## Cost and performance considerations

### Storage cost

MicroVM images are stored as Lambda layers. Storage cost is negligible (pennies per month
for typical images). Larger images with many pre-installed packages may cost slightly more
but remain well under $1/month.

### Cold start impact

Larger images take longer to provision because they contain more data that must be loaded
into the MicroVM. Approximate impact:

| Image size | Additional cold start | Notes |
|---|---|---|
| Base (~200 MB) | Baseline (~3-5s) | Default Python + runtime |
| + system tools (~50 MB) | +0.5-1s | git, curl, jq |
| + Node.js (~100 MB) | +1-2s | nodejs + npm |
| + Java JRE (~200 MB) | +2-3s | default-jre-headless |
| + R + packages (~500 MB) | +3-5s | r-base + dependencies |
| + data science stack (~1 GB) | +5-8s | numpy, pandas, scikit-learn |

These are approximate. Actual cold start depends on MicroVM size configuration
(memory/vCPU), Region, and concurrent load.

### Best practices

1. **Install only what you need.** Every package adds to image size and cold start time.
   Use `--no-install-recommends` with apt-get.
2. **Clean up caches.** Remove apt lists (`rm -rf /var/lib/apt/lists/*`) and pip caches
   (`--no-cache-dir`) in the same layer.
3. **Layer ordering matters.** Put rarely-changing layers (system packages) before
   frequently-changing ones (application code) for faster rebuilds.
4. **Use multi-stage builds for compilation.** If a package needs build tools at install
   time but not at runtime, use a multi-stage Dockerfile.
5. **Pin versions.** Use specific package versions for reproducible builds.
6. **Test locally first.** Build and test the Dockerfile locally before running the
   MicroVM image build, which takes 3-5 minutes per attempt.

### Reducing first-command latency with disk prewarming

The MicroVM rootfs is lazily loaded — disk pages are fetched from the backing store
on first access. This means the first command in a new session pays a "cold page"
penalty while binaries like `python3` or `git` are loaded into memory.

You can reduce this by **prewarming critical disk paths** during the image validation
stage. The `/ready` lifecycle hook (called once when Lambda validates the image for
resumability) is the ideal place to trigger this:

```python
# In runtime/__main__.py, inside the /ready handler:
import subprocess
# Fire-and-forget: touch the cold paths so they're in the page cache
# when the first real command arrives.
subprocess.run(["python3", "--version"], capture_output=True)
subprocess.run(["git", "--version"], capture_output=True)
```

This forces the OS to page in the Python interpreter and git binary during validation.
Since Lambda snapshots the validated state as the template, every subsequent MicroVM
boots with those pages already warm.

**Expected improvement** (based on MicroVM disk prewarming benchmarks):

| Metric | Without prewarming | With prewarming | Improvement |
|--------|-------------------|-----------------|-------------|
| VM boot time | ~3.4s | ~3.3s | ~3% (noise) |
| First command latency | ~7.0s | ~4.1s | ~41% |
| Total (boot + first command) | ~10.3s | ~7.4s | ~25% |

> **Note**: This optimization is not enabled by default. Add the prewarm calls to your
> runtime's `/ready` handler if first-command latency is important for your use case.
> The trade-off is a slightly longer image validation step (one-time cost per image build).

## The `imageVersion` CDK context parameter

The `ControlPlaneStack` reads `imageVersion` from CDK context to determine which MicroVM
image to use. The format is `<image-name>:<version-number>`, for example
`sandbox-runtime-v6:1`.

When no `imageVersion` is provided, the stack emits a synthesis warning and uses a
placeholder string. You must build an image and redeploy with the version string before
sandboxes can be provisioned.

Multiple image versions can coexist. To switch between them, redeploy with a different
`imageVersion` value. Existing running sandboxes are not affected — only new sessions
use the updated image.

## Debugging with shell access

You can get an interactive shell inside a running MicroVM for debugging custom images.
This uses the Lambda MicroVMs `create-microvm-shell-auth-token` API, which requires the
**SHELL_INGRESS connector** to be enabled on the MicroVM.

### Prerequisites

The SHELL_INGRESS connector must be configured when creating the MicroVM. Without it,
`create-microvm-shell-auth-token` returns a `ValidationException`. This connector is a
Lambda MicroVMs service feature — it is not configured by this repository's CDK stacks
and must be enabled separately if you need interactive shell access.

### Getting a shell token

```bash
# Get a shell auth token for a running MicroVM
aws lambda-microvms create-microvm-shell-auth-token \
    --microvm-id <MICROVM_ID> \
    --region us-east-1
```

The token is short-lived and grants SSH-like access to the MicroVM. Use it with the
Lambda MicroVMs shell client to connect.

> **Note**: Shell access is intended for debugging custom images during development,
> not for production use. The sandbox SDK's `execute()` method is the supported way
> to run commands inside a session.
