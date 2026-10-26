# MicroVM Image Templates

Custom MicroVM image templates for the AWS Serverless Agent Sandbox. Each template
adds tools, runtimes, or configurations on top of the base sandbox runtime image.

## How templates work

The default sandbox image (`sandbox-runtime`) includes Python 3.13, Git, curl, jq,
and the sandbox runtime. Templates extend this with additional packages for specific
use cases — Node.js for coding agents, R for data science, etc.

Each template is a directory containing:
- `Dockerfile` — the image definition
- `README.md` — what's included, how to build, how to configure
- Any additional files baked into the image (adapters, configs, etc.)

## Building a template

1. Review the template's `README.md` for any prerequisites.

2. Modify `scripts/build-image.py` to use the template's Dockerfile. Replace the
   `_DOCKERFILE` string with the template's Dockerfile content, or copy the template's
   Dockerfile and point the build script at it:

   ```bash
   # Option A: edit _DOCKERFILE in build-image.py directly
   # Option B: build manually with the template's Dockerfile
   uv run python scripts/build-image.py --region us-east-1 --name <template-name>
   ```

3. The build uploads a zip (Dockerfile + runtime code) to S3 and triggers the
   MicroVM image build API. Build time is 3-5 minutes. Check progress in CloudWatch
   at `/aws/lambda-microvms/<image-name>`.

4. Deploy with the new image:

   ```bash
   npx cdk deploy ControlPlaneStack \
     -c imageVersion=<new-image-arn> \
     -c proxyImageUri=<existing-proxy-uri> \
     --require-approval never
   ```

## Running multiple images

The control plane currently uses one image for all sessions (set at deploy time via
`imageVersion`). To switch between images, redeploy `ControlPlaneStack` with a
different `imageVersion`. Both images remain built and ready — switching takes ~60
seconds.

The MicroVM API itself supports per-request image selection. A future control plane
update will allow specifying the image per session at creation time.

## Available templates

| Template | Use case | Adds | Example |
|----------|----------|------|---------|
| default (built-in) | General-purpose sandbox | Python 3.13, Git, curl, jq (built by `scripts/build-image.py`) | [01-05](../examples/) |
| [software-factory](software-factory/) | AI coding agents (opencode, Claude Code) | Node.js 22, npm, ripgrep, opencode, CDK CLI, Bedrock proxy adapter | [06](../examples/06_software_factory.py) |

## Creating a new template

1. Create a directory under `templates/` with your template name.
2. Add a `Dockerfile` that extends the base image packages.
3. Add a `README.md` documenting what's included and how to use it.
4. Test by building the image and running the demo suite.

Key constraints:
- The Dockerfile must start from `public.ecr.aws/amazonlinux/amazonlinux:2023`
- It must include the sandbox runtime (`COPY runtime runtime`, `COPY protocol protocol`)
- It must end with `CMD ["python3.13", "-m", "runtime"]`
- User code runs as uid 1000 — system packages must be installed as root during build
- The `tar` and `gzip` packages are needed if you download tarballs during build
