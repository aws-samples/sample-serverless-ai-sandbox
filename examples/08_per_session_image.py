#!/usr/bin/env python3
# kiro-classification: public
"""Per-session image selection — inspect what's installed in any MicroVM image.

Spins up a session with the given image (or the deployment default) and
reports the installed tools and runtimes.

Usage:
    export API_URL="https://xxx.execute-api.us-east-1.amazonaws.com"
    export AWS_REGION="us-east-1"

    # Deployment default image
    python examples/08_per_session_image.py

    # Specific image
    python examples/08_per_session_image.py \
        --image arn:aws:lambda:us-east-1:ACCOUNT:microvm-image:sandbox-runtime-v57
"""

import argparse
import os

from agent_sandbox import SandboxClient

# Commands to discover what's installed — each tries the tool and
# falls back to "not installed" so the script never fails.
PROBES = [
    ("python3 --version 2>&1",                          "Python"),
    ("node --version 2>&1 || echo not installed",       "Node.js"),
    ("git --version 2>&1 || echo not installed",        "Git"),
    ("rg --version 2>&1 | head -1 || echo not installed", "ripgrep"),
    ("cdk --version 2>&1 | head -1 || echo not installed", "CDK CLI"),
    ("npm --version 2>&1 || echo not installed",        "npm"),
    ("pip --version 2>&1 | head -1 || echo not installed", "pip"),
    ("curl --version 2>&1 | head -1 || echo not installed", "curl"),
    ("jq --version 2>&1 || echo not installed",         "jq"),
    ("uname -m 2>&1",                                   "Architecture"),
    ("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo unknown", "OS"),
    ("df -h / | tail -1 | awk '{print $2}'",            "Disk"),
    ("free -h 2>/dev/null | awk '/Mem/{print $2}' || echo N/A", "Memory"),
]


def main():
    parser = argparse.ArgumentParser(description="Inspect a MicroVM image")
    parser.add_argument("--image", default="", help="MicroVM image ARN (omit for deployment default)")
    args = parser.parse_args()

    api_url = os.environ.get("API_URL", "")
    if not api_url:
        print("Set API_URL environment variable.")
        exit(1)
    region = os.environ.get("AWS_REGION", "us-east-1")
    token = os.environ.get("SANDBOX_TOKEN")

    client = SandboxClient(api_url=api_url, region=region, token=token)

    kwargs = {"max_duration_seconds": 180, "idle_seconds": 60}
    if args.image:
        kwargs["image_ref"] = args.image
        name = args.image.rsplit(":", 1)[-1]
    else:
        name = "(deployment default)"

    print(f"Image: {name}")
    print("=" * 50)

    # Context manager: session.terminate() is called automatically when the block exits
    with client.create_session(**kwargs) as session:
        session.wait_ready(timeout=180)
        for cmd, label in PROBES:
            r = session.execute(cmd, timeout_seconds=10)
            output = r.stdout.strip().split("\n")[0]
            installed = "not installed" not in output.lower() and "command not found" not in output.lower()
            mark = "✓" if installed else "✗"
            print(f"  {mark} {label:14s} {output}")

    print("\nSession terminated.")


if __name__ == "__main__":
    main()
