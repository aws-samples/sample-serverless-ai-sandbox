# kiro-classification: public
"""Example 06: Software Factory — AI coding agent in a governed sandbox.

Demonstrates running opencode (AI coding agent) inside a MicroVM with:
- Bedrock model access through the governed egress proxy
- Git clone through the proxy
- The Bedrock proxy adapter bridging Node.js AI SDK to the egress proxy

Prerequisites:
- Deploy with the software-factory image (see templates/software-factory/README.md)
- Add github.com to the egress allowlist
- Amazon Bedrock model access enabled in your account

Usage:
    uv run python examples/06_software_factory.py \
        --api-url https://xxx.execute-api.us-east-1.amazonaws.com \
        --region us-east-1
"""
from __future__ import annotations

import argparse
import json
import time

from agent_sandbox import SandboxClient


def main() -> None:
    parser = argparse.ArgumentParser(description="Software Factory example")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    client = SandboxClient(api_url=args.api_url, region=args.region)

    print("Creating sandbox session...")
    with client.create_session() as session:
        session.wait_ready(timeout=120)
        print("Session ready\n")

        # 1. Verify the software-factory image tools
        print("=== Tool versions ===")
        for cmd, label in [
            ("node --version", "Node.js"),
            ("opencode --version 2>&1 | head -1", "opencode"),
            ("rg --version | head -1", "ripgrep"),
            ("cdk --version 2>&1 | head -1", "CDK CLI"),
        ]:
            r = session.execute(cmd, timeout_seconds=15)
            print(f"  {label}: {r.stdout.strip()}")

        # 2. Start the Bedrock proxy adapter
        print("\n=== Starting Bedrock adapter ===")
        adapter = session.execute_background("node /opt/bedrock-adapter.js")
        time.sleep(2)
        print(f"  Adapter PID: {adapter.pid}, running: {adapter.is_running()}")

        # 3. Test Bedrock via adapter
        print("\n=== Bedrock via adapter ===")
        bedrock_test = (
            'import http.client, json, os, re\n'
            'raw = os.environ.get("http_proxy", "")\n'
            'if not raw: print("NO_PROXY"); exit()\n'
            'm = re.match(r"http://([^:]+):(\\d+)", raw)\n'
            'h, p = m.group(1), int(m.group(2))\n'
            'b = "bedrock-runtime.us-east-1.amazonaws.com"\n'
            'body = json.dumps({"modelId": "amazon.nova-micro-v1:0",\n'
            '  "messages": [{"role": "user", "content": [{"text": "Say hello in 3 words"}]}],\n'
            '  "inferenceConfig": {"maxTokens": 20}}).encode()\n'
            'c = http.client.HTTPConnection(h, p, timeout=30)\n'
            'c.request("POST", f"http://{b}/model/amazon.nova-micro-v1:0/converse",\n'
            '  body=body, headers={"Host": b, "Content-Type": "application/json"})\n'
            'd = json.loads(c.getresponse().read())\n'
            'print(d["output"]["message"]["content"][0]["text"])\n'
        )
        session.write_file("/tmp/bedrock_test.py", bedrock_test)
        r = session.execute("python3 /tmp/bedrock_test.py", timeout_seconds=30)
        print(f"  Bedrock response: {r.stdout.strip()}")

        # 4. Clone a repo through the proxy
        print("\n=== Git clone through proxy ===")
        r = session.execute(
            "git clone --depth 1 https://github.com/aws-samples/sample-serverless-ai-sandbox.git /tmp/repo 2>&1",
            timeout_seconds=60,
        )
        r2 = session.execute("ls /tmp/repo/README.md && wc -l /tmp/repo/README.md", timeout_seconds=10)
        print(f"  Cloned: {r2.stdout.strip()}")

        # 5. Write and run a Node.js file
        print("\n=== Node.js execution ===")
        session.write_file("/tmp/hello.js", 'console.log("Hello from Node " + process.version)')
        r = session.execute("node /tmp/hello.js", timeout_seconds=10)
        print(f"  {r.stdout.strip()}")

        # 6. Write opencode config
        print("\n=== opencode config ===")
        config = json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "provider": {"amazon-bedrock": {"options": {"region": args.region}}},
            "model": "amazon-bedrock/amazon.nova-micro-v1:0",
            "permission": {"*": "allow"},
        }, indent=2)
        session.write_file("/tmp/repo/opencode.json", config)
        print("  Config written to /tmp/repo/opencode.json")

        print("\n=== Done ===")
        print("The sandbox is ready for opencode headless mode.")
        print("To drive a coding session, use the @opencode-ai/sdk against the")
        print("opencode serve endpoint inside the MicroVM.")

    print("\nSession terminated.")


if __name__ == "__main__":
    main()
