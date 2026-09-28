<!-- kiro-classification: public -->

# Agent Sandbox Guide

> A practical guide for AI agents using the AWS Serverless Agent Sandbox.
> Every command and pattern below was tested and verified in a live sandbox.

## Environment Summary

| Property | Value |
|----------|-------|
| OS | Amazon Linux 2023 (aarch64) |
| Kernel | 6.1.x aarch64 |
| User | uid=1000 gid=1000 (non-root) |
| Python | 3.13 |
| Git | 2.50+ |
| curl | 8.21+ |
| jq | 1.8+ |
| CPUs | 4 |
| Memory | ~8 GB |
| Root disk | 7.8 GB (ephemeral) |
| Persistent storage | /mnt/workspace (8 EB NFS, S3-backed) |

## Filesystem

| Path | Type | Survives restart? | Writable? | Notes |
|------|------|-------------------|-----------|-------|
| `/tmp` | Ephemeral | No | Yes | Default working directory. Lost on terminate. |
| `/mnt/workspace` | Persistent (S3 Files NFS) | Yes | Yes | Survives suspend, resume, termination. Only available when session created with `persistence: true`. |
| `/home` | Ephemeral | No | No (root-owned) | Not writable by uid 1000. |
| `/root` | Ephemeral | No | No (root-owned) | Not writable. Do not use for pip cache. |

**Rule**: Always work in `/tmp` for ephemeral tasks or `/mnt/workspace` for persistent projects.

## Installing Packages

The sandbox user (uid 1000) cannot write to system directories. Use `--target`:

```bash
# Install to a local directory
HOME=/tmp pip install --quiet --target /tmp/pylibs requests==2.32.3

# Use the installed package
PYTHONPATH=/tmp/pylibs python3 -c "import requests; print(requests.__version__)"
```

For persistent installs (survive suspend/resume):
```bash
HOME=/tmp pip install --quiet --target /mnt/workspace/pylibs numpy==2.1.3 pandas==2.2.3
PYTHONPATH=/mnt/workspace/pylibs python3 -c "import numpy; print(numpy.__version__)"
```

**Do NOT use**: `pip install requests` (writes to /root, permission denied),
`sudo pip install` (no sudo), `pip install --user` (writes to /root/.local).

## Calling Amazon Bedrock

### Direct boto3 is BLOCKED

The sandbox has an explicit IAM deny on `bedrock:InvokeModel*`. This is intentional
security: untrusted sandbox code must not call Bedrock directly with the VM's credentials.

```python
# THIS WILL FAIL with AccessDeniedException:
import boto3
client = boto3.client('bedrock-runtime', region_name='us-east-1')
client.converse(modelId='amazon.nova-micro-v1:0', ...)
# Error: explicit deny in an identity-based policy
```

### Use the HTTP Forward Proxy (correct pattern)

The sandbox has an egress proxy that re-signs Bedrock requests with its own SigV4 credentials.
The proxy endpoint is available in the `http_proxy` environment variable.

```python
import http.client, json, os, re

# Extract proxy from environment
raw = os.environ.get('http_proxy', '')
m = re.match(r'http://([^:]+):(\d+)', raw)
if not m:
    raise RuntimeError(f'http_proxy not set: {raw}')
proxy_host, proxy_port = m.group(1), int(m.group(2))

# Bedrock endpoint
region = 'us-east-1'
bedrock_host = f'bedrock-runtime.{region}.amazonaws.com'
model_id = 'amazon.nova-micro-v1:0'

# Build the request
body = json.dumps({
    'modelId': model_id,
    'messages': [{'role': 'user', 'content': [{'text': 'Your prompt here'}]}],
    'inferenceConfig': {'maxTokens': 512, 'temperature': 0.7}
}).encode()

# Send through the proxy (plain HTTP to proxy, proxy adds TLS + SigV4)
conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=60)
conn.request(
    'POST',
    f'http://{bedrock_host}/model/{model_id}/converse',
    body=body,
    headers={
        'Host': bedrock_host,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
)
resp = conn.getresponse()
data = json.loads(resp.read())
text = data['output']['message']['content'][0]['text']
print(text)  # Production: log metadata only, not full response
```

**Available models**: `amazon.nova-micro-v1:0`, `amazon.nova-lite-v1:0` (and others
enabled in the account). Use the Converse API format.

### Reusable Helper

Save this as a module for repeated use:

```python
# /tmp/bedrock_helper.py
import http.client, json, os, re

def call_bedrock(prompt, model='amazon.nova-micro-v1:0', max_tokens=512, temperature=0.7):
    raw = os.environ.get('http_proxy', '')
    m = re.match(r'http://([^:]+):(\d+)', raw)
    if not m: raise RuntimeError('No proxy')
    host, port = m.group(1), int(m.group(2))
    bedrock = f'bedrock-runtime.us-east-1.amazonaws.com'
    body = json.dumps({
        'modelId': model,
        'messages': [{'role': 'user', 'content': [{'text': prompt}]}],
        'inferenceConfig': {'maxTokens': max_tokens, 'temperature': temperature}
    }).encode()
    conn = http.client.HTTPConnection(host, port, timeout=60)
    conn.request('POST', f'http://{bedrock}/model/{model}/converse',
                 body=body, headers={'Host': bedrock, 'Content-Type': 'application/json'})
    data = json.loads(conn.getresponse().read())
    return data['output']['message']['content'][0]['text']
```

Usage: `from bedrock_helper import call_bedrock; print(call_bedrock("Explain quicksort"))`

## Network and Egress

### Proxy Configuration

All outbound traffic routes through a governed forward proxy:

| Variable | Value |
|----------|-------|
| `http_proxy` | `http://<NLB>:443` |
| `https_proxy` | `http://<NLB>:443` |
| `NO_PROXY` | `169.254.169.254,169.254.170.2,127.0.0.1,localhost,.amazonaws.com,.api.aws` |

Note: `.amazonaws.com` is in `NO_PROXY` — AWS SDK calls (boto3) bypass the proxy
and go direct. This is why direct Bedrock calls hit the IAM deny instead of going
through the proxy.

### What's Allowed

| Destination | Works? | Method |
|-------------|--------|--------|
| `pypi.org`, `files.pythonhosted.org` | Yes | `pip install`, `curl` |
| `registry.npmjs.org` | Yes | `npm install` |
| `cdn.amazonlinux.com` | Yes | `dnf install` |
| Amazon Bedrock | Yes | Via proxy only (see above) |
| `google.com`, `example.com` | No | Blocked by proxy allowlist |
| Direct IP connections | No | Blocked |
| AWS services (S3, DynamoDB, etc.) | Via IMDS creds | Scoped by IAM deny policies |

### curl Examples

```bash
# Allowed (goes through proxy)
curl -s --max-time 10 https://pypi.org/simple/ | head -5

# Blocked (proxy rejects)
curl -s --max-time 5 https://www.google.com
# Returns: 403 Forbidden or empty
```

## Git Operations

Git works for local repositories. On `/mnt/workspace` (NFS), you need to mark the
directory as safe due to ownership mismatch:

```bash
# Required for /mnt/workspace repos (NFS ownership != uid 1000)
git config --global --add safe.directory '*'

# Then normal git operations work
cd /mnt/workspace/myproject
git init
git add .
git config user.email "agent@sandbox"
git config user.name "Agent"
git commit -m "initial commit"
```

**On /tmp** (no safe.directory needed):
```bash
cd /tmp && git init myproject && cd myproject
echo "# Project" > README.md
git add . && git commit -m "init"
```

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| `pip install` permission denied | uid 1000 can't write /root | `pip install --target /tmp/pylibs` |
| Bedrock AccessDeniedException | DenyBedrockDirect IAM policy | Use HTTP proxy pattern (see above) |
| `curl https://google.com` empty/403 | Egress allowlist blocks it | Only allowed destinations work |
| Git "dubious ownership" | NFS uid mismatch | `git config --global --add safe.directory '*'` |
| `find` command not found | Not installed in AL2023 minimal | Use `ls -R` instead |
| `sudo` not available | No sudo in sandbox | Work as uid 1000, use --target for installs |
| Files disappear after terminate | Written to /tmp (ephemeral) | Use /mnt/workspace for persistence |
| boto3 S3/DynamoDB calls scoped | IAM deny policies | Only session-scoped access allowed |

## Example Workflows

### Code Generation + Testing

```bash
# Create project
mkdir -p /tmp/project

# Write code
cat > /tmp/project/calc.py << 'PY'
def add(a, b): return a + b
def sub(a, b): return a - b
def mul(a, b): return a * b
def div(a, b):
    if b == 0: raise ValueError("division by zero")
    return a / b
PY

# Write tests
cat > /tmp/project/test_calc.py << 'PY'
from calc import add, sub, mul, div
assert add(2, 3) == 5
assert sub(5, 3) == 2
assert mul(4, 3) == 12
assert div(10, 2) == 5.0
try: div(1, 0)
except ValueError: pass
else: assert False, "should raise"
print("All tests passed!")
PY

# Run
cd /tmp/project && python3 test_calc.py
```

### Data Analysis

```bash
# Install packages
HOME=/tmp pip install --quiet --target /tmp/pylibs pandas==2.2.3

# Run analysis
PYTHONPATH=/tmp/pylibs python3 << 'PY'
import pandas as pd
import json

data = [
    {"product": "Widget A", "price": 29.99, "qty": 150},
    {"product": "Widget B", "price": 49.99, "qty": 75},
    {"product": "Widget C", "price": 9.99, "qty": 500},
]
df = pd.DataFrame(data)
df["revenue"] = df["price"] * df["qty"]
print(df.to_string())
print(f"\nTotal revenue: ${df['revenue'].sum():,.2f}")
print(f"Top product: {df.loc[df['revenue'].idxmax(), 'product']}")
PY
```

### AI-Powered Workflow (Bedrock + Code Execution)

```python
# Save as /tmp/ai_workflow.py
import sys
sys.path.insert(0, '/tmp')

# 1. Ask Bedrock to generate code
from bedrock_helper import call_bedrock

prompt = "Write a Python function that finds all prime numbers up to N using the Sieve of Eratosthenes. Include a test that prints primes up to 100. Return ONLY the code, no markdown."
code = call_bedrock(prompt, temperature=0.0)

# 2. Save and execute the generated code
with open('/tmp/generated.py', 'w') as f:
    f.write(code)

import subprocess
result = subprocess.run(['python3', '/tmp/generated.py'], capture_output=True, text=True, timeout=10)
print("Output:", result.stdout)
if result.stderr:
    print("Errors:", result.stderr[:200])
```
