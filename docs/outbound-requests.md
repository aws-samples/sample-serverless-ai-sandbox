<!-- kiro-classification: public -->

# How Outbound Requests Work From Inside the Sandbox

## The short version

Your sandbox has no direct internet access. All outbound traffic goes through a
governed proxy. If a domain is on the allowlist, your request works transparently.
If it's not, the connection is refused.

```
Your code  ──http_proxy──▶  Fargate Proxy  ──▶  Internet
                              │
                              ├─ Allowlist check (DynamoDB)
                              ├─ Tier 1: SigV4 re-signing (Bedrock)
                              ├─ Tier 2: Token injection (3rd-party APIs)
                              └─ Tier 3: CONNECT tunnel (package repos)
```

## What happens when you make a request

### `pip install requests==2.32.3` (allowed domain)

```bash
pip install requests==2.32.3
# ✅ Works. pip uses $https_proxy automatically.
# pypi.org and files.pythonhosted.org are on the default allowlist.
```

The runtime injects `http_proxy`, `https_proxy`, and `no_proxy` environment
variables at boot. Most tools (curl, pip, npm, wget, Python requests, boto3) honor
these automatically.

### `curl https://pypi.org/` (allowed domain)

```bash
curl https://pypi.org/
# ✅ Works. curl uses $https_proxy and the proxy tunnels to pypi.org.
```

### `curl http://evil.com` (disallowed domain)

```bash
curl http://evil.com
# ❌ Connection refused or timeout.
# The proxy returns 403 Forbidden for domains not on the allowlist.
```

This is not a DNS failure — the domain resolves fine. The proxy actively rejects the
connection after checking the allowlist.

### `curl http://evil.com` (no proxy, direct)

```bash
curl --noproxy '*' http://evil.com
# ❌ Timeout. The sandbox subnet has zero routes to the internet.
# There is no NAT gateway, no internet gateway. The packet has nowhere to go.
```

Even if you bypass the proxy environment variables, there is no network path. The
VPC connector subnets are routing dead ends by design.

### `nc -z 1.2.3.4 80` (raw TCP)

```bash
nc -z 1.2.3.4 80
# ❌ Timeout. Same reason — no route.
```

## Proxy tiers explained

### Tier 1: SigV4 re-signing (AWS services)

For Bedrock and other AWS service endpoints. The proxy strips whatever credentials
your request carries (which are none, since IMDS is blocked) and re-signs the request
with its own IAM role's credentials.

```python
import boto3
# This does NOT work directly — the sandbox has no Bedrock credentials.
# Route through the proxy:
client = boto3.client("bedrock-runtime", region_name="us-east-1",
                      endpoint_url="https://bedrock-runtime.egress.internal")
```

The proxy's IAM role has `bedrock:InvokeModel` permission. Your sandbox's role has
an explicit `Deny` on all Bedrock actions.

### Tier 2: Token injection (third-party APIs)

For APIs that need authentication (OpenAI, Anthropic, Stripe, etc.). The proxy
fetches the API key from Secrets Manager and injects it as a header. Your code never
sees the key.

```bash
# The proxy is an HTTP forward proxy. Set http_proxy and use the alias hostname:
export http_proxy=http://<nlb-endpoint>:443
curl http://openai-api.egress.internal/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
# The proxy injects Authorization: Bearer <secret> and forwards to api.openai.com
```

Tier 2 requires an entry in the DynamoDB egress policy table with a `tier2` array
specifying the secret ARN and header configuration.

### Tier 3: CONNECT tunnel (passthrough)

For allowed domains that don't need credential injection (package registries, CDNs).
The proxy creates a TCP tunnel — your TLS session goes end-to-end.

```bash
curl https://registry.npmjs.org/
# ✅ Works. Proxy opens a CONNECT tunnel, your TLS handshake is with npmjs.org.
```

## Environment variables

The runtime sets these before your code runs:

| Variable | Value | Purpose |
|----------|-------|---------|
| `http_proxy` | `http://<nlb>:443` | Forward proxy for HTTP |
| `https_proxy` | `http://<nlb>:443` | Forward proxy for HTTPS |
| `HTTP_PROXY` | `http://<nlb>:443` | Some tools check uppercase |
| `HTTPS_PROXY` | `http://<nlb>:443` | Some tools check uppercase |
| `no_proxy` | `169.254.169.254,169.254.170.2,...` | Skip proxy for IMDS, localhost |

`no_proxy` includes IMDS addresses, localhost, and internal AWS endpoints. This
ensures that internal AWS SDK calls don't accidentally route through the proxy.

## Default allowlist

The CDK deploys these domains by default:

| Domain | Purpose |
|--------|---------|
| `pypi.org` | Python package index |
| `files.pythonhosted.org` | Python package downloads |
| `registry.npmjs.org` | npm package index |
| `registry.yarnpkg.com` | Yarn package index |
| `al2023-repos-*.s3.dualstack.*.amazonaws.com` | AL2023 system packages |
| `cdn.amazonlinux.com` | AL2023 CDN |
| `amazonlinux-2-repos-*.s3.dualstack.*.amazonaws.com` | AL2 system packages |
| `bedrock-runtime.*.amazonaws.com` | Bedrock (Tier 1) |

Operators add domains by putting items in the DynamoDB egress policy table.

## Troubleshooting

### "Connection refused" or 403 on a domain I need

The domain is not on the allowlist. Ask your operator to add it:

```bash
aws dynamodb put-item --table-name <egress-policy-table> --item '{
  "pk": {"S": "DOMAIN#api.example.com"},
  "sk": {"S": "POLICY"},
  "allowed": {"BOOL": true}
}'
```

### "Timeout" with no error

You're probably trying to reach the internet directly (bypassing the proxy). Check
that `$https_proxy` is set:

```bash
echo $https_proxy
# Should print http://<nlb-endpoint>:443
```

### pip/npm install hangs

The download domain might not be on the allowlist. pip and npm sometimes use CDN
domains that differ from the registry domain. Check the proxy logs:

```bash
aws logs filter-log-events --log-group-name /ecs/egress-proxy \
  --filter-pattern "DENIED"
```

### boto3 raises NoCredentialsError

This is by design. The sandbox blocks IMDS so untrusted code cannot steal credentials.
Use the egress proxy for AWS service access (Tier 1 SigV4 re-signing).
