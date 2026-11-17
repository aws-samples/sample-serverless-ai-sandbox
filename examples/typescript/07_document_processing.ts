/** Document processing — summarize a document with Bedrock inside an isolated sandbox.
 * Mirrors the core of python/07 (Bedrock via the governed egress proxy; no creds in the sandbox). */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

const SAMPLE_DOCUMENT = [
  'MERGER AGREEMENT dated October 28, 2026, between Acme Technologies Inc., a Delaware',
  'corporation ("Buyer"), and Widget Corp., a California corporation ("Seller").',
  'Buyer shall acquire 100% of Seller shares for $450 million: $300M cash and $150M in',
  'Buyer common stock based on the 30-day VWAP. Closing is subject to regulatory approval',
  'and a material adverse change clause. Seller provides standard reps and warranties.',
].join('\n');

// Runs inside the sandbox: calls Bedrock through the egress proxy (Tier 1 re-signs with SigV4;
// the sandbox itself holds no Bedrock credentials).
const ANALYZE = [
  'import os, json, http.client',
  'from urllib.parse import urlparse',
  'doc = open("/tmp/document.txt").read()',
  'p = urlparse(os.environ.get("https_proxy") or os.environ.get("http_proxy", ""))',
  'host, port = p.hostname, p.port or 443',
  'region = os.environ.get("AWS_REGION", "us-east-1")',
  'bedrock = "bedrock-runtime.%s.amazonaws.com" % region',
  'model = "amazon.nova-micro-v1:0"',
  'prompt = "Summarize this merger agreement in one paragraph:\\n\\n" + doc[:2000]',
  'body = json.dumps({"modelId": model, "messages": [{"role": "user", "content": [{"text": prompt}]}], "inferenceConfig": {"maxTokens": 300}}).encode()',
  'conn = http.client.HTTPConnection(host, port, timeout=30)',
  'conn.request("POST", "http://%s/model/%s/converse" % (bedrock, model), body=body, headers={"Host": bedrock, "Content-Type": "application/json"})',
  'resp = json.loads(conn.getresponse().read())',
  'print(resp["output"]["message"]["content"][0]["text"])',
].join('\n');

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;

  const client = new SandboxClient({ apiUrl, region, token });
  console.log('Document Processing Example');
  console.log('='.repeat(50));
  const session = await client.createSession({ maxDurationSeconds: 600, persistence: true });
  try {
    await session.waitReady({ timeout: 120_000 });
    console.log(`Session: ${session.sessionId.slice(0, 12)}... (Firecracker MicroVM, uid 1000, governed egress)\n`);
    await session.writeFile('/tmp/document.txt', SAMPLE_DOCUMENT);
    await session.writeFile('/tmp/analyze.py', ANALYZE);
    const r = await session.execute('python3 /tmp/analyze.py', { timeoutSeconds: 60 });
    console.log('AI summary (via Bedrock, no creds in sandbox):\n' + r.stdout.trim());
  } finally {
    await session.terminate();
    console.log('\nSession terminated — document destroyed with the MicroVM.');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
