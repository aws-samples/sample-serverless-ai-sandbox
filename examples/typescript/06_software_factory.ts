/** Software Factory — an AI coding agent (opencode) in a governed sandbox.
 * Mirrors python/06: runs opencode inside a MicroVM with Bedrock model access
 * through the governed egress proxy and Git clone through the proxy.
 *
 * Requires the software-factory MicroVM image. Pass it with --image or SANDBOX_IMAGE:
 *   SANDBOX_TOKEN=... API_URL=... \
 *     npx tsx ../../examples/typescript/06_software_factory.ts \
 *     --image arn:aws:lambda:us-east-1:ACCOUNT:microvm-image:sandbox-software-factory-v7
 *
 * Prerequisites: software-factory image deployed, github.com on the egress
 * allowlist, and Amazon Bedrock model access enabled in your account. */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

// Runs inside the sandbox: calls Bedrock through the egress proxy (Tier 1 re-signs
// with SigV4; the sandbox itself holds no Bedrock credentials).
const BEDROCK_TEST = [
  'import os, json, http.client',
  'from urllib.parse import urlparse',
  'raw = os.environ.get("https_proxy") or os.environ.get("http_proxy", "")',
  'p = urlparse(raw)',
  'host, port = p.hostname, p.port or 443',
  'region = os.environ.get("AWS_REGION", "us-east-1")',
  'bedrock = "bedrock-runtime.%s.amazonaws.com" % region',
  'model = "amazon.nova-micro-v1:0"',
  'body = json.dumps({"modelId": model, "messages": [{"role": "user", "content": [{"text": "Say hello in 3 words"}]}], "inferenceConfig": {"maxTokens": 20}}).encode()',
  'conn = http.client.HTTPConnection(host, port, timeout=30)',
  'conn.request("POST", "http://%s/model/%s/converse" % (bedrock, model), body=body, headers={"Host": bedrock, "Content-Type": "application/json"})',
  'resp = json.loads(conn.getresponse().read())',
  'print(resp["output"]["message"]["content"][0]["text"])',
].join('\n');

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;
  const imageRef = argValue('--image') ?? process.env.SANDBOX_IMAGE;
  if (!imageRef) {
    console.error('Pass the software-factory image via --image <arn> or SANDBOX_IMAGE.');
    process.exit(1);
  }

  const client = new SandboxClient({ apiUrl, region, token });
  console.log('Creating sandbox session...');
  const session = await client.createSession({ imageRef, maxDurationSeconds: 600 });
  try {
    await session.waitReady({ timeout: 120_000 });
    console.log('Session ready\n');

    // 1. Verify the software-factory image tools. opencode and the CDK CLI are
    // self-extracting wrappers that unpack a bundled binary on first run, so
    // give them a generous timeout.
    console.log('=== Tool versions ===');
    const checks: Array<[string, string, number]> = [
      ['node --version', 'Node.js', 15],
      ['opencode --version 2>&1 | head -1', 'opencode', 60],
      ['rg --version | head -1', 'ripgrep', 15],
      ['cdk --version 2>&1 | head -1', 'CDK CLI', 60],
    ];
    for (const [cmd, label, timeoutSeconds] of checks) {
      const r = await session.execute(cmd, { timeoutSeconds });
      console.log(`  ${label}: ${r.stdout.trim()}`);
    }

    // 2. Start the Bedrock proxy adapter as a background process.
    console.log('\n=== Starting Bedrock adapter ===');
    const adapter = await session.executeBackground('node /opt/bedrock-adapter.js');
    await new Promise((r) => setTimeout(r, 2000));
    console.log(`  Adapter PID: ${adapter.pid}, running: ${await adapter.isRunning()}`);

    // 3. Test Bedrock via the governed egress proxy.
    console.log('\n=== Bedrock via proxy ===');
    await session.writeFile('/tmp/bedrock_test.py', BEDROCK_TEST);
    const bedrock = await session.execute('python3 /tmp/bedrock_test.py', { timeoutSeconds: 30 });
    console.log(`  Bedrock response: ${bedrock.stdout.trim()}`);

    // 4. Clone a repo through the proxy (requires github.com on the allowlist).
    console.log('\n=== Git clone through proxy ===');
    await session.execute(
      'git clone --depth 1 https://github.com/aws-samples/sample-serverless-ai-sandbox.git /tmp/repo 2>&1',
      { timeoutSeconds: 60 },
    );
    const cloned = await session.execute('ls /tmp/repo/README.md && wc -l < /tmp/repo/README.md',
      { timeoutSeconds: 10 });
    console.log(`  Cloned README: ${cloned.stdout.trim()}`);

    // 5. Write and run a Node.js file.
    console.log('\n=== Node.js execution ===');
    await session.writeFile('/tmp/hello.js', 'console.log("Hello from Node " + process.version)');
    const hello = await session.execute('node /tmp/hello.js', { timeoutSeconds: 10 });
    console.log(`  ${hello.stdout.trim()}`);

    // 6. Write an opencode config pointed at Bedrock.
    console.log('\n=== opencode config ===');
    const config = JSON.stringify({
      $schema: 'https://opencode.ai/config.json',
      provider: { 'amazon-bedrock': { options: { region } } },
      model: 'amazon-bedrock/amazon.nova-micro-v1:0',
      permission: { '*': 'allow' },
    }, null, 2);
    await session.writeFile('/tmp/repo/opencode.json', config);
    console.log('  Config written to /tmp/repo/opencode.json');

    console.log('\n=== Done ===');
    console.log('The sandbox is ready for opencode headless mode.');
  } finally {
    await session.terminate();
    console.log('\nSession terminated.');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
