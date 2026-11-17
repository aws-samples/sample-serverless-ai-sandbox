/** Per-session image — inspect what's installed in a MicroVM image. Mirrors python/08.
 * Usage: npx tsx 08_per_session_image.ts [--image <arn>] */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

const PROBES: [string, string][] = [
  ['python3 --version 2>&1', 'Python'],
  ['node --version 2>&1 || echo not installed', 'Node.js'],
  ['git --version 2>&1 || echo not installed', 'Git'],
  ['rg --version 2>&1 | head -1 || echo not installed', 'ripgrep'],
  ['npm --version 2>&1 || echo not installed', 'npm'],
  ['pip --version 2>&1 | head -1 || echo not installed', 'pip'],
  ['curl --version 2>&1 | head -1 || echo not installed', 'curl'],
  ['jq --version 2>&1 || echo not installed', 'jq'],
  ['uname -m 2>&1', 'Architecture'],
  ["cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo unknown", 'OS'],
];

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;

  const imageIdx = process.argv.indexOf('--image');
  const imageRef = imageIdx !== -1 ? process.argv[imageIdx + 1] : undefined;

  const client = new SandboxClient({ apiUrl, region, token });
  console.log(`Image: ${imageRef ?? '(deployment default)'}`);
  console.log('='.repeat(50));

  const session = await client.createSession({
    maxDurationSeconds: 180,
    idleSeconds: 60,
    ...(imageRef ? { imageRef } : {}),
  });
  try {
    await session.waitReady({ timeout: 180_000 });
    for (const [cmd, label] of PROBES) {
      const r = await session.execute(cmd, { timeoutSeconds: 10 });
      const out = (r.stdout.trim().split('\n')[0] ?? '').trim();
      const lo = out.toLowerCase();
      const installed = !lo.includes('not installed') && !lo.includes('command not found');
      console.log(`  ${installed ? '\u2713' : '\u2717'} ${label.padEnd(14)} ${out}`);
    }
  } finally {
    await session.terminate();
    console.log('\nSession terminated.');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
