/** Persistent workspace — two sessions share /mnt/workspace via affinityKey. Mirrors python/03. */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;
  const client = new SandboxClient({ apiUrl, region, token });
  const affinityKey = `ts-persist-demo`;

  console.log('=== Session 1: write to /mnt/workspace ===');
  const s1 = await client.createSession({ persistence: true, affinityKey });
  try {
    await s1.waitReady({ timeout: 60_000 });
    await s1.execute('echo "Created by TS session 1 at $(date -u)" > /mnt/workspace/hello.txt');
    await s1.execute('printf \'{"counter": 1, "source": "ts-session-1"}\' > /mnt/workspace/state.json');
    const r = await s1.execute('cat /mnt/workspace/hello.txt /mnt/workspace/state.json');
    console.log(r.stdout);
  } finally { await s1.terminate(); }

  console.log('=== Session 2: same affinityKey, read + append ===');
  const s2 = await client.createSession({ persistence: true, affinityKey });
  try {
    await s2.waitReady({ timeout: 60_000 });
    await s2.execute('echo "Appended by TS session 2 at $(date -u)" >> /mnt/workspace/hello.txt');
    const r = await s2.execute('cat /mnt/workspace/hello.txt');
    console.log('Session 2 sees:\n' + r.stdout);
  } finally { await s2.terminate(); }
  console.log('Files persisted across sessions via S3 Files.');
}
main().catch((err) => { console.error(err); process.exit(1); });
