/** Suspend / resume — state survives a snapshot. Mirrors python/04. */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;
  const client = new SandboxClient({ apiUrl, region, token });

  const session = await client.createSession({ maxDurationSeconds: 600 });
  try {
    await session.waitReady({ timeout: 60_000 });
    console.log(`Session ready: ${session.sessionId.slice(0, 12)}...`);
    await session.execute('echo "written before suspend" > /tmp/marker.txt');

    console.log('Suspending...');
    await session.suspend();
    console.log('Resuming...');
    await session.resume();
    await session.waitReady({ timeout: 60_000 });

    const r = await session.execute('cat /tmp/marker.txt');
    console.log('After resume, /tmp/marker.txt = ' + r.stdout.trim());
  } finally {
    await session.terminate();
    console.log('Session terminated.');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
