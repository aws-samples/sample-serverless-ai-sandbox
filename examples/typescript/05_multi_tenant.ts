/** Multi-tenant isolation — two tenants, isolated partitions. Mirrors python/05.
 * Requires a multi-tenant deployment (bearer tokens). */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';

  const tenantA = new SandboxClient({ apiUrl, region, token: 'demo-token-tenant-a' });
  const tenantB = new SandboxClient({ apiUrl, region, token: 'demo-token-tenant-b' });

  try {
    const a0 = await tenantA.listSessions();
    console.log(`Tenant A sees ${a0.length} session(s)`);
    const b0 = await tenantB.listSessions();
    console.log(`Tenant B sees ${b0.length} session(s)`);

    console.log('=== Creating a session as Tenant A ===');
    const session = await tenantA.createSession();
    try {
      await session.waitReady({ timeout: 60_000 });
      const r = await session.execute("echo 'Hello from Tenant A sandbox'");
      console.log('Output: ' + r.stdout.trim());
      const a1 = await tenantA.listSessions();
      console.log(`Tenant A now sees ${a1.length} session(s)`);
      const b1 = await tenantB.listSessions();
      console.log(`Tenant B still sees ${b1.length} session(s) (isolation!)`);
    } finally { await session.terminate(); }
  } catch (err: unknown) {
    const msg = String(err);
    if (msg.includes('403')) {
      console.error('This example requires a multi-tenant deployment (bearer tokens rejected by single-tenant).');
      process.exit(1);
    }
    throw err;
  }
  console.log('Tenant A session terminated.');
}
main().catch((err) => { console.error(err); process.exit(1); });
