/** Hello sandbox — create a session, run a command, read the output. */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) {
    console.error('Set API_URL. Example: export API_URL=https://xxx.execute-api.us-east-1.amazonaws.com');
    process.exit(1);
  }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN; // unset => SigV4 (single-tenant); set => bearer (multi-tenant)

  const client = new SandboxClient({ apiUrl, region, token });
  const session = await client.createSession();
  try {
    await session.waitReady({ timeout: 120_000 });
    console.log(`Session ready: ${session.sessionId.slice(0, 12)}...`);
    const result = await session.execute(
      `python3 -c 'import json; print(json.dumps({"pi": 3.14159, "sandbox": True}, indent=2))'`,
    );
    console.log('Python output:');
    console.log(result.stdout);
  } finally {
    await session.terminate();
    console.log('Session terminated.');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
