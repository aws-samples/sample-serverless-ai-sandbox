/** Data analysis — upload a CSV, install pandas, run analysis. Mirrors python/02. */
import { SandboxClient } from '../../sdk/typescript/src/index.js';

async function main(): Promise<void> {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) { console.error('Set API_URL.'); process.exit(1); }
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const token = process.env.SANDBOX_TOKEN;

  const client = new SandboxClient({ apiUrl, region, token });
  console.log('Creating sandbox session...');
  const session = await client.createSession({ maxDurationSeconds: 600 });
  try {
    await session.waitReady({ timeout: 60_000 });
    console.log(`Session ready: ${session.sessionId.slice(0, 12)}...\n`);

    const csv = 'name,age,city\nAlice,30,Seattle\nBob,25,Portland\nCharlie,35,San Francisco\nDiana,28,Denver';
    await session.writeFile('/tmp/people.csv', csv);
    console.log('Uploaded people.csv');

    console.log('Installing pandas...');
    await session.execute('HOME=/tmp pip install --quiet --target /tmp/pylibs pandas', { timeoutSeconds: 120 });

    const script = [
      'import sys; sys.path.insert(0, "/tmp/pylibs")',
      'import pandas as pd',
      'df = pd.read_csv("/tmp/people.csv")',
      'print("=== Data ===")',
      'print(df.to_string(index=False))',
      'print("=== Stats ===")',
      'print("Average age: %.1f" % df["age"].mean())',
      'print("Oldest: %s (%d)" % (df.loc[df["age"].idxmax(), "name"], df["age"].max()))',
      'print("Youngest: %s (%d)" % (df.loc[df["age"].idxmin(), "name"], df["age"].min()))',
      'print("Cities: " + ", ".join(df["city"].unique()))',
    ].join('\n');
    await session.writeFile('/tmp/analyze.py', script);
    const result = await session.execute('PYTHONPATH=/tmp/pylibs python3 /tmp/analyze.py');
    console.log('\n' + result.stdout);
  } finally {
    await session.terminate();
    console.log('Session terminated.');
  }
}
main().catch((err) => { console.error(err); process.exit(1); });
