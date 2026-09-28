# TypeScript SDK Reference

## Installation

```bash
cd sdk/typescript
npm install
npm run build
```

Or install directly:

```bash
npm install ./sdk/typescript
```

## Quick Start

```typescript
import { SandboxClient } from 'agent-sandbox';

const client = new SandboxClient({
  apiUrl: 'https://xxx.execute-api.us-east-1.amazonaws.com',
  region: 'us-east-1',
});

const session = await client.createSession();
await session.waitReady();
const sandbox = session.connection;

const result = await sandbox.execute('echo hello');
console.log(result.stdout); // "hello\n"

await session.terminate();
```

## Classes

### SandboxClient

Entry point. Manages sessions via the Control Plane API.

```typescript
const client = new SandboxClient({
  apiUrl: 'https://xxx.execute-api.us-east-1.amazonaws.com',
  region: 'us-east-1',
  token: 'bearer-token', // optional, for multi-tenant
});
```

| Method | Returns | Description |
|--------|---------|-------------|
| `createSession(opts?)` | `SandboxSession` | Create a new session. Options: `maxDurationSeconds`, `idleSeconds`, `suspendedSeconds`, `autoResume`, `persistence`, `affinityKey` |
| `getSession(sessionId)` | `SandboxSession` | Get an existing session |
| `listSessions()` | `SessionData[]` | List sessions for the tenant |
| `resolveSession(affinityKey, opts?)` | `SandboxSession` | Get-or-create by affinity key |

### SandboxSession

Represents one session.

| Method / Property | Returns | Description |
|-------------------|---------|-------------|
| `sessionId` | `string` | The session identifier |
| `waitReady(timeoutMs?)` | `void` | Poll until RUNNING |
| `connection` | `SandboxConnection` | The connection for operations |
| `suspend()` | `void` | Suspend (preserves state) |
| `resume()` | `void` | Resume from suspension |
| `terminate()` | `void` | Terminate and release resources |
| `refreshConnection()` | `ConnectionDescriptor` | Mint a fresh credential |

### SandboxConnection

Speaks the Sandbox Protocol to the MicroVM.

#### Command Execution

| Method | Returns | Description |
|--------|---------|-------------|
| `execute(command, opts?)` | `CommandResult` | Run a command |

```typescript
// Simple command
const result = await sandbox.execute('echo hello');

// With options
const result = await sandbox.execute('python3 script.py', {
  cwd: '/tmp/project',
  env: { DEBUG: '1' },
  timeoutSeconds: 300, // for long Bedrock calls
});
```

`command` is a string (passed to `sh -c`). `timeoutSeconds` controls both the
MicroVM command timeout and the HTTP timeout. Default 60s.

#### File System

| Method | Returns | Description |
|--------|---------|-------------|
| `writeFile(path, content)` | `void` | Write a Uint8Array to a file |
| `readFile(path)` | `Uint8Array` | Read file contents |
| `listFiles(path?)` | `FileEntry[]` | List directory |
| `deleteFile(path, opts?)` | `void` | Delete a file or directory |

### Types

```typescript
interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

interface FileEntry {
  name: string;
  kind: 'file' | 'directory';
  size: number;
}

interface ConnectionDescriptor {
  baseUrl: string;
  authHeaderName: string;
  authHeaderValue: string;
}
```

## Examples

### Run a script

```typescript
const encoder = new TextEncoder();
await sandbox.writeFile('/tmp/test.py', encoder.encode('print("hello from python")'));
const result = await sandbox.execute('python3 /tmp/test.py');
console.log(result.stdout);
```

### Persistent workspace (S3 Files)

```typescript
const client = new SandboxClient({
  apiUrl: 'https://xxx.execute-api.us-east-1.amazonaws.com',
  region: 'us-east-1',
});

// Mount /mnt/workspace backed by S3 Files
const session = await client.createSession({ persistence: true });
await session.waitReady();
const sandbox = session.connection;

await sandbox.execute(['sh', '-c', 'echo "data" > /mnt/workspace/output.txt']);
const result = await sandbox.execute(['cat', '/mnt/workspace/output.txt']);
console.log(result.stdout); // "data"

await session.terminate();
```

### Shared workspace with affinity key

```typescript
// Session A
const sessionA = await client.createSession({ persistence: true, affinityKey: 'my-project' });
await sessionA.waitReady();
await sessionA.connection.execute(['sh', '-c', 'echo "shared" > /mnt/workspace/data.txt']);
await sessionA.terminate();

// Session B — same affinityKey = same workspace
const sessionB = await client.createSession({ persistence: true, affinityKey: 'my-project' });
await sessionB.waitReady();
const result = await sessionB.connection.execute(['cat', '/mnt/workspace/data.txt']);
console.log(result.stdout); // "shared" — written by Session A
await sessionB.terminate();
```

### Multi-tenant

```typescript
const client = new SandboxClient({
  apiUrl: 'https://xxx.execute-api.us-east-1.amazonaws.com',
  region: 'us-east-1',
  token: 'tenant-a-token',
});

// Affinity key: same sandbox across conversation turns
const session = await client.resolveSession('conversation-123');
await session.waitReady();
```

### Error handling

```typescript
try {
  const result = await sandbox.execute('exit 1');
  if (result.exitCode !== 0) {
    console.error(`Command failed: ${result.stderr}`);
  }
} catch (err) {
  console.error('Protocol error:', err);
}
```

## Naming Convention

The TypeScript SDK mirrors the Python SDK with camelCase naming:

| Python | TypeScript |
|--------|-----------|
| `create_session()` | `createSession()` |
| `execute_background()` | Not yet implemented |
| `write_file()` | `writeFile()` |
| `read_file()` | `readFile()` |
| `list_files()` | `listFiles()` |
| `delete_file()` | `deleteFile()` |
| `timeout_seconds` | `timeoutSeconds` |
