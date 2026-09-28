# Python SDK Reference

## Installation

The SDK is in `sdk/python/`. It requires `httpx`, `cbor2`, and `websockets`:

```bash
cd sdk/python
pip install -e .
```

## Quick Start

```python
from agent_sandbox import SandboxClient

client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
)

# Create a session and connect
session = client.create_session()
session.wait_ready()
sandbox = session.connection

# Run a command
result = sandbox.execute(["echo", "hello"])
print(result.stdout)  # "hello\n"

# Clean up
session.terminate()
```

## Classes

### SandboxClient

Entry point. Manages sessions via the Control Plane API.

```python
client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
    token="bearer-token",  # optional, for multi-tenant
)
```

| Method | Description |
|--------|-------------|
| `create_session(**opts)` | Create a new session. Returns `SandboxSession`. |
| `get_session(session_id)` | Get an existing session. Returns `SandboxSession`. |
| `list_sessions()` | List all sessions for the authenticated tenant. |
| `resolve_session(affinity_key)` | Get-or-create by affinity key (multi-turn agents). |

### SandboxSession

Represents one session. Wraps lifecycle operations.

| Method / Property | Description |
|-------------------|-------------|
| `session_id` | The session identifier. |
| `wait_ready(timeout=60)` | Poll until RUNNING and connection is available. |
| `connection` | The `SandboxConnection` for executing commands. |
| `suspend()` | Suspend the session (preserves memory + disk). |
| `resume()` | Resume a suspended session. |
| `terminate()` | Terminate the session and release resources. |
| `refresh_connection()` | Mint a fresh connection credential. |

### SandboxConnection

Speaks the Sandbox Protocol (CBOR over HTTPS) to the MicroVM. All sandbox operations go through this.

#### Command Execution

| Method | Description |
|--------|-------------|
| `execute(command, cwd="/tmp", env=None, timeout_seconds=60)` | Run a command. Returns `CommandResult`. |
| `execute_background(command, cwd="/tmp")` | Start a background process. Returns `ProcessHandle`. |
| `execute_stream(command, cwd="/tmp", timeout_seconds=60)` | Stream stdout/stderr as they arrive. |

`command` is a `list[str]` (argv), e.g. `["python3", "-c", "print(1)"]` or `["sh", "-c", "echo hello && ls"]`.

`timeout_seconds` controls both the MicroVM command timeout AND the HTTP round-trip timeout. Default 60s. For long Bedrock calls or data processing, increase to 300+ seconds.

#### File System

| Method | Description |
|--------|-------------|
| `write_file(path, content, mode=0o644)` | Write bytes to a file. |
| `read_file(path)` | Read file contents. Returns `bytes`. |
| `list_files(path="/tmp")` | List directory. Returns `list[FileEntry]`. |
| `delete_file(path, recursive=False)` | Delete a file or directory. |
| `file_exists(path)` | Check if a path exists. Returns `bool`. |
| `file_info(path)` | Get file metadata. Returns `FileInfo`. |
| `make_dir(path, parents=True)` | Create a directory. |
| `rename_file(old_path, new_path)` | Rename/move a file. |
| `list_files_recursive(path, depth=3)` | Recursive directory listing. |
| `write_files(files)` | Write multiple files at once. |
| `watch_files(path, timeout, poll_interval)` | Watch for file changes (inotify). |

#### Metrics & Terminal

| Method | Description |
|--------|-------------|
| `get_metrics()` | Get sandbox metrics (CPU, memory, disk). Returns `Metrics`. |
| `open_pty(cols=80, rows=24)` | Open an interactive PTY session. Returns `PtySession`. |

### Data Classes

| Class | Fields |
|-------|--------|
| `CommandResult` | `exit_code: int`, `stdout: str`, `stderr: str` |
| `FileEntry` | `name: str`, `kind: str`, `size: int` |
| `FileInfo` | `size: int`, `kind: str`, `mode: int`, `modified: float` |
| `Metrics` | `memory_total_kb`, `memory_available_kb`, `load_1m`, `uptime_seconds` |
| `ProcessHandle` | `pid: int`, methods: `is_running()`, `read_stdout()`, `kill()`, `wait()` |
| `PtySession` | methods: `send(text)`, `resize(cols, rows)`, `close()` |
| `FileEvent` | `path: str`, `event_type: str` |

## Examples

### Run a Python script

```python
sandbox.write_file("/tmp/analyze.py", b"""
import json
data = {"total": 42, "items": ["a", "b", "c"]}
print(json.dumps(data, indent=2))
""")
result = sandbox.execute(["python3", "/tmp/analyze.py"])
print(result.stdout)
```

### Background process

```python
proc = sandbox.execute_background("python3 -m http.server 9000", cwd="/tmp")
print(f"PID: {proc.pid}, running: {proc.is_running()}")
# ... later
proc.kill()
```

### Git operations

```python
sandbox.execute(["sh", "-c", "cd /tmp && git clone https://github.com/user/repo.git"])
sandbox.execute(["sh", "-c", "cd /tmp/repo && git status"])
```

### Async SDK

```python
import asyncio
from agent_sandbox import AsyncSandboxClient

async def main():
    async with AsyncSandboxClient(
        api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
        region="us-east-1",
    ) as client:
        session = await client.create_session(persistence=True, affinity_key="my-project")
        await session.wait_ready()

        result = await session.execute(["python3", "-c", "print('hello from async')"])
        print(result.stdout)

        await session.write_file("/mnt/workspace/output.txt", b"async result")
        content = await session.read_file("/mnt/workspace/output.txt")

        await session.terminate()

asyncio.run(main())
```

The async client (`AsyncSandboxClient`) mirrors the sync API with `await`. All operations
(`create_session`, `execute`, `write_file`, `read_file`, `list_files`, `suspend`, `resume`,
`terminate`) are async. Use it in agent frameworks that run async event loops (Strands, LangChain).

### Multi-tenant with affinity key

```python
client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
    token="tenant-a-token",
)
# Same affinity key = same sandbox across turns
session = client.resolve_session(affinity_key="conversation-123")
session.wait_ready()
sandbox = session.connection
sandbox.execute(["echo", "turn 1"])
# ... later, same affinity_key reconnects to the same sandbox
```
