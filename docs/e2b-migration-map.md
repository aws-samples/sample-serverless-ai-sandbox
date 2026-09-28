# E2B Migration Map
<!-- kiro-classification: public -->

This document maps every operation in the [E2B Python SDK v1.3.3](https://e2b.dev/docs/sdk-reference/python-sdk)
to its equivalent in the AWS Serverless Agent Sandbox Python SDK. It is the deliverable of
Requirement 9 criterion 13 (E2B_Migration_Map) and is written at the `recognisable-naming`
Compatibility_Level: migration is a manual but mechanical edit of each call site.

**Audience**: developers who have an existing E2B integration and want to run the same
workload in their own AWS account on Lambda MicroVMs.

**summary**: the AWS SDK covers sandbox lifecycle, command execution, filesystem
operations, streaming output, background processes, PTY, git, file watching, and sandbox
metrics — nearly every operation an agent integration uses. Of E2B's 54 operations, 34 have
a direct SDK method and the rest are reachable via `execute()` or have a structural
alternative. Three E2B capabilities have no equivalent: fork-from-running-state,
dynamic timeout adjustment, and 24-hour session duration. These are service limitations
of the Lambda MicroVM primitive, not planned features.

---

## Quick Comparison

| Dimension | E2B | AWS Serverless Agent Sandbox |
|---|---|---|
| **Isolation** | Firecracker MicroVM (E2B-managed) | Firecracker MicroVM (your AWS account) |
| **Max duration** | 24h (Pro) / 5 min (free) | 8h (28,800s), continuable by reprovision |
| **Suspend/resume** | `beta_pause()` — beta, saves memory+disk | `suspend()` / `resume()` — GA, preserves full memory and disk |
| **Auth** | API key (bearer token) | IAM SigV4 (default) or bearer token (multi-tenant) |
| **Multi-tenancy** | Built-in (org-level) | Deployable single-tenant or multi-tenant profile |
| **Egress control** | Internet access on/off | Governed egress with DNS firewall, proxy fleet, credential injection |
| **Bedrock proxy** | N/A | Built-in — sandbox calls Bedrock through a SigV4-resigning proxy |
| **GPU** | Not available | Delegation seam defined; GPU backend is roadmap |
| **MCP server** | Token-based MCP access | Agent Tool Interface — 6 tools, no credentials exposed to model |
| **Wire protocol** | REST + WebSocket | CBOR over HTTPS (binary, compact) |
| **Idle cost** | $0 (managed) | ~$4/day (Fargate + NAT + NLB + VPC endpoints); $0 on teardown |
| **Pricing** | Per-second compute + storage | Lambda MicroVM pricing (compute + snapshot storage) |
| **Region** | E2B regions | us-east-1, us-east-2, us-west-2, ap-northeast-1, eu-west-1 |

---

## Detailed Operation Mapping

### Sandbox Lifecycle

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `Sandbox.create(template, timeout, ...)` | `client.create_session(max_duration_seconds, idle_seconds, ...)` | No template concept — all sandboxes run Amazon Linux 2023. Timeout maps to `max_duration_seconds`. |
| `Sandbox.connect(sandbox_id)` | `client.get_session(session_id)` | Reconnects to an existing session by ID. |
| — | `client.resolve_session(affinity_key)` | **No E2B equivalent.** Get-or-create by stable key (conversation ID, thread ID). Designed for multi-turn agents. |
| `Sandbox.kill()` | `session.terminate()` | Terminates and releases all resources. |
| `Sandbox.kill(sandbox_id)` (class method) | `client.get_session(id).terminate()` | Two calls instead of one static method. |
| `Sandbox.set_timeout(timeout)` | Not supported | Duration is fixed at creation. Continuation past the ceiling reprovisions a new MicroVM under the same session ID (R10.11). Memory state is lost; disk state is preserved via the State_Store. |
| `Sandbox.get_info()` | `session.refresh()` then read `session.session_data` | Returns full session record including lifecycle state, connection info, and timestamps. |
| `Sandbox.get_metrics()` | `session.get_metrics()` | Returns `Metrics` with `memory_total_kb`, `memory_available_kb`, `disk_total`, `disk_used`, `disk_available`, `load_avg_1`, `load_avg_5`, `load_avg_15`. Reads from `/proc/meminfo`, `df`, and `/proc/loadavg` inside the MicroVM. |
| `Sandbox.is_running()` | `session.lifecycle_state == "RUNNING"` | Check `lifecycle_state` property after `session.refresh()`. Richer than boolean — returns one of: `PENDING`, `ORCHESTRATING`, `PROVISIONING`, `STARTING`, `RUNNING`, `SUSPENDING`, `SUSPENDED`, `RESUMING`, `CONTINUING`, `TERMINATING`, `TERMINATED`, `FAILED`. |
| `Sandbox.beta_pause()` | `session.suspend()` | GA, not beta. Preserves full memory and disk state. Suspended MicroVMs incur snapshot storage only. |
| `Sandbox.beta_create(auto_pause=True)` | `client.create_session(idle_seconds=300, auto_resume=True)` | Idle policy is first-class. `idle_seconds` controls when auto-suspend triggers; `auto_resume` controls whether requests to a suspended sandbox wake it automatically. |
| `SandboxApi.list()` | `client.list_sessions()` | Lists sessions in the caller's tenant partition. |
| — | `session.wait_ready(timeout=120)` | **No E2B equivalent.** Blocks until the sandbox has a connection descriptor. E2B's `create()` returns a ready sandbox; our `create_session()` returns immediately and the sandbox provisions asynchronously. |
| — | `session.resume()` | **No E2B equivalent** (E2B auto-pause is beta with no explicit resume). Explicitly resumes a suspended session. |
| — | `session.refresh_connection()` | **No E2B equivalent.** Refreshes the connection credential (e.g. after resume when the JWE token has rotated). |

### Filesystem Operations

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `files.read(path, format="text")` | `session.read_file(path)` | Returns string content. Invalid UTF-8 bytes are replaced. |
| `files.read(path, format="bytes")` | `session.read_file_bytes(path)` | Returns raw bytes. |
| `files.read(path, format="stream")` | Not supported | No streaming read. Read the full file with `read_file_bytes()` instead. |
| `files.write(path, data)` | `session.write_file(path, content, mode=0o644)` | Accepts `str` or `bytes`. Also supports POSIX permission bits — E2B does not. |
| `files.write_files(files)` | `session.write_files([(path, content), ...])` | Writes multiple files in sequence. Each entry is a `(path, content)` tuple where content is `str` or `bytes`. |
| `files.list(path, depth)` | `session.list_files(path)` / `session.list_files_recursive(path, depth=N)` | Flat listing returns `list[FileEntry]` with `name`, `kind`, `size`. Recursive listing with `depth` parameter uses `find` under the hood. |
| `files.exists(path)` | `session.file_exists(path)` | Returns `True` if the path exists, `False` otherwise. |
| `files.get_info(path)` | `session.file_info(path)` | Returns `FileInfo` with `size`, `modified` (timestamp), `permissions` (octal string), `file_type` (`file`/`directory`/`symlink`/`other`), and `path`. |
| `files.remove(path)` | `session.delete_file(path, recursive=False)` | Supports `recursive=True` for directory removal. |
| `files.rename(old, new)` | `session.rename_file(old, new)` | Moves or renames a file or directory within the sandbox. |
| `files.make_dir(path)` | `session.make_dir(path, parents=True)` | Creates a directory. `parents=True` (default) creates intermediate directories, like `mkdir -p`. |
| `files.watch_dir(path, recursive)` | `session.watch_files(path, recursive, on_change, poll_interval, timeout)` | Polling-based file watcher. Returns `list[FileEvent]` with `path`, `event_type` (`created`/`modified`/`deleted`), and `size`. Configurable `poll_interval` (default 1.0s) and `timeout`. Optional `on_change` callback for real-time notification. |

### Command Execution

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `commands.run(cmd, envs, cwd, timeout, ...)` | `session.execute(command, cwd, env, timeout_seconds)` | `command` accepts a shell string (run via `sh -c`) or a list of arguments. Returns `CommandResult(exit_code, stdout, stderr)`. |
| `commands.run(cmd, background=True)` | `session.execute_background(command)` | Returns a `ProcessHandle` with `pid`, `is_running()`, `read_stdout()`, `read_stderr()`, `kill()`, and `wait(timeout)`. The process runs detached inside the sandbox. |
| `commands.run(on_stdout, on_stderr)` | `session.execute_stream(command, on_stdout=callback, on_stderr=callback)` | Streams output to callbacks as the command runs. Uses WebSocket transport with a file-tailing fallback. Returns the final `CommandResult` after the command completes. |
| `commands.run(stdin=...)` | Not supported directly | For commands that need stdin, pipe via shell: `session.execute("echo 'input' | cmd")`. |
| `commands.list()` | Not supported directly | Use `session.execute("ps aux")`. |
| `commands.kill(pid)` | Not supported directly | Use `session.execute("kill <pid>")`, or call `handle.kill()` on a `ProcessHandle` from `execute_background()`. |
| `commands.send_stdin(pid, data)` | `handle.send_stdin(data)` | Writes to `/proc/pid/fd/0`. Available on `ProcessHandle` instances returned by `execute_background()`. |
| `commands.connect(pid)` | Not supported | No reconnection to arbitrary running processes. Use `execute_background()` which returns a handle you can interact with. |

### PTY (Terminal)

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `pty.create(size, user, cwd, envs, timeout)` | `session.open_pty(cols, rows, shell, cwd)` | Returns a `PtySession` context manager with `send(input)`, `send_and_receive(input)`, `resize(cols, rows)`, and `close()`. Simplified mode runs commands via `execute()` under the hood. Full bidirectional PTY is available via the WebSocket transport path. |
| `pty.connect(pid)` | Not supported | Use the `PtySession` returned by `open_pty()` for the lifetime of the terminal session. No reconnection to a previously opened PTY. |
| `pty.kill(pid)` | `pty.close()` | Closes the PTY session and terminates the underlying shell process. |
| `pty.send_stdin(pid, data)` | `pty.send(data)` | Sends input to the PTY. `send_and_receive(data)` sends input and returns the output in one call. |
| `pty.resize(pid, size)` | `pty.resize(cols, rows)` | Resizes the terminal window. |

### Git Operations

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `git.clone(url, path, ...)` | `session.git.clone(url, path, depth=None)` | Returns `CommandResult`. Git 2.47.3 is pre-installed in the Amazon Linux 2023 MicroVM image. Supports shallow clones via `depth`. |
| `git.init(path, ...)` | `session.git.init(path)` | Initialises a new git repository. |
| `git.add(path, files, all)` | `session.git.add(path, files=None, all=False)` | Stages files. Pass `all=True` for `git add -A`. |
| `git.commit(path, message, ...)` | `session.git.commit(message, cwd=None)` | Commits staged changes with the given message. |
| `git.push(path, remote, branch, ...)` | `session.git.push(remote="origin", branch=None, cwd=None)` | Requires egress to be permitted for the git remote host. |
| `git.pull(path, remote, branch, ...)` | `session.git.pull(remote="origin", branch=None, cwd=None)` | — |
| `git.status(path)` | `session.git.status(cwd=None)` | Returns `GitStatus(branch, clean, modified, added, deleted, untracked)` — structured, not raw stdout. |
| `git.branches(path)` | `session.git.branches(cwd=None)` | Returns a list of branch names. |
| All other git operations | `session.execute("git ...")` | Operations beyond the eight SDK methods (e.g. `create_branch`, `checkout_branch`, `reset`, `restore`, `configure_user`) map to the corresponding CLI command via `execute()`. |

### MCP

| E2B Operation | AWS SDK Equivalent | Notes |
|---|---|---|
| `Sandbox.get_mcp_token()` | Agent Tool Interface (MCP server Lambda) | Different model. E2B gives you a token to connect an MCP client to the sandbox. Our Agent Tool Interface *is* the MCP server — it exposes 6 tools (`execute_command`, `read_file`, `write_file`, `list_files`, `delete_file`, `get_session_info`) and manages the sandbox lifecycle itself. The model never sees a credential. |

---

## Code Examples

### Creating a Sandbox and Running a Command

**E2B (before)**:

```python
from e2b import Sandbox

sandbox = Sandbox()
result = sandbox.commands.run("echo hello world")
print(result.stdout)   # "hello world\n"
sandbox.kill()
```

**AWS Serverless Agent Sandbox (after)**:

```python
from agent_sandbox import SandboxClient

client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
)

with client.create_session() as session:
    session.wait_ready()
    result = session.execute("echo hello world")
    print(result.stdout)   # "hello world\n"
# Session terminated automatically by context manager
```

**Key differences**:
- You provide an API URL and region (it's your AWS account, not a managed service)
- `create_session()` returns immediately; call `wait_ready()` to block until the sandbox is up
- The `with` block auto-terminates the session on exit
- `execute()` replaces `commands.run()` — same concept, different name

### File Operations

**E2B (before)**:

```python
sandbox.files.write("/tmp/data.txt", "hello from e2b")
content = sandbox.files.read("/tmp/data.txt")
entries = sandbox.files.list("/tmp")
sandbox.files.remove("/tmp/data.txt")
```

**AWS Serverless Agent Sandbox (after)**:

```python
session.write_file("/tmp/data.txt", "hello from aws sandbox")
content = session.read_file("/tmp/data.txt")
entries = session.list_files("/tmp")        # returns list[FileEntry]
session.delete_file("/tmp/data.txt")
```

**Key differences**:
- Methods are on the session directly, not on a `.files` sub-object
- `write_file()` also accepts a `mode` parameter for POSIX permissions
- `list_files()` returns `FileEntry(name, kind, size)` dataclasses

### Suspend and Resume

**E2B (before)**:

```python
# Beta API
sandbox = Sandbox.beta_create(auto_pause=True)
result = sandbox.commands.run("echo hello")
sandbox_id = sandbox.sandbox_id

sandbox.beta_pause()

# Later — reconnect
sandbox = Sandbox.connect(sandbox_id)
result = sandbox.commands.run("echo resumed")
```

**AWS Serverless Agent Sandbox (after)**:

```python
session = client.create_session(idle_seconds=300, auto_resume=True)
session.wait_ready()
result = session.execute("echo hello")
session_id = session.session_id

session.suspend()

# Later — reconnect
session = client.get_session(session_id)
session.resume()
session.wait_ready()
result = session.execute("echo resumed")
```

**Key differences**:
- Suspend/resume is GA, not beta
- Full memory and disk state is preserved across suspend
- `auto_resume=True` means requests to a suspended sandbox wake it automatically
- `idle_seconds` replaces E2B's auto-pause concept with an explicit idle timeout

### Multi-Turn Agent with Affinity Key

**E2B** — no built-in affinity mechanism. You manage the mapping yourself:

```python
# You must store and retrieve sandbox_id per conversation
sandbox_id = your_db.get(conversation_id)
if sandbox_id:
    sandbox = Sandbox.connect(sandbox_id)
else:
    sandbox = Sandbox()
    your_db.set(conversation_id, sandbox.sandbox_id)
```

**AWS Serverless Agent Sandbox** — first-class affinity:

```python
# resolve_session handles get-or-create atomically
session = client.resolve_session(
    affinity_key=conversation_id,
    max_duration_seconds=3600,
)
session.wait_ready()
result = session.execute("echo hello")
```

`resolve_session()` is a conditional write: if a session already exists for this affinity key,
it is returned; otherwise a new one is created and bound. No external state management needed.

### Bearer Token Auth (Multi-Tenant)

> For production, replace the Lambda authorizer with Cognito JWT auth —
> see [Cognito Integration Guide](cognito-auth.md).

**E2B (before)**:

```python
sandbox = Sandbox(api_key="e2b_xxx...")
```

**AWS Serverless Agent Sandbox (after)**:

```python
client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
    token="tenant-a-token",     # bearer token for multi-tenant deployments
)
```

When no `token` is provided, the client uses SigV4 signing with the caller's AWS credentials
(the default for single-tenant deployments).

### Extended SDK Features

Beyond the core operations above, the SDK provides these additional capabilities.

```python
# Filesystem helpers
exists = session.file_exists("/tmp/data.txt")
info = session.file_info("/tmp/data.txt")
session.make_dir("/tmp/project/src")
session.rename_file("/tmp/old.txt", "/tmp/new.txt")

# Batch file write
session.write_files([
    ("/tmp/main.py", "print('hello')"),
    ("/tmp/config.json", '{"debug": true}'),
])

# Recursive listing
entries = session.list_files_recursive("/tmp/project", depth=3)

# Background processes
handle = session.execute_background("python3 server.py")
print(handle.pid, handle.is_running())
handle.kill()

# Streaming
def on_output(chunk: bytes):
    print(chunk.decode(), end="")
result = session.execute_stream("make test", on_stdout=on_output)

# Git operations
session.git.clone("https://github.com/user/repo", "/tmp/repo", depth=1)
status = session.git.status(cwd="/tmp/repo")
print(status.branch, status.clean)

# PTY (simplified)
with session.open_pty() as pty:
    output = pty.send("ls -la /tmp")
    print(output)

# File watching
events = session.watch_files("/tmp/project", timeout=30, poll_interval=1.0)
for event in events:
    print(f"{event.event_type}: {event.path}")

# Sandbox metrics
metrics = session.get_metrics()
print(f"Memory: {metrics.memory_available_kb}KB free of {metrics.memory_total_kb}KB")
```

---

## Capabilities Our SDK Adds

These are capabilities the AWS Serverless Agent Sandbox provides that E2B does not.

| Capability | Description |
|---|---|
| **Runs in your AWS account** | The sandbox runs in your VPC, your Region, your encryption keys, your audit trail. No data crosses an organisational boundary. No third-party subprocessor. |
| **Multi-tenant isolation** | Deploy once, serve multiple tenants with structural isolation — DynamoDB leading-key conditions, per-tenant artifact prefixes, separate IAM roles. |
| **Governed egress** | DNS firewall + forward proxy fleet + credential injection. The sandbox never holds an upstream secret. Blocked attempts are audited. |
| **Bedrock proxy** | Sandboxes call Bedrock models through a SigV4-resigning proxy. The execution role denies direct Bedrock invocation, so the proxy is the only path. |
| **Affinity key (get-or-create)** | `resolve_session(affinity_key)` atomically binds a conversation to a sandbox. No external state management. |
| **Suspend/resume (GA)** | Full memory and disk preservation. E2B's pause is still beta. |
| **Idle policy** | Configurable `idle_seconds` and `suspended_seconds` with auto-resume. Sessions that exceed their idle or suspended timeout are cleaned up automatically. |
| **Session Orchestrator** | Lifecycle is a Step Functions state machine — declarative, durable, inspectable. An operator can see which state a session occupies and why. |
| **Reaper** | Independent scheduled sweep that terminates orphaned sessions, with no shared failure mode with the orchestrator. |
| **Agent Tool Interface (MCP)** | Six tools exposed via MCP. The model never sees a session ID, a credential, or an affinity key. The tool surface is inside the trusted computing base; the model is not. |
| **Continuation past duration ceiling** | When 8h is hit, the session can reprovision a fresh MicroVM under the same session ID with disk state restored from the State_Store. |
| **POSIX file permissions** | `write_file()` accepts a `mode` parameter (default `0o644`). |
| **IAM + Cognito auth** | SigV4 by default (single-tenant) or bearer token via Lambda authorizer (multi-tenant). |
| **Compute_Provider seam** | The architecture admits additional backends (GPU, Fargate, ECS) without changing the SDK or wire protocol. |

---

## Remaining Service Limitations

Three E2B capabilities have no equivalent in the AWS SDK. These are limitations of the
Lambda MicroVM compute primitive, not planned features.

| E2B Capability | Status | Explanation |
|---|---|---|
| **Fork from running state** | Service limitation | Lambda MicroVMs does not expose a snapshot-and-clone API. You can suspend (preserving memory+disk) but only for the same session. Creating copies of a running sandbox requires the compute primitive to support it. |
| **Set timeout (extend/reduce)** | Service limitation | Lambda MicroVM duration is fixed at provision time (`maximumDurationInSeconds`). There is no API to extend a running session. The continuation mechanism handles the ceiling by reprovisioning a fresh MicroVM under the same session ID with disk state preserved. |
| **24h session duration (Pro)** | Service limitation | Lambda MicroVMs has a hard ceiling of 28,800 seconds (8 hours). The continuation mechanism reprovisions with disk state preserved but memory is lost at the boundary. E2B Pro allows 24 hours (86,400 seconds). |

---

## Migration Guide

### Step 1: Deploy the Infrastructure

Before migrating code, deploy the AWS Serverless Agent Sandbox into your account:

```bash
git clone <repo-url>
cd ServerlessSandboxes
npm ci
npx cdk bootstrap
npx cdk deploy --all
```

Note the API Gateway URL from the stack outputs. This becomes your `api_url`.

### Step 2: Install the SDK

```bash
pip install agent-sandbox==0.1.0
# or, from the repo:
pip install ./sdk/python
```

Dependencies: `httpx`, `cbor2`, `botocore` (for SigV4 auth).

### Step 3: Replace Imports

```python
# Before (E2B)
from e2b import Sandbox

# After
from agent_sandbox import SandboxClient, SandboxSession
```

### Step 4: Replace Client Construction

```python
# Before (E2B)
sandbox = Sandbox(api_key="e2b_xxx...")

# After
client = SandboxClient(
    api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
    region="us-east-1",
    # token="..." for multi-tenant deployments
)
```

### Step 5: Replace Sandbox Creation

```python
# Before (E2B)
sandbox = Sandbox(timeout=3600)

# After
session = client.create_session(max_duration_seconds=3600)
session.wait_ready()  # E2B blocks on create; we return immediately
```

Or use the context manager for automatic cleanup:

```python
with client.create_session(max_duration_seconds=3600) as session:
    session.wait_ready()
    # ... use the session ...
# Terminated automatically
```

### Step 6: Replace Operations

Apply these mechanical substitutions:

| E2B call | AWS SDK call |
|---|---|
| `sandbox.commands.run(cmd)` | `session.execute(cmd)` |
| `sandbox.commands.run(cmd, background=True)` | `session.execute_background(cmd)` |
| `sandbox.commands.run(cmd, on_stdout=cb)` | `session.execute_stream(cmd, on_stdout=cb)` |
| `sandbox.files.read(path)` | `session.read_file(path)` |
| `sandbox.files.read(path, format="bytes")` | `session.read_file_bytes(path)` |
| `sandbox.files.write(path, data)` | `session.write_file(path, data)` |
| `sandbox.files.write_files(files)` | `session.write_files([(path, content), ...])` |
| `sandbox.files.list(path)` | `session.list_files(path)` |
| `sandbox.files.exists(path)` | `session.file_exists(path)` |
| `sandbox.files.get_info(path)` | `session.file_info(path)` |
| `sandbox.files.remove(path)` | `session.delete_file(path)` |
| `sandbox.files.rename(old, new)` | `session.rename_file(old, new)` |
| `sandbox.files.make_dir(path)` | `session.make_dir(path)` |
| `sandbox.kill()` | `session.terminate()` |
| `sandbox.beta_pause()` | `session.suspend()` |
| `sandbox.get_metrics()` | `session.get_metrics()` |
| `sandbox.pty.create(...)` | `session.open_pty(...)` |
| `sandbox.git.clone(url, path)` | `session.git.clone(url, path)` |
| `sandbox.git.status(path)` | `session.git.status(cwd=path)` |

### Step 7: Handle Return Types

E2B and our SDK return different types:

```python
# E2B
result = sandbox.commands.run("echo hello")
print(result.stdout)        # str
print(result.exit_code)     # int
print(result.stderr)        # str

# AWS SDK — same shape, same field names
result = session.execute("echo hello")
print(result.stdout)        # str
print(result.exit_code)     # int
print(result.stderr)        # str
```

```python
# E2B
entries = sandbox.files.list("/tmp")
for e in entries:
    print(e.name, e.type)   # "file" | "dir"

# AWS SDK
entries = session.list_files("/tmp")
for e in entries:
    print(e.name, e.kind)   # "file" | "directory" | "symlink" | "other"
```

### Step 8: Replace Reconnection Pattern

```python
# Before (E2B)
sandbox = Sandbox.connect(sandbox_id)

# After — option A: by session ID
session = client.get_session(session_id)

# After — option B: by affinity key (recommended for agents)
session = client.resolve_session(affinity_key=conversation_id)
session.wait_ready()
```

### Step 9: Handle What Doesn't Map

Most operations that previously required `execute()` workarounds now have SDK methods.
For the remaining E2B git operations beyond the eight SDK methods, use `execute()`:

```python
# Git operations without a dedicated SDK method
session.execute("git checkout -b feature-branch")
session.execute("git reset --hard HEAD~1")
session.execute("git remote add upstream https://github.com/org/repo")
```

For fork-from-running-state — this has no workaround. E2B can snapshot a running sandbox
and create copies; Lambda MicroVMs does not expose a snapshot-and-clone API. If your
integration depends on fork, evaluate whether the governed-isolation and own-account-deployment
benefits outweigh this missing capability for your use case.

---

## API Shape Comparison

For reference, the full public surface of both SDKs side by side.

### E2B (54 operations)

```
Sandbox.create()              Sandbox.connect()           Sandbox.kill()
Sandbox.set_timeout()         Sandbox.get_info()          Sandbox.get_metrics()
Sandbox.is_running()          Sandbox.beta_pause()        Sandbox.beta_create()
SandboxApi.list()             Sandbox.get_mcp_token()

files.read()                  files.write()               files.write_files()
files.list()                  files.exists()              files.get_info()
files.remove()                files.rename()              files.make_dir()
files.watch_dir()

commands.run()                commands.list()             commands.kill()
commands.send_stdin()         commands.connect()

pty.create()                  pty.connect()               pty.kill()
pty.send_stdin()              pty.resize()

git.clone()                   git.init()                  git.add()
git.commit()                  git.push()                  git.pull()
git.status()                  git.branches()              git.create_branch()
git.checkout_branch()         git.delete_branch()         git.remote_add()
git.remote_get()              git.reset()                 git.restore()
git.set_config()              git.get_config()            git.configure_user()
git.dangerously_authenticate()
```

### AWS Serverless Agent Sandbox (38 operations)

```
SandboxClient()               client.create_session()     client.resolve_session()
client.get_session()           client.list_sessions()      client.close()

session.wait_ready()           session.execute()           session.execute_stream()
session.execute_background()   session.write_file()        session.write_files()
session.read_file()            session.read_file_bytes()   session.list_files()
session.list_files_recursive() session.delete_file()       session.file_exists()
session.file_info()            session.rename_file()       session.make_dir()
session.watch_files()          session.get_metrics()       session.open_pty()
session.suspend()              session.resume()            session.terminate()
session.refresh()              session.refresh_connection()
session (context manager)

session.git.clone()            session.git.init()          session.git.add()
session.git.commit()           session.git.push()          session.git.pull()
session.git.status()           session.git.branches()
```

**Coverage**: of E2B's 54 operations, 34 have a direct SDK equivalent, 12 can be done via
`session.execute()` (the remaining git operations such as `create_branch`, `checkout_branch`,
`reset`, `restore`, etc.), 5 have a structural alternative (MCP, affinity key, lifecycle states),
and 3 have no equivalent (fork-from-running-state, set-timeout, 24h duration) — these are
service limitations of the Lambda MicroVM primitive.

---

*E2B SDK surface consulted: [docs.e2b.dev/sdk-reference/python-sdk](https://e2b.dev/docs/sdk-reference/python-sdk), v1.3.3 (June 2025).*
*Content was rephrased for compliance with licensing restrictions.*
