// kiro-classification: public
/**
 * Sandbox Protocol operations — execute commands and manage files inside a Sandbox.
 *
 * Uses `cbor-x` for CBOR serialisation. The wire format matches the Sandbox_Protocol
 * message catalogue (`protocol/messages.yaml`).
 */

import { Encoder, decode as cborDecode } from 'cbor-x';

// Configure cbor-x to NOT use tag 259 for Maps (the runtime expects plain CBOR maps)
// and to encode Uint8Array as plain bytestrings (not tagged).
const cborEncoder = new Encoder({ mapsAsObjects: false, tagUint8Array: false });
const encode = (value: unknown): Uint8Array => cborEncoder.encode(value);
function toMap(obj: unknown): unknown {
  if (obj instanceof Map) return obj;
  if (obj instanceof Uint8Array) return obj;
  if (Array.isArray(obj)) return obj.map(toMap);
  if (obj && typeof obj === 'object') {
    const entries = Object.entries(obj).map(([k, v]) => {
      const numKey = parseInt(k);
      return [isNaN(numKey) ? k : numKey, toMap(v)] as [unknown, unknown];
    });
    return new Map(entries);
  }
  return obj;
}

const decode = (data: Uint8Array): unknown => {
  return toMap(cborDecode(data));
};
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Small shell/parse helpers (shared by the execute-based operations below)
// ---------------------------------------------------------------------------

/** Quote a string for safe use inside a `sh -c` command (mirrors Python's shlex.quote). */
function shQuote(s: string): string {
  if (s.length === 0) return "''";
  if (/^[a-zA-Z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + s.replace(/'/g, `'"'"'`) + "'";
}

/** Split on runs of whitespace at most `maxsplit` times, keeping the remainder as the last
 *  element (mirrors Python's str.split(None, maxsplit)). */
function splitWhitespace(s: string, maxsplit: number): string[] {
  const parts: string[] = [];
  let rest = s.replace(/^\s+/, '');
  while (parts.length < maxsplit && rest.length > 0) {
    const m = rest.match(/\s/);
    if (!m || m.index === undefined) break;
    parts.push(rest.slice(0, m.index));
    rest = rest.slice(m.index).replace(/^\s+/, '');
  }
  if (rest.length > 0) parts.push(rest);
  return parts;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Protocol constants — from the message catalogue
// ---------------------------------------------------------------------------

/** Envelope key positions (sorted ascending for deterministic CBOR). */
const KEY_VERSION = 1;
const KEY_TYPE = 2;
const KEY_ID = 3;
const KEY_BODY = 4;

/** Protocol version emitted by this SDK. */
const PROTOCOL_VERSION = 1;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Result of a command execution inside the Sandbox. */
export interface CommandResult {
  /** Process exit code (0 = success, negative = killed by signal). */
  readonly exitCode: number;
  /** Standard output as a string. */
  readonly stdout: string;
  /** Standard error as a string. */
  readonly stderr: string;
}

/** One entry from a directory listing. */
export interface FileEntry {
  /** File or directory name (not the full path). */
  readonly name: string;
  /** One of `"file"`, `"directory"`, `"symlink"`, `"other"`. */
  readonly kind: string;
  /** Size in bytes. */
  readonly size: number;
}

/** Metadata about a single file or directory. */
export interface FileInfo {
  /** Size in bytes. */
  readonly size: number;
  /** Last modification time as a Unix timestamp. */
  readonly modified: number;
  /** Octal permission string (e.g. `"644"`). */
  readonly permissions: string;
  /** Human-readable type (e.g. `"regular file"`, `"directory"`). */
  readonly fileType: string;
  /** Absolute path inside the Sandbox. */
  readonly path: string;
}

/** Sandbox resource usage snapshot. */
export interface Metrics {
  readonly memoryTotalKb: number;
  readonly memoryAvailableKb: number;
  readonly diskTotal: string;
  readonly diskUsed: string;
  readonly diskAvailable: string;
  readonly loadAvg1: number;
  readonly loadAvg5: number;
  readonly loadAvg15: number;
}

/** A detected file change inside the Sandbox. */
export interface FileEvent {
  /** Absolute path of the changed file. */
  readonly path: string;
  /** One of `"created"`, `"modified"`, `"deleted"`. */
  readonly eventType: string;
  /** File size in bytes (0 for deleted files). */
  readonly size: number;
}

// ---------------------------------------------------------------------------
// Connection descriptor
// ---------------------------------------------------------------------------

/** Shape of the `connection` map returned by the Control Plane. */
export interface ConnectionDescriptor {
  baseUrl: string;
  authHeaderName: string;
  authHeaderValue: string;
}

// ---------------------------------------------------------------------------
// Sandbox Protocol client
// ---------------------------------------------------------------------------

/** Options for constructing a {@link SandboxConnection}. */
export interface SandboxConnectionOptions {
  baseUrl: string;
  authHeaderName: string;
  authHeaderValue: string;
}

/**
 * Speaks the Sandbox Protocol (CBOR over HTTPS) to a MicroVM endpoint.
 */
/** Error thrown when a Sandbox Protocol request returns a non-2xx status. */
export class SandboxProtocolError extends Error {
  readonly status: number;
  constructor(status: number, statusText: string) {
    super(`Sandbox protocol request failed: ${status} ${statusText}`);
    this.name = 'SandboxProtocolError';
    this.status = status;
  }
}

/** Handle to a background process running inside the Sandbox.
 *
 * Created by {@link SandboxConnection.executeBackground}. Stdout and stderr are redirected to
 * temporary files inside the Sandbox so they can be read incrementally. */
export class ProcessHandle {
  readonly pid: number;
  readonly stdoutPath: string;
  readonly stderrPath: string;
  /** Path to the file the launcher writes the process exit code to once it finishes. */
  readonly rcPath: string;
  readonly #sandbox: SandboxConnection;

  constructor(options: {
    pid: number;
    sandbox: SandboxConnection;
    stdoutPath: string;
    stderrPath: string;
    rcPath?: string;
  }) {
    this.pid = options.pid;
    this.#sandbox = options.sandbox;
    this.stdoutPath = options.stdoutPath;
    this.stderrPath = options.stderrPath;
    this.rcPath = options.rcPath ?? '';
  }

  /** Return `true` if the process is still running. */
  async isRunning(): Promise<boolean> {
    const result = await this.#sandbox.execute(['kill', '-0', String(this.pid)], { timeoutSeconds: 5 });
    return result.exitCode === 0;
  }

  /** Read the current stdout output. */
  async readStdout(): Promise<string> {
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(await this.#sandbox.readFile(this.stdoutPath));
    } catch {
      return '';
    }
  }

  /** Read the current stderr output. */
  async readStderr(): Promise<string> {
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(await this.#sandbox.readFile(this.stderrPath));
    } catch {
      return '';
    }
  }

  /** Send SIGKILL to the process. */
  async kill(): Promise<void> {
    await this.#sandbox.execute(['kill', '-9', String(this.pid)], { timeoutSeconds: 5 });
  }

  /** Wait for the process to finish and return the final result.
   *
   * Polls until the process exits (or the timeout elapses), then reads the exit code the launcher
   * wrote to {@link rcPath}. The POSIX `wait` builtin can't be used here: each operation runs in a
   * fresh shell where the pid is not a child, so `wait` would always report 127. */
  async wait(options?: { timeout?: number }): Promise<CommandResult> {
    const timeout = options?.timeout ?? 60;
    await this.#sandbox.execute(
      [
        'sh', '-c',
        `i=0; while kill -0 ${this.pid} 2>/dev/null && [ $i -lt ${timeout} ]; do sleep 1; i=$((i+1)); done`,
      ],
      { timeoutSeconds: timeout + 5 },
    );
    let exitCode = -1;
    if (this.rcPath) {
      const rc = await this.#sandbox.execute(['cat', this.rcPath], { timeoutSeconds: 5 });
      if (rc.exitCode === 0) {
        const parsed = Number.parseInt(rc.stdout.trim(), 10);
        if (!Number.isNaN(parsed)) exitCode = parsed;
      }
    }
    return {
      exitCode,
      stdout: await this.readStdout(),
      stderr: await this.readStderr(),
    };
  }
}

/** Pseudo-terminal session using {@link SandboxConnection.execute} under the hood.
 *
 * Provides request/response style interaction with a shell inside the Sandbox. For truly
 * interactive bidirectional I/O, use the WebSocket protocol path directly. */
export class PtySession {
  cols: number;
  rows: number;
  readonly #sandbox: SandboxConnection;
  readonly #shell: string;
  readonly #cwd: string;
  #closed = false;

  constructor(options: {
    sandbox: SandboxConnection;
    shell?: string;
    cwd?: string;
    cols?: number;
    rows?: number;
  }) {
    this.#sandbox = options.sandbox;
    this.#shell = options.shell ?? '/bin/bash';
    this.#cwd = options.cwd ?? '/tmp';
    this.cols = options.cols ?? 80;
    this.rows = options.rows ?? 24;
  }

  /** Send a command and return combined stdout + stderr. */
  async send(inputText: string, options?: { timeoutSeconds?: number }): Promise<string> {
    const r = await this.sendAndReceive(inputText, options);
    return r.stdout + (r.stderr ? r.stderr : '');
  }

  /** Send a command and return the full CommandResult. */
  async sendAndReceive(inputText: string, options?: { timeoutSeconds?: number }): Promise<CommandResult> {
    if (this.#closed) throw new Error('PTY session is closed');
    return this.#sandbox.execute([this.#shell, '-c', inputText], {
      cwd: this.#cwd,
      timeoutSeconds: options?.timeoutSeconds ?? 10,
    });
  }

  /** Update the terminal dimensions (informational in simplified mode). */
  resize(cols: number, rows: number): void {
    this.cols = cols;
    this.rows = rows;
  }

  /** Close the PTY session. */
  close(): void {
    this.#closed = true;
  }
}

export class SandboxConnection {
  readonly #baseUrl: string;
  readonly #authHeaderName: string;
  readonly #authHeaderValue: string;

  constructor(options: SandboxConnectionOptions) {
    this.#baseUrl = options.baseUrl;
    this.#authHeaderName = options.authHeaderName;
    this.#authHeaderValue = options.authHeaderValue;
  }

  /** Build from the `connection` map returned by the Control Plane. */
  static fromConnectionDescriptor(descriptor: ConnectionDescriptor): SandboxConnection {
    return new SandboxConnection({
      baseUrl: descriptor.baseUrl,
      authHeaderName: descriptor.authHeaderName,
      authHeaderValue: descriptor.authHeaderValue,
    });
  }

  // ------------------------------------------------------------------
  // High-level operations
  // ------------------------------------------------------------------

  /**
   * Execute a command inside the Sandbox and return the result.
   *
   * @param command - The command as an array of arguments.
   * @param options - Working directory, environment, and timeout.
   */
  async execute(
    command: string[],
    options?: {
      cwd?: string;
      env?: Record<string, string>;
      timeoutSeconds?: number;
    },
  ): Promise<CommandResult> {
    const cwd = options?.cwd ?? '/tmp';
    const env = options?.env ?? {};
    const timeoutSeconds = options?.timeoutSeconds ?? 60;

    const body = new Map<number, unknown>([
      [1, command.map((arg) => new TextEncoder().encode(arg))], // argv: list[bytes]
      [2, new TextEncoder().encode(cwd)], // cwd: bytes
      [
        3,
        new Map(
          Object.entries(env).map(([k, v]) => [
            new TextEncoder().encode(k),
            new TextEncoder().encode(v),
          ]),
        ),
      ], // env: map
      [4, timeoutSeconds * 1000], // timeoutMs: uint (ms)
      [5, false], // stream: bool
    ]);

    const response = await this.#send('exec.request', body, (timeoutSeconds + 10) * 1000);
    const respBody = response.get(KEY_BODY) as Map<number, unknown>;

    const exitCode = respBody.get(1);
    const stdoutBytes = respBody.get(2);
    const stderrBytes = respBody.get(3);

    return {
      exitCode: typeof exitCode === 'number' ? exitCode : -1,
      stdout:
        stdoutBytes instanceof Uint8Array
          ? new TextDecoder('utf-8', { fatal: false }).decode(stdoutBytes)
          : String(stdoutBytes ?? ''),
      stderr:
        stderrBytes instanceof Uint8Array
          ? new TextDecoder('utf-8', { fatal: false }).decode(stderrBytes)
          : String(stderrBytes ?? ''),
    };
  }

  /**
   * Write a file inside the Sandbox.
   *
   * @param path - Absolute path inside the Sandbox.
   * @param content - File content as bytes.
   * @param options - POSIX permission bits (default: 0o644).
   */
  async writeFile(
    path: string,
    content: Uint8Array,
    options?: { mode?: number },
  ): Promise<void> {
    const mode = options?.mode ?? 0o644;
    const body = new Map<number, unknown>([
      [1, new TextEncoder().encode(path)], // path: bytes
      [2, content], // data: bytes
      [3, mode], // mode: uint
    ]);
    await this.#send('fs.write', body);
  }

  /**
   * Read a file from the Sandbox.
   *
   * @param path - Absolute path inside the Sandbox.
   * @returns The file content as bytes.
   */
  async readFile(path: string): Promise<Uint8Array> {
    const body = new Map<number, unknown>([
      [1, new TextEncoder().encode(path)], // path: bytes
    ]);
    const response = await this.#send('fs.read', body);
    const respBody = response.get(KEY_BODY) as Map<number, unknown>;
    const content = respBody.get(1);
    if (!(content instanceof Uint8Array)) {
      throw new Error(
        `Expected Uint8Array from fs.content, got ${typeof content}`,
      );
    }
    return content;
  }

  /**
   * List files and directories at the given path.
   *
   * @param path - Directory path inside the Sandbox.
   */
  async listFiles(path: string = '/tmp'): Promise<FileEntry[]> {
    const body = new Map<number, unknown>([
      [1, new TextEncoder().encode(path)], // path: bytes
    ]);
    const response = await this.#send('fs.list', body);
    const respBody = response.get(KEY_BODY) as Map<number, unknown>;

    const entriesRaw = respBody.get(1);
    const entries: FileEntry[] = [];
    if (Array.isArray(entriesRaw)) {
      for (const entry of entriesRaw) {
        if (entry instanceof Map) {
          const nameBytes = entry.get(1);
          const name =
            nameBytes instanceof Uint8Array
              ? new TextDecoder('utf-8', { fatal: false }).decode(nameBytes)
              : String(nameBytes ?? '');
          const kind = (entry.get(2) as string) ?? 'other';
          const size = (entry.get(3) as number) ?? 0;
          entries.push({ name, kind, size });
        }
      }
    }
    return entries;
  }

  /**
   * Delete a file or directory from the Sandbox.
   *
   * @param path - Absolute path inside the Sandbox.
   * @param options - If `recursive` is true, delete directories recursively.
   */
  async deleteFile(
    path: string,
    options?: { recursive?: boolean },
  ): Promise<void> {
    const recursive = options?.recursive ?? false;
    const body = new Map<number, unknown>([
      [1, new TextEncoder().encode(path)], // path: bytes
      [2, recursive], // recursive: bool
    ]);
    await this.#send('fs.delete', body);
  }

  // ------------------------------------------------------------------
  // Filesystem helpers
  // ------------------------------------------------------------------

  /** Check if a file or directory exists inside the Sandbox. */
  async fileExists(path: string): Promise<boolean> {
    const result = await this.execute(['test', '-e', path], { timeoutSeconds: 5 });
    return result.exitCode === 0;
  }

  /** Get metadata about a file or directory. */
  async fileInfo(path: string): Promise<FileInfo> {
    const result = await this.execute(['stat', '-c', '%s %Y %a %F %n', path], { timeoutSeconds: 5 });
    if (result.exitCode !== 0) {
      throw new Error(`stat failed for ${path}: ${result.stderr}`);
    }
    const parts = splitWhitespace(result.stdout.trim(), 4);
    if (parts.length < 5) {
      throw new Error(`Unexpected stat output: ${JSON.stringify(result.stdout)}`);
    }
    return {
      size: Number.parseInt(parts[0]!, 10),
      modified: Number.parseInt(parts[1]!, 10),
      permissions: parts[2]!,
      fileType: parts[3]!,
      path: parts[4]!,
    };
  }

  /** Create a directory inside the Sandbox (with parents by default). */
  async makeDir(path: string, options?: { parents?: boolean }): Promise<void> {
    const parents = options?.parents ?? true;
    const cmd = parents ? ['mkdir', '-p', path] : ['mkdir', path];
    const result = await this.execute(cmd, { timeoutSeconds: 5 });
    if (result.exitCode !== 0) {
      throw new Error(`mkdir failed: ${result.stderr}`);
    }
  }

  /** Rename or move a file or directory inside the Sandbox. */
  async renameFile(oldPath: string, newPath: string): Promise<void> {
    const result = await this.execute(['mv', oldPath, newPath], { timeoutSeconds: 5 });
    if (result.exitCode !== 0) {
      throw new Error(`rename failed: ${result.stderr}`);
    }
  }

  /** List files recursively to a given depth (default: 3).
   *
   * Implemented by recursing over the `fs.list` wire op rather than shelling out to `find`, so it
   * works on minimal images with no findutils. Each returned entry's `name` is a full path.
   * `depth` counts levels below `path`: `depth: 1` is the immediate children. */
  async listFilesRecursive(path: string = '/tmp', options?: { depth?: number }): Promise<FileEntry[]> {
    const depth = options?.depth ?? 3;
    const out: FileEntry[] = [];
    const walk = async (dir: string, remaining: number): Promise<void> => {
      let entries: FileEntry[];
      try {
        entries = await this.listFiles(dir);
      } catch {
        return;
      }
      const base = dir.replace(/\/+$/, '');
      for (const e of entries) {
        const full = `${base}/${e.name}`;
        out.push({ name: full, kind: e.kind, size: e.size });
        if (e.kind === 'directory' && remaining > 1) {
          await walk(full, remaining - 1);
        }
      }
    };
    await walk(path, depth);
    return out;
  }

  /** Write multiple files in sequence. */
  async writeFiles(
    files: Array<[string, string | Uint8Array]>,
    options?: { mode?: number },
  ): Promise<void> {
    for (const [path, content] of files) {
      const data = typeof content === 'string' ? new TextEncoder().encode(content) : content;
      await this.writeFile(path, data, options);
    }
  }

  // ------------------------------------------------------------------
  // Background and streaming execution
  // ------------------------------------------------------------------

  /** Start a background process and return a {@link ProcessHandle}.
   *
   * Stdout and stderr are redirected to temporary files inside the Sandbox so they can be
   * read incrementally. A string command is passed to the shell as-is (pipes, redirects work);
   * an array is shell-quoted. */
  async executeBackground(
    command: string | string[],
    options?: { cwd?: string; env?: Record<string, string> },
  ): Promise<ProcessHandle> {
    const cmdStr = Array.isArray(command) ? command.map(shQuote).join(' ') : command;
    const tag = randomBytes(4).toString('hex');
    const stdoutPath = `/tmp/.bg_stdout_${tag}`;
    const stderrPath = `/tmp/.bg_stderr_${tag}`;
    const rcPath = `/tmp/.bg_rc_${tag}`;
    // Append the exit-code capture inside the backgrounded shell so wait() can read the real
    // status (the `wait` builtin can't, since each operation is a separate, non-parent shell).
    const inner = `trap 'echo $? > ${rcPath}' EXIT; ${cmdStr}`;
    const result = await this.execute(
      ['sh', '-c', `nohup sh -c ${shQuote(inner)} > ${stdoutPath} 2> ${stderrPath} & echo $!`],
      { cwd: options?.cwd ?? '/tmp', env: options?.env, timeoutSeconds: 10 },
    );
    const pid = Number.parseInt(result.stdout.trim(), 10);
    if (Number.isNaN(pid)) {
      throw new Error(`Failed to start background process, got: ${JSON.stringify(result.stdout)}`);
    }
    return new ProcessHandle({ pid, sandbox: this, stdoutPath, stderrPath, rcPath });
  }

  /** Execute a command with streaming stdout/stderr callbacks.
   *
   * Implemented by redirecting to temp files and tailing them (polling), which delivers
   * incremental chunks and a final {@link CommandResult}. (The Python SDK additionally attempts
   * a WebSocket path; the file-tailing behaviour here matches its fallback.) */
  async executeStream(
    command: string[],
    options?: {
      cwd?: string;
      env?: Record<string, string>;
      timeoutSeconds?: number;
      onStdout?: (chunk: Uint8Array) => void;
      onStderr?: (chunk: Uint8Array) => void;
    },
  ): Promise<CommandResult> {
    const cwd = options?.cwd ?? '/tmp';
    const env = options?.env;
    const timeoutSeconds = options?.timeoutSeconds ?? 60;
    const onStdout = options?.onStdout;
    const onStderr = options?.onStderr;

    const tag = randomBytes(4).toString('hex');
    const stdoutPath = `/tmp/.stream_stdout_${tag}`;
    const stderrPath = `/tmp/.stream_stderr_${tag}`;
    const rcPath = `/tmp/.stream_rc_${tag}`;
    const cmdStr = command.map(shQuote).join(' ');
    const inner = `trap 'echo $? > ${rcPath}' EXIT; ${cmdStr}`;

    const start = await this.execute(
      ['sh', '-c', `nohup sh -c ${shQuote(inner)} > ${stdoutPath} 2> ${stderrPath} & echo $!`],
      { cwd, env, timeoutSeconds: 10 },
    );
    const pid = Number.parseInt(start.stdout.trim(), 10);
    if (Number.isNaN(pid)) {
      throw new Error(`Failed to start streaming process: ${JSON.stringify(start.stdout)}`);
    }

    let stdoutOffset = 0;
    let stderrOffset = 0;
    const deadline = Date.now() + timeoutSeconds * 1000;

    while (Date.now() < deadline) {
      const alive = await this.execute(['kill', '-0', String(pid)], { timeoutSeconds: 5 });
      try {
        const raw = await this.readFile(stdoutPath);
        const chunk = raw.slice(stdoutOffset);
        if (chunk.length > 0 && onStdout) onStdout(chunk);
        stdoutOffset = raw.length;
      } catch { /* not yet readable */ }
      try {
        const raw = await this.readFile(stderrPath);
        const chunk = raw.slice(stderrOffset);
        if (chunk.length > 0 && onStderr) onStderr(chunk);
        stderrOffset = raw.length;
      } catch { /* not yet readable */ }
      if (alive.exitCode !== 0) break;
      await sleep(500);
    }

    const decoder = new TextDecoder('utf-8', { fatal: false });
    let fullStdout = '';
    let fullStderr = '';
    try { fullStdout = decoder.decode(await this.readFile(stdoutPath)); } catch { /* ignore */ }
    try { fullStderr = decoder.decode(await this.readFile(stderrPath)); } catch { /* ignore */ }

    const rc = await this.execute(['cat', rcPath], { timeoutSeconds: 5 });
    const exitCode = rc.exitCode === 0 ? Number.parseInt(rc.stdout.trim(), 10) : -1;

    try { await this.deleteFile(stdoutPath); } catch { /* ignore */ }
    try { await this.deleteFile(stderrPath); } catch { /* ignore */ }
    try { await this.deleteFile(rcPath); } catch { /* ignore */ }

    return {
      exitCode: Number.isNaN(exitCode) ? -1 : exitCode,
      stdout: fullStdout,
      stderr: fullStderr,
    };
  }

  // ------------------------------------------------------------------
  // Metrics, PTY, and file watching
  // ------------------------------------------------------------------

  /** Get the Sandbox's current memory, disk, and load snapshot. */
  async getMetrics(): Promise<Metrics> {
    const result = await this.execute(
      ['sh', '-c', "cat /proc/meminfo | head -3; echo '---'; df /tmp | tail -1; echo '---'; cat /proc/loadavg"],
      { timeoutSeconds: 5 },
    );
    if (result.exitCode !== 0) {
      throw new Error(`metrics collection failed: ${result.stderr}`);
    }
    const sections = result.stdout.split('---');

    let memTotal = 0;
    let memAvailable = 0;
    for (const line of (sections[0] ?? '').trim().split('\n')) {
      if (line.startsWith('MemTotal:')) memTotal = Number.parseInt(line.split(/\s+/)[1] ?? '0', 10);
      else if (line.startsWith('MemAvailable:') || line.startsWith('MemFree:')) memAvailable = Number.parseInt(line.split(/\s+/)[1] ?? '0', 10);
    }

    let diskTotal = '', diskUsed = '', diskAvailable = '';
    const dfParts = (sections[1] ?? '').trim().split(/\s+/);
    if (dfParts.length >= 4) {
      diskTotal = dfParts[1]!;
      diskUsed = dfParts[2]!;
      diskAvailable = dfParts[3]!;
    }

    let load1 = 0, load5 = 0, load15 = 0;
    const loadParts = (sections[2] ?? '').trim().split(/\s+/);
    if (loadParts.length >= 3) {
      load1 = Number.parseFloat(loadParts[0]!);
      load5 = Number.parseFloat(loadParts[1]!);
      load15 = Number.parseFloat(loadParts[2]!);
    }

    return {
      memoryTotalKb: Number.isNaN(memTotal) ? 0 : memTotal,
      memoryAvailableKb: Number.isNaN(memAvailable) ? 0 : memAvailable,
      diskTotal, diskUsed, diskAvailable,
      loadAvg1: Number.isNaN(load1) ? 0 : load1,
      loadAvg5: Number.isNaN(load5) ? 0 : load5,
      loadAvg15: Number.isNaN(load15) ? 0 : load15,
    };
  }

  /** Open a simplified pseudo-terminal session that wraps {@link execute}. */
  openPty(options?: { cols?: number; rows?: number; shell?: string; cwd?: string }): PtySession {
    return new PtySession({
      sandbox: this,
      shell: options?.shell ?? '/bin/bash',
      cwd: options?.cwd ?? '/tmp',
      cols: options?.cols ?? 80,
      rows: options?.rows ?? 24,
    });
  }

  /** Watch a directory for file changes using polling (size as a change proxy).
   *  Returns on the first batch of changes or when the timeout elapses. */
  async watchFiles(
    path: string,
    options?: {
      recursive?: boolean;
      onChange?: (event: FileEvent) => void;
      pollInterval?: number;
      timeout?: number;
    },
  ): Promise<FileEvent[]> {
    const recursive = options?.recursive ?? false;
    const onChange = options?.onChange;
    const pollInterval = options?.pollInterval ?? 1.0;
    const timeout = options?.timeout ?? 60.0;

    const base = path.replace(/\/+$/, '');
    const snapshot = async (): Promise<Map<string, number>> => {
      const files = new Map<string, number>();
      const entries = recursive
        ? await this.listFilesRecursive(path, { depth: 64 })
        : await this.listFiles(path);
      for (const e of entries) {
        if (e.kind !== 'file') continue;
        const full = recursive ? e.name : `${base}/${e.name}`;
        files.set(full, e.size);
      }
      return files;
    };

    const events: FileEvent[] = [];
    let known = await snapshot();
    const deadline = Date.now() + timeout * 1000;

    while (Date.now() < deadline) {
      await sleep(pollInterval * 1000);
      const current = await snapshot();
      for (const [fpath, size] of current) {
        if (!known.has(fpath)) {
          const evt: FileEvent = { path: fpath, eventType: 'created', size };
          events.push(evt);
          onChange?.(evt);
        } else if (known.get(fpath) !== size) {
          const evt: FileEvent = { path: fpath, eventType: 'modified', size };
          events.push(evt);
          onChange?.(evt);
        }
      }
      for (const fpath of known.keys()) {
        if (!current.has(fpath)) {
          const evt: FileEvent = { path: fpath, eventType: 'deleted', size: 0 };
          events.push(evt);
          onChange?.(evt);
        }
      }
      known = current;
      if (events.length > 0) break;
    }
    return events;
  }

  // ------------------------------------------------------------------
  // Protocol transport
  // ------------------------------------------------------------------

  /** Serialise a protocol message, send it, and return the decoded response.
   *  Retries with exponential backoff on 502/503 (transient infrastructure errors).
   */
  async #send(
    messageType: string,
    body: Map<number, unknown>,
    timeoutMs: number = 70_000,
  ): Promise<Map<number, unknown>> {
    const RETRYABLE = new Set([502, 503]);
    const MAX_RETRIES = 3;
    const BASE_DELAY = 1000;
    const MAX_DELAY = 10_000;

    const requestId = randomBytes(16);

    // Build the deterministic envelope — keys must be ascending integers.
    const envelope = new Map<number, unknown>([
      [KEY_VERSION, PROTOCOL_VERSION],
      [KEY_TYPE, messageType],
      [KEY_ID, requestId],
      [KEY_BODY, body],
    ]);

    const wire = encode(envelope);
    const url = this.#baseUrl.replace(/\/+$/, '') + '/protocol';
    let lastError: SandboxProtocolError | null = null;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          [this.#authHeaderName]: this.#authHeaderValue,
          'Content-Type': 'application/cbor',
        },
        body: wire,
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!RETRYABLE.has(resp.status)) {
        if (!resp.ok) {
          throw new SandboxProtocolError(resp.status, resp.statusText);
        }
        const responseBytes = new Uint8Array(await resp.arrayBuffer());
        return decode(responseBytes) as Map<number, unknown>;
      }

      // Retryable error
      lastError = new SandboxProtocolError(resp.status, resp.statusText);

      if (attempt < MAX_RETRIES) {
        const delay = Math.min(
          BASE_DELAY * 2 ** attempt + Math.random() * 1000,
          MAX_DELAY,
        );
        await new Promise((r) => setTimeout(r, delay));
      }
    }

    throw lastError!;
  }
}
