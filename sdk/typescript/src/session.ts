// kiro-classification: public
/**
 * SandboxSession — represents one sandbox session with lifecycle and sandbox operations.
 *
 * A session wraps the Control Plane session record and, once the sandbox is ready,
 * provides command execution and file operations over the Sandbox Protocol.
 */

import type { Auth } from './auth.js';
import {
  SandboxConnection,
  SandboxProtocolError,
  ProcessHandle,
  PtySession,
  type CommandResult,
  type FileEntry,
  type FileInfo,
  type Metrics,
  type FileEvent,
  type ConnectionDescriptor,
} from './sandbox.js';
import { GitOperations } from './git.js';

export type { CommandResult, FileEntry, FileInfo, Metrics, FileEvent };
export { ProcessHandle, PtySession };

/** Default polling interval when waiting for a sandbox to become ready (ms). */
const POLL_INTERVAL_MS = 2_000;

/**
 * Default readiness probe schedule (ms between attempts). Chosen from measured time-to-serve
 * (~2-4s warm, ~11s cold): tight early to catch the common warm start without overshoot,
 * backing off to 5s for cold. The last value repeats. Pass a number for a flat interval, or
 * your own array if you know your workload's timing.
 */
const DEFAULT_POLL_SCHEDULE_MS: number[] = [1_000, 2_000, 3_000, 5_000];

/** Session record shape returned by the Control Plane. */
export interface SessionData {
  sessionId?: string;
  lifecycleState?: string;
  connection?: ConnectionDescriptor;
  [key: string]: unknown;
}

/** Options for constructing a {@link SandboxSession}. */
export interface SandboxSessionOptions {
  sessionId: string;
  apiUrl: string;
  auth: Auth;
  sessionData?: SessionData;
  /** Whether to auto-resume on 502/503 from a suspended sandbox. */
  autoResume?: boolean;
}

/**
 * A single sandbox session with lifecycle and sandbox operations.
 *
 * Typically created via {@link SandboxClient.createSession} rather than directly.
 */
export class SandboxSession {
  readonly #sessionId: string;
  readonly #apiUrl: string;
  readonly #auth: Auth;
  readonly #autoResume: boolean;
  #sessionData: SessionData;
  #sandbox: SandboxConnection | null = null;

  constructor(options: SandboxSessionOptions) {
    this.#sessionId = options.sessionId;
    this.#apiUrl = options.apiUrl;
    this.#auth = options.auth;
    this.#autoResume = options.autoResume ?? false;
    this.#sessionData = options.sessionData ?? {};
  }

  // ------------------------------------------------------------------
  // Properties
  // ------------------------------------------------------------------

  /** The session identifier. */
  get sessionId(): string {
    return this.#sessionId;
  }

  /** The current lifecycle state (e.g. `RUNNING`, `SUSPENDED`). */
  get lifecycleState(): string {
    return this.#sessionData.lifecycleState ?? 'UNKNOWN';
  }

  /** The connection descriptor, or `undefined` if the sandbox isn't ready yet. */
  get connection(): ConnectionDescriptor | undefined {
    return this.#sessionData.connection ?? undefined;
  }

  /** Whether the sandbox has a connection descriptor (i.e. is reachable). */
  get isReady(): boolean {
    return this.connection !== undefined;
  }

  /** The full session data record. */
  get sessionData(): SessionData {
    return { ...this.#sessionData };
  }

  // ------------------------------------------------------------------
  // Lifecycle operations (Control Plane)
  // ------------------------------------------------------------------

  /** Fetch the latest session state from the Control Plane. */
  async refresh(): Promise<void> {
    this.#sessionData = await this.#cpRequest(
      'GET',
      `/sessions/${this.#sessionId}`,
    );
  }

  /**
   * Block until the sandbox has a connection descriptor.
   *
   * @param options.timeout - Maximum milliseconds to wait (default: 120_000).
   * @param options.pollInterval - Milliseconds between polls (default: 2_000).
   *
   * @throws {Error} If the sandbox is not ready within the timeout.
   * @throws {Error} If the session enters a terminal state (`TERMINATED` or `FAILED`).
   */
  async waitReady(options?: {
    timeout?: number;
    pollInterval?: number | number[];
  }): Promise<void> {
    const timeout = options?.timeout ?? 120_000;
    const scheduleOpt = options?.pollInterval ?? DEFAULT_POLL_SCHEDULE_MS;
    const schedule =
      typeof scheduleOpt === 'number'
        ? [scheduleOpt]
        : scheduleOpt.length > 0
          ? scheduleOpt
          : [POLL_INTERVAL_MS];
    const intervalAt = (n: number): number =>
      schedule[Math.min(n, schedule.length - 1)] ?? POLL_INTERVAL_MS;
    const deadline = Date.now() + timeout;
    const remaining = (): number => deadline - Date.now();
    const raiseIfTerminal = (): void => {
      const state = this.lifecycleState;
      if (state === 'TERMINATED' || state === 'FAILED') {
        const reason = (this.#sessionData['stateReason'] as string | undefined) ?? '';
        throw new Error(
          `Session ${this.#sessionId} entered terminal state '${state}' while starting` +
            (reason ? `: ${reason}` : '') +
            '.',
        );
      }
    };

    // Phase 1: wait for a connection descriptor to appear. It is published early (while the
    // sandbox is still starting), so its presence no longer means the endpoint serves.
    let phase1 = 0;
    while (!this.isReady) {
      raiseIfTerminal();
      if (remaining() <= 0) {
        throw new Error(
          `Session ${this.#sessionId} had no connection descriptor within ${timeout}ms. ` +
            `Last state: ${this.lifecycleState}`,
        );
      }
      await sleep(Math.min(intervalAt(phase1), Math.max(0, remaining())));
      phase1 += 1;
      await this.refresh();
    }

    // Phase 2: probe the endpoint directly until it accepts a request. The Lambda MicroVM
    // platform does not forward traffic to the sandbox until its /run hook (which performs the
    // in-guest hardening) has returned 200, so a probe that succeeds means the sandbox is both
    // hardened and serving. Only then does this resolve, so caller code never touches a
    // non-serving endpoint.
    let probes = 0;
    let lastError: unknown;
    while (remaining() > 0) {
      try {
        await this.#getSandbox().execute(['test', '-e', '/'], { timeoutSeconds: 5 });
        return; // the endpoint served a request: hardened and ready
      } catch (err) {
        lastError = err;
        probes += 1;
        // Every few failed probes, confirm the session did not fail, so a genuine startup
        // failure surfaces as a clear error rather than a blind timeout.
        if (probes % 3 === 0) {
          try {
            await this.refresh();
          } catch {
            // transient control-plane read; keep probing
          }
          raiseIfTerminal();
        }
        if (remaining() <= 0) break;
        await sleep(Math.min(intervalAt(probes - 1), Math.max(0, remaining())));
      }
    }

    throw new Error(
      `Sandbox for session ${this.#sessionId} did not start serving within ${timeout}ms ` +
        `(last probe error: ${String(lastError)}).`,
    );
  }

  /** Suspend the session, preserving memory and disk state. */
  async suspend(): Promise<SessionData> {
    const result = await this.#cpRequest(
      'POST',
      `/sessions/${this.#sessionId}/suspend`,
    );
    Object.assign(this.#sessionData, result);
    return result;
  }

  /** Resume a suspended session. */
  async resume(): Promise<SessionData> {
    const result = await this.#cpRequest(
      'POST',
      `/sessions/${this.#sessionId}/resume`,
    );
    Object.assign(this.#sessionData, result);
    this.#sandbox = null; // connection descriptor may have changed
    return result;
  }

  /** Terminate the session and release all resources. */
  async terminate(): Promise<SessionData> {
    const result = await this.#cpRequest(
      'POST',
      `/sessions/${this.#sessionId}/terminate`,
    );
    Object.assign(this.#sessionData, result);
    this.#sandbox = null;
    return result;
  }

  /** Refresh the connection credential (e.g. after resume). */
  async refreshConnection(): Promise<SessionData> {
    const result = await this.#cpRequest(
      'POST',
      `/sessions/${this.#sessionId}/connection`,
    );
    Object.assign(this.#sessionData, result);
    this.#sandbox = null; // force re-creation with new credential
    return result;
  }

  // ------------------------------------------------------------------
  // Sandbox operations
  // ------------------------------------------------------------------

  /**
   * Execute a command inside the sandbox.
   *
   * @param command - A shell command string (run via `sh -c`) or a list of arguments.
   * @param options - Working directory, environment, and timeout.
   */
  async execute(
    command: string | string[],
    options?: {
      cwd?: string;
      env?: Record<string, string>;
      timeoutSeconds?: number;
    },
  ): Promise<CommandResult> {
    const argv =
      typeof command === 'string' ? ['sh', '-c', command] : command;
    return this.#sandboxRequest(() => this.#getSandbox().execute(argv, options));
  }

  /**
   * Write a file inside the sandbox.
   *
   * @param path - Absolute path inside the Sandbox.
   * @param content - File content as a string (UTF-8 encoded) or bytes.
   * @param options - POSIX permission bits (default: 0o644).
   */
  async writeFile(
    path: string,
    content: string | Uint8Array,
    options?: { mode?: number },
  ): Promise<void> {
    const data =
      typeof content === 'string'
        ? new TextEncoder().encode(content)
        : content;
    return this.#sandboxRequest(() => this.#getSandbox().writeFile(path, data, options));
  }

  /**
   * Read a file from the sandbox as a string.
   *
   * @param path - Absolute path inside the Sandbox.
   */
  async readFile(path: string): Promise<string> {
    return this.#sandboxRequest(async () => {
      const bytes = await this.#getSandbox().readFile(path);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    });
  }

  /**
   * Read a file from the sandbox as raw bytes.
   *
   * @param path - Absolute path inside the Sandbox.
   */
  async readFileBytes(path: string): Promise<Uint8Array> {
    return this.#sandboxRequest(() => this.#getSandbox().readFile(path));
  }

  /**
   * List files and directories at the given path.
   *
   * @param path - Directory path inside the Sandbox (default: `/tmp`).
   */
  async listFiles(path: string = '/tmp'): Promise<FileEntry[]> {
    return this.#sandboxRequest(() => this.#getSandbox().listFiles(path));
  }

  /**
   * Delete a file or directory from the sandbox.
   *
   * @param path - Absolute path inside the Sandbox.
   * @param options - If `recursive` is true, delete directories recursively.
   */
  async deleteFile(
    path: string,
    options?: { recursive?: boolean },
  ): Promise<void> {
    return this.#sandboxRequest(() => this.#getSandbox().deleteFile(path, options));
  }


  // ------------------------------------------------------------------
  // Workspace upload (via pre-signed S3 URL)
  // ------------------------------------------------------------------

  /**
   * Upload a file to the session's persistent workspace via S3.
   *
   * The file appears at `/mnt/workspace/{remotePath}` inside the sandbox.
   * This method requests a pre-signed S3 PUT URL from the Control Plane,
   * then uploads directly to S3 — the file never passes through API Gateway,
   * so there is no payload size limit beyond S3's 5 GB single-PUT maximum.
   *
   * Requires `persistence: true` on the session.
   *
   * @param remotePath - Path relative to `/mnt/workspace/` (e.g. `"docs/contract.pdf"`).
   * @param data - File content as a string (UTF-8 encoded) or Uint8Array.
   */
  async uploadFile(remotePath: string, data: string | Uint8Array): Promise<void> {
    const bytes = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;

    // Step 1: get pre-signed URL from the Control Plane
    const resp = await this.#cpRequest(
      'POST',
      `/sessions/${this.#sessionId}/upload-url`,
      { filename: remotePath },
    );
    const uploadUrl = resp.uploadUrl as string;
    if (!uploadUrl) {
      throw new Error('Control Plane did not return an uploadUrl');
    }

    // Step 2: upload directly to S3 (bypasses API Gateway entirely)
    const putResp = await fetch(uploadUrl, {
      method: 'PUT',
      body: bytes,
    });
    if (!putResp.ok) {
      throw new Error(
        `S3 upload failed: ${putResp.status} ${putResp.statusText}`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Filesystem helpers
  // ------------------------------------------------------------------

  /** Check if a file or directory exists inside the sandbox. */
  async fileExists(path: string): Promise<boolean> {
    return this.#sandboxRequest(() => this.#getSandbox().fileExists(path));
  }

  /** Get metadata (size, mtime, permissions, type) about a file or directory. */
  async fileInfo(path: string): Promise<FileInfo> {
    return this.#sandboxRequest(() => this.#getSandbox().fileInfo(path));
  }

  /** Create a directory inside the sandbox (with parents by default). */
  async makeDir(path: string, options?: { parents?: boolean }): Promise<void> {
    return this.#sandboxRequest(() => this.#getSandbox().makeDir(path, options));
  }

  /** Rename or move a file or directory inside the sandbox. */
  async renameFile(oldPath: string, newPath: string): Promise<void> {
    return this.#sandboxRequest(() => this.#getSandbox().renameFile(oldPath, newPath));
  }

  /** List files recursively to a given depth (default: 3). */
  async listFilesRecursive(path: string = '/tmp', options?: { depth?: number }): Promise<FileEntry[]> {
    return this.#sandboxRequest(() => this.#getSandbox().listFilesRecursive(path, options));
  }

  /** Write multiple files in sequence. */
  async writeFiles(
    files: Array<[string, string | Uint8Array]>,
    options?: { mode?: number },
  ): Promise<void> {
    return this.#sandboxRequest(() => this.#getSandbox().writeFiles(files, options));
  }

  // ------------------------------------------------------------------
  // Background and streaming execution
  // ------------------------------------------------------------------

  /** Start a background process and return a {@link ProcessHandle}. */
  async executeBackground(
    command: string | string[],
    options?: { cwd?: string; env?: Record<string, string> },
  ): Promise<ProcessHandle> {
    return this.#sandboxRequest(() => this.#getSandbox().executeBackground(command, options));
  }

  /** Execute a command with streaming stdout/stderr callbacks. A string command is run via
   *  the shell (pipes, redirects work); an array is passed as argv. */
  async executeStream(
    command: string | string[],
    options?: {
      cwd?: string;
      env?: Record<string, string>;
      timeoutSeconds?: number;
      onStdout?: (chunk: Uint8Array) => void;
      onStderr?: (chunk: Uint8Array) => void;
    },
  ): Promise<CommandResult> {
    const argv = typeof command === 'string' ? ['sh', '-c', command] : command;
    return this.#sandboxRequest(() => this.#getSandbox().executeStream(argv, options));
  }

  // ------------------------------------------------------------------
  // Metrics, PTY, and file watching
  // ------------------------------------------------------------------

  /** Get the sandbox's current memory, disk, and load snapshot. */
  async getMetrics(): Promise<Metrics> {
    return this.#sandboxRequest(() => this.#getSandbox().getMetrics());
  }

  /** Open a simplified pseudo-terminal session that wraps {@link execute}. */
  openPty(options?: { cols?: number; rows?: number; shell?: string; cwd?: string }): PtySession {
    return this.#getSandbox().openPty(options);
  }

  /** Watch a directory for file changes using polling. Returns on the first batch of changes
   *  or when the timeout elapses. */
  async watchFiles(
    path: string,
    options?: {
      recursive?: boolean;
      onChange?: (event: FileEvent) => void;
      pollInterval?: number;
      timeout?: number;
    },
  ): Promise<FileEvent[]> {
    return this.#getSandbox().watchFiles(path, options);
  }

  // ------------------------------------------------------------------
  // Git operations
  // ------------------------------------------------------------------

  /** Git operations wrapper for this sandbox. */
  get git(): GitOperations {
    return new GitOperations(this.#getSandbox());
  }

  // ------------------------------------------------------------------
  // Async disposable — automatic cleanup
  // ------------------------------------------------------------------

  async [Symbol.asyncDispose](): Promise<void> {
    try {
      await this.terminate();
    } catch {
      // Best-effort cleanup; don't mask the original exception.
    }
  }

  // ------------------------------------------------------------------
  // Internal helpers
  // ------------------------------------------------------------------


  /**
   * Call a sandbox operation, auto-resuming on 502/503 if suspended.
   *
   * When auto_resume is enabled and the MicroVM returns 502 or 503, the SDK
   * checks the session state. If SUSPENDED, it resumes, waits for ready,
   * refreshes the connection, and retries the operation once.
   */
  async #sandboxRequest<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (err) {
      if (!this.#autoResume) throw err;
      if (!(err instanceof SandboxProtocolError)) throw err;
      if (err.status !== 502 && err.status !== 503) throw err;
      // Check session state via control plane.
      await this.refresh();
      if (this.lifecycleState !== 'SUSPENDED') throw err;
      // Resume and retry.
      await this.resume();
      await this.waitReady({ timeout: 60_000 });
      await this.refreshConnection();
      return operation();
    }
  }

  /** Return the sandbox connection, creating it lazily from the connection descriptor. */
  #getSandbox(): SandboxConnection {
    if (this.#sandbox !== null) {
      return this.#sandbox;
    }

    const conn = this.connection;
    if (conn === undefined) {
      throw new Error(
        `Session ${this.#sessionId} has no connection descriptor. ` +
          'Call waitReady() first, or check isReady.',
      );
    }

    this.#sandbox = SandboxConnection.fromConnectionDescriptor(conn);
    return this.#sandbox;
  }

  /**
   * Send an authenticated request to the Control Plane API.
   * Retries with exponential backoff on 429, 502, and 503.
   */
  async #cpRequest(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<SessionData> {
    const url =
      this.#apiUrl.replace(/\/+$/, '') + '/' + path.replace(/^\/+/, '');
    const data = body !== undefined ? JSON.stringify(body) : undefined;
    const bodyBytes =
      data !== undefined ? new TextEncoder().encode(data) : undefined;

    const RETRYABLE = new Set([429, 502, 503]);
    const MAX_RETRIES = 5;
    const BASE_DELAY = 1000;
    const MAX_DELAY = 30000;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      let headers: Record<string, string> = {};
      if (data !== undefined) {
        headers['Content-Type'] = 'application/json';
      }
      headers = await this.#auth.apply(method, url, headers, bodyBytes);
      const resp = await fetch(url, {
        method,
        headers,
        body: data,
      });

      if (!RETRYABLE.has(resp.status)) {
        if (!resp.ok) {
          throw new Error(
            `Control Plane request failed: ${method} ${path} → ${resp.status} ${resp.statusText}`,
          );
        }
        return (await resp.json()) as SessionData;
      }

      // Retryable error
      lastError = new Error(
        `Control Plane request failed: ${method} ${path} → ${resp.status} ${resp.statusText}`,
      );

      if (attempt < MAX_RETRIES) {
        const delay = Math.min(BASE_DELAY * 2 ** attempt + Math.random() * 1000, MAX_DELAY);
        await new Promise((r) => setTimeout(r, delay));
      }
    }

    throw lastError!;
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
