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
  type CommandResult,
  type FileEntry,
  type ConnectionDescriptor,
} from './sandbox.js';

export type { CommandResult, FileEntry };

/** Default polling interval when waiting for a sandbox to become ready (ms). */
const POLL_INTERVAL_MS = 2_000;

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
  #sessionData: SessionData;
  #sandbox: SandboxConnection | null = null;

  constructor(options: SandboxSessionOptions) {
    this.#sessionId = options.sessionId;
    this.#apiUrl = options.apiUrl;
    this.#auth = options.auth;
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
    pollInterval?: number;
  }): Promise<void> {
    const timeout = options?.timeout ?? 120_000;
    const pollInterval = options?.pollInterval ?? POLL_INTERVAL_MS;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      await this.refresh();
      if (this.isReady) {
        return;
      }
      const state = this.lifecycleState;
      if (state === 'TERMINATED' || state === 'FAILED') {
        throw new Error(
          `Session ${this.#sessionId} entered terminal state '${state}' ` +
            'while waiting for the sandbox to become ready.',
        );
      }
      await sleep(pollInterval);
    }

    throw new Error(
      `Sandbox for session ${this.#sessionId} was not ready within ${timeout}ms. ` +
        `Last state: ${this.lifecycleState}`,
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
    const sandbox = this.#getSandbox();
    const argv =
      typeof command === 'string' ? ['sh', '-c', command] : command;
    return sandbox.execute(argv, options);
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
    const sandbox = this.#getSandbox();
    const data =
      typeof content === 'string'
        ? new TextEncoder().encode(content)
        : content;
    return sandbox.writeFile(path, data, options);
  }

  /**
   * Read a file from the sandbox as a string.
   *
   * @param path - Absolute path inside the Sandbox.
   */
  async readFile(path: string): Promise<string> {
    const sandbox = this.#getSandbox();
    const bytes = await sandbox.readFile(path);
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  /**
   * Read a file from the sandbox as raw bytes.
   *
   * @param path - Absolute path inside the Sandbox.
   */
  async readFileBytes(path: string): Promise<Uint8Array> {
    const sandbox = this.#getSandbox();
    return sandbox.readFile(path);
  }

  /**
   * List files and directories at the given path.
   *
   * @param path - Directory path inside the Sandbox (default: `/tmp`).
   */
  async listFiles(path: string = '/tmp'): Promise<FileEntry[]> {
    const sandbox = this.#getSandbox();
    return sandbox.listFiles(path);
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
    const sandbox = this.#getSandbox();
    return sandbox.deleteFile(path, options);
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

  /** Send an authenticated request to the Control Plane API. */
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

    if (!resp.ok) {
      throw new Error(
        `Control Plane request failed: ${method} ${path} → ${resp.status} ${resp.statusText}`,
      );
    }

    return (await resp.json()) as SessionData;
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
