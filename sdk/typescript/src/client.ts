// kiro-classification: public
/**
 * SandboxClient — the main entry point for the TypeScript Client SDK.
 *
 * @example
 * ```typescript
 * import { SandboxClient } from '@agent-sandbox/sdk';
 *
 * // Bearer token auth (multi-tenant deployments)
 * const client = new SandboxClient({
 *   apiUrl: 'https://xxx.execute-api.us-east-1.amazonaws.com',
 *   region: 'us-east-1',
 *   token: 'demo-token-tenant-a',
 * });
 *
 * // Create a session and wait for the sandbox
 * const session = await client.createSession({ maxDurationSeconds: 3600 });
 * await session.waitReady({ timeout: 120_000 });
 *
 * // Execute commands
 * const result = await session.execute('echo hello world');
 * console.log(result.stdout); // "hello world\n"
 *
 * // Automatic cleanup with using
 * await using session2 = await client.createSession();
 * await session2.waitReady();
 * await session2.execute('echo managed');
 * // Session terminated automatically
 * ```
 */

import type { Auth } from './auth.js';
import { BearerAuth, SigV4Auth } from './auth.js';
import { SandboxSession, type SessionData } from './session.js';

/** Options for constructing a {@link SandboxClient}. */
export interface SandboxClientOptions {
  /** The root URL of the deployed Control Plane HTTP API. */
  apiUrl: string;
  /** The AWS Region the API is deployed in. */
  region: string;
  /**
   * Optional bearer token for multi-tenant deployments. When set, requests
   * use `Authorization: Bearer <token>` instead of SigV4.
   */
  token?: string;
}

/** Options for creating a new session. */
export interface CreateSessionOptions {
  /** Maximum session duration in seconds (1–28800, default: 3600). */
  maxDurationSeconds?: number;
  /** Seconds of inactivity before auto-suspend (default: 300). */
  idleSeconds?: number;
  /** Maximum seconds in suspended state (default: 600). */
  suspendedSeconds?: number;
  /** Whether to auto-resume on request to a suspended sandbox (default: true). */
  autoResume?: boolean;
  /**
   * Mount an S3 Files workspace at `/mnt/workspace` inside the sandbox.
   * Files sync bidirectionally to S3 and persist across suspend/resume.
   * Default: false (ephemeral /tmp only).
   */
  persistence?: boolean;
  /**
   * Share a workspace across sessions. Sessions with the same (tenant, affinityKey)
   * see the same /mnt/workspace contents. Requires persistence=true.
   */
  affinityKey?: string;
}

/** Options for resolving a session by affinity key. */
export interface ResolveSessionOptions extends CreateSessionOptions {
  /** A caller-supplied stable identifier (e.g. conversation ID). */
  affinityKey: string;
}

/**
 * Client for the AWS Serverless Agent Sandbox.
 *
 * Creates and manages sandbox sessions. Each session wraps a Lambda MicroVM
 * with command execution and file operations.
 */
export class SandboxClient {
  readonly #apiUrl: string;
  readonly #region: string;
  readonly #auth: Auth;

  constructor(options: SandboxClientOptions) {
    this.#apiUrl = options.apiUrl;
    this.#region = options.region;
    this.#auth =
      options.token !== undefined
        ? new BearerAuth(options.token)
        : new SigV4Auth(options.region);
  }

  // ------------------------------------------------------------------
  // Session management
  // ------------------------------------------------------------------

  /**
   * Create a new sandbox session.
   *
   * The session is created asynchronously. Call {@link SandboxSession.waitReady}
   * to block until the sandbox is reachable.
   */
  async createSession(options?: CreateSessionOptions): Promise<SandboxSession> {
    const body = {
      maxDurationSeconds: options?.maxDurationSeconds ?? 3600,
      ...(options?.persistence ? { persistence: true } : {}),
      ...(options?.affinityKey ? { affinityKey: options.affinityKey } : {}),
      idleSeconds: options?.idleSeconds ?? 300,
      suspendedSeconds: options?.suspendedSeconds ?? 600,
      autoResume: options?.autoResume ?? true,
    };
    const data = await this.#cpRequest('POST', '/sessions', body);
    const sessionId = (data.sessionId as string) ?? '';
    return new SandboxSession({
      sessionId,
      apiUrl: this.#apiUrl,
      auth: this.#auth,
      sessionData: data,
    });
  }

  /**
   * Get or create a session by affinity key.
   *
   * If a session already exists for this affinity key, it is returned.
   * Otherwise a new session is created and bound to the key.
   */
  async resolveSession(options: ResolveSessionOptions): Promise<SandboxSession> {
    const body = {
      affinityKey: options.affinityKey,
      maxDurationSeconds: options.maxDurationSeconds ?? 3600,
      idleSeconds: options.idleSeconds ?? 300,
      suspendedSeconds: options.suspendedSeconds ?? 600,
      autoResume: options.autoResume ?? true,
    };
    const data = await this.#cpRequest('POST', '/sessions/resolve', body);
    const sessionId = (data.sessionId as string) ?? '';
    return new SandboxSession({
      sessionId,
      apiUrl: this.#apiUrl,
      auth: this.#auth,
      sessionData: data,
    });
  }

  /**
   * Get an existing session by its ID.
   */
  async getSession(sessionId: string): Promise<SandboxSession> {
    const data = await this.#cpRequest('GET', `/sessions/${sessionId}`);
    return new SandboxSession({
      sessionId,
      apiUrl: this.#apiUrl,
      auth: this.#auth,
      sessionData: data,
    });
  }

  /**
   * List sessions in the caller's tenant partition.
   */
  async listSessions(): Promise<SessionData[]> {
    const data = await this.#cpRequest('GET', '/sessions');
    const sessions = data.sessions;
    if (Array.isArray(sessions)) {
      return sessions as SessionData[];
    }
    // Single-item fallback (same as Python SDK)
    if (data.sessionId !== undefined) {
      return [data];
    }
    return [];
  }

  // ------------------------------------------------------------------
  // Internal
  // ------------------------------------------------------------------

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
