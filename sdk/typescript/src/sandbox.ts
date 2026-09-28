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
  // Protocol transport
  // ------------------------------------------------------------------

  /** Serialise a protocol message, send it, and return the decoded response. */
  async #send(
    messageType: string,
    body: Map<number, unknown>,
    timeoutMs: number = 70_000,
  ): Promise<Map<number, unknown>> {
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

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        [this.#authHeaderName]: this.#authHeaderValue,
        'Content-Type': 'application/cbor',
      },
      body: wire,
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) {
      throw new Error(
        `Sandbox protocol request failed: ${resp.status} ${resp.statusText}`,
      );
    }

    const responseBytes = new Uint8Array(await resp.arrayBuffer());
    return decode(responseBytes) as Map<number, unknown>;
  }
}
