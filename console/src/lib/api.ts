// API client for the AWS Serverless Agent Sandbox Control Plane
// Supports both SigV4 (single-tenant) and bearer token (multi-tenant) auth

export interface SandboxConfig {
  apiUrl: string;
  region: string;
  token?: string; // bearer token for multi-tenant
  egressTable?: string; // DynamoDB table name for egress policy
}

export interface SessionSummary {
  sessionId: string;
  lifecycleState: string;
  tenantId?: string;
  createdAt?: number;
  updatedAt?: number;
  connection?: {
    baseUrl: string;
    authHeaderName: string;
    authHeaderValue: string;
  };
}

// Store config in localStorage
export function getConfig(): SandboxConfig | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem("sandbox-config");
  return raw ? JSON.parse(raw) : null;
}

export function setConfig(config: SandboxConfig) {
  localStorage.setItem("sandbox-config", JSON.stringify(config));
}

// API calls routed through the Next.js API proxy to avoid CORS.
// Instead of calling config.apiUrl directly (which triggers CORS from localhost),
// we call /api/proxy/... (same origin) and the server-side route forwards to the API Gateway.
export async function apiRequest(
  method: string,
  path: string,
  body?: Record<string, unknown>
): Promise<Response> {
  const config = getConfig();
  if (!config) throw new Error("Not configured");

  // Route through the Next.js API proxy to avoid CORS
  const proxyUrl = `/api/proxy/${path.replace(/^\/+/, "")}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-api-url": config.apiUrl,
    "x-api-region": config.region || "us-east-1",
  };
  if (config.token) {
    headers["x-api-token"] = config.token;
  }
  // If no token, proxy will use SigV4 with local AWS credentials

  return fetch(proxyUrl, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function createSession(opts?: {
  maxDurationSeconds?: number;
  idleSeconds?: number;
  suspendedSeconds?: number;
  autoResume?: boolean;
  persistence?: boolean;
  affinityKey?: string;
}): Promise<SessionSummary> {
  const body: Record<string, unknown> = {
    maxDurationSeconds: opts?.maxDurationSeconds ?? 3600,
    idleSeconds: opts?.idleSeconds ?? 300,
    suspendedSeconds: opts?.suspendedSeconds ?? 600,
    autoResume: opts?.autoResume ?? true,
  };
  if (opts?.persistence) body.persistence = true;
  if (opts?.affinityKey) body.affinityKey = opts.affinityKey;
  const resp = await apiRequest("POST", "/sessions", body);
  return resp.json();
}

export async function getSession(sessionId: string): Promise<SessionSummary> {
  const resp = await apiRequest("GET", `/sessions/${sessionId}`);
  return resp.json();
}

export async function listSessions(): Promise<{ sessions: SessionSummary[] }> {
  const resp = await apiRequest("GET", "/sessions");
  return resp.json();
}

export async function suspendSession(sessionId: string) {
  return apiRequest("POST", `/sessions/${sessionId}/suspend`);
}

export async function resumeSession(sessionId: string) {
  return apiRequest("POST", `/sessions/${sessionId}/resume`);
}

export async function terminateSession(sessionId: string) {
  return apiRequest("POST", `/sessions/${sessionId}/terminate`);
}


// --- Sandbox operations (command execution, file I/O) ---
// These go through /api/sandbox proxy which handles CBOR serialization server-side.

export async function executeCommand(
  connection: SessionSummary["connection"],
  command: string,
  cwd: string = "/tmp"
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  if (!connection) throw new Error("No connection");

  const resp = await fetch("/api/sandbox", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      baseUrl: connection.baseUrl,
      authHeaderName: connection.authHeaderName,
      authHeaderValue: connection.authHeaderValue,
      action: "execute",
      command,
      cwd,
    }),
  });
  return resp.json();
}

export async function readSandboxFile(
  connection: SessionSummary["connection"],
  path: string
): Promise<string> {
  if (!connection) throw new Error("No connection");

  const resp = await fetch("/api/sandbox", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      baseUrl: connection.baseUrl,
      authHeaderName: connection.authHeaderName,
      authHeaderValue: connection.authHeaderValue,
      action: "read_file",
      path,
    }),
  });
  const data = await resp.json();
  return data.content;
}

export async function writeSandboxFile(
  connection: SessionSummary["connection"],
  path: string,
  content: string
): Promise<void> {
  if (!connection) throw new Error("No connection");

  await fetch("/api/sandbox", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      baseUrl: connection.baseUrl,
      authHeaderName: connection.authHeaderName,
      authHeaderValue: connection.authHeaderValue,
      action: "write_file",
      path,
      content,
    }),
  });
}

export async function listSandboxFiles(
  connection: SessionSummary["connection"],
  path: string = "/tmp"
): Promise<Array<{ name: string; kind: string; size: number }>> {
  if (!connection) throw new Error("No connection");

  const resp = await fetch("/api/sandbox", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      baseUrl: connection.baseUrl,
      authHeaderName: connection.authHeaderName,
      authHeaderValue: connection.authHeaderValue,
      action: "list_files",
      path,
    }),
  });
  const data = await resp.json();
  return data.files;
}
