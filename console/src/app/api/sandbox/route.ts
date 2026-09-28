import { NextRequest, NextResponse } from "next/server";
import { encode as cborgEncode } from "cborg";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { baseUrl, authHeaderName, authHeaderValue, action, ...params } = body;

  if (!baseUrl || !authHeaderName || !authHeaderValue) {
    return NextResponse.json({ error: "Missing connection info" }, { status: 400 });
  }

  // PCSR Finding 8: constrain baseUrl to Lambda MicroVM endpoints only.
  // Reject private-range, link-local, and non-Lambda targets to prevent SSRF.
  try {
    const parsed = new URL(baseUrl);
    if (!parsed.hostname.endsWith(".on.aws") && !parsed.hostname.endsWith(".amazonaws.com")) {
      return NextResponse.json({ error: "baseUrl must be a Lambda MicroVM or API Gateway endpoint" }, { status: 400 });
    }
    if (parsed.protocol !== "https:") {
      return NextResponse.json({ error: "baseUrl must use HTTPS" }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: "Invalid baseUrl" }, { status: 400 });
  }

  try {
    // Use cborg for encoding (produces deterministic CBOR without tags)
    // Use cbor-x for decoding responses (handles any valid CBOR)
    const { decode } = await import("cbor-x");

    const te = new TextEncoder();
    const requestId = crypto.getRandomValues(new Uint8Array(16));

    let cborBody: Map<number, unknown>;
    let messageType: string;

    if (action === "execute") {
      messageType = "exec.request";
      const argv = ["sh", "-c", params.command];
      cborBody = new Map<number, unknown>([
        [1, argv.map((a: string) => te.encode(a))],
        [2, te.encode(params.cwd || "/tmp")],
        [3, new Map()],
        [4, 60000],
        [5, false],
      ]);
    } else if (action === "read_file") {
      messageType = "fs.read";
      cborBody = new Map<number, unknown>([
        [1, te.encode(params.path)],
      ]);
    } else if (action === "write_file") {
      messageType = "fs.write";
      cborBody = new Map<number, unknown>([
        [1, te.encode(params.path)],
        [2, te.encode(params.content)],
        [3, 0o644],
      ]);
    } else if (action === "list_files") {
      messageType = "fs.list";
      cborBody = new Map<number, unknown>([
        [1, te.encode(params.path || "/tmp")],
      ]);
    } else {
      return NextResponse.json({ error: `Unknown action: ${action}` }, { status: 400 });
    }

    const envelope = new Map<number, unknown>([
      [1, 1],
      [2, messageType],
      [3, requestId],
      [4, cborBody],
    ]);

    // cborg.encode() produces deterministic CBOR — no tags, canonical key ordering
    const wire = cborgEncode(envelope);
    const url = `${baseUrl.replace(/\/+$/, "")}/protocol`;

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        [authHeaderName]: authHeaderValue,
        "Content-Type": "application/cbor",
      },
      body: wire,
    });

    if (!resp.ok) {
      const text = await resp.text();
      return NextResponse.json(
        { error: `Sandbox error: ${resp.status} ${text}` },
        { status: resp.status }
      );
    }

    const responseBytes = new Uint8Array(await resp.arrayBuffer());
    const decoded = decode(responseBytes);

    // Extract the body (key 4 in the envelope)
    const respBody = extractField(decoded, 4);

    if (action === "execute") {
      const exitCode = extractField(respBody, 1);
      const stdoutRaw = extractField(respBody, 2);
      const stderrRaw = extractField(respBody, 3);

      return NextResponse.json({
        exitCode: typeof exitCode === "number" ? exitCode : 0,
        stdout: bytesToString(stdoutRaw),
        stderr: bytesToString(stderrRaw),
      });
    } else if (action === "read_file") {
      const content = extractField(respBody, 1);
      return NextResponse.json({ content: bytesToString(content) });
    } else if (action === "write_file") {
      return NextResponse.json({ ok: true });
    } else if (action === "list_files") {
      const entries = extractField(respBody, 1);
      const files = Array.isArray(entries)
        ? entries.map((e: unknown) => {
            const name = extractField(e, 1);
            const kind = extractField(e, 2);
            const size = extractField(e, 3);
            return {
              name: bytesToString(name),
              kind: typeof kind === "string" ? kind : "other",
              size: typeof size === "number" ? size : 0,
            };
          })
        : [];
      return NextResponse.json({ files });
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("Sandbox proxy error:", error);
    return NextResponse.json({ error: String(error) }, { status: 502 });
  }
}

function extractField(obj: unknown, key: number): unknown {
  if (obj == null) return undefined;
  if (obj instanceof Map) return obj.get(key);
  if (typeof obj === "object") {
    const o = obj as Record<string | number, unknown>;
    if (key in o) return o[key];
    if (String(key) in o) return o[String(key)];
  }
  return undefined;
}

function bytesToString(val: unknown): string {
  if (val == null) return "";
  if (typeof val === "string") return val;
  if (Buffer.isBuffer(val)) return val.toString("utf-8");
  if (val instanceof Uint8Array) return Buffer.from(val).toString("utf-8");
  if (typeof val === "number") return String(val);
  return String(val);
}
