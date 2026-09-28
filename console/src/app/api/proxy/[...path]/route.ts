import { NextRequest, NextResponse } from "next/server";
import { SignatureV4 } from "@smithy/signature-v4";
import { Hash } from "@smithy/hash-node";
import { HttpRequest } from "@smithy/protocol-http";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";

// Proxy all API requests to the Control Plane.
// Supports two modes:
// 1. Bearer token (multi-tenant) — forwards Authorization header as-is
// 2. SigV4 (single-tenant) — signs with local AWS credentials server-side

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  return proxyRequest(request, await params, "GET");
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  return proxyRequest(request, await params, "POST");
}

async function proxyRequest(
  request: NextRequest,
  params: { path: string[] },
  method: string
): Promise<NextResponse> {
  const apiUrl = request.headers.get("x-api-url");
  const token = request.headers.get("x-api-token");
  const region = request.headers.get("x-api-region") || "us-east-1";

  if (!apiUrl) {
    return NextResponse.json({ error: "x-api-url header required" }, { status: 400 });
  }

  const path = "/" + params.path.join("/");
  const parsedUrl = new URL(apiUrl);
  const hostname = parsedUrl.hostname;
  const url = `${apiUrl.replace(/\/+$/, "")}${path}`;

  try {
    const body = method !== "GET" ? await request.text() : undefined;

    let headers: Record<string, string> = {
      "Content-Type": "application/json",
      "host": hostname,
    };

    if (token) {
      // Multi-tenant: use bearer token
      headers["Authorization"] = `Bearer ${token}`;
    } else {
      // Single-tenant: sign with SigV4 using local AWS credentials
      const signer = new SignatureV4({
        service: "execute-api",
        region,
        credentials: fromNodeProviderChain(),
        sha256: Hash.bind(null, "sha256"),
      });

      const httpRequest = new HttpRequest({
        method,
        protocol: "https:",
        hostname,
        path,
        headers: {
          "Content-Type": "application/json",
          host: hostname,
        },
        body: body || undefined,
      });

      const signed = await signer.sign(httpRequest);
      headers = signed.headers as Record<string, string>;
    }

    const resp = await fetch(url, {
      method,
      headers,
      body: body || undefined,
    });

    const data = await resp.text();
    return new NextResponse(data, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Proxy error:", error);
    return NextResponse.json(
      { error: `Proxy error: ${String(error)}` },
      { status: 502 }
    );
  }
}
