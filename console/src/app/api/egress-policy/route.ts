import { NextRequest, NextResponse } from "next/server";

// Table name comes from the x-egress-table header (set in Settings), or EGRESS_TABLE env var.
function getTableName(req: NextRequest): string | null {
  return req.headers.get("x-egress-table") || process.env.EGRESS_TABLE || null;
}
function getRegion(req: NextRequest): string {
  return req.headers.get("x-api-region") || process.env.AWS_REGION || "us-east-1";
}

// PCSR Finding 8: simple auth check — require a shared secret or API key.
// In production, replace with proper session auth.
function checkAuth(req: NextRequest): boolean {
  // Console is local-only by default; if CONSOLE_AUTH_TOKEN is set, require it.
  const requiredToken = process.env.CONSOLE_AUTH_TOKEN;
  if (!requiredToken) return true; // Local-only mode: no auth required.
  const authHeader = req.headers.get("authorization") || "";
  return authHeader === `Bearer ${requiredToken}`;
}

async function getDDBClient(region: string) {
  const { DynamoDBClient, GetItemCommand, PutItemCommand } = await import("@aws-sdk/client-dynamodb");
  return { client: new DynamoDBClient({ region }), GetItemCommand, PutItemCommand };
}

export async function GET(req: NextRequest) {
  if (!checkAuth(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const TABLE_NAME = getTableName(req);
  if (!TABLE_NAME) {
    return NextResponse.json({ error: "Egress table not configured. Set it in Settings or via EGRESS_TABLE env var." }, { status: 500 });
  }
  try {
    const { client, GetItemCommand } = await getDDBClient(getRegion(req));
    const resp = await client.send(new GetItemCommand({
      TableName: TABLE_NAME,
      Key: { pk: { S: "EGRESS_POLICY" } },
    }));
    const policyStr = resp.Item?.policy?.S || "{}";
    return NextResponse.json(JSON.parse(policyStr));
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

export async function PUT(req: NextRequest) {
  if (!checkAuth(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const TABLE_NAME = getTableName(req);
  if (!TABLE_NAME) {
    return NextResponse.json({ error: "Egress table not configured. Set it in Settings or via EGRESS_TABLE env var." }, { status: 500 });
  }
  try {
    const policy = await req.json();
    // PCSR Finding 8: basic schema validation — require policyVersion.
    if (!policy || typeof policy.policyVersion !== "number") {
      return NextResponse.json({ error: "Invalid policy: policyVersion (number) required" }, { status: 400 });
    }
    const { client, PutItemCommand } = await getDDBClient(getRegion(req));
    await client.send(new PutItemCommand({
      TableName: TABLE_NAME,
      Item: {
        pk: { S: "EGRESS_POLICY" },
        policy: { S: JSON.stringify(policy) },
      },
    }));
    return NextResponse.json({ ok: true, policyVersion: policy.policyVersion });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
