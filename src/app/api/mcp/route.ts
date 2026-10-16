import { NextRequest, NextResponse } from "next/server";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { resolveApiKeyPrincipal } from "@/lib/auth-guard";
import { ipFromHeaders } from "@/lib/audit-log";
import { createPepperMcpServer } from "@/lib/mcp/pepper-mcp-server";

/**
 * Model Context Protocol endpoint (Streamable HTTP transport, stateless).
 *
 * IDE assistants that speak MCP — GitHub Copilot, JetBrains AI Assistant,
 * Cursor, Claude Code, Continue, … — connect here with a Pepper API key in
 * `Authorization: Bearer <key>` and get tools to read findings, start scans and
 * triage. Each POST carries complete JSON-RPC messages and is answered with
 * JSON; no session state is kept between requests, so any API replica can
 * serve any request and nothing outside this instance is contacted.
 */
export const dynamic = "force-dynamic";

function jsonRpcError(status: number, code: number, message: string, headers?: Record<string, string>) {
  return NextResponse.json(
    { jsonrpc: "2.0", error: { code, message }, id: null },
    { status, headers },
  );
}

function appUrl(req: NextRequest): string {
  const configured = process.env.NEXTAUTH_URL || process.env.NEXT_PUBLIC_APP_URL;
  return (configured || new URL(req.url).origin).replace(/\/+$/, "");
}

export async function POST(req: NextRequest) {
  const principal = await resolveApiKeyPrincipal(req.headers.get("authorization"));
  if (!principal) {
    return jsonRpcError(
      401,
      -32001,
      "Unauthorized: send a valid Pepper API key as 'Authorization: Bearer <key>'.",
      { "WWW-Authenticate": 'Bearer realm="pepper"' },
    );
  }

  const server = createPepperMcpServer({
    principal,
    ipAddress: ipFromHeaders(req.headers),
    appUrl: appUrl(req),
  });
  // Stateless: a fresh transport per request, answered with plain JSON.
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  try {
    await server.connect(transport);
    return await transport.handleRequest(req);
  } finally {
    await server.close().catch(() => undefined);
  }
}

/**
 * No server-initiated stream: a stateless server answers every request inline
 * (and has no sessions to DELETE, which Next.js answers with 405 itself).
 */
export async function GET() {
  return jsonRpcError(
    405,
    -32000,
    "Method not allowed: this MCP server is stateless; send JSON-RPC messages with POST.",
    { Allow: "POST" },
  );
}
