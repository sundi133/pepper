import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  apiKey: { findUnique: vi.fn() },
  orgMember: { findFirst: vi.fn() },
  scan: { findMany: vi.fn(), count: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/auth", () => ({ authOptions: {} }));
const verifyApiKey = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api-key", () => ({ verifyApiKey }));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: vi.fn() } }));
vi.mock("@/lib/minio", () => ({ objectExists: vi.fn(), uploadObject: vi.fn(), ensureBucket: vi.fn() }));

import { GET, POST } from "./route";

const VALID = "ppr_valid";

function rpc(body: unknown, opts: { auth?: string | null; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...opts.headers,
  };
  const auth = opts.auth === undefined ? `Bearer ${VALID}` : opts.auth;
  if (auth) headers.authorization = auth;
  return POST(
    new NextRequest("http://localhost/api/mcp", { method: "POST", headers, body: JSON.stringify(body) }),
  );
}

const initialize = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "vitest", version: "1" } },
};

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.NEXTAUTH_URL;
  delete process.env.NEXT_PUBLIC_APP_URL;
  verifyApiKey.mockImplementation(async (header: string | null) =>
    header === `Bearer ${VALID}`
      ? { apiKeyId: "k1", organizationId: "org1", organization: { name: "Acme", slug: "acme" } }
      : null,
  );
  db.apiKey.findUnique.mockResolvedValue({ createdBy: "u1" });
  db.orgMember.findFirst.mockResolvedValue({ userId: "u1", role: "ADMIN" });
  db.scan.findMany.mockResolvedValue([]);
  db.scan.count.mockResolvedValue(0);
});

describe("MCP endpoint authentication", () => {
  it("rejects a request without an API key", async () => {
    const res = await rpc(initialize, { auth: null });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Bearer");
    expect((await res.json()).error.message).toMatch(/Unauthorized/);
  });

  it("rejects an unknown or expired API key", async () => {
    const res = await rpc(initialize, { auth: "Bearer ppr_wrong" });
    expect(res.status).toBe(401);
  });

  it("rejects a key whose creator has left the organization", async () => {
    db.orgMember.findFirst.mockResolvedValue(null);
    const res = await rpc(initialize);
    expect(res.status).toBe(401);
    expect(db.orgMember.findFirst.mock.calls[0][0].where).toEqual({ userId: "u1", organizationId: "org1" });
  });

  it("does not offer a server-initiated GET stream", async () => {
    const res = await GET();
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
  });
});

describe("MCP over JSON-RPC (Streamable HTTP)", () => {
  it("initializes and identifies as the Pepper server", async () => {
    const res = await rpc(initialize);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.id).toBe(1);
    expect(body.result.serverInfo.name).toBe("pepper");
    expect(body.result.capabilities.tools).toBeDefined();
    expect(body.result.instructions).toMatch(/findings_for_file/);
  });

  it("acknowledges the initialized notification", async () => {
    const res = await rpc({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(res.status).toBe(202);
  });

  it("lists the tools", async () => {
    const res = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, { headers: { "mcp-protocol-version": "2025-06-18" } });
    expect(res.status).toBe(200);
    const { result } = await res.json();
    const names = result.tools.map((t: { name: string }) => t.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "list_repositories",
        "list_scans",
        "get_scan",
        "list_findings",
        "get_finding",
        "findings_for_file",
        "start_scan",
        "rescan",
        "update_finding_status",
      ]),
    );
  });

  it("runs a tool scoped to the key's organization, linking to the configured instance URL", async () => {
    process.env.NEXTAUTH_URL = "https://pepper.internal/";
    db.scan.findMany.mockResolvedValue([
      {
        id: "s1",
        project: { id: "p1", name: "app" },
        status: "COMPLETED",
        scanType: "FULL",
        branch: "main",
        commitSha: null,
        sourceType: "GIT_CLONE",
        sourceRef: "https://github.com/acme/app",
        gateResult: "PASSED",
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
        criticalCount: 0,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
      },
    ]);
    db.scan.count.mockResolvedValue(1);

    const res = await rpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "list_scans", arguments: {} },
    });
    expect(res.status).toBe(200);
    const { result } = await res.json();
    expect(result.isError).toBeFalsy();
    const data = JSON.parse(result.content[0].text);
    expect(data.scans[0].url).toBe("https://pepper.internal/scans/s1");
    expect(db.scan.findMany.mock.calls[0][0].where).toEqual({ project: { organizationId: "org1" } });
  });

  it("caps an Admin's key at Developer, as for every API-key request", async () => {
    const res = await rpc({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "update_finding_status", arguments: { findingId: "f1", status: "FALSE_POSITIVE" } },
    });
    const { result } = await res.json();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Security or Admin role/);
  });

  it("answers malformed JSON-RPC with a protocol error", async () => {
    const res = await rpc({ hello: "world" });
    expect(res.status).toBe(400);
  });
});
