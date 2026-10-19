import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const principal = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth-guard", () => ({ resolveApiKeyPrincipal: principal }));
const apiKey = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api-key", () => ({ verifyApiKey: apiKey }));
const db = vi.hoisted(() => ({
  project: { findMany: vi.fn(), findFirst: vi.fn() },
  scan: { findFirst: vi.fn() },
  finding: { findMany: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { GET as repositoryGET } from "./repository/route";
import { GET as findingsGET } from "./findings/route";

const get = (handler: (r: NextRequest) => Promise<Response>, path: string, auth = "Bearer pep_test") =>
  handler(new NextRequest(`http://localhost${path}`, { headers: auth ? { authorization: auth } : {} }));

beforeEach(() => {
  vi.clearAllMocks();
  principal.mockResolvedValue({ organizationId: "o1", userId: "u1", role: "DEVELOPER" });
  apiKey.mockResolvedValue({ organizationId: "o1", apiKeyId: "k1" });
});

describe("GET /api/ide/repository", () => {
  it("refuses a missing or unknown key", async () => {
    principal.mockResolvedValue(null);
    expect((await get(repositoryGET, "/api/ide/repository?remote=x", "")).status).toBe(401);
  });

  it("needs a remote or a name", async () => {
    expect((await get(repositoryGET, "/api/ide/repository")).status).toBe(400);
  });

  it("lists every repository of the organization for a picker", async () => {
    db.project.findMany.mockResolvedValue([{ id: "p1", name: "api", repoUrl: null, defaultBranch: "main" }, { id: "p2", name: "web", repoUrl: null, defaultBranch: "main" }]);
    const body = await (await get(repositoryGET, "/api/ide/repository?all=true")).json();
    expect(body).toMatchObject({ repository: null, candidates: [{ id: "p1" }, { id: "p2" }] });
  });

  it("looks only at the key's organization and returns the match", async () => {
    db.project.findMany.mockResolvedValue([{ id: "p1", name: "api", repoUrl: "https://github.com/acme/api.git", defaultBranch: "main" }]);
    const res = await get(repositoryGET, "/api/ide/repository?remote=" + encodeURIComponent("git@github.com:acme/api.git"));
    expect(db.project.findMany.mock.calls[0][0].where).toEqual({ organizationId: "o1" });
    expect(await res.json()).toEqual({ repository: { id: "p1", name: "api", repoUrl: "https://github.com/acme/api.git", defaultBranch: "main" }, matchedBy: "url", candidates: [] });
  });
});

describe("GET /api/ide/findings", () => {
  const finding = (over: Record<string, unknown> = {}) => ({
    id: "f1", severity: "HIGH", title: "SQL injection", description: "d", filePath: "src/a.ts", startLine: 3, endLine: 3,
    ruleId: "r", cveId: null, cweId: "CWE-89", scanner: "SAST_LLM", confidence: 0.9, status: "OPEN", snippet: "3: q(x)", riskScore: 80,
    metadata: { remediation: "Use parameters", attackPath: "GET /a?x=1' OR 1=1", validation: "confirmed", internal: "not exposed" },
    ...over,
  });

  beforeEach(() => {
    db.project.findFirst.mockResolvedValue({ id: "p1", name: "api" });
    db.finding.findMany.mockResolvedValue([finding()]);
    process.env.NEXTAUTH_URL = "https://pepper.example/";
  });

  it("accepts repositoryId as well as projectId and adds the fields the IDE shows", async () => {
    db.scan.findFirst.mockResolvedValue({ id: "s1", completedAt: null, commitSha: "abc", branch: "main" });
    const body = await (await get(findingsGET, "/api/ide/findings?repositoryId=p1")).json();
    expect(db.project.findFirst.mock.calls[0][0].where).toEqual({ id: "p1", organizationId: "o1" });
    expect(body.findings[0]).toMatchObject({ id: "f1", snippet: "3: q(x)", remediation: "Use parameters", attackPath: "GET /a?x=1' OR 1=1", validation: "confirmed", url: "https://pepper.example/scans/s1" });
    expect(body.findings[0].metadata).toBeUndefined();
    expect(body).toMatchObject({ webBaseUrl: "https://pepper.example", truncated: false });
    expect((await get(findingsGET, "/api/ide/findings?projectId=p1")).status).toBe(200);
  });

  it("prefers the branch's latest scan and falls back to the repository's latest", async () => {
    db.scan.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: "s-main", branch: "main" });
    const body = await (await get(findingsGET, "/api/ide/findings?repositoryId=p1&branch=feature")).json();
    expect(db.scan.findFirst.mock.calls[0][0].where).toMatchObject({ projectId: "p1", status: "COMPLETED", branch: "feature" });
    expect(db.scan.findFirst.mock.calls[1][0].where.branch).toBeUndefined();
    expect(body.scan.id).toBe("s-main");
  });

  it("shows only open findings unless triaged ones are asked for", async () => {
    db.scan.findFirst.mockResolvedValue({ id: "s1" });
    await get(findingsGET, "/api/ide/findings?repositoryId=p1");
    expect(db.finding.findMany.mock.calls[0][0].where.status).toEqual({ in: ["OPEN", "IN_PROGRESS"] });
    await get(findingsGET, "/api/ide/findings?repositoryId=p1&includeTriaged=true");
    expect(db.finding.findMany.mock.calls[1][0].where.status).toEqual({ not: "FALSE_POSITIVE" });
  });

  it("still refuses without a key or repository", async () => {
    apiKey.mockResolvedValue(null);
    expect((await get(findingsGET, "/api/ide/findings?repositoryId=p1", "")).status).toBe(401);
    apiKey.mockResolvedValue({ organizationId: "o1" });
    expect((await get(findingsGET, "/api/ide/findings")).status).toBe(400);
    db.project.findFirst.mockResolvedValue(null);
    expect((await get(findingsGET, "/api/ide/findings?repositoryId=other-org")).status).toBe(404);
  });
});
