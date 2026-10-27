import { beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const db = vi.hoisted(() => ({
  project: { findMany: vi.fn(), findFirst: vi.fn() },
  scan: {
    findMany: vi.fn(),
    findFirst: vi.fn(),
    findUnique: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
  },
  finding: { findMany: vi.fn(), findFirst: vi.fn(), count: vi.fn(), update: vi.fn(), groupBy: vi.fn() },
  orgSettings: { findUnique: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/auth", () => ({ authOptions: {} }));
const audit = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: audit, ipFromHeaders: vi.fn(() => null) }));
const queueAdd = vi.hoisted(() => vi.fn(async () => ({ id: "job1" })));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: queueAdd } }));
vi.mock("@/lib/minio", () => ({ objectExists: vi.fn(async () => true), uploadObject: vi.fn(), ensureBucket: vi.fn() }));
vi.mock("@/lib/active-project-scans", () => ({ cancelActiveScansForProject: vi.fn(async () => undefined) }));
vi.mock("@/lib/scan-notifications", () => ({ createScanQueuedNotification: vi.fn(async () => undefined) }));
vi.mock("@/lib/org-settings-job", () => ({ buildOrgSettingsForJob: vi.fn(() => ({})) }));
vi.mock("@/lib/github-connection", () => ({ getOrgGithubAccessToken: vi.fn(async () => null) }));
const createProject = vi.hoisted(() => vi.fn(async () => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: createProject }));
const suppress = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@/lib/suppression-rules", () => ({ generateSuppressionRule: suppress }));
vi.mock("child_process", () => ({ execFileSync: vi.fn(() => "") }));

import { createPepperMcpServer, redactUrlCredentials, type PepperMcpContext } from "./pepper-mcp-server";

type Role = PepperMcpContext["principal"]["role"];

async function connect(role: Role = "DEVELOPER") {
  const server = createPepperMcpServer({
    principal: { apiKeyId: "k1", userId: "u1", organizationId: "org1", role },
    ipAddress: "10.0.0.1",
    appUrl: "https://pepper.example",
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(clientSide);
  return client;
}

async function call(name: string, args: Record<string, unknown>, role?: Role) {
  const client = await connect(role);
  const res = (await client.callTool({ name, arguments: args })) as {
    isError?: boolean;
    content: Array<{ type: string; text: string }>;
  };
  const text = res.content[0]?.text ?? "";
  let data: unknown = null;
  try {
    data = JSON.parse(text);
  } catch {
    // error text
  }
  return { isError: !!res.isError, text, data: data as Record<string, unknown> & { [k: string]: unknown } };
}

const counts = { criticalCount: 1, highCount: 2, mediumCount: 3, lowCount: 4 };
const findingRow = {
  id: "f1",
  scanId: "s1",
  title: "SQL injection",
  severity: "HIGH",
  scanner: "SAST_LLM",
  status: "OPEN",
  statusNote: null,
  filePath: "src/db.ts",
  startLine: 10,
  endLine: 12,
  snippet: "db.query(`SELECT * FROM t WHERE id=${id}`)",
  ruleId: "sqli",
  cweId: "CWE-89",
  cveId: null,
  confidence: 0.9,
  isNew: true,
  riskScore: 80,
  masked: false,
  description: "User input reaches a SQL query.",
  metadata: { stepsToReproduce: ["Send id=1 OR 1=1"], remediation: ["Use parameterized queries."] },
};

beforeEach(() => {
  vi.clearAllMocks();
  db.scan.create.mockResolvedValue({ id: "s-new", projectId: "p1" });
  db.scan.update.mockResolvedValue({});
  db.finding.groupBy.mockResolvedValue([]);
  db.orgSettings.findUnique.mockResolvedValue(null);
});

describe("tool catalogue", () => {
  it("lists every tool with a JSON input schema", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "findings_for_file",
      "get_finding",
      "get_scan",
      "list_findings",
      "list_repositories",
      "list_scans",
      "rescan",
      "start_scan",
      "update_finding_status",
    ]);
    for (const t of tools) {
      expect(t.description).toBeTruthy();
      expect(t.inputSchema.type).toBe("object");
    }
    const status = tools.find((t) => t.name === "update_finding_status")!;
    expect(status.inputSchema.required).toEqual(["findingId", "status"]);
  });

  it("rejects input that does not match the schema", async () => {
    const res = await call("update_finding_status", { findingId: "f1", status: "DELETED" });
    expect(res.isError).toBe(true);
    expect(db.finding.update).not.toHaveBeenCalled();
  });
});

describe("read tools", () => {
  it("list_repositories: org-scoped, with latest status and severity counts, credentials removed", async () => {
    db.project.findMany.mockResolvedValue([
      {
        id: "p1",
        name: "app",
        repoUrl: "https://ghp_secret@github.com/acme/app.git",
        defaultBranch: "main",
        scans: [{ id: "s2", status: "RUNNING", scanType: "FULL", gateResult: "PENDING", createdAt: new Date(), completedAt: null }],
      },
    ]);
    db.scan.findMany.mockResolvedValue([{ id: "s1", projectId: "p1", completedAt: new Date(), gateResult: "FAILED", ...counts }]);

    const res = await call("list_repositories", { search: "ap" });
    expect(db.project.findMany.mock.calls[0][0].where).toEqual({
      organizationId: "org1",
      name: { contains: "ap", mode: "insensitive" },
    });
    const repo = (
      res.data.repositories as Array<{
        repoUrl: string;
        latestScan: { status: string };
        latestCompletedScan: { severityCounts: Record<string, number>; url: string };
      }>
    )[0];
    expect(repo.repoUrl).toBe("https://github.com/acme/app.git");
    expect(res.text).not.toContain("ghp_secret");
    expect(repo.latestScan.status).toBe("RUNNING");
    expect(repo.latestCompletedScan.severityCounts).toEqual({ critical: 1, high: 2, medium: 3, low: 4 });
    expect(repo.latestCompletedScan.url).toBe("https://pepper.example/scans/s1");
  });

  it("list_scans: newest first, filtered and paged within the key's organization", async () => {
    db.scan.findMany.mockResolvedValue([
      {
        id: "s1",
        project: { id: "p1", name: "app" },
        status: "COMPLETED",
        scanType: "FULL",
        branch: "main",
        commitSha: "abc",
        sourceType: "GIT_CLONE",
        sourceRef: "https://user:pw@git.example/app.git",
        gateResult: "PASSED",
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
        ...counts,
      },
    ]);
    db.scan.count.mockResolvedValue(41);

    const res = await call("list_scans", { repositoryId: "p1", status: "COMPLETED", page: 3, limit: 20 });
    const q = db.scan.findMany.mock.calls[0][0];
    expect(q.where).toEqual({ project: { organizationId: "org1" }, projectId: "p1", status: "COMPLETED" });
    expect(q.orderBy).toEqual({ createdAt: "desc" });
    expect(q.skip).toBe(40);
    expect(res.data.pagination).toEqual({ page: 3, limit: 20, total: 41, totalPages: 3 });
    expect(res.text).not.toContain("pw@");
  });

  it("get_scan: progress, counts, gate and the incomplete-scan note", async () => {
    db.scan.findFirst.mockResolvedValue({
      id: "s1",
      project: { id: "p1", name: "app" },
      status: "COMPLETED",
      scanType: "FULL",
      branch: "main",
      commitSha: null,
      sourceType: "UPLOAD",
      sourceRef: "scans/s1/source.zip",
      createdAt: new Date(),
      startedAt: new Date(),
      completedAt: new Date(),
      scannerProgress: { SAST_LLM: { status: "DONE", findingsCount: 3 } },
      newFindingCount: 2,
      autoResolvedCount: 0,
      filesScanned: 120,
      depsScanned: 30,
      gateResult: "FAILED",
      errorMessage: "AI analysis did not run: the provider refused the request.",
      ...counts,
    });

    const res = await call("get_scan", { scanId: "s1" });
    expect(db.scan.findFirst.mock.calls[0][0].where).toEqual({ id: "s1", project: { organizationId: "org1" } });
    expect(res.data).toMatchObject({
      status: "COMPLETED",
      progressPercent: 100,
      gateResult: "FAILED",
      totalFindings: 10,
      source: "uploaded archive",
      incompleteScan: true,
      incompleteScanNote: "Incomplete scan: AI analysis did not run: the provider refused the request.",
    });
  });

  it("get_scan: a running scan reports progress; another organization's scan is not found", async () => {
    db.scan.findFirst.mockResolvedValueOnce({
      id: "s1",
      project: { id: "p1", name: "app" },
      status: "RUNNING",
      sourceType: "GIT_CLONE",
      sourceRef: null,
      scannerProgress: { SAST_LLM: { status: "RUNNING", filesCompleted: 5, filesTotal: 10 } },
      errorMessage: null,
      ...counts,
    });
    const running = await call("get_scan", { scanId: "s1" });
    expect(running.data.progressPercent).toBeGreaterThan(10);
    expect(running.data.progressPercent).toBeLessThan(100);
    expect(running.data.incompleteScanNote).toBeUndefined();

    db.scan.findFirst.mockResolvedValueOnce(null);
    const other = await call("get_scan", { scanId: "theirs" });
    expect(other.isError).toBe(true);
    expect(other.text).toBe("Scan not found.");
  });

  it("list_findings: hides false positives and INFO by default, like the UI", async () => {
    db.scan.findFirst.mockResolvedValue({ id: "s1" });
    db.finding.findMany.mockResolvedValue([findingRow]);
    db.finding.count.mockResolvedValue(1);

    const res = await call("list_findings", { scanId: "s1" });
    expect(db.scan.findFirst.mock.calls[0][0].where).toEqual({ id: "s1", project: { organizationId: "org1" } });
    expect(db.finding.findMany.mock.calls[0][0].where).toEqual({
      scanId: "s1",
      status: { not: "FALSE_POSITIVE" },
      severity: { notIn: ["INFO"] },
    });
    expect((res.data.findings as unknown[])[0]).toMatchObject({ id: "f1", severity: "HIGH", filePath: "src/db.ts" });

    await call("list_findings", {
      scanId: "s1",
      severity: ["CRITICAL", "HIGH"],
      scanner: ["SCA"],
      status: ["OPEN"],
      filePath: "./src/",
    });
    expect(db.finding.findMany.mock.calls[1][0].where).toEqual({
      scanId: "s1",
      severity: { in: ["CRITICAL", "HIGH"] },
      scanner: { in: ["SCA"] },
      status: { in: ["OPEN"] },
      filePath: { contains: "src/" },
    });
  });

  it("get_finding: full details with OWASP, reproduction steps and remediation", async () => {
    db.finding.findFirst.mockResolvedValue({ ...findingRow, scan: { id: "s1", branch: "main", project: { id: "p1", name: "app" } } });

    const res = await call("get_finding", { findingId: "f1" });
    expect(db.finding.findFirst.mock.calls[0][0].where).toEqual({
      id: "f1",
      scan: { project: { organizationId: "org1" } },
    });
    expect(res.data).toMatchObject({
      id: "f1",
      cweId: "CWE-89",
      owasp: expect.stringContaining("Injection"),
      location: { filePath: "src/db.ts", startLine: 10, endLine: 12 },
      stepsToReproduce: ["Send id=1 OR 1=1"],
      remediation: ["Use parameterized queries."],
    });
    expect(res.data.summary).toBeTruthy();
  });

  it("get_finding: secrets come back masked only", async () => {
    db.finding.findFirst.mockResolvedValueOnce({
      ...findingRow,
      scanner: "SECRETS_PATTERN",
      masked: true,
      snippet: "12: AWS_KEY=AKIA****XY",
      metadata: { maskedValue: "AKIA****XY" },
      scan: { id: "s1", branch: null, project: { id: "p1", name: "app" } },
    });
    const masked = await call("get_finding", { findingId: "f1" });
    expect(masked.data).toMatchObject({ snippet: "12: AWS_KEY=AKIA****XY", maskedValue: "AKIA****XY" });

    db.finding.findFirst.mockResolvedValueOnce({
      ...findingRow,
      scanner: "SECRETS_LLM",
      masked: false,
      snippet: "token = 'raw-secret-value'",
      metadata: {},
      scan: { id: "s1", branch: null, project: { id: "p1", name: "app" } },
    });
    const unmasked = await call("get_finding", { findingId: "f1" });
    expect(unmasked.data.snippet).toBeNull();
    expect(unmasked.text).not.toContain("raw-secret-value");
  });

  it("findings_for_file: latest completed scan of the repository, matching an absolute editor path", async () => {
    db.project.findMany.mockResolvedValueOnce([{ id: "p1", name: "app", repoUrl: null, defaultBranch: "main" }]);
    db.scan.findFirst.mockResolvedValue({ id: "s9", branch: "main", commitSha: "abc", completedAt: new Date(), errorMessage: null });
    db.finding.findMany.mockResolvedValue([
      findingRow,
      { ...findingRow, id: "f2", filePath: "lib/src/db.ts" },
    ]);

    const res = await call("findings_for_file", {
      repository: "APP",
      filePath: "C:\\work\\app\\src\\db.ts",
      minSeverity: "HIGH",
    });
    expect(db.project.findMany.mock.calls[0][0].where).toEqual({
      organizationId: "org1",
      name: { equals: "APP", mode: "insensitive" },
    });
    expect(db.scan.findFirst.mock.calls[0][0]).toMatchObject({
      where: { projectId: "p1", status: "COMPLETED", project: { organizationId: "org1" } },
      orderBy: { completedAt: "desc" },
    });
    const where = db.finding.findMany.mock.calls[0][0].where;
    expect(where).toEqual({
      scanId: "s9",
      filePath: { endsWith: "db.ts" },
      severity: { in: ["CRITICAL", "HIGH"] },
      status: { not: "FALSE_POSITIVE" },
    });
    expect((res.data.findings as Array<{ id: string }>).map((f) => f.id)).toEqual(["f1"]);
  });

  it("findings_for_file: finds the repository by URL and says when nothing was scanned yet", async () => {
    db.project.findMany
      .mockResolvedValueOnce([]) // no name match
      .mockResolvedValueOnce([{ id: "p2", name: "svc", repoUrl: "https://github.com/acme/svc.git", defaultBranch: "main" }]);
    db.scan.findFirst.mockResolvedValue(null);

    const res = await call("findings_for_file", { repository: "git@github.com:acme/svc", filePath: "a.py" });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ repository: { id: "p2", name: "svc" }, scan: null, findings: [] });
  });
});

describe("start_scan / rescan", () => {
  it("scans a known repository by id from its repository URL, attributed and audited", async () => {
    db.project.findFirst
      .mockResolvedValueOnce({ id: "p1", name: "app", repoUrl: "https://github.com/acme/app", defaultBranch: "develop" })
      .mockResolvedValueOnce({ id: "p1", name: "app", organizationId: "org1", buildGate: null });

    const res = await call("start_scan", { repositoryId: "p1", scanType: "SAST_ONLY" });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ scanId: "s-new", repositoryId: "p1", status: "QUEUED" });
    expect(db.project.findFirst.mock.calls[0][0].where).toEqual({ id: "p1", organizationId: "org1" });
    expect(db.scan.create.mock.calls[0][0].data).toMatchObject({
      projectId: "p1",
      scanType: "SAST_ONLY",
      branch: "develop",
      sourceType: "GIT_CLONE",
      triggeredBy: "u1",
    });
    expect(queueAdd).toHaveBeenCalled();
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: "org1",
        userId: "u1",
        action: "scan.queued",
        ipAddress: "10.0.0.1",
        details: expect.objectContaining({ via: "mcp" }),
      }),
    );
  });

  it("scans a new repository URL, creating the repository; refuses URLs carrying credentials", async () => {
    db.project.findMany.mockResolvedValue([]);
    db.project.findFirst.mockResolvedValue({ id: "p-new", name: "lib", organizationId: "org1", buildGate: null });
    const res = await call("start_scan", { repoUrl: "https://github.com/acme/lib", branch: "main" });
    expect(res.isError).toBe(false);
    expect(createProject).toHaveBeenCalledWith(expect.objectContaining({ organizationId: "org1", repoUrl: "https://github.com/acme/lib" }));

    vi.clearAllMocks();
    const withToken = await call("start_scan", { repoUrl: "https://ghp_x@github.com/acme/lib" });
    expect(withToken.isError).toBe(true);
    expect(withToken.text).toMatch(/credentials/);
    const option = await call("start_scan", { repoUrl: "--upload-pack=touch /tmp/x" });
    expect(option.isError).toBe(true);
    expect(db.scan.create).not.toHaveBeenCalled();
  });

  it("rescan repeats an earlier scan of the organization", async () => {
    db.scan.findFirst.mockResolvedValue({
      id: "s1",
      projectId: "p1",
      sourceType: "UPLOAD",
      sourceRef: "scans/s1/source.zip",
      scanType: "FULL",
      branch: null,
      baseSha: null,
      commitSha: null,
      prNumber: null,
      project: { name: "app", buildGate: null, connectedViaGithub: false, connectedViaBitbucket: false, connectedViaAzure: false },
    });
    const res = await call("rescan", { scanId: "s1" });
    expect(res.data).toMatchObject({ scanId: "s-new", previousScanId: "s1", status: "QUEUED" });
    expect(db.scan.findFirst.mock.calls[0][0].where).toEqual({ id: "s1", project: { organizationId: "org1" } });
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "scan.rescanned", details: expect.objectContaining({ via: "mcp" }) }));
  });

  it("a Viewer key cannot start or repeat scans", async () => {
    const start = await call("start_scan", { repositoryId: "p1" }, "VIEWER");
    const again = await call("rescan", { scanId: "s1" }, "VIEWER");
    for (const res of [start, again]) {
      expect(res.isError).toBe(true);
      expect(res.text).toMatch(/requires the DEVELOPER role/);
    }
    expect(db.scan.create).not.toHaveBeenCalled();
    expect(queueAdd).not.toHaveBeenCalled();
  });
});

describe("update_finding_status", () => {
  it("updates, audits and recounts the scan's severity totals", async () => {
    db.finding.findFirst.mockResolvedValue({ id: "f1", status: "OPEN" });
    db.finding.update.mockResolvedValue({ ...findingRow, status: "RESOLVED", statusNote: "fixed in #12" });
    db.finding.groupBy.mockResolvedValue([{ severity: "HIGH", _count: { _all: 1 } }]);
    db.scan.findUnique.mockResolvedValue({ ...counts, highCount: 1 });

    const res = await call("update_finding_status", { findingId: "f1", status: "RESOLVED", note: "fixed in #12" });
    expect(res.isError).toBe(false);
    expect(db.finding.findFirst.mock.calls[0][0].where).toEqual({ id: "f1", scan: { project: { organizationId: "org1" } } });
    expect(db.finding.update.mock.calls[0][0]).toMatchObject({
      where: { id: "f1" },
      data: { status: "RESOLVED", statusNote: "fixed in #12", statusUpdatedBy: "u1" },
    });
    // recountScanSeverities
    expect(db.finding.groupBy.mock.calls[0][0].where).toEqual({ scanId: "s1", status: { not: "FALSE_POSITIVE" } });
    expect(db.scan.update).toHaveBeenCalledWith(expect.objectContaining({ where: { id: "s1" }, data: expect.objectContaining({ highCount: 1 }) }));
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "finding.status_changed",
        resourceId: "f1",
        details: expect.objectContaining({ from: "OPEN", to: "RESOLVED", via: "mcp" }),
      }),
    );
    expect(res.data).toMatchObject({ previousStatus: "OPEN", status: "RESOLVED", scanSeverityCounts: { high: 1 } });
  });

  it("refuses false positive / accepted risk without the Security role, as the findings API does", async () => {
    for (const status of ["FALSE_POSITIVE", "ACCEPTED_RISK"]) {
      const res = await call("update_finding_status", { findingId: "f1", status });
      expect(res.isError).toBe(true);
      expect(res.text).toMatch(/requires the Security or Admin role/);
    }
    const viewer = await call("update_finding_status", { findingId: "f1", status: "RESOLVED" }, "VIEWER");
    expect(viewer.isError).toBe(true);
    expect(db.finding.update).not.toHaveBeenCalled();
    expect(suppress).not.toHaveBeenCalled();
  });

  it("a Security principal may mark a false positive, which also creates a suppression rule", async () => {
    db.finding.findFirst
      .mockResolvedValueOnce({ id: "f1", status: "OPEN" })
      .mockResolvedValueOnce({ scan: { project: { id: "p1", organizationId: "org1" } } });
    db.finding.update.mockResolvedValue({ ...findingRow, status: "FALSE_POSITIVE" });
    db.scan.findUnique.mockResolvedValue(counts);
    const res = await call("update_finding_status", { findingId: "f1", status: "FALSE_POSITIVE" }, "SECURITY");
    expect(res.isError).toBe(false);
    expect(suppress).toHaveBeenCalled();
  });

  it("another organization's finding is not found", async () => {
    db.finding.findFirst.mockResolvedValue(null);
    const res = await call("update_finding_status", { findingId: "theirs", status: "RESOLVED" });
    expect(res).toMatchObject({ isError: true, text: "Finding not found." });
    expect(db.finding.update).not.toHaveBeenCalled();
  });
});

describe("redactUrlCredentials", () => {
  it("removes tokens and passwords but keeps plain URLs", () => {
    expect(redactUrlCredentials("https://x-access-token:abc@github.com/a/b.git")).toBe("https://github.com/a/b.git");
    expect(redactUrlCredentials("https://github.com/a/b")).toBe("https://github.com/a/b");
    expect(redactUrlCredentials("ssh://git@host/a/b.git")).toBe("ssh://git@host/a/b.git");
    expect(redactUrlCredentials("git@github.com:a/b.git")).toBe("git@github.com:a/b.git");
    expect(redactUrlCredentials(null)).toBeNull();
  });
});
