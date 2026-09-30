import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ─── In-memory stand-ins for the tables this module touches ─────────────────
type Row = Record<string, unknown>;
const db = {
  integrations: [] as Row[],
  scans: [] as Row[],
  findings: [] as Row[],
  tickets: [] as Row[],
};
const pick = (row: Row, select?: Record<string, unknown>) =>
  select ? Object.fromEntries(Object.keys(select).map((k) => [k, row[k]])) : row;
const matches = (row: Row, where: Record<string, unknown>) =>
  Object.entries(where).every(([k, v]) => {
    if (v && typeof v === "object" && "in" in v) return (v as { in: unknown[] }).in.includes(row[k]);
    return row[k] === v;
  });

vi.mock("@/lib/prisma", () => ({
  prisma: {
    integrationConfig: {
      findMany: vi.fn(async ({ where }: { where: Row }) => db.integrations.filter((r) => matches(r, where))),
    },
    scan: {
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => db.scans.find((s) => s.id === where.id) ?? null),
    },
    finding: {
      findMany: vi.fn(async ({ where, select }: { where: Row; select?: Record<string, unknown> }) =>
        db.findings.filter((f) => matches(f, where)).map((f) => pick(f, select)),
      ),
    },
    findingTicket: {
      findUnique: vi.fn(async ({ where }: { where: { projectId_system_target_fingerprint: Row } }) =>
        db.tickets.find((t) => matches(t, where.projectId_system_target_fingerprint)) ?? null,
      ),
      findMany: vi.fn(async ({ where }: { where: Row }) => db.tickets.filter((t) => matches(t, where))),
      create: vi.fn(async ({ data }: { data: Row }) => {
        const key = ["projectId", "system", "target", "fingerprint"];
        if (db.tickets.some((t) => key.every((k) => t[k] === data[k]))) throw Object.assign(new Error("unique"), { code: "P2002" });
        const row = { id: `t${db.tickets.length + 1}`, fixedNotifiedAt: null, missedScans: 0, ...data };
        db.tickets.push(row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: { where: { id: string }; data: Row }) => {
        const row = db.tickets.find((t) => t.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
    },
  },
}));
vi.mock("@/lib/token-encryption", () => ({ decryptSecret: (s: string) => s, encryptSecret: (s: string) => s }));
const orgConnection = vi.fn();
vi.mock("@/lib/azure-devops-connection", () => ({ getOrgAzureDevOpsAuth: (...a: unknown[]) => orgConnection(...a) }));

import {
  missesToConfirmFix,
  raiseAzureBoardsWorkItem,
  scanRanScanner,
  syncAzureBoardsForScan,
  type TicketFinding,
} from "./finding-tickets";
import type { AzureBoardsConfig } from "./types";

// ─── Fixtures ────────────────────────────────────────────────────────────────
const repo = { id: "p1", name: "payments-api", organizationId: "o1", azureProjectName: "Payments" };
const ALL_SCANNERS = ["SAST_LLM", "SAST_PATTERN", "SCA", "SECRETS_PATTERN", "SECRETS_LLM"];

function addIntegration(config: AzureBoardsConfig, id = "i1") {
  db.integrations.push({ id, name: "Boards", organizationId: "o1", kind: "AZURE_BOARDS", enabled: true, configEnc: JSON.stringify(config) });
  return { id, name: "Boards", config };
}
/** Like a real rescan: the project's previous scan and its findings are replaced. */
function addScan(id: string, opts: { scanType?: string; branch?: string | null; ran?: string[] } = {}) {
  db.findings = db.findings.filter((f) => !db.scans.some((s) => s.id === f.scanId));
  db.scans = [];
  const ran = opts.ran ?? ALL_SCANNERS;
  db.scans.push({
    id,
    status: "COMPLETED",
    scanType: opts.scanType ?? "FULL",
    branch: opts.branch === undefined ? "main" : opts.branch,
    scannerProgress: Object.fromEntries(ran.map((n) => [n, { status: "DONE" }])),
    project: repo,
  });
}
function addFinding(scanId: string, over: Partial<TicketFinding> & { id: string }): TicketFinding {
  const f = {
    scanId,
    scanner: "SAST_LLM",
    severity: "HIGH",
    status: "OPEN",
    title: "SQL injection",
    description: "desc",
    filePath: "src/orders.ts",
    startLine: 42,
    snippet: null,
    ruleId: "sqli",
    cveId: null,
    cweId: "CWE-89",
    riskScore: 50,
    ...over,
  };
  db.findings.push(f);
  return f;
}

type Call = { method: string; url: string; body: Array<{ path: string; value: unknown }> };
let calls: Call[] = [];
let nextId = 100;
beforeEach(() => {
  db.integrations = [];
  db.scans = [];
  db.findings = [];
  db.tickets = [];
  calls = [];
  nextId = 100;
  orgConnection.mockResolvedValue({ organization: "acme", pat: "conn-pat" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : [] });
      if (method === "GET") return Response.json({ fields: { "System.State": "Active" } });
      return Response.json({ id: method === "POST" ? nextId++ : 1 });
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const creates = () => calls.filter((c) => c.method === "POST");
const comments = () => calls.filter((c) => c.method === "PATCH");
const lastComment = () => String(comments().at(-1)?.body[0].value ?? "");
const auth = { organization: "acme", pat: "own" };

/** File a work item for one finding on a fresh scan of main. */
async function fileOne(finding: Partial<TicketFinding> = {}, config: AzureBoardsConfig = { organization: "acme" }) {
  const integration = addIntegration(config);
  addScan("s1");
  const f = addFinding("s1", { id: "f1", ...finding });
  await raiseAzureBoardsWorkItem({ integration, auth, repo, finding: f, branch: "main" });
  return f;
}

// ─── Tests ───────────────────────────────────────────────────────────────────
describe("helpers", () => {
  it("confirms LLM-scanner absences twice, rule-based ones once", () => {
    expect(missesToConfirmFix("SAST_LLM")).toBe(2);
    expect(missesToConfirmFix("ZERO_DAY")).toBe(2);
    expect(missesToConfirmFix("SCA")).toBe(1);
    expect(missesToConfirmFix("SECRETS_PATTERN")).toBe(1);
  });

  it("knows which scanners a scan actually ran", () => {
    expect(scanRanScanner({ SAST_LLM: { status: "DONE" } }, "SAST_LLM")).toBe(true);
    expect(scanRanScanner({ SAST_LLM: { status: "RUNNING" } }, "SAST_LLM")).toBe(false);
    expect(scanRanScanner({ SCA: { status: "DONE" } }, "SAST_LLM")).toBe(false);
    expect(scanRanScanner({ IAC_RULES: { status: "DONE" } }, "K8S")).toBe(true);
    expect(scanRanScanner(null, "SCA")).toBe(false);
  });
});

describe("raiseAzureBoardsWorkItem", () => {
  it("files an issue once, even from a later scan's finding row", async () => {
    const integration = addIntegration({ organization: "acme", pat: "own" });
    addScan("s1");
    const first = await raiseAzureBoardsWorkItem({ integration, auth, repo, finding: addFinding("s1", { id: "f1" }), branch: "main" });
    expect(first).toMatchObject({ id: "100", existing: false });
    // Rescan, line moved slightly: same fingerprint bucket.
    addScan("s2");
    const again = await raiseAzureBoardsWorkItem({ integration, auth, repo, finding: addFinding("s2", { id: "f2", startLine: 43 }), branch: "main" });
    expect(again).toMatchObject({ id: "100", existing: true });
    expect(creates()).toHaveLength(1);
    // The repository's own ADO project is used when none is configured.
    expect(creates()[0].url).toContain("/acme/Payments/_apis/wit/workitems/$Bug");
    expect(db.tickets[0]).toMatchObject({ findingId: "f2", scanner: "SAST_LLM", branch: "main", target: "https://dev.azure.com/acme/payments" });
  });

  it("needs a project when the repository isn't from Azure DevOps", async () => {
    const integration = addIntegration({ organization: "acme" });
    addScan("s1");
    await expect(
      raiseAzureBoardsWorkItem({ integration, auth, repo: { ...repo, azureProjectName: null }, finding: addFinding("s1", { id: "f1" }), branch: "main" }),
    ).rejects.toThrow(/No Azure DevOps project/);
    expect(calls).toHaveLength(0);
  });
});

describe("syncAzureBoardsForScan: filing", () => {
  it("auto-files open findings at the chosen severities, once per issue, highest first", async () => {
    addIntegration({ organization: "acme", autoCreateSeverities: ["CRITICAL", "HIGH"] });
    addScan("s1");
    addFinding("s1", { id: "low", severity: "LOW", ruleId: "a" });
    addFinding("s1", { id: "fp", status: "FALSE_POSITIVE", ruleId: "b" });
    addFinding("s1", { id: "high", severity: "HIGH", ruleId: "c" });
    addFinding("s1", { id: "crit", severity: "CRITICAL", ruleId: "d" });
    await syncAzureBoardsForScan("s1");
    expect(db.tickets.map((t) => t.findingId)).toEqual(["crit", "high"]);
    // Reused the org's Azure DevOps connection PAT.
    expect(orgConnection).toHaveBeenCalledWith("o1");

    // Rescan finds the same issues: nothing new is filed.
    addScan("s2");
    addFinding("s2", { id: "high2", severity: "HIGH", ruleId: "c" });
    addFinding("s2", { id: "crit2", severity: "CRITICAL", ruleId: "d" });
    await syncAzureBoardsForScan("s2");
    expect(creates()).toHaveLength(2);
    expect(db.tickets.map((t) => t.findingId)).toEqual(["crit2", "high2"]);
  });

  it("is manual-only by default and never files from pull request scans", async () => {
    addIntegration({ organization: "acme" });
    addScan("s1");
    addFinding("s1", { id: "f1", severity: "CRITICAL" });
    await syncAzureBoardsForScan("s1");
    db.integrations[0].configEnc = JSON.stringify({ organization: "acme", autoCreateSeverities: ["CRITICAL"] });
    addScan("pr", { scanType: "INCREMENTAL", branch: "feature" });
    addFinding("pr", { id: "f2", severity: "CRITICAL" });
    await syncAzureBoardsForScan("pr");
    expect(calls).toHaveLength(0);
  });

  it("caps automatic filing per scan", async () => {
    addIntegration({ organization: "acme", autoCreateSeverities: ["HIGH"] });
    addScan("s1");
    for (let i = 0; i < 30; i++) addFinding("s1", { id: `f${i}`, ruleId: `r${i}` });
    await syncAzureBoardsForScan("s1");
    expect(creates()).toHaveLength(25);
  });

  it("skips boards without credentials instead of failing the scan", async () => {
    orgConnection.mockResolvedValue(null);
    addIntegration({ organization: "acme", autoCreateSeverities: ["HIGH"] });
    addScan("s1");
    addFinding("s1", { id: "f1" });
    await expect(syncAzureBoardsForScan("s1")).resolves.toBeUndefined();
    expect(calls).toHaveLength(0);
  });
});

describe("syncAzureBoardsForScan: no longer detected", () => {
  it("rule-based issue: reports it gone after one clean scan, once, and again if it returns", async () => {
    await fileOne({ scanner: "SCA", ruleId: "CVE-2024-1" }, { organization: "acme", fixedState: "Resolved" });

    addScan("s2");
    await syncAzureBoardsForScan("s2", "https://pepper.local/scans/s2");
    expect(comments()).toHaveLength(1);
    expect(comments()[0].body.map((o) => o.path)).toEqual(["/fields/System.History", "/fields/System.State"]);
    expect(lastComment()).toMatch(/no longer detects this issue<\/b> in the latest scan of <code>main<\/code>/);
    expect(db.tickets[0].fixedNotifiedAt).toBeInstanceOf(Date);

    addScan("s3");
    await syncAzureBoardsForScan("s3");
    expect(comments()).toHaveLength(1);

    addScan("s4");
    addFinding("s4", { id: "f4", scanner: "SCA", ruleId: "CVE-2024-1" });
    await syncAzureBoardsForScan("s4");
    expect(comments()).toHaveLength(2);
    expect(lastComment()).toMatch(/detected this issue again/);
    expect(db.tickets[0]).toMatchObject({ fixedNotifiedAt: null, findingId: "f4", missedScans: 0 });
  });

  it("LLM issue: needs two scans in a row without it", async () => {
    await fileOne({ scanner: "SAST_LLM" });
    addScan("s2");
    await syncAzureBoardsForScan("s2");
    expect(comments()).toHaveLength(0);
    expect(db.tickets[0].missedScans).toBe(1);

    // Seen again: the count restarts.
    addScan("s3");
    addFinding("s3", { id: "f3" });
    await syncAzureBoardsForScan("s3");
    expect(db.tickets[0].missedScans).toBe(0);

    addScan("s4");
    await syncAzureBoardsForScan("s4");
    addScan("s5");
    await syncAzureBoardsForScan("s5");
    expect(comments()).toHaveLength(1);
    expect(lastComment()).toMatch(/latest 2 scans/);
  });

  it("says nothing when the scan couldn't have seen the issue", async () => {
    await fileOne({ scanner: "SCA", ruleId: "CVE-2024-1" });
    addScan("other-branch", { branch: "release/1.0" });
    await syncAzureBoardsForScan("other-branch");
    addScan("sast-only", { ran: ["SAST_LLM", "SAST_PATTERN"] });
    await syncAzureBoardsForScan("sast-only");
    expect(comments()).toHaveLength(0);
    expect(db.tickets[0]).toMatchObject({ missedScans: 0, fixedNotifiedAt: null });
  });

  it("LLM analysis off: SAST_LLM issues stay open", async () => {
    await fileOne({ scanner: "SAST_LLM" });
    for (const id of ["s2", "s3", "s4"]) {
      addScan(id, { ran: ["SCA", "SECRETS_PATTERN", "SAST_PATTERN"] });
      await syncAzureBoardsForScan(id);
    }
    expect(comments()).toHaveLength(0);
  });
});
