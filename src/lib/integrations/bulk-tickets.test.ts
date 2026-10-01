import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/prisma", () => ({ prisma: {} }));
vi.mock("@/lib/token-encryption", () => ({ decryptSecret: (s: string) => s }));
const raiseBoards = vi.fn();
const raiseJira = vi.fn();
const boardsAuth = vi.fn();
vi.mock("./finding-tickets", () => ({
  boardsAuthResolver: () => (...a: unknown[]) => boardsAuth(...a),
  raiseAzureBoardsWorkItem: (...a: unknown[]) => raiseBoards(...a),
  raiseJiraIssue: (...a: unknown[]) => raiseJira(...a),
}));

import { raiseTicketsForFindings, type TicketIntegration } from "./bulk-tickets";

const repo = { id: "p1", name: "app", organizationId: "o1", azureProjectName: null };
const finding = (id: string) => ({
  id,
  scanId: "s1",
  scanner: "SAST_PATTERN",
  severity: "HIGH",
  status: "OPEN",
  title: `Finding ${id}`,
  description: "d",
  filePath: "src/a.js",
  startLine: 1,
  snippet: null,
  ruleId: "r",
  cveId: null,
  cweId: null,
  branch: "main",
});
const boards: TicketIntegration = { id: "b1", name: "Azure Boards (poc2)", kind: "AZURE_BOARDS", config: { organization: "DefaultCollection", project: "poc2" } };
const jira: TicketIntegration = { id: "j1", name: "Jira SEC", kind: "JIRA", config: { baseUrl: "https://x", email: "e", apiToken: "t", projectKey: "SEC" } };

beforeEach(() => {
  vi.clearAllMocks();
  boardsAuth.mockResolvedValue({ organization: "DefaultCollection", pat: "p" });
});

describe("raiseTicketsForFindings", () => {
  it("files every finding in every chosen system and counts new vs already tracked", async () => {
    raiseBoards.mockImplementation(async ({ finding: f }: { finding: { id: string } }) => ({ id: `1${f.id}`, url: `u/${f.id}`, existing: f.id === "a" }));
    raiseJira.mockImplementation(async ({ finding: f }: { finding: { id: string } }) => ({ key: `SEC-${f.id}`, url: `j/${f.id}`, existing: false }));
    const results = await raiseTicketsForFindings({ orgId: "o1", repo, findings: [finding("a"), finding("b")], integrations: [boards, jira] });
    expect(results.map((r) => [r.name, r.created, r.existing, r.failed.length])).toEqual([
      ["Azure Boards (poc2)", 1, 1, 0],
      ["Jira SEC", 2, 0, 0],
    ]);
    expect(results[1].tickets.map((t) => t.id)).toEqual(["SEC-a", "SEC-b"]);
  });

  it("reports failures per finding and stops a system after repeated identical errors", async () => {
    raiseBoards.mockRejectedValue(new Error("the PAT was rejected"));
    raiseJira.mockResolvedValue({ key: "SEC-1", url: "j", existing: false });
    const findings = ["a", "b", "c", "d", "e"].map(finding);
    const [b, j] = await raiseTicketsForFindings({ orgId: "o1", repo, findings, integrations: [boards, jira] });
    expect(b.failed).toHaveLength(3);
    expect(b.failed[0]).toEqual({ findingId: "a", title: "Finding a", error: "the PAT was rejected" });
    expect(b.stoppedEarly).toMatch(/2 finding\(s\) not attempted/);
    // One broken system doesn't stop the others.
    expect(j.created).toBe(5);
  });

  it("fails a board with no credentials instead of throwing", async () => {
    boardsAuth.mockResolvedValue(null);
    const [b] = await raiseTicketsForFindings({ orgId: "o1", repo, findings: [finding("a")], integrations: [boards] });
    expect(b.failed[0].error).toMatch(/No PAT/);
    expect(raiseBoards).not.toHaveBeenCalled();
  });
});

describe("ticketTargetDetail", () => {
  it("tells integrations of the same kind apart without secrets", async () => {
    const { ticketTargetDetail } = await import("./bulk-tickets");
    expect(ticketTargetDetail({ ...boards, config: { organization: "x", project: "poc2", workItemType: "Issue", pat: "secret" } })).toBe("poc2 · Issue");
    expect(ticketTargetDetail({ ...boards, config: { organization: "x" } })).toBe("each repository's project · Bug, or Issue");
    expect(ticketTargetDetail(jira)).toBe("SEC · Bug");
  });
});
