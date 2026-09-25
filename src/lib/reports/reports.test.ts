import { describe, expect, it } from "vitest";
import {
  buildExecutiveHtml,
  buildExecutivePdf,
  buildExecutiveSummary,
  type ExecutiveFinding,
  type ExecutiveScan,
} from "./executive-report";
import {
  buildComplianceHtml,
  buildCompliancePdf,
  type ComplianceExportInput,
} from "./compliance-report";

const scan: ExecutiveScan = {
  id: "scan1",
  status: "COMPLETED",
  scanType: "FULL",
  branch: "main",
  commitSha: "abcdef1234567890",
  sourceType: "GIT_CLONE",
  sourceRef: null,
  gateResult: "FAILED",
  createdAt: new Date("2026-09-01T10:00:00Z"),
  completedAt: new Date("2026-09-01T10:30:00Z"),
  filesScanned: 120,
  depsScanned: 40,
  autoResolvedCount: 2,
  project: { name: "acme/<shop>", repoUrl: "https://github.com/acme/shop" },
};

function finding(over: Partial<ExecutiveFinding>): ExecutiveFinding {
  return {
    id: Math.random().toString(36).slice(2),
    scanner: "SAST_LLM",
    severity: "MEDIUM",
    title: "Issue",
    status: "OPEN",
    cweId: null,
    ...over,
  };
}

describe("buildExecutiveSummary", () => {
  it("counts only open / in-progress findings toward posture", () => {
    const s = buildExecutiveSummary(scan, [
      finding({ severity: "CRITICAL", status: "RESOLVED" }),
      finding({ severity: "CRITICAL", status: "FALSE_POSITIVE" }),
      finding({ severity: "HIGH", status: "IN_PROGRESS" }),
      finding({ severity: "LOW" }),
    ]);
    expect(s.active.critical).toBe(0);
    expect(s.active.high).toBe(1);
    expect(s.posture.level).toBe("HIGH");
    expect(s.statusCounts).toMatchObject({ open: 1, inProgress: 1, resolved: 1, falsePositive: 1 });
  });

  it("reports LOW posture when nothing is open", () => {
    const s = buildExecutiveSummary(scan, []);
    expect(s.posture.level).toBe("LOW");
    expect(s.topRisks).toHaveLength(0);
  });

  it("ranks top risks by severity then risk score and prefers report titles/impact", () => {
    const s = buildExecutiveSummary(scan, [
      finding({ severity: "MEDIUM", title: "m" }),
      finding({ severity: "HIGH", title: "h-low", riskScore: 10 }),
      finding({ severity: "HIGH", title: "h-high", riskScore: 90 }),
      finding({
        severity: "CRITICAL",
        title: "raw",
        isNew: true,
        metadata: {
          reportSections: {
            vulnerabilityName: "SQL injection in checkout",
            impact: "Attackers can read every customer order. More detail follows.",
          },
        },
      }),
    ]);
    expect(s.topRisks.map((r) => r.title)).toEqual([
      "SQL injection in checkout",
      "h-high",
      "h-low",
      "m",
    ]);
    expect(s.topRisks[0].impact).toBe("Attackers can read every customer order.");
    expect(s.topRisks[0].isNew).toBe(true);
    expect(s.newFindings).toBe(1);
  });

  it("groups repeated issues into one top risk with an occurrence count", () => {
    const s = buildExecutiveSummary(scan, [
      finding({ severity: "CRITICAL", title: "Exposed DATABASE_PASSWORD" }),
      finding({ severity: "CRITICAL", title: "Exposed DATABASE_PASSWORD", isNew: true }),
      finding({ severity: "CRITICAL", title: "exposed database_password " }),
      finding({ severity: "HIGH", title: "SQL injection" }),
    ]);
    expect(s.topRisks).toHaveLength(2);
    expect(s.topRisks[0]).toMatchObject({ title: "Exposed DATABASE_PASSWORD", occurrences: 3, isNew: true });
    expect(s.topRisks[1]).toMatchObject({ title: "SQL injection", occurrences: 1 });
  });

  it("adds context-specific recommendations", () => {
    const s = buildExecutiveSummary(scan, [
      finding({ severity: "CRITICAL", scanner: "SECRETS_PATTERN" }),
      finding({ severity: "HIGH", scanner: "SCA" }),
    ]);
    const text = s.recommendations.join(" ");
    expect(text).toMatch(/release blockers/);
    expect(text).toMatch(/Rotate any exposed credentials/);
    expect(text).toMatch(/dependencies/);
    expect(text).toMatch(/build gate failed/);
  });
});

describe("executive renderers", () => {
  const summary = buildExecutiveSummary(scan, [
    finding({ severity: "CRITICAL", title: "<script>alert(1)</script>", cweId: "CWE-89" }),
    finding({ severity: "MEDIUM" }),
  ]);

  it("escapes user-controlled content in HTML", () => {
    const html = buildExecutiveHtml(summary);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("acme/&lt;shop&gt;");
    expect(html).toContain("Executive Security Summary");
  });

  it("produces a PDF", async () => {
    const pdf = await buildExecutivePdf(summary);
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  });
});

describe("compliance renderers", () => {
  const input: ComplianceExportInput = {
    projectName: "acme/shop",
    repoUrl: null,
    commitSha: "abcdef1234567890",
    scanDate: new Date("2026-09-01T10:30:00Z"),
    mode: "deep",
    model: "google/gemini-2.5-flash",
    totalFindings: 3,
    reports: [
      {
        framework: "GDPR",
        version: "Regulation (EU) 2016/679",
        mappingSource: "agentic",
        totalControls: 3,
        impactedControls: 1,
        buckets: {
          gapsFound: [
            { controlId: "Art.32", title: "Security of <processing>", theme: "Technical", findingCount: 2, criticalHighCount: 1 },
          ],
          noIssuesDetected: [
            { controlId: "Art.25", title: "Data protection by design", findingCount: 0, criticalHighCount: 0 },
          ],
          notCovered: [
            { controlId: "Art.37", title: "DPO designation", findingCount: 0, criticalHighCount: 0, reason: "Not assessable by SAST" },
          ],
        },
        findings: [
          { id: "f1", title: "Plaintext passwords", severity: "HIGH", filePath: "auth.ts", startLine: 3, controls: [{ controlId: "Art.32", title: "Security of processing", relevance: "direct" }] },
          { id: "f2", title: "Unmapped", severity: "LOW", controls: [] },
        ],
      },
    ],
  };

  it("renders frameworks, gaps and escapes content in HTML", () => {
    const html = buildComplianceHtml(input);
    expect(html).toContain("GDPR");
    expect(html).toContain("Art.32");
    expect(html).toContain("Security of &lt;processing&gt;");
    expect(html).toContain("Plaintext passwords");
    expect(html).not.toContain("Unmapped");
    expect(html).toContain("Agentic · google/gemini-2.5-flash");
    // 1 gap, 1 clear → 50% of assessable controls clear
    expect(html).toContain("50%");
  });

  it("tolerates cached reports without coverage buckets", () => {
    const html = buildComplianceHtml({
      ...input,
      reports: [{ ...input.reports[0], buckets: undefined }],
    });
    expect(html).toContain("GDPR");
  });

  it("produces a PDF", async () => {
    const pdf = await buildCompliancePdf(input);
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  });
});
