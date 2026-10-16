/** Shared scan data for the custom report tests. */
import { buildReportData, type ReportFinding, type ReportSources } from "./tools";

type FindingInput = Partial<Omit<ReportFinding, "ref">> & { id: string };

export function finding(f: FindingInput): Omit<ReportFinding, "ref"> {
  return {
    scanner: "SAST_PATTERN",
    severity: "HIGH",
    title: `Finding ${f.id}`,
    description: "desc",
    status: "OPEN",
    filePath: "src/app.ts",
    startLine: 10,
    ruleId: null,
    cweId: null,
    cveId: null,
    confidence: 0.9,
    riskScore: 50,
    isNew: null,
    snippet: null,
    metadata: null,
    ...f,
  };
}

/** Four findings; refs by severity: F1 = critical, F2/F3 = high, F4 = low (false positive). */
export function sampleData() {
  return buildReportData(
    {
      id: "scan_1",
      projectName: "payments",
      repoUrl: "https://github.com/acme/payments",
      branch: "main",
      commitSha: "abc1234",
      scanType: "FULL",
      status: "COMPLETED",
      gateResult: "FAILED",
      createdAt: new Date("2026-10-01T10:00:00Z"),
      completedAt: new Date("2026-10-01T10:05:00Z"),
      filesScanned: 120,
      depsScanned: 300,
    },
    [
      finding({ id: "cmabcdefghij0123456789xyz", severity: "CRITICAL", title: "SQL injection", cweId: "CWE-89", isNew: true }),
      finding({ id: "f-high-1", title: "XSS in profile", cweId: "CWE-79", riskScore: 80 }),
      finding({
        id: "f-high-2",
        scanner: "SCA",
        title: "lodash prototype pollution",
        riskScore: 40,
        metadata: { packageName: "lodash", packageVersion: "4.17.15", fixVersion: "4.17.21" },
      }),
      finding({ id: "f-low-fp", severity: "LOW", title: "Weak hash", status: "FALSE_POSITIVE" }),
    ],
  );
}

export function stubSources(overrides: Partial<ReportSources> = {}): ReportSources {
  return {
    delta: async () => ({
      baselineScanId: "scan_0",
      baselineScanType: "FULL",
      baselineCompletedAt: "2026-09-01T00:00:00.000Z",
      newFindingIds: ["cmabcdefghij0123456789xyz"],
      fixed: [{ severity: "MEDIUM", title: "Open redirect", filePath: "src/r.ts", scanner: "SAST_PATTERN" }],
      fixedComparable: true,
      persistingCount: 2,
    }),
    compliance: async () => ({ available: ["OWASP Top 10"], reports: [] }),
    dependencies: async () => ({ sbomAvailable: true, components: 300, ecosystems: { npm: 300 }, licenses: [] }),
    ...overrides,
  };
}
