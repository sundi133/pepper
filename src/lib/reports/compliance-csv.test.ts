import { describe, expect, it } from "vitest";
import { buildComplianceCsv, csvCell } from "./compliance-csv";
import type { ComplianceExportInput } from "./compliance-report";
import type { ComplianceFramework } from "@/lib/compliance/pdf-parser";

const framework = {
  name: "OWASP ASVS",
  fileName: "x",
  controlCatalog: "",
  controls: [
    { controlId: "V5.3.4", title: "Parameterised queries", theme: "V5 Validation", levels: [1, 2, 3] },
    { controlId: "V1.1.1", title: "Secure SDLC", theme: "V1 Architecture", levels: [2, 3] },
  ],
} as unknown as ComplianceFramework;

const input: ComplianceExportInput = {
  projectName: "p",
  repoUrl: null,
  commitSha: null,
  scanDate: new Date(0),
  mode: "fast",
  model: null,
  totalFindings: 1,
  reports: [
    {
      framework: "OWASP ASVS",
      version: "4.0.3",
      totalControls: 2,
      impactedControls: 1,
      buckets: {
        gapsFound: [{ controlId: "V5.3.4", title: "Parameterised queries", coverage: "assessable", findingCount: 1, criticalHighCount: 1 }],
        noIssuesDetected: [],
        notCovered: [{ controlId: "V1.1.1", title: "Secure SDLC", coverage: "not-assessable", findingCount: 0, criticalHighCount: 0 }],
      },
      findings: [
        { id: "f1", title: "=cmd|' /C calc'!A0", severity: "HIGH", filePath: "a.ts", startLine: 3, status: "OPEN", controls: [{ controlId: "V5.3.4", title: "Parameterised queries", relevance: "direct", reasoning: "CWE-89" }] },
      ],
    },
  ],
};

describe("compliance CSV", () => {
  it("writes one row per control, with levels and status", () => {
    const lines = buildComplianceCsv(input, [framework], "controls").trimEnd().split("\r\n");
    expect(lines[0]).toBe("framework,version,controlId,control,section,levels,coverage,status,findings,criticalHigh,findingIds");
    expect(lines[1]).toBe("OWASP ASVS,4.0.3,V5.3.4,Parameterised queries,V5 Validation,L1 L2 L3,assessable,Gap found,1,1,f1");
    expect(lines[2]).toBe("OWASP ASVS,4.0.3,V1.1.1,Secure SDLC,V1 Architecture,L2 L3,not-assessable,Not covered by code scanning,0,0,");
  });

  it("writes finding mappings with formula-safe cells", () => {
    const lines = buildComplianceCsv(input, [framework], "findings").trimEnd().split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(`"'=cmd|' /C calc'!A0"`.replace(/^"|"$/g, ""));
    expect(csvCell("+1")).toBe("'+1");
  });
});
