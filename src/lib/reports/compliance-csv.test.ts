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
    expect(lines[0]).toBe("framework,version,controlId,control,section,levels,coverage,status,findings,criticalHigh,findingIds,category,stigId");
    expect(lines[1]).toBe("OWASP ASVS,4.0.3,V5.3.4,Parameterised queries,V5 Validation,L1 L2 L3,assessable,Gap found,1,1,f1,,");
    expect(lines[2]).toBe("OWASP ASVS,4.0.3,V1.1.1,Secure SDLC,V1 Architecture,L2 L3,not-assessable,Not covered by code scanning,0,0,,,");
  });

  it("adds the STIG category and STIG ID for STIG requirements", () => {
    const stig = {
      name: "DISA ASD STIG",
      fileName: "x",
      controlCatalog: "",
      controls: [
        { controlId: "V-222607", title: "SQLi", theme: "SI System and Information Integrity", category: "CAT I", stig: { stigId: "APSC-DV-002540" } },
      ],
    } as unknown as ComplianceFramework;
    const stigInput: ComplianceExportInput = {
      ...input,
      reports: [
        {
          framework: "DISA ASD STIG",
          version: "V6R5",
          totalControls: 1,
          impactedControls: 1,
          buckets: {
            gapsFound: [{ controlId: "V-222607", title: "SQLi", coverage: "assessable", findingCount: 1, criticalHighCount: 1 }],
            noIssuesDetected: [],
            notCovered: [],
          },
          findings: [],
        },
      ],
    };
    const lines = buildComplianceCsv(stigInput, [stig], "controls").trimEnd().split("\r\n");
    expect(lines[1]).toBe("DISA ASD STIG,V6R5,V-222607,SQLi,SI System and Information Integrity,,assessable,Gap found,1,1,,CAT I,APSC-DV-002540");
  });

  it("writes finding mappings with formula-safe cells", () => {
    const lines = buildComplianceCsv(input, [framework], "findings").trimEnd().split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(`"'=cmd|' /C calc'!A0"`.replace(/^"|"$/g, ""));
    expect(csvCell("+1")).toBe("'+1");
  });
});
