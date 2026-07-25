import { describe, it, expect } from "vitest";
import {
  buildVexStatements,
  generateCycloneDxVex,
  generateOpenVex,
  justificationForFinding,
  statusForFinding,
  summarizeVex,
  type VexSourceFinding,
  type VexStatement,
} from "./vex-generator";

const meta = {
  productName: "demo-app",
  productId: "pkg:generic/demo-app@abc123",
  scanId: "scan_1",
  commitSha: "abc123",
  branch: "main",
  generatedAt: "2026-07-25T00:00:00.000Z",
};

function finding(over: Partial<VexSourceFinding> = {}): VexSourceFinding {
  return {
    cveId: "CVE-2024-0001",
    ruleId: "GHSA-aaaa-bbbb-cccc",
    title: "Prototype pollution in deepmerge",
    severity: "HIGH",
    status: "OPEN",
    metadata: {
      packageName: "deepmerge",
      packageVersion: "1.0.0",
      ecosystem: "npm",
      fixVersion: "1.0.1",
    },
    ...over,
  };
}

const purlFor = (name: string, version: string, ecosystem: string) =>
  `pkg:${ecosystem}/${name}@${version}`;

describe("status mapping", () => {
  it("maps finding statuses to VEX statuses", () => {
    expect(statusForFinding("OPEN")).toBe("affected");
    expect(statusForFinding("IN_PROGRESS")).toBe("affected");
    expect(statusForFinding("FALSE_POSITIVE")).toBe("not_affected");
    expect(statusForFinding("RESOLVED")).toBe("fixed");
  });

  it("treats an accepted risk as affected rather than not_affected", () => {
    // Claiming not_affected for a risk we chose to live with would be false.
    expect(statusForFinding("ACCEPTED_RISK")).toBe("affected");
  });

  it("defaults unknown or missing statuses to affected", () => {
    expect(statusForFinding(null)).toBe("affected");
    expect(statusForFinding("SOMETHING_NEW")).toBe("affected");
  });
});

describe("justification derivation", () => {
  it("maps a dev-only dependency to component_not_present", () => {
    expect(
      justificationForFinding(finding({ metadata: { isDev: true } })),
    ).toBe("component_not_present");
  });

  it("maps an explicit unreachable verdict to not_in_execute_path", () => {
    expect(
      justificationForFinding(finding({ metadata: { reachable: false } })),
    ).toBe("vulnerable_code_not_in_execute_path");
  });

  it("maps an unused dependency note to vulnerable_code_not_present", () => {
    expect(
      justificationForFinding(
        finding({ statusNote: "package not imported in source" }),
      ),
    ).toBe("vulnerable_code_not_present");
  });

  it("maps a non-attacker-controlled note to the matching justification", () => {
    expect(
      justificationForFinding(
        finding({ statusNote: "input cannot be controlled by an attacker" }),
      ),
    ).toBe("vulnerable_code_cannot_be_controlled_by_adversary");
  });

  it("maps a compensating control to inline_mitigations_already_exist", () => {
    expect(
      justificationForFinding(
        finding({ statusNote: "WAF rule blocks this payload" }),
      ),
    ).toBe("inline_mitigations_already_exist");
  });

  it("returns undefined when no listed justification applies", () => {
    // Inventing one would make the VEX assert something never established.
    expect(
      justificationForFinding(finding({ statusNote: "team reviewed, seems fine" })),
    ).toBeUndefined();
  });
});

describe("buildVexStatements", () => {
  it("skips findings with no vulnerability identifier", () => {
    expect(
      buildVexStatements([finding({ cveId: null, metadata: {} })]),
    ).toEqual([]);
  });

  it("falls back to the OSV id when there is no CVE", () => {
    const statements = buildVexStatements([
      finding({ cveId: null, metadata: { osvId: "GHSA-xxxx-yyyy-zzzz" } }),
    ]);
    expect(statements[0].vulnerabilityId).toBe("GHSA-xxxx-yyyy-zzzz");
  });

  it("attaches an action statement for affected findings", () => {
    const [s] = buildVexStatements([finding()]);
    expect(s.status).toBe("affected");
    expect(s.actionStatement).toContain("1.0.1");
  });

  it("names the introducing dependency in the action statement", () => {
    const [s] = buildVexStatements([
      finding({
        metadata: {
          packageName: "qs",
          packageVersion: "6.9.0",
          ecosystem: "npm",
          fixVersion: "6.11.0",
          introducedBy: "express",
        },
      }),
    ]);
    expect(s.actionStatement).toContain("express");
  });

  it("attaches a justification for a suppressed finding", () => {
    const [s] = buildVexStatements([
      finding({ status: "FALSE_POSITIVE", metadata: { reachable: false } }),
    ]);
    expect(s.status).toBe("not_affected");
    expect(s.justification).toBe("vulnerable_code_not_in_execute_path");
    expect(s.impactStatement).toBeUndefined();
  });

  it("falls back to an impact statement carrying the human reason", () => {
    const [s] = buildVexStatements([
      finding({
        status: "FALSE_POSITIVE",
        statusNote: "Only affects the Windows build, which we do not ship",
      }),
    ]);
    // Spec requires justification OR impact_statement — never neither.
    expect(s.justification).toBeUndefined();
    expect(s.impactStatement).toContain("Windows");
  });

  it("always provides justification or impact statement for not_affected", () => {
    const [s] = buildVexStatements([
      finding({ status: "FALSE_POSITIVE", statusNote: null }),
    ]);
    expect(Boolean(s.justification || s.impactStatement)).toBe(true);
  });

  it("records an accepted risk as affected with the acceptance rationale", () => {
    // Generic upgrade advice here would misrepresent a formal decision not to
    // remediate as "remediation pending".
    const [s] = buildVexStatements([
      finding({ status: "ACCEPTED_RISK", statusNote: "Accepted until Q4 rewrite" }),
    ]);
    expect(s.status).toBe("affected");
    expect(s.actionStatement).toMatch(/^Risk accepted:/);
    expect(s.actionStatement).toContain("Q4");
  });

  it("still surfaces the available fix on an accepted risk", () => {
    const [s] = buildVexStatements([
      finding({ status: "ACCEPTED_RISK", statusNote: "Accepted until Q4 rewrite" }),
    ]);
    expect(s.actionStatement).toContain("1.0.1");
  });

  it("builds a subcomponent purl matching the SBOM", () => {
    const [s] = buildVexStatements([finding()], { purlFor });
    expect(s.subcomponentPurl).toBe("pkg:npm/deepmerge@1.0.0");
  });

  it("collapses duplicate findings for the same vulnerability and component", () => {
    const statements = buildVexStatements([finding(), finding()], { purlFor });
    expect(statements).toHaveLength(1);
  });

  it("prefers a decided status over a default open one", () => {
    const statements = buildVexStatements(
      [finding({ status: "OPEN" }), finding({ status: "FALSE_POSITIVE" })],
      { purlFor },
    );
    expect(statements).toHaveLength(1);
    expect(statements[0].status).toBe("not_affected");
  });

  it("keeps separate statements for the same CVE in different components", () => {
    const statements = buildVexStatements(
      [
        finding(),
        finding({
          metadata: {
            packageName: "other",
            packageVersion: "2.0.0",
            ecosystem: "npm",
          },
        }),
      ],
      { purlFor },
    );
    expect(statements).toHaveLength(2);
  });

  it("sorts statements by vulnerability id for stable output", () => {
    const statements = buildVexStatements(
      [
        finding({ cveId: "CVE-2024-0009" }),
        finding({ cveId: "CVE-2024-0002" }),
      ],
      { purlFor },
    );
    expect(statements.map((s) => s.vulnerabilityId)).toEqual([
      "CVE-2024-0002",
      "CVE-2024-0009",
    ]);
  });
});

describe("OpenVEX document", () => {
  const statements: VexStatement[] = buildVexStatements(
    [
      finding(),
      finding({
        cveId: "CVE-2024-0002",
        status: "FALSE_POSITIVE",
        metadata: {
          packageName: "lodash",
          packageVersion: "4.17.21",
          ecosystem: "npm",
          reachable: false,
        },
      }),
      finding({ cveId: "CVE-2024-0003", status: "RESOLVED" }),
    ],
    { purlFor },
  );

  const doc = JSON.parse(generateOpenVex(statements, meta));

  it("emits a valid 0.2.0 envelope", () => {
    expect(doc["@context"]).toBe("https://openvex.dev/ns/v0.2.0");
    expect(doc["@id"]).toContain("scan_1");
    expect(doc.author).toBe("Pepper");
    expect(doc.timestamp).toBe(meta.generatedAt);
    expect(doc.version).toBe(1);
  });

  it("emits one statement per assertion", () => {
    expect(doc.statements).toHaveLength(3);
  });

  it("references the product and the vulnerable subcomponent", () => {
    const s = doc.statements.find(
      (x: { vulnerability: { name: string } }) =>
        x.vulnerability.name === "CVE-2024-0001",
    );
    expect(s.products[0]["@id"]).toBe(meta.productId);
    expect(s.products[0].subcomponents[0]["@id"]).toBe(
      "pkg:npm/deepmerge@1.0.0",
    );
  });

  it("uses spec field names for justification and statements", () => {
    const notAffected = doc.statements.find(
      (x: { status: string }) => x.status === "not_affected",
    );
    expect(notAffected.justification).toBe(
      "vulnerable_code_not_in_execute_path",
    );

    const affected = doc.statements.find(
      (x: { status: string }) => x.status === "affected",
    );
    expect(affected.action_statement).toBeTruthy();
  });

  it("emits fixed status for resolved findings", () => {
    expect(
      doc.statements.some((x: { status: string }) => x.status === "fixed"),
    ).toBe(true);
  });

  it("never emits not_affected without a justification or impact statement", () => {
    for (const s of doc.statements) {
      if (s.status === "not_affected") {
        expect(Boolean(s.justification || s.impact_statement)).toBe(true);
      }
    }
  });

  it("produces an empty statement list for no findings", () => {
    const empty = JSON.parse(generateOpenVex([], meta));
    expect(empty.statements).toEqual([]);
  });
});

describe("CycloneDX VEX document", () => {
  const statements = buildVexStatements(
    [
      finding(),
      finding({
        cveId: "CVE-2024-0002",
        status: "FALSE_POSITIVE",
        metadata: {
          packageName: "lodash",
          packageVersion: "4.17.21",
          ecosystem: "npm",
          reachable: false,
        },
      }),
      finding({ cveId: "CVE-2024-0003", status: "RESOLVED" }),
    ],
    { purlFor },
  );

  const doc = JSON.parse(generateCycloneDxVex(statements, meta));

  it("emits a valid 1.5 envelope", () => {
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.5");
    expect(doc.serialNumber).toMatch(/^urn:uuid:/);
    expect(doc.metadata.component.name).toBe("demo-app");
  });

  it("translates VEX status into CycloneDX analysis state vocabulary", () => {
    const states = doc.vulnerabilities.map(
      (v: { analysis: { state: string } }) => v.analysis.state,
    );
    expect(states).toContain("exploitable"); // affected
    expect(states).toContain("not_affected");
    expect(states).toContain("resolved"); // fixed
  });

  it("translates justifications into CycloneDX vocabulary", () => {
    const notAffected = doc.vulnerabilities.find(
      (v: { analysis: { state: string } }) => v.analysis.state === "not_affected",
    );
    // OpenVEX vulnerable_code_not_in_execute_path -> CycloneDX code_not_reachable
    expect(notAffected.analysis.justification).toBe("code_not_reachable");
  });

  it("points affects at the component purl", () => {
    const v = doc.vulnerabilities.find(
      (x: { id: string }) => x.id === "CVE-2024-0001",
    );
    expect(v.affects[0].ref).toBe("pkg:npm/deepmerge@1.0.0");
  });

  it("carries severity ratings", () => {
    const v = doc.vulnerabilities.find(
      (x: { id: string }) => x.id === "CVE-2024-0001",
    );
    expect(v.ratings[0].severity).toBe("high");
  });
});

describe("summarizeVex", () => {
  it("counts statements by status", () => {
    const statements = buildVexStatements(
      [
        finding(),
        finding({ cveId: "CVE-2024-0002", status: "FALSE_POSITIVE" }),
        finding({ cveId: "CVE-2024-0003", status: "RESOLVED" }),
      ],
      { purlFor },
    );
    expect(summarizeVex(statements)).toEqual({
      affected: 1,
      not_affected: 1,
      fixed: 1,
      under_investigation: 0,
    });
  });
});
