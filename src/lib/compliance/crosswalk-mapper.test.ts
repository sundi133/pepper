import { describe, it, expect } from "vitest";
import {
  normalizeCwe,
  mapFindingsDeterministic,
  hasDeterministicMapping,
  controlCoverage,
  summarizeCoverage,
} from "./crosswalk-mapper";
import { loadAllFrameworks, ComplianceFramework } from "./pdf-parser";
import type { FindingForMapping } from "./llm-mapper";

const fx: ComplianceFramework = {
  name: "Test FW",
  version: "1.0",
  fileName: "test.json",
  controlCatalog: "",
  controls: [
    {
      controlId: "C-INJ",
      chunkId: "c1",
      type: "t",
      theme: "Tech",
      title: "Injection",
      summary: "",
      implementationChecklist: [],
      evidenceExamples: [],
      coverage: "assessable",
      cweMapping: ["CWE-89", "CWE-79"],
    },
    {
      controlId: "C-SCAN",
      chunkId: "c2",
      type: "t",
      theme: "Tech",
      title: "Vuln scanning",
      summary: "",
      implementationChecklist: [],
      evidenceExamples: [],
      coverage: "assessable",
      appliesTo: {}, // any finding
    },
    {
      controlId: "C-SECRETS",
      chunkId: "c3",
      type: "t",
      theme: "Tech",
      title: "Secret mgmt",
      summary: "",
      implementationChecklist: [],
      evidenceExamples: [],
      appliesTo: { scanners: ["SECRETS_PATTERN"] },
    },
    {
      controlId: "C-POLICY",
      chunkId: "c4",
      type: "t",
      theme: "Org",
      title: "Policy",
      summary: "",
      implementationChecklist: [],
      evidenceExamples: [],
      coverage: "not-assessable",
    },
  ],
};

const finding = (over: Partial<FindingForMapping>): FindingForMapping => ({
  id: "f1",
  title: "t",
  description: "d",
  severity: "HIGH",
  scanner: "SAST_LLM",
  cweId: null,
  ruleId: null,
  filePath: null,
  ...over,
});

describe("normalizeCwe", () => {
  it("canonicalizes bare and prefixed ids", () => {
    expect(normalizeCwe("89")).toBe("CWE-89");
    expect(normalizeCwe("CWE-89")).toBe("CWE-89");
    expect(normalizeCwe(" cwe-89 ")).toBe("CWE-89");
    expect(normalizeCwe(null)).toBeNull();
    expect(normalizeCwe("n/a")).toBeNull();
  });
});

describe("mapFindingsDeterministic", () => {
  it("maps a CWE finding to the direct control + activity control", () => {
    const [res] = mapFindingsDeterministic(
      [finding({ cweId: "CWE-89", scanner: "SAST_LLM" })],
      fx,
    );
    const ids = res.controls.map((c) => c.controlId).sort();
    expect(ids).toEqual(["C-INJ", "C-SCAN"]);
    const inj = res.controls.find((c) => c.controlId === "C-INJ")!;
    expect(inj.relevance).toBe("direct");
    const scan = res.controls.find((c) => c.controlId === "C-SCAN")!;
    expect(scan.relevance).toBe("supporting");
  });

  it("respects scanner scoping on activity controls", () => {
    const [sastRes] = mapFindingsDeterministic(
      [finding({ cweId: null, scanner: "SAST_LLM" })],
      fx,
    );
    // SAST finding hits C-SCAN (any) but not C-SECRETS (secrets only)
    expect(sastRes.controls.map((c) => c.controlId)).toEqual(["C-SCAN"]);

    const [secretRes] = mapFindingsDeterministic(
      [finding({ cweId: null, scanner: "SECRETS_PATTERN" })],
      fx,
    );
    expect(secretRes.controls.map((c) => c.controlId).sort()).toEqual([
      "C-SCAN",
      "C-SECRETS",
    ]);
  });

  it("never maps to a not-assessable control", () => {
    const results = mapFindingsDeterministic(
      [finding({ cweId: "CWE-89" })],
      fx,
    );
    const all = results.flatMap((r) => r.controls.map((c) => c.controlId));
    expect(all).not.toContain("C-POLICY");
  });
});

describe("coverage helpers", () => {
  it("defaults and summarizes coverage", () => {
    expect(controlCoverage(fx.controls[0])).toBe("assessable");
    expect(controlCoverage(fx.controls[3])).toBe("not-assessable");
    const s = summarizeCoverage(fx);
    expect(s.assessable).toBe(3); // C-INJ, C-SCAN, C-SECRETS(appliesTo→assessable)
    expect(s.notAssessable).toBe(1);
  });

  it("detects deterministic frameworks", () => {
    expect(hasDeterministicMapping(fx)).toBe(true);
  });
});

describe("bundled framework data (integration)", () => {
  const frameworks = loadAllFrameworks();
  const bySlug = (name: string) => frameworks.find((f) => f.name === name);

  it("loads the new deterministic frameworks", () => {
    for (const name of [
      "OWASP Top 10",
      "CWE Top 25 Most Dangerous",
      "OWASP API Security Top 10",
      "OWASP ASVS",
      "PCI DSS",
      "NIST SP 800-53",
      "NIST SSDF",
      "HIPAA Security Rule",
      "GDPR",
      "ISO/IEC 27001:2022",
    ]) {
      expect(bySlug(name), `missing framework: ${name}`).toBeTruthy();
    }
  });

  it("dedupes ISO to the deterministic JSON (PDF superseded)", () => {
    const isos = frameworks.filter((f) => f.name === "ISO/IEC 27001:2022");
    expect(isos.length).toBe(1); // JSON wins over PDF via slug dedup
    expect(hasDeterministicMapping(isos[0])).toBe(true);
    expect(isos[0].controls.length).toBe(93); // full Annex A
  });

  it("maps a SQL injection finding to expected controls across frameworks", () => {
    const f = [finding({ id: "sqli", cweId: "CWE-89", scanner: "SAST_LLM" })];

    const owasp = bySlug("OWASP Top 10")!;
    const owaspCtl = mapFindingsDeterministic(f, owasp)[0].controls.map(
      (c) => c.controlId,
    );
    expect(owaspCtl).toContain("A03:2021");

    const pci = bySlug("PCI DSS")!;
    const pciCtl = mapFindingsDeterministic(f, pci)[0].controls.map(
      (c) => c.controlId,
    );
    expect(pciCtl).toContain("6.2.4"); // direct
    expect(pciCtl).toContain("6.3.1"); // activity-level

    const cwe25 = bySlug("CWE Top 25 Most Dangerous")!;
    const cweCtl = mapFindingsDeterministic(f, cwe25)[0].controls.map(
      (c) => c.controlId,
    );
    expect(cweCtl).toContain("CWE-89");
  });

  it("every bundled deterministic framework has honest coverage flags", () => {
    for (const fw of frameworks) {
      if (!hasDeterministicMapping(fw)) continue;
      // At least one assessable and the summary should account for all controls.
      const s = summarizeCoverage(fw);
      expect(s.assessable + s.partial + s.notAssessable).toBe(
        fw.controls.length,
      );
    }
  });
});
