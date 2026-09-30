import { describe, expect, it } from "vitest";
import { hasDeterministicMapping, mapFindingsDeterministic, normalizeRuleId } from "./crosswalk-mapper";
import { loadAllFrameworks } from "./pdf-parser";
import { buildFrameworkReport, complianceCacheKey, toFindingsForMapping, type FindingRow } from "./report-run";
import { focusedCatalog } from "./agentic-mapper";
import type { FindingForMapping } from "./llm-mapper";

const frameworks = loadAllFrameworks();
const fw = (name: string) => {
  const f = frameworks.find((x) => x.name === name);
  if (!f) throw new Error(`missing framework ${name}`);
  return f;
};
const finding = (over: Partial<FindingForMapping>): FindingForMapping => ({
  id: "f1",
  title: "t",
  description: "d",
  severity: "HIGH",
  scanner: "IAC",
  cweId: null,
  ruleId: null,
  filePath: null,
  ...over,
});
const ids = (f: FindingForMapping, name: string) => mapFindingsDeterministic([f], fw(name))[0].controls.map((c) => c.controlId);

describe("normalizeRuleId", () => {
  it("normalizes Trivy check ids across versions and keeps other ids", () => {
    expect(normalizeRuleId("AVD-KSV-0017")).toBe("KSV-0017");
    expect(normalizeRuleId("ksv017")).toBe("KSV-0017");
    expect(normalizeRuleId("AWS-0086")).toBe("AWS-0086");
    expect(normalizeRuleId("dockerfile-no-user")).toBe("DOCKERFILE-NO-USER");
    expect(normalizeRuleId("")).toBeNull();
  });
});

describe("OWASP ASVS 4.0.3 (requirement level)", () => {
  const asvs = fw("OWASP ASVS");

  it("carries every active requirement (278) with levels and official CWEs", () => {
    expect(asvs.version).toBe("4.0.3");
    expect(asvs.controls).toHaveLength(278);
    const v5_3_4 = asvs.controls.find((c) => c.controlId === "V5.3.4")!;
    expect(v5_3_4).toMatchObject({ cweMapping: ["CWE-89"], levels: [1, 2, 3], coverage: "assessable", theme: "V5 Validation, Sanitization and Encoding" });
    expect(asvs.controls.every((c) => c.levels!.length > 0)).toBe(true);
  });

  it("maps SQL injection to the parameterised-query requirement, not a whole chapter", () => {
    // Official ASVS mapping: CWE-89 → V5.3.4 (parameterised queries) and V5.3.5 (encoding fallback).
    expect(ids(finding({ scanner: "SAST_LLM", cweId: "CWE-89" }), "OWASP ASVS")).toEqual(["V5.3.4", "V5.3.5"]);
    expect(ids(finding({ scanner: "SAST_LLM", cweId: "CWE-79" }), "OWASP ASVS")).toContain("V5.3.3");
  });

  it("reports levels on every bucket entry", () => {
    const rows: FindingRow[] = [
      { id: "f1", title: "SQLi", description: "", severity: "HIGH", scanner: "SAST_LLM", cweId: "CWE-89", ruleId: null, filePath: "a.ts", startLine: 1, status: "OPEN" },
    ];
    const report = buildFrameworkReport(asvs, rows, mapFindingsDeterministic(toFindingsForMapping(rows), asvs), "crosswalk");
    expect(report.buckets.gapsFound).toEqual([
      expect.objectContaining({ controlId: "V5.3.4", levels: [1, 2, 3] }),
      expect.objectContaining({ controlId: "V5.3.5", levels: [1, 2, 3] }),
    ]);
    expect(report.buckets.gapsFound.length + report.buckets.noIssuesDetected.length + report.buckets.notCovered.length).toBe(278);
  });
});

describe("CIS benchmarks (rule-id crosswalk)", () => {
  it("maps Kubernetes manifest checks to CIS Kubernetes 5.x controls", () => {
    const k8s = fw("CIS Kubernetes Benchmark");
    expect(hasDeterministicMapping(k8s)).toBe(true);
    const privileged = ids(finding({ scanner: "K8S", ruleId: "KSV-0017" }), "CIS Kubernetes Benchmark");
    expect(privileged.length).toBeGreaterThan(0);
    expect(privileged.every((id) => id.startsWith("5."))).toBe(true);
    // Node-level controls need a live cluster.
    expect(k8s.controls.find((c) => c.controlId === "1.1.1")!.coverage).toBe("not-assessable");
  });

  it("maps grouped findings through their underlying check ids", () => {
    const grouped = finding({ ruleId: "AWS-S3-PUBLIC-ACCESS-BLOCK", ruleIds: ["AWS-0086", "AWS-0087", "AWS-0091", "AWS-0093", "AWS-0094"] });
    const aws = fw("CIS AWS Foundations Benchmark");
    const mapped = mapFindingsDeterministic([grouped], aws)[0].controls;
    expect(mapped.map((c) => c.controlId)).toEqual(["2.1.5"]);
    expect(mapped[0].relevance).toBe("direct");
    // Pepper's IaC supplement is labelled as such.
    expect(aws.controls.find((c) => c.controlId === "2.1.5")).toMatchObject({ mappingSource: "pepper", coverage: "partial" });
  });

  it("maps Pepper's Dockerfile lint to CIS Docker 4.x", () => {
    expect(ids(finding({ scanner: "CONTAINER", ruleId: "DOCKERFILE-NO-USER" }), "CIS Docker Benchmark v1.6")).toEqual(["4.1"]);
    expect(ids(finding({ scanner: "CONTAINER", ruleId: "DOCKERFILE-HARDCODED-SECRET-ENV" }), "CIS Docker Benchmark v1.6")).toEqual(["4.10"]);
  });

  it("reads grouped check ids from finding metadata", () => {
    const [f] = toFindingsForMapping([
      { id: "g", title: "", description: "", severity: "HIGH", scanner: "IAC", cweId: null, ruleId: "X", filePath: null, startLine: null, status: "OPEN", metadata: { checkIds: ["AWS-0086", 7] } },
    ]);
    expect(f.ruleIds).toEqual(["AWS-0086"]);
  });
});

describe("report cache keys", () => {
  it("adds the catalog revision only when a catalog has one", () => {
    expect(complianceCacheKey({ name: "PCI DSS" }, "fast", "det")).toBe("pci-dss::fast::det");
    expect(complianceCacheKey(fw("OWASP ASVS"), "deep", "gpt")).toBe("owasp-asvs@4.0.3-requirements::deep::gpt");
  });
});

describe("focusedCatalog", () => {
  const cat = (n: number, section = (i: number) => `S${i % 10}`) =>
    Array.from({ length: n }, (_, i) => ({ controlId: `C${i}`, title: "", theme: "", section: section(i), coverage: "assessable", summary: "", requirements: "" }));

  it("sends small catalogs whole", () => {
    expect(focusedCatalog(cat(50), new Set(["C1"]))).toHaveLength(50);
  });

  it("sends large catalogs as hints plus their sections, capped", () => {
    const picked = focusedCatalog(cat(300), new Set(["C3", "C13"]));
    expect(picked.slice(0, 2).map((c) => c.controlId)).toEqual(["C3", "C13"]);
    expect(picked.every((c) => c.section === "S3")).toBe(true);
    expect(picked).toHaveLength(30); // every S3 control
    expect(focusedCatalog(cat(300, () => "same"), new Set(["C0"]))).toHaveLength(60);
  });
});
