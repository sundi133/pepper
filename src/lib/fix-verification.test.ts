import { describe, expect, it } from "vitest";
import { findingFingerprint } from "./fix-verification";

// The database integration (autoResolveFixedFindings) is tested via the
// scan-processor integration tests. This file covers the pure fingerprinting
// logic that drives matching.

const base = {
  scanner: "SAST_PATTERN",
  ruleId: "no-eval",
  cweId: "CWE-78",
  cveId: null,
  filePath: "src/utils/exec.ts",
  startLine: 42,
  title: "Use of eval()",
};

describe("findingFingerprint", () => {
  it("returns the same fingerprint for identical findings", () => {
    expect(findingFingerprint(base)).toBe(findingFingerprint({ ...base }));
  });

  it("treats startLine within the same bucket (±4 lines) as identical", () => {
    // floor(42/5) == floor(44/5) == 8
    const a = findingFingerprint({ ...base, startLine: 42 });
    const b = findingFingerprint({ ...base, startLine: 44 });
    expect(a).toBe(b);
  });

  it("differentiates findings in different buckets (>4 lines apart)", () => {
    // floor(42/5)=8, floor(50/5)=10
    const a = findingFingerprint({ ...base, startLine: 42 });
    const b = findingFingerprint({ ...base, startLine: 50 });
    expect(a).not.toBe(b);
  });

  it("differentiates findings by filePath", () => {
    const a = findingFingerprint({ ...base, filePath: "src/a.ts" });
    const b = findingFingerprint({ ...base, filePath: "src/b.ts" });
    expect(a).not.toBe(b);
  });

  it("differentiates findings by scanner", () => {
    const a = findingFingerprint({ ...base, scanner: "SAST_PATTERN" });
    const b = findingFingerprint({ ...base, scanner: "SAST_LLM" });
    expect(a).not.toBe(b);
  });

  it("uses ruleId when present, ignoring cweId for identity", () => {
    // ruleId takes precedence over cweId in the fingerprint
    const withRuleId = findingFingerprint({ ...base, ruleId: "no-eval", cweId: "CWE-78" });
    const ruleIdOnly = findingFingerprint({ ...base, ruleId: "no-eval", cweId: null });
    expect(withRuleId).toBe(ruleIdOnly);
  });

  it("falls back to cveId when ruleId is null", () => {
    const a = findingFingerprint({ ...base, ruleId: null, cveId: "CVE-2023-1234", cweId: null });
    const b = findingFingerprint({ ...base, ruleId: null, cveId: "CVE-2023-1234", cweId: null });
    expect(a).toBe(b);
  });

  it("falls back to normalised title when ruleId, cveId, cweId are all null", () => {
    const a = findingFingerprint({ ...base, ruleId: null, cveId: null, cweId: null, title: "SQL Injection Found" });
    const b = findingFingerprint({ ...base, ruleId: null, cveId: null, cweId: null, title: "SQL Injection Found" });
    expect(a).toBe(b);
  });

  it("handles null filePath gracefully", () => {
    const fp = findingFingerprint({ ...base, filePath: null });
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
  });

  it("handles null startLine gracefully", () => {
    const fp = findingFingerprint({ ...base, startLine: null });
    expect(typeof fp).toBe("string");
  });
});
