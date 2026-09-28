import { describe, expect, it } from "vitest";
import { findingFingerprint } from "./fix-verification";
import { compareFindingSets, type CompareFinding } from "./scan-compare";

function f(
  title: string,
  filePath: string,
  startLine: number,
  extra: Partial<CompareFinding> = {},
): CompareFinding {
  const base = {
    scanner: "SAST_LLM",
    severity: "HIGH",
    status: "OPEN",
    title,
    filePath,
    startLine,
    ruleId: null,
    cweId: null,
    cveId: null,
    ...extra,
  };
  return { ...base, fingerprint: findingFingerprint(base) };
}

describe("compareFindingSets", () => {
  it("classifies fixed, new and still-present findings", () => {
    const sqli = f("SQL injection", "src/db.ts", 10, { cweId: "CWE-89", severity: "CRITICAL" });
    const xss = f("XSS", "src/view.ts", 40, { cweId: "CWE-79" });
    const ssrf = f("SSRF", "src/http.ts", 5, { cweId: "CWE-918" });
    const r = compareFindingSets([sqli, xss], [xss, ssrf]);
    expect(r.fixed.map((x) => x.title)).toEqual(["SQL injection"]);
    expect(r.introduced.map((x) => x.title)).toEqual(["SSRF"]);
    expect(r.persisting.map((p) => p.target.title)).toEqual(["XSS"]);
    expect(r.bySeverity.CRITICAL).toEqual({ fixed: 1, introduced: 0, persisting: 0 });
    expect(r.bySeverity.HIGH).toEqual({ fixed: 0, introduced: 1, persisting: 1 });
  });

  it("treats code that moved (e.g. after an AI fix added lines) as the same finding", () => {
    const before = f("Command injection", "src/login.js", 8, { cweId: "CWE-78" });
    const after = f("Command injection", "src/login.js", 21, { cweId: "CWE-78" });
    expect(before.fingerprint).not.toBe(after.fingerprint);
    const r = compareFindingSets([before], [after]);
    expect(r.fixed).toEqual([]);
    expect(r.introduced).toEqual([]);
    expect(r.persisting).toMatchObject([{ moved: true }]);
  });

  it("pairs duplicates one-to-one by nearest line", () => {
    const a1 = f("Hardcoded secret", "cfg.ts", 3, { ruleId: "SECRET-AWS" });
    const a2 = f("Hardcoded secret", "cfg.ts", 90, { ruleId: "SECRET-AWS" });
    const b1 = f("Hardcoded secret", "cfg.ts", 92, { ruleId: "SECRET-AWS" });
    const r = compareFindingSets([a1, a2], [b1]);
    expect(r.persisting).toHaveLength(1);
    expect(r.persisting[0].base.startLine).toBe(90);
    expect(r.fixed.map((x) => x.startLine)).toEqual([3]);
  });

  it("flags re-rated findings", () => {
    const r = compareFindingSets(
      [f("Weak crypto", "a.ts", 1, { cweId: "CWE-327", severity: "MEDIUM" })],
      [f("Weak crypto", "a.ts", 1, { cweId: "CWE-327", severity: "HIGH" })],
    );
    expect(r.persisting[0].severityChanged).toBe(true);
  });

  it("does not count suppression as a fix, nor suppressed findings as new", () => {
    const open = f("Path traversal", "a.ts", 5, { cweId: "CWE-22" });
    const nowFp = { ...open, status: "FALSE_POSITIVE" };
    const oldFp = f("Debug flag", "b.ts", 1, { cweId: "CWE-489", status: "FALSE_POSITIVE" });
    const r = compareFindingSets([open, oldFp], [nowFp]);
    expect(r.fixed).toEqual([]);
    expect(r.introduced).toEqual([]);
    expect(r.persisting).toEqual([]);
    expect(r.suppressed).toBe(1);
  });

  it("summarises the files with the most change", () => {
    const r = compareFindingSets(
      [f("A", "x.ts", 1, { ruleId: "A" }), f("B", "x.ts", 20, { ruleId: "B" })],
      [f("C", "y.ts", 1, { ruleId: "C" })],
    );
    expect(r.byFile).toEqual([
      { filePath: "x.ts", fixed: 2, introduced: 0, net: -2 },
      { filePath: "y.ts", fixed: 0, introduced: 1, net: 1 },
    ]);
  });
});
