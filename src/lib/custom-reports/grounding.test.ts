import { describe, expect, it } from "vitest";
import { groundReport, referencedFindingsAppendix } from "./grounding";
import { filterFindings, placeholderValues, runTool } from "./tools";
import { sampleData, stubSources } from "./test-fixtures";

describe("grounding check", () => {
  const data = sampleData();

  it("removes a fabricated finding ref and keeps real ones", () => {
    const out = groundReport("The worst issues are [F1, F99] and [F2].", data);
    expect(out.markdown).toBe("The worst issues are [F1] and [F2].");
    expect(out.cited).toEqual(["F1", "F2"]);
    expect(out.removed).toEqual(["F99"]);
  });

  it("drops a list item or table row whose only citation is fabricated", () => {
    const md = ["- SQL injection in login [F1]", "- Remote code execution in upload [F42]", "| F77 | CRITICAL | RCE |", "| F2 | HIGH | XSS |"].join("\n");
    const out = groundReport(md, data);
    expect(out.markdown).toBe(["- SQL injection in login [F1]", "| F2 | HIGH | XSS |"].join("\n"));
    expect(out.droppedLines).toBe(2);
    expect(out.removed).toEqual(["F42", "F77"]);
  });

  it("rewrites real raw finding ids to refs and removes unknown ones", () => {
    const out = groundReport(
      "See cmabcdefghij0123456789xyz. Also czzzzzzzzzzzz9999999999zz is bad.",
      data,
    );
    expect(out.markdown).toBe("See [F1]. Also is bad.");
    expect(out.corrected).toEqual([{ from: "cmabcdefghij0123456789xyz", to: "F1" }]);
    expect(out.removed).toEqual(["czzzzzzzzzzzz9999999999zz"]);
  });

  it("leaves code blocks untouched", () => {
    const md = "```\nF99 is not a citation here\n```";
    expect(groundReport(md, data).markdown).toBe(md);
  });

  it("warns about severity counts that match nothing in the scan", () => {
    const out = groundReport("There are 1 critical findings and 7 high findings.", data);
    expect(out.warnings).toHaveLength(1);
    expect(out.warnings[0]).toContain("7 high findings");
  });

  it("builds the referenced-findings appendix from the data, not the model", () => {
    const md = referencedFindingsAppendix(["F2", "F1"], data.byRef);
    expect(md).toContain("| F1 | CRITICAL | SQL injection | src/app.ts:10 | OPEN |");
    expect(md.indexOf("| F1 ")).toBeLessThan(md.indexOf("| F2 "));
    expect(referencedFindingsAppendix([], data.byRef)).toBe("");
  });
});

describe("report tools", () => {
  const data = sampleData();
  const sources = stubSources();

  it("excludes false positives by default", () => {
    expect(filterFindings(data, {}).map((f) => f.ref)).toEqual(["F1", "F2", "F3"]);
    expect(filterFindings(data, { includeFalsePositives: true })).toHaveLength(4);
    expect(filterFindings(data, { severity: ["HIGH"], scanner: "SCA" }).map((f) => f.title)).toEqual([
      "lodash prototype pollution",
    ]);
    expect(filterFindings(data, { cwe: "79" }).map((f) => f.ref)).toEqual(["F2"]);
  });

  it("caps list pages and reports the total", async () => {
    const res = (await runTool(data, sources, { tool: "list_findings", args: { limit: 5000 } })) as {
      total: number;
      items: unknown[];
    };
    expect(res.total).toBe(3);
    expect(res.items).toHaveLength(3);
  });

  it("returns an error for unknown refs and tools instead of inventing data", async () => {
    const res = (await runTool(data, sources, { tool: "get_finding", args: { refs: ["F1", "F99"] } })) as {
      findings: Array<{ ref: string; error?: string; title?: string }>;
    };
    expect(res.findings[0].title).toBe("SQL injection");
    expect(res.findings[1].error).toMatch(/No finding/);
    expect(await runTool(data, sources, { tool: "drop_tables" })).toEqual({ error: 'Unknown tool "drop_tables".' });
  });

  it("compares with the previous scan using refs for new findings", async () => {
    const res = (await runTool(data, sources, { tool: "compare_with_previous_scan" })) as {
      newCount: number;
      fixedCount: number;
      newFindings: Array<{ ref: string }>;
    };
    expect(res.newCount).toBe(1);
    expect(res.fixedCount).toBe(1);
    expect(res.newFindings[0].ref).toBe("F1");
  });

  it("computes placeholder values from the data (false positives excluded)", () => {
    const v = placeholderValues(data, null, new Date("2026-10-16T12:00:00Z"));
    expect(v).toMatchObject({
      "scan.repository": "payments",
      "scan.commit": "abc1234",
      "findings.total": 3,
      "findings.critical_count": 1,
      "findings.high_count": 2,
      "findings.low_count": 0,
      "findings.false_positive_count": 1,
      "findings.new_count": null,
      "report.date": "2026-10-16 12:00 UTC",
    });
  });
});
