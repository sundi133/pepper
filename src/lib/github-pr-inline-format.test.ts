import { describe, it, expect } from "vitest";
import {
  buildFindingMarker,
  extractFindingMarkers,
  parsePatchAddedLines,
  buildInlineCommentBody,
  selectFindingsForInline,
} from "./github-pr-inline-format";

describe("buildFindingMarker", () => {
  it("produces a stable marker for the same finding", () => {
    const a = buildFindingMarker({
      severity: "HIGH",
      title: "SQL injection",
      description: "x",
      filePath: "src/a.ts",
      startLine: 10,
      ruleId: "sast/sqli",
      cweId: "CWE-89",
    });
    const b = buildFindingMarker({
      severity: "HIGH",
      title: "SQL injection",
      description: "different description here",
      filePath: "src/a.ts",
      startLine: 10,
      ruleId: "sast/sqli",
      cweId: "CWE-89",
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^<!-- pepper-finding:[a-f0-9]{16} -->$/);
  });

  it("changes when file path or line changes", () => {
    const base = {
      severity: "HIGH",
      title: "x",
      description: "",
      filePath: "src/a.ts",
      startLine: 10,
      ruleId: "r",
      cweId: null,
    };
    const moved = { ...base, startLine: 11 };
    const renamed = { ...base, filePath: "src/b.ts" };
    expect(buildFindingMarker(base)).not.toBe(buildFindingMarker(moved));
    expect(buildFindingMarker(base)).not.toBe(buildFindingMarker(renamed));
  });

  it("is case-insensitive on file path", () => {
    const lower = buildFindingMarker({
      severity: "HIGH",
      title: "x",
      description: "",
      filePath: "src/a.ts",
      startLine: 1,
      ruleId: "r",
      cweId: null,
    });
    const upper = buildFindingMarker({
      severity: "HIGH",
      title: "x",
      description: "",
      filePath: "SRC/A.TS",
      startLine: 1,
      ruleId: "r",
      cweId: null,
    });
    expect(lower).toBe(upper);
  });
});

describe("extractFindingMarkers", () => {
  it("returns all markers embedded in a body", () => {
    const body = `prefix <!-- pepper-finding:aaaaaaaaaaaaaaaa --> middle <!-- pepper-finding:bbbbbbbbbbbbbbbb --> suffix`;
    expect(extractFindingMarkers(body)).toEqual([
      "<!-- pepper-finding:aaaaaaaaaaaaaaaa -->",
      "<!-- pepper-finding:bbbbbbbbbbbbbbbb -->",
    ]);
  });

  it("returns empty for missing or empty bodies", () => {
    expect(extractFindingMarkers(null)).toEqual([]);
    expect(extractFindingMarkers("")).toEqual([]);
    expect(extractFindingMarkers("no markers here")).toEqual([]);
  });
});

describe("parsePatchAddedLines", () => {
  it("collects RIGHT-side line numbers for context and added lines", () => {
    const patch = [
      "@@ -10,5 +20,6 @@ header",
      " context a",
      "-removed",
      "+added new",
      " context b",
      "+another added",
      " context c",
    ].join("\n");

    const lines = parsePatchAddedLines(patch);
    // RIGHT-side starts at 20.
    // line 20: " context a" → 20
    // "-removed" doesn't advance RIGHT
    // line 21: "+added new" → 21
    // line 22: " context b" → 22
    // line 23: "+another added" → 23
    // line 24: " context c" → 24
    expect([...lines].sort((a, b) => a - b)).toEqual([20, 21, 22, 23, 24]);
  });

  it("handles multiple hunks", () => {
    const patch = [
      "@@ -1,1 +1,2 @@",
      " a",
      "+b",
      "@@ -10,1 +100,2 @@",
      " c",
      "+d",
    ].join("\n");
    expect([...parsePatchAddedLines(patch)].sort((a, b) => a - b)).toEqual([
      1, 2, 100, 101,
    ]);
  });

  it("ignores \\ no newline markers", () => {
    const patch = ["@@ -1,1 +1,1 @@", "+only", "\\ No newline at end of file"].join(
      "\n",
    );
    expect([...parsePatchAddedLines(patch)]).toEqual([1]);
  });

  it("returns empty for null or empty patch", () => {
    expect(parsePatchAddedLines(null).size).toBe(0);
    expect(parsePatchAddedLines("").size).toBe(0);
  });
});

describe("buildInlineCommentBody", () => {
  const finding = {
    severity: "HIGH",
    title: "Hardcoded secret detected",
    description: "An API key was found embedded in source.",
    filePath: "src/x.ts",
    startLine: 12,
    ruleId: "secrets/api-key",
    cweId: "CWE-798",
  };

  it("includes the marker, severity, title, and link", () => {
    const body = buildInlineCommentBody(finding, {
      reviewUrl: "https://pepper.example.com/scans/s1",
    });
    expect(body).toMatch(/^<!-- pepper-finding:[a-f0-9]{16} -->/);
    expect(body).toContain("**Hardcoded secret detected**");
    expect(body).toContain("HIGH · secrets/api-key");
    expect(body).toContain("CWE-798");
    expect(body).toContain(
      "[View full finding in Pepper](https://pepper.example.com/scans/s1)",
    );
  });

  it("escapes angle brackets in titles", () => {
    const body = buildInlineCommentBody(
      { ...finding, title: "XSS via <img onerror=>" },
      { reviewUrl: null },
    );
    expect(body).toContain("&lt;img onerror=&gt;");
    expect(body).not.toContain("<img onerror=>");
  });

  it("truncates very long descriptions", () => {
    const body = buildInlineCommentBody(
      { ...finding, description: "x".repeat(1500) },
      { reviewUrl: null },
    );
    expect(body.length).toBeLessThan(1500);
    expect(body).toContain("…");
  });
});

describe("selectFindingsForInline", () => {
  const fileLines = new Map<string, Set<number>>([
    ["src/a.ts", new Set([10, 11, 12])],
    ["src/b.ts", new Set([1, 2])],
  ]);

  const make = (over: Partial<Parameters<typeof buildFindingMarker>[0]>) => ({
    severity: "HIGH",
    title: "t",
    description: "",
    filePath: "src/a.ts",
    startLine: 10,
    ruleId: "r",
    cweId: null,
    ...over,
  });

  it("keeps findings whose line is in the diff", () => {
    const picked = selectFindingsForInline(
      [make({}), make({ startLine: 11 })],
      fileLines,
      new Set(),
      50,
    );
    expect(picked).toHaveLength(2);
    expect(picked[0]).toEqual({
      path: "src/a.ts",
      line: 10,
      side: "RIGHT",
      body: "",
    });
  });

  it("drops findings outside the diff", () => {
    const picked = selectFindingsForInline(
      [
        make({ filePath: "src/not-in-pr.ts" }),
        make({ startLine: 99 }),
        make({ startLine: 11 }),
      ],
      fileLines,
      new Set(),
      50,
    );
    expect(picked).toHaveLength(1);
    expect(picked[0].line).toBe(11);
  });

  it("skips findings whose marker already exists", () => {
    const dup = make({});
    const existing = new Set([buildFindingMarker(dup)]);
    const picked = selectFindingsForInline(
      [dup, make({ startLine: 11 })],
      fileLines,
      existing,
      50,
    );
    expect(picked).toHaveLength(1);
    expect(picked[0].line).toBe(11);
  });

  it("respects the maxComments cap", () => {
    const picked = selectFindingsForInline(
      [
        make({ startLine: 10 }),
        make({ startLine: 11 }),
        make({ startLine: 12 }),
      ],
      fileLines,
      new Set(),
      2,
    );
    expect(picked).toHaveLength(2);
  });

  it("ignores findings with no file path or line", () => {
    const picked = selectFindingsForInline(
      [make({ filePath: null }), make({ startLine: null })],
      fileLines,
      new Set(),
      50,
    );
    expect(picked).toHaveLength(0);
  });
});
