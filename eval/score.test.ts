import { describe, expect, it } from "vitest";
import { classOf, scoreApp, type Truth } from "./score";

const truth: Truth = {
  app: "demo",
  language: "python",
  expected: [
    { id: "idor", file: "api/books.py", lines: [48, 52], class: "authorization", cwe: ["CWE-639", "CWE-284"] },
    { id: "sqli", file: "models/user.py", lines: [70, 72], class: "injection", cwe: ["CWE-89"] },
  ],
  must_not_report: [{ id: "orm", file: "models/book.py", lines: [20, 24], reason: "bound parameters" }],
  debatable: [{ id: "debug", file: "app.py", lines: [16, 16], class: "hardening" }],
};
const f = (o: Partial<Parameters<typeof classOf>[0]> & Record<string, unknown>) => ({
  scanner: "SAST_LLM",
  severity: "HIGH",
  title: "x",
  ...o,
});

describe("scoring", () => {
  it("credits a hit by file, nearby line and class or CWE, once", () => {
    const s = scoreApp(
      [
        f({ title: "IDOR in get_by_title", cweId: "CWE-639", filePath: "api/books.py", startLine: 55 }),
        f({ title: "Broken object level authorization", cweId: "CWE-284", filePath: "api/books.py", startLine: 50 }),
      ],
      truth,
    );
    expect(s.scored.map((x) => x.outcome.kind)).toEqual(["hit", "duplicate"]);
    expect(s.recall).toBe(0.5);
    expect(s.missed.map((m) => m.id)).toEqual(["sqli"]);
  });

  it("credits a finding at one of the item's alternative locations", () => {
    const t: Truth = {
      ...truth,
      expected: [{ ...truth.expected[1], id: "plain", class: "crypto", cwe: ["CWE-256"], alt: [{ file: "api/users.py", lines: [90, 95] }] }],
    };
    const s = scoreApp([f({ title: "Passwords compared in plaintext", cweId: "CWE-256", filePath: "api/users.py", startLine: 93 })], t);
    expect(s.scored[0].outcome).toEqual({ kind: "hit", id: "plain" });
  });

  it("does not credit the right place with the wrong kind of issue", () => {
    const s = scoreApp([f({ title: "Weak hash", cweId: "CWE-328", filePath: "models/user.py", startLine: 71 })], truth);
    expect(s.scored[0].outcome.kind).toBe("unlabelled");
  });

  it("counts findings on code labelled safe as false positives, and ignores debatable ones", () => {
    const s = scoreApp(
      [
        f({ title: "SQL injection", cweId: "CWE-89", filePath: "models/book.py", startLine: 22 }),
        f({ title: "Debug mode", cweId: "CWE-489", filePath: "app.py", startLine: 16 }),
        f({ title: "SQL injection", cweId: "CWE-89", filePath: "./models/user.py", startLine: 71 }),
      ],
      truth,
    );
    expect(s.scored.map((x) => x.outcome.kind)).toEqual(["safe-hit", "debatable", "hit"]);
    expect(s.precisionLabelled).toBe(0.5);
    expect(s.precisionLowerBound).toBe(0.5);
  });

  it("classifies by CWE first, then by title", () => {
    expect(classOf({ cweId: "CWE-862", title: "anything" })).toBe("authorization");
    expect(classOf({ cweId: null, title: "Mass assignment lets users become admin" })).toBe("authorization");
    expect(classOf({ cweId: "CWE-20", title: "Input not validated" })).toBe("other");
  });
});
