import { describe, expect, it } from "vitest";
import {
  applyEditsToContent,
  diffHasPlaceholder,
  diffStats,
  unrelatedDeletions,
  safeRepoRelativePath,
  unifiedDiff,
} from "./edits";

describe("applyEditsToContent", () => {
  const file = 'const q = "SELECT * FROM users WHERE id = " + id;\ndb.query(q);\n';

  it("applies an exact unique search block", () => {
    const r = applyEditsToContent(
      file,
      [
        {
          search: 'const q = "SELECT * FROM users WHERE id = " + id;\ndb.query(q);',
          replace: 'db.query("SELECT * FROM users WHERE id = $1", [id]);',
        },
      ],
      "a.ts",
    );
    expect(r).toEqual({ ok: true, content: 'db.query("SELECT * FROM users WHERE id = $1", [id]);\n' });
  });

  it("does not interpret $ patterns in the replacement", () => {
    const r = applyEditsToContent("x = 1\n", [{ search: "x = 1", replace: "x = '$&$1'" }], "a.py");
    expect(r).toEqual({ ok: true, content: "x = '$&$1'\n" });
  });

  it("tolerates trailing whitespace / CRLF differences line by line", () => {
    const crlf = "a();  \r\nb();\r\nc();\r\n";
    const r = applyEditsToContent(crlf, [{ search: "a();\nb();", replace: "a2();\nb2();" }], "a.js");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.content).toBe("a2();\r\nb2();\r\nc();\r\n");
  });

  it("rejects an ambiguous search block", () => {
    const r = applyEditsToContent("x();\nx();\n", [{ search: "x();", replace: "y();" }], "a.js");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/matches 2 places/);
  });

  it("rejects a missing search block", () => {
    const r = applyEditsToContent("x();\n", [{ search: "nope();", replace: "y();" }], "a.js");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not found/);
  });

  it("applies sequential edits against the updated content", () => {
    const r = applyEditsToContent(
      "one\ntwo\n",
      [
        { search: "one", replace: "uno" },
        { search: "uno\ntwo", replace: "uno\ndos" },
      ],
      "a.txt",
    );
    expect(r).toEqual({ ok: true, content: "uno\ndos\n" });
  });

  it("creates a new file only with an empty search", () => {
    expect(applyEditsToContent(null, [{ search: "", replace: "new\n" }], "n.ts")).toEqual({ ok: true, content: "new\n" });
    expect(applyEditsToContent(null, [{ search: "x", replace: "y" }], "n.ts").ok).toBe(false);
    expect(applyEditsToContent("x", [{ search: "", replace: "y" }], "n.ts").ok).toBe(false);
  });
});

describe("unifiedDiff", () => {
  it("returns empty when nothing changed", () => {
    expect(unifiedDiff("a.ts", "same\n", "same\n")).toBe("");
  });

  it("renders a single hunk with context", () => {
    const before = ["1", "2", "3", "4", "5", "6", "7"].join("\n") + "\n";
    const after = ["1", "2", "3", "FOUR", "5", "6", "7"].join("\n") + "\n";
    expect(unifiedDiff("a.ts", before, after)).toBe(
      ["--- a/a.ts", "+++ b/a.ts", "@@ -1,7 +1,7 @@", " 1", " 2", " 3", "-4", "+FOUR", " 5", " 6", " 7"].join("\n"),
    );
  });

  it("splits distant changes into separate hunks", () => {
    const lines = Array.from({ length: 30 }, (_, i) => `l${i + 1}`);
    const after = [...lines];
    after[1] = "X2";
    after[27] = "X28";
    const diff = unifiedDiff("f", lines.join("\n") + "\n", after.join("\n") + "\n");
    expect(diff.match(/^@@/gm)).toHaveLength(2);
    expect(diff).toContain("@@ -1,5 +1,5 @@");
    expect(diff).toContain("@@ -25,6 +25,6 @@");
  });

  it("marks new files against /dev/null", () => {
    const diff = unifiedDiff("n.ts", null, "a\nb\n");
    expect(diff.split("\n").slice(0, 3)).toEqual(["--- /dev/null", "+++ b/n.ts", "@@ -0,0 +1,2 @@"]);
    expect(diffStats(diff)).toEqual({ added: 2, removed: 0 });
  });
});

describe("safeRepoRelativePath", () => {
  it("normalizes separators and leading ./ or /", () => {
    expect(safeRepoRelativePath("./src\\app.ts")).toBe("src/app.ts");
    expect(safeRepoRelativePath("/src/app.ts")).toBe("src/app.ts");
  });

  it("rejects traversal, .git and empty paths", () => {
    expect(safeRepoRelativePath("../etc/passwd")).toBeNull();
    expect(safeRepoRelativePath("src/../../x")).toBeNull();
    expect(safeRepoRelativePath(".git/config")).toBeNull();
    expect(safeRepoRelativePath("   ")).toBeNull();
  });
});

describe("diffHasPlaceholder", () => {
  it("flags elided code in added lines only", () => {
    expect(diffHasPlaceholder("+  // ... existing code\n")).toBe(true);
    expect(diffHasPlaceholder("-  // ... existing code\n+ real();\n")).toBe(false);
    expect(diffHasPlaceholder("+ const rest = [...items];\n")).toBe(false);
  });
});

describe("unrelatedDeletions", () => {
  const before = [
    "function login(req, res) {",
    "  const user = req.query.user;",
    "  const q = \"SELECT * FROM users WHERE name = '\" + user + \"'\";",
    "  db.query(q);",
    "  // Command injection",
    "  exec('echo ' + req.query.msg);",
    "  eval(req.query.expr);",
    "}",
    "",
  ].join("\n");

  it("flags neighbouring statements a fix deleted outright (e2e regression)", () => {
    const after = before
      .replace(/ {2}const q = .*\n {2}db\.query\(q\);\n[\s\S]*eval\(req\.query\.expr\);\n/, "  const q = \"SELECT * FROM users WHERE name = ?\";\n  db.query(q, [user]);\n");
    const deleted = unrelatedDeletions(unifiedDiff("src/login.js", before, after));
    expect(deleted.map((d) => d.text)).toEqual(["exec('echo ' + req.query.msg);", "eval(req.query.expr);"]);
    expect(deleted.map((d) => d.line)).toEqual([6, 7]);
  });

  it("accepts rewrites of the flagged lines", () => {
    const after = before
      .replace("\" + user + \"'\";", "?\";")
      .replace("db.query(q);", "db.query(q, [user]);");
    expect(unrelatedDeletions(unifiedDiff("src/login.js", before, after))).toEqual([]);
  });
});
