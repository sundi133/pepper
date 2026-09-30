import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { applyQualityGates } from "../shared/quality-gates";
import {
  buildOpengrepArgs,
  extractCwe,
  findingTitle,
  formatDescription,
  indexRulePacks,
  loadOpengrepPacks,
  mapOpengrepResults,
  mapSeverity,
  opengrepTargets,
  runOpengrepScanner,
  type OpengrepOutput,
} from "./opengrep";

const ROOT = path.join(process.cwd(), "rules", "opengrep");

function result(over: Partial<OpengrepOutput["results"][number]> & { meta?: Record<string, unknown>; severity?: string; message?: string }) {
  return {
    check_id: over.check_id ?? "pepper.js.sql-injection",
    path: over.path ?? "src/api.ts",
    start: over.start ?? { line: 7, col: 9 },
    end: over.end ?? { line: 7, col: 40 },
    extra: {
      message: over.message ?? "Request input reaches a SQL query string. Fix: use parameterised queries.",
      severity: over.severity ?? "ERROR",
      lines: "await pool.query(`SELECT ${id}`);",
      metadata: over.meta ?? {
        cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        owasp: "A03:2021 - Injection",
        confidence: "HIGH",
        pepper_severity: "CRITICAL",
      },
    },
  };
}

describe("OpenGrep result mapping", () => {
  it("maps a Pepper rule to a SAST_PATTERN finding", () => {
    const [f] = mapOpengrepResults({ results: [result({})] }, "/nowhere");
    expect(f).toMatchObject({
      scanner: "SAST_PATTERN",
      severity: "CRITICAL",
      title: "SQL Injection",
      ruleId: "pepper.js.sql-injection",
      cweId: "CWE-89",
      confidence: 0.9,
      filePath: "src/api.ts",
      startLine: 7,
      snippet: "await pool.query(`SELECT ${id}`);",
    });
    expect(f.description).toBe("Request input reaches a SQL query string.\n\n**Fix:** use parameterised queries.");
  });

  it("de-duplicates taint results reported once per source path", () => {
    const r = result({});
    expect(mapOpengrepResults({ results: [r, r, r] }, "/nowhere")).toHaveLength(1);
  });

  it("derives severity from pepper_severity, then security-severity, then rule severity", () => {
    expect(mapSeverity({ severity: "WARNING", metadata: { pepper_severity: "critical" } })).toBe("CRITICAL");
    expect(mapSeverity({ severity: "INFO", metadata: { "security-severity": "HIGH" } })).toBe("HIGH");
    expect(mapSeverity({ severity: "ERROR" })).toBe("HIGH");
    expect(mapSeverity({ severity: "WARNING" })).toBe("MEDIUM");
    expect(mapSeverity({ severity: "INFO" })).toBe("LOW");
  });

  it("reads CWE ids and titles from both rule styles", () => {
    expect(extractCwe({ cwe: "CWE-89" })).toBe("CWE-89");
    expect(extractCwe({ cwe: ["CWE-79: Cross-site Scripting"] })).toBe("CWE-79");
    expect(findingTitle({ shortDescription: "Improper neutralization of special elements used in an SQL command\n (SQL Injection)" }, "x")).toBe(
      "Improper neutralization of special elements used in an SQL command (SQL Injection)",
    );
    expect(findingTitle({}, "Something happened. More detail.")).toBe("Something happened.");
    expect(formatDescription("No fix section here.")).toBe("No fix section here.");
  });

  it("labels findings with the pack (and license) the rule came from", () => {
    const packs = loadOpengrepPacks(ROOT, "");
    const index = indexRulePacks(packs);
    const [ours, lgpl] = mapOpengrepResults(
      { results: [result({}), result({ check_id: "rules_lgpl_javascript_eval_rule-eval-nodejs", path: "b.js" })] },
      "/nowhere",
      index,
    );
    expect(ours.metadata).toMatchObject({ rulePack: "pepper", engine: "opengrep" });
    expect(lgpl.metadata).toMatchObject({ rulePack: "gitlab-lgpl", ruleLicense: "LGPL-3.0-only" });
  });
});

describe("OpenGrep packs and arguments", () => {
  it("bundles only redistributable packs and applies their exclusions", () => {
    const packs = loadOpengrepPacks(ROOT, "");
    expect(packs.map((p) => [p.id, p.license])).toEqual([
      ["pepper", "Pepper (proprietary)"],
      ["gitlab-lgpl", "LGPL-3.0-only"],
    ]);
    const args = buildOpengrepArgs({ packs, targets: ["."], outputFile: "/tmp/o.json", jobs: 2 });
    expect(args).toContain("--no-rewrite-rule-ids");
    expect(args.join(" ")).toContain("--exclude *.min.js");
    expect(args.join(" ")).toContain("--exclude-rule rules_lgpl_javascript_ssrf_rule-node-ssrf");
    expect(args.slice(-2)).toEqual(["--", "."]);
    // Commons-Clause / EE rule sets must never be vendored.
    expect(fs.existsSync(path.join(ROOT, "third_party", "gitlab-lgpl-cc"))).toBe(false);
    expect(fs.readFileSync(path.join(ROOT, "third_party", "gitlab-lgpl", "LICENSE"), "utf8")).toMatch(/LESSER GENERAL PUBLIC LICENSE/);
  });

  it("scans only changed files on incremental scans", () => {
    expect(opengrepTargets({ scanType: "INCREMENTAL", fileList: ["a.ts", "b.ts"] })).toEqual(["a.ts", "b.ts"]);
    expect(opengrepTargets({ scanType: "FULL", fileList: ["a.ts"] })).toEqual(["."]);
  });

  it("loads customer packs from OPENGREP_EXTRA_RULES", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "custom-rules-"));
    const packs = loadOpengrepPacks(ROOT, `${dir}:/does/not/exist`);
    expect(packs.at(-1)).toMatchObject({ id: `custom:${path.basename(dir)}`, license: "customer-provided" });
    fs.rmSync(dir, { recursive: true });
  });
});

describe("quality gates for rule-based findings", () => {
  const base = mapOpengrepResults({ results: [result({})] }, "/nowhere")[0];
  it("keeps real findings, drops test code and low-confidence rules", () => {
    expect(applyQualityGates([base])).toHaveLength(1);
    expect(applyQualityGates([{ ...base, filePath: "src/__tests__/api.test.ts" }])).toHaveLength(0);
    expect(applyQualityGates([{ ...base, confidence: 0.55 }])).toHaveLength(0);
    // Third-party rules without a "Fix:" section or confidence still pass on their CWE.
    expect(applyQualityGates([{ ...base, description: "NoSQL injection via $where.", confidence: 0.75, cweId: "CWE-943" }])).toHaveLength(1);
    expect(applyQualityGates([{ ...base, description: "No CWE, no fix.", confidence: 0.75, cweId: undefined }])).toHaveLength(0);
  });
});

// End-to-end with the real binary (skipped when OpenGrep isn't installed).
const OPENGREP = process.env.OPENGREP_BIN || "opengrep";
const hasOpengrep = spawnSync(OPENGREP, ["--version"], { encoding: "utf8" }).status === 0;

describe.skipIf(!hasOpengrep)("OpenGrep end-to-end", () => {
  it("finds injection in request handlers and ignores safe code", async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "og-e2e-"));
    fs.mkdirSync(path.join(work, "src"));
    fs.writeFileSync(
      path.join(work, "src", "orders.ts"),
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/orders/:id", async (req, res) => {',
        "  await pool.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);",
        '  await pool.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);',
        "  res.end();",
        "});",
        "",
      ].join("\n"),
    );
    const findings = await runOpengrepScanner({
      workDir: work,
      fileList: ["src/orders.ts"],
      scanType: "FULL",
      orgSettings: { llmProvider: "", llmBaseUrl: "", llmModel: "", enableLlmSast: false, enableLlmSecrets: false, osvApiUrl: "", vulnDbMode: "offline" },
    });
    fs.rmSync(work, { recursive: true });
    expect(findings.map((f) => [f.ruleId, f.startLine, f.severity])).toEqual([["pepper.js.sql-injection", 4, "CRITICAL"]]);
    expect(findings[0].metadata).toMatchObject({ rulePack: "pepper" });
  }, 120_000);
});
