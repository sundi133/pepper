/**
 * Score findings exported from a Pepper scan (scan page → CSV export) against
 * the corpus labels. Use this to measure a deployed instance:
 *
 *   npx tsx eval/score-export.ts vampi=~/Downloads/vampi-findings.csv govwa=~/Downloads/govwa.csv
 *
 * Options: --all (score every scanner, not only AI SAST and zero-day),
 * --out <file.md> (default eval/results/export-<date>.md).
 */
import * as fs from "fs";
import * as path from "path";
import { scoreApp, type AppScore, type EvalFinding, type Truth } from "./score";

const AI_SCANNERS = new Set(["SAST_LLM", "ZERO_DAY"]);

/** RFC 4180 CSV: quoted fields may contain commas, quotes ("") and newlines. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { row.push(field); field = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
    } else field += ch;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((c) => c !== ""));
}

/** Findings from Pepper's CSV export (columns by header name). */
export function findingsFromExport(csv: string, allScanners = false): EvalFinding[] {
  const [header, ...rows] = parseCsv(csv);
  const col = (name: string) => header.indexOf(name);
  const need = ["Severity", "Scanner", "Title", "File Path", "Start Line", "End Line", "CWE ID", "Confidence"];
  for (const n of need) if (col(n) < 0) throw new Error(`Not a Pepper findings export: column "${n}" missing`);
  const num = (v: string) => (v === "" ? null : Number(v));
  return rows
    .map((r) => ({
      scanner: r[col("Scanner")],
      severity: r[col("Severity")],
      title: r[col("Title")],
      filePath: r[col("File Path")] || null,
      startLine: num(r[col("Start Line")]),
      endLine: num(r[col("End Line")]),
      cweId: r[col("CWE ID")] || null,
      confidence: num(r[col("Confidence")]),
    }))
    .filter((f) => allScanners || AI_SCANNERS.has(f.scanner));
}

const pct = (x: number | null) => (x === null ? "–" : `${Math.round(x * 100)}%`);

function main() {
  const args = process.argv.slice(2);
  const all = args.includes("--all");
  const outIdx = args.indexOf("--out");
  const out = outIdx >= 0 ? args[outIdx + 1] : path.join(__dirname, "results", `export-${new Date().toISOString().slice(0, 10)}.md`);
  const pairs = args.filter((a, i) => a.includes("=") && args[i - 1] !== "--out");
  if (!pairs.length) throw new Error("usage: npx tsx eval/score-export.ts <app>=<export.csv> [...] [--all] [--out report.md]");

  const scores: AppScore[] = [];
  for (const pair of pairs) {
    const [app, file] = pair.split("=");
    const truthPath = path.join(__dirname, "truth", `${app}.json`);
    const truth: Truth = fs.existsSync(truthPath)
      ? JSON.parse(fs.readFileSync(truthPath, "utf8"))
      : { app, language: "?", expected: [], must_not_report: [], debatable: [] };
    let findings = findingsFromExport(fs.readFileSync(file.replace(/^~/, process.env.HOME || "~"), "utf8"), all);
    // Scans of the whole repository: score only the files the labels cover.
    if (truth.include?.length) findings = findings.filter((f) => truth.include!.includes((f.filePath || "").replace(/^\.?\//, "")));
    scores.push(scoreApp(findings, truth));
  }

  const lines = ["# Scored export", "", "| App | Recall | Precision ≥ | Precision (labelled) | Findings | Safe-code hits | Unlabelled |", "|---|---|---|---|---|---|---|"];
  for (const s of scores) {
    const n = (k: string) => s.scored.filter((x) => x.outcome.kind === k).length;
    lines.push(`| ${s.app} | ${pct(s.recall)} | ${pct(s.precisionLowerBound)} | ${pct(s.precisionLabelled)} | ${s.scored.length} | ${n("safe-hit")} | ${n("unlabelled")} |`);
  }
  lines.push("", "## Recall by class", "", "| Class | Expected | Found | Recall |", "|---|---|---|---|");
  const byClass = new Map<string, { e: number; h: number }>();
  for (const s of scores) for (const [k, v] of Object.entries(s.byClass)) {
    const c = byClass.get(k) ?? { e: 0, h: 0 };
    c.e += v.expected; c.h += v.hits; byClass.set(k, c);
  }
  for (const [k, v] of [...byClass].sort()) if (v.e) lines.push(`| ${k} | ${v.e} | ${v.h} | ${pct(v.h / v.e)} |`);
  for (const s of scores) {
    lines.push("", `## ${s.app}`, "", `Missed: ${s.missed.map((m) => `${m.id} (${m.class})`).join(", ") || "none"}`, "");
    const review = s.scored.filter((x) => x.outcome.kind === "unlabelled" || x.outcome.kind === "safe-hit");
    if (review.length) {
      lines.push("To review (unlabelled or on safe code):", "");
      for (const r of review) lines.push(`- ${r.outcome.kind === "safe-hit" ? "**safe code** " : ""}${r.severity} ${r.title} — \`${r.filePath}:${r.startLine}\` (${r.cweId || r.class})`);
    }
  }
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, lines.join("\n") + "\n");
  console.log(lines.slice(0, 4 + scores.length).join("\n"));
  console.log(`\nFull report: ${out}`);
}

if (require.main === module) main();
