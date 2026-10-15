/**
 * AI SAST evaluation harness (docs/AI_SAST_ACCURACY_SPEC.md, part A).
 *
 *   eval/run.sh --apps vampi,govwa --runs 2 --label baseline
 *
 * Runs the AI scanners on each pinned app the way a scan does (runScanners,
 * AI settings from LLM_* environment variables), scores the findings against
 * eval/truth/<app>.json and writes eval/results/<label>/ (raw findings, logs,
 * summary.json, report.md).
 */
import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import { runScanners } from "@/scanners";
import type { RawFinding } from "@/scanners/types";
import { scoreApp, type AppScore, type EvalFinding, type Truth } from "./score";
import { logger } from "@/lib/logger";

interface CorpusApp { name: string; repo: string; commit: string; language: string; kind: "vulnerable" | "clean" }

interface SummaryRow {
  app: string;
  language: string;
  kind: string;
  run: number;
  score: Omit<AppScore, "scored" | "missed"> & { missed: string[] };
  ledger: Record<string, number>;
  seconds: number;
}

const args = Object.fromEntries(
  process.argv.slice(2).reduce<string[][]>((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : "true"]] : acc), []),
);
const ROOT = path.resolve(__dirname);
const CACHE = args.cache || process.env.EVAL_CACHE || path.join(ROOT, ".cache");
const LABEL = args.label || new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
const RUNS = Number(args.runs || 1);
const SCAN_TYPES = (args.scans || "SAST_ONLY,ZERO_DAY_ONLY").split(",");
const OUT = path.join(ROOT, "results", LABEL);

const corpus: CorpusApp[] = JSON.parse(fs.readFileSync(path.join(ROOT, "corpus.json"), "utf8")).apps;
const selected = args.apps ? corpus.filter((a) => args.apps.split(",").includes(a.name)) : corpus;

const SKIP = new Set(["node_modules", ".git", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv", ".next", "coverage"]);
function enumerate(dir: string, prefix = ""): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP.has(e.name)) out.push(...enumerate(path.join(dir, e.name), path.join(prefix, e.name))); }
    else if (e.isFile()) out.push(path.join(prefix, e.name));
  }
  return out;
}

function checkout(app: CorpusApp): string {
  const dir = path.join(CACHE, app.name);
  if (!fs.existsSync(path.join(dir, ".git"))) {
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("git", ["init", "-q", dir]);
    execFileSync("git", ["-C", dir, "remote", "add", "origin", app.repo]);
  }
  const head = (() => { try { return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"]).toString().trim(); } catch { return ""; } })();
  if (head !== app.commit) {
    execFileSync("git", ["-C", dir, "fetch", "-q", "--depth", "1", "origin", app.commit]);
    execFileSync("git", ["-C", dir, "checkout", "-q", app.commit]);
  }
  return dir;
}

function loadTruth(app: CorpusApp): Truth {
  const p = path.join(ROOT, "truth", `${app.name}.json`);
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  return { app: app.name, language: app.language, expected: [], must_not_report: [], debatable: [] };
}

const slim = (f: RawFinding): EvalFinding => ({
  scanner: f.scanner, severity: f.severity, title: f.title, cweId: f.cweId, filePath: f.filePath,
  startLine: f.startLine, endLine: f.endLine, confidence: f.confidence,
  validation: (f.metadata as Record<string, unknown> | undefined)?.validation as string | undefined,
});

/** Pipeline counters read from the scan's log lines (the per-stage drop ledger, until it is stored on scans). */
const LEDGER: Array<[string, RegExp]> = [
  ["provider errors", /API call failed/],
  ["unreadable answers", /failed to parse LLM JSON/],
  ["cut-off answers recovered", /answer was cut off/],
  ["dropped: evidence check", /Dropping SAST finding/],
  ["dropped: validator", /pass-2 rejected candidate/],
  ["kept unconfirmed", /keeping it unconfirmed/],
  ["dropped: low confidence", /Filtered (near-threshold|low-confidence)/],
  ["dropped: CWE-798 to secrets", /Filtering CWE-798/],
];

async function scanOnce(app: CorpusApp, dir: string, truth: Truth, logFile: string): Promise<EvalFinding[]> {
  let fileList = enumerate(dir);
  if (truth.include?.length) fileList = fileList.filter((f) => truth.include!.includes(f));
  const findings: RawFinding[] = [];
  const log = fs.createWriteStream(logFile);
  // Record every logger call (any level, even ones the logger would drop) for
  // the pipeline counters. pino writes to the file descriptor directly, so its
  // output can't be captured from process.stdout.
  type LogFn = (...a: unknown[]) => void;
  const levels = ["debug", "info", "warn", "error"] as const;
  const original = Object.fromEntries(levels.map((l) => [l, (logger as unknown as Record<string, LogFn>)[l]]));
  for (const l of levels) {
    (logger as unknown as Record<string, LogFn>)[l] = (...a: unknown[]) => {
      const msg = typeof a[0] === "string" ? a[0] : typeof a[1] === "string" ? a[1] : "";
      const obj = typeof a[0] === "object" && a[0] ? (a[0] as Record<string, unknown>) : {};
      log.write(`${l} ${msg} ${JSON.stringify({ title: obj.title, status: obj.status, reason: obj.reason })}\n`);
      if (l !== "debug") original[l].apply(logger, a);
    };
  }
  try {
    for (const scanType of SCAN_TYPES) {
      await runScanners({
        workDir: dir, fileList, scanType,
        orgSettings: {
          llmProvider: process.env.LLM_PROVIDER || "openrouter",
          llmBaseUrl: process.env.LLM_BASE_URL || "https://openrouter.ai/api/v1",
          llmModel: process.env.LLM_MODEL || "",
          llmApiKey: process.env.LLM_API_KEY,
          enableLlmSast: true, enableLlmSecrets: false,
          osvApiUrl: "https://api.osv.dev", vulnDbMode: "offline",
        },
        onProgress: (m: string) => log.write(`[progress] ${m}\n`),
        onScannerComplete: async (_n: string, fs_: RawFinding[]) => { findings.push(...fs_); },
      } as never);
    }
  } finally {
    for (const l of levels) (logger as unknown as Record<string, LogFn>)[l] = original[l];
    await new Promise((r) => log.end(r));
  }
  return findings.filter((f) => f.scanner === "SAST_LLM" || f.scanner === "ZERO_DAY").map(slim);
}

function ledger(logFile: string): Record<string, number> {
  const text = fs.readFileSync(logFile, "utf8");
  return Object.fromEntries(LEDGER.map(([k, re]) => [k, text.split("\n").filter((l) => re.test(l)).length]));
}

const pct = (x: number | null) => (x === null ? "–" : `${Math.round(x * 100)}%`);

(async () => {
  if (!process.env.LLM_API_KEY) throw new Error("LLM_API_KEY is not set (see eval/README.md)");
  fs.mkdirSync(OUT, { recursive: true });
  const summary: SummaryRow[] = [];
  for (const app of selected) {
    const dir = checkout(app);
    const truth = loadTruth(app);
    for (let run = 1; run <= RUNS; run++) {
      const t0 = Date.now();
      const logFile = path.join(OUT, `${app.name}-run${run}.log`);
      console.error(`[eval] ${app.name} run ${run}/${RUNS}…`);
      const findings = await scanOnce(app, dir, truth, logFile);
      const score = scoreApp(findings, truth);
      fs.writeFileSync(path.join(OUT, `${app.name}-run${run}.json`), JSON.stringify(score.scored, null, 2));
      const { scored: _s, missed, ...rest } = score;
      void _s;
      summary.push({ app: app.name, language: app.language, kind: app.kind, run, score: { ...rest, missed: missed.map((m) => m.id) }, ledger: ledger(logFile), seconds: Math.round((Date.now() - t0) / 1000) });
      console.error(`[eval] ${app.name} run ${run}: recall ${pct(score.recall)}, precision ≥ ${pct(score.precisionLowerBound)}, ${findings.length} findings`);
    }
  }
  fs.writeFileSync(path.join(OUT, "summary.json"), JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(OUT, "report.md"), report(summary));
  console.error(`[eval] wrote ${OUT}/report.md`);
})().catch((e) => { console.error("[eval] FAILED", e); process.exit(1); });

function report(rows: SummaryRow[]): string {
  const lines = [`# Evaluation ${LABEL}`, "", `Model: \`${process.env.LLM_MODEL}\` · scans: ${SCAN_TYPES.join(", ")} · runs per app: ${RUNS}`, ""];
  lines.push("| App | Lang | Run | Recall | Precision ≥ | Precision (labelled) | Findings | Safe-code hits | Unlabelled | Time |", "|---|---|---|---|---|---|---|---|---|---|");
  for (const r of rows) {
    const c = Object.values(r.score.byClass);
    const found = c.reduce((n, x) => n + x.found, 0);
    lines.push(`| ${r.app} | ${r.language} | ${r.run} | ${pct(r.score.recall)} | ${pct(r.score.precisionLowerBound)} | ${pct(r.score.precisionLabelled)} | ${found} | ${c.reduce((n, x) => n + x.safeHits, 0)} | ${c.reduce((n, x) => n + x.unlabelled, 0)} | ${r.seconds}s |`);
  }
  const classes = new Map<string, { expected: number; hits: number }>();
  for (const r of rows) for (const [k, v] of Object.entries(r.score.byClass)) {
    const c = classes.get(k) ?? { expected: 0, hits: 0 };
    c.expected += v.expected; c.hits += v.hits; classes.set(k, c);
  }
  lines.push("", "## Recall by class (all apps, all runs)", "", "| Class | Expected | Found | Recall |", "|---|---|---|---|");
  for (const [k, v] of [...classes].sort()) if (v.expected) lines.push(`| ${k} | ${v.expected} | ${v.hits} | ${pct(v.hits / v.expected)} |`);
  lines.push("", "## Pipeline (summed over runs)", "", "| Stage | Count |", "|---|---|");
  const led: Record<string, number> = {};
  for (const r of rows) for (const [k, v] of Object.entries(r.ledger)) led[k] = (led[k] ?? 0) + v;
  for (const [k, v] of Object.entries(led)) lines.push(`| ${k} | ${v} |`);
  lines.push("", "## Missed (by app, run 1)", "");
  for (const r of rows.filter((x) => x.run === 1)) lines.push(`- **${r.app}**: ${r.score.missed.join(", ") || "none"}`);
  return lines.join("\n") + "\n";
}
