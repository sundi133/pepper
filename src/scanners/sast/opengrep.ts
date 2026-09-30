/**
 * Rule-based SAST with OpenGrep (the LGPL-2.1 fork of Semgrep).
 *
 * Runs the rule packs in rules/opengrep/packs.json (plus any customer packs
 * in OPENGREP_EXTRA_RULES) over the checkout, fully offline, and maps results
 * to Pepper findings with scanner SAST_PATTERN. Deterministic, so it runs
 * even when LLM SAST is disabled.
 */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { logger } from "@/lib/logger";
import type { RawFinding, ScanContext, SeverityLevel } from "../types";

// ─── Packs ────────────────────────────────────────────────────────────

export interface OpengrepPack {
  id: string;
  /** Absolute directory of the pack's rules. */
  dir: string;
  license: string;
  source?: string;
  excludeRules: string[];
}

interface PackManifest {
  packs: Array<{
    id: string;
    path: string;
    license: string;
    source?: string;
    enabled?: boolean;
    excludeRules?: Record<string, string> | string[];
  }>;
}

export function opengrepRulesRoot(): string {
  return process.env.OPENGREP_RULES_DIR?.trim() || path.join(process.cwd(), "rules", "opengrep");
}

/** Bundled packs from packs.json plus customer packs from OPENGREP_EXTRA_RULES. */
export function loadOpengrepPacks(
  root = opengrepRulesRoot(),
  extra = process.env.OPENGREP_EXTRA_RULES,
): OpengrepPack[] {
  const packs: OpengrepPack[] = [];
  const manifestPath = path.join(root, "packs.json");
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as PackManifest;
    for (const p of manifest.packs) {
      if (p.enabled === false) continue;
      const dir = path.resolve(root, p.path);
      if (!fs.existsSync(dir)) continue;
      const excl = Array.isArray(p.excludeRules) ? p.excludeRules : Object.keys(p.excludeRules ?? {});
      packs.push({ id: p.id, dir, license: p.license, source: p.source, excludeRules: excl });
    }
  }
  for (const d of (extra ?? "").split(":").map((s) => s.trim()).filter(Boolean)) {
    const dir = path.resolve(d);
    if (!fs.existsSync(dir)) {
      logger.warn({ dir }, "OPENGREP_EXTRA_RULES directory not found; skipping");
      continue;
    }
    packs.push({ id: `custom:${path.basename(dir)}`, dir, license: "customer-provided", excludeRules: [] });
  }
  return packs;
}

function walkYaml(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walkYaml(p, out);
    else if (/\.ya?ml$/i.test(entry.name)) out.push(p);
  }
  return out;
}

const RULE_ID_LINE = /^\s*-\s*id:\s*["']?([^"'\s#]+)["']?\s*$/gm;

/** rule id → pack id, read from the `- id:` lines of each pack's YAML files. */
export function indexRulePacks(packs: OpengrepPack[]): Map<string, OpengrepPack> {
  const index = new Map<string, OpengrepPack>();
  for (const pack of packs) {
    for (const file of walkYaml(pack.dir)) {
      const text = fs.readFileSync(file, "utf8");
      for (const m of text.matchAll(RULE_ID_LINE)) index.set(m[1], pack);
    }
  }
  return index;
}

// ─── Result mapping ───────────────────────────────────────────────────

export interface OpengrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: Record<string, unknown>;
  };
}

export interface OpengrepOutput {
  results: OpengrepResult[];
  errors?: Array<{ type?: unknown; message?: string; path?: string; level?: string }>;
  paths?: { scanned?: string[] };
}

const SEVERITIES: SeverityLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function asSeverity(v: unknown): SeverityLevel | null {
  const s = typeof v === "string" ? v.trim().toUpperCase() : "";
  if (s === "MODERATE") return "MEDIUM";
  return (SEVERITIES as string[]).includes(s) ? (s as SeverityLevel) : null;
}

export function mapSeverity(extra: OpengrepResult["extra"]): SeverityLevel {
  const meta = extra.metadata ?? {};
  const explicit = asSeverity(meta.pepper_severity) ?? asSeverity(meta["security-severity"]);
  if (explicit) return explicit;
  switch ((extra.severity ?? "").toUpperCase()) {
    case "ERROR":
      return "HIGH";
    case "WARNING":
      return "MEDIUM";
    case "INFO":
      return "LOW";
    default:
      return "MEDIUM";
  }
}

export function mapConfidence(meta: Record<string, unknown>): number {
  switch (String(meta.confidence ?? "").toUpperCase()) {
    case "HIGH":
      return 0.9;
    case "MEDIUM":
      return 0.75;
    case "LOW":
      return 0.55; // below the quality-gate floor: dropped
    default:
      return 0.75;
  }
}

function firstString(v: unknown): string | undefined {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.find((x): x is string => typeof x === "string");
  return undefined;
}

export function extractCwe(meta: Record<string, unknown>): string | undefined {
  const raw = firstString(meta.cwe) ?? firstString(meta["cwe-id"]);
  return raw?.match(/CWE-\d+/i)?.[0]?.toUpperCase();
}

/** "…('SQL Injection')" → "SQL Injection"; otherwise the short description / first sentence. */
export function findingTitle(meta: Record<string, unknown>, message: string): string {
  const cwe = firstString(meta.cwe) ?? "";
  const quoted = cwe.match(/\('([^']+)'\)/)?.[1];
  const short = typeof meta.shortDescription === "string" ? meta.shortDescription : undefined;
  const title =
    quoted ??
    short?.replace(/\s+/g, " ").trim() ??
    cwe.replace(/^CWE-\d+:\s*/i, "").trim() ??
    "";
  const fallback = message.split(/(?<=\.)\s/)[0] ?? message;
  const t = (title || fallback).replace(/\s+/g, " ").trim();
  return t.length > 120 ? `${t.slice(0, 117)}...` : t;
}

/** Split "… Fix: …" into a description with a **Fix:** section. */
export function formatDescription(message: string): string {
  const text = message.replace(/\s+\n/g, "\n").trim();
  const idx = text.search(/\bFix:\s/);
  if (idx === -1) return text;
  return `${text.slice(0, idx).trim()}\n\n**Fix:** ${text.slice(idx + 4).trim()}`;
}

function snippetFor(r: OpengrepResult, workDir: string): string | undefined {
  const lines = r.extra.lines?.trim();
  if (lines && lines !== "requires login") return lines.slice(0, 1000);
  try {
    const all = fs.readFileSync(path.join(workDir, r.path), "utf8").split("\n");
    const end = Math.min(r.end.line, r.start.line + 4);
    return all.slice(r.start.line - 1, end).join("\n").slice(0, 1000);
  } catch {
    return undefined;
  }
}

/**
 * Map OpenGrep JSON to findings. Taint rules report one result per source
 * path, so results are de-duplicated per rule + location.
 */
export function mapOpengrepResults(
  output: OpengrepOutput,
  workDir: string,
  ruleIndex: Map<string, OpengrepPack> = new Map(),
): RawFinding[] {
  const seen = new Set<string>();
  const findings: RawFinding[] = [];
  for (const r of output.results ?? []) {
    const filePath = r.path.replace(/^\.\//, "");
    const key = `${r.check_id}|${filePath}|${r.start.line}|${r.start.col}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const meta = r.extra.metadata ?? {};
    const message = (r.extra.message ?? "").trim();
    const pack = ruleIndex.get(r.check_id);
    const references = Array.isArray(meta.references)
      ? (meta.references as unknown[]).filter((x): x is string => typeof x === "string")
      : undefined;
    findings.push({
      scanner: "SAST_PATTERN",
      severity: mapSeverity(r.extra),
      title: findingTitle(meta, message),
      description: formatDescription(message),
      filePath,
      startLine: r.start.line,
      endLine: r.end.line,
      snippet: snippetFor({ ...r, path: filePath }, workDir),
      ruleId: r.check_id,
      cweId: extractCwe(meta),
      confidence: mapConfidence(meta),
      metadata: {
        detectionMethod: "Rule-based (OpenGrep)",
        engine: "opengrep",
        rulePack: pack?.id ?? "unknown",
        ruleLicense: pack?.license,
        owasp: firstString(meta.owasp),
        category: typeof meta.category === "string" ? meta.category : "security",
        references,
      },
    });
  }
  return findings;
}

// ─── Runner ───────────────────────────────────────────────────────────

let cachedBinary: string | null | undefined;

/** OPENGREP_BIN, else `opengrep` on PATH. Null when unavailable. */
export function resolveOpengrepBinary(): string | null {
  if (cachedBinary !== undefined) return cachedBinary;
  const candidate = process.env.OPENGREP_BIN?.trim() || "opengrep";
  const probe = spawnSync(candidate, ["--version"], {
    encoding: "utf8",
    timeout: 20_000,
    env: { ...process.env, LC_ALL: "C.UTF-8", LANG: "C.UTF-8" },
  });
  cachedBinary = probe.status === 0 ? candidate : null;
  if (!cachedBinary) {
    logger.warn({ candidate }, "OpenGrep not found; rule-based SAST is disabled");
  }
  return cachedBinary;
}

export function opengrepEnabled(): boolean {
  return (process.env.ENABLE_OPENGREP_SAST ?? "true").toLowerCase() !== "false";
}

const EXCLUDES = [
  "node_modules",
  "vendor",
  "bower_components",
  "dist",
  "build",
  ".next",
  "target",
  "coverage",
  "*.min.js",
  "*.bundle.js",
];

export function buildOpengrepArgs(opts: {
  packs: OpengrepPack[];
  targets: string[];
  outputFile: string;
  jobs: number;
}): string[] {
  const args = [
    "scan",
    "--json",
    "--json-output",
    opts.outputFile,
    "--quiet",
    "--disable-version-check",
    "--no-rewrite-rule-ids",
    "--timeout",
    process.env.OPENGREP_RULE_TIMEOUT_SECONDS?.trim() || "10",
    "--timeout-threshold",
    "3",
    "--max-target-bytes",
    "1000000",
    "--jobs",
    String(opts.jobs),
  ];
  for (const p of opts.packs) args.push("--config", p.dir);
  for (const p of opts.packs) for (const r of p.excludeRules) args.push("--exclude-rule", r);
  for (const e of EXCLUDES) args.push("--exclude", e);
  args.push("--", ...opts.targets);
  return args;
}

/** Changed files for incremental scans, the whole checkout otherwise. */
export function opengrepTargets(ctx: Pick<ScanContext, "scanType" | "fileList">): string[] {
  if (ctx.scanType === "INCREMENTAL" && ctx.fileList.length > 0 && ctx.fileList.length <= 2000) {
    return ctx.fileList;
  }
  return ["."];
}

export async function runOpengrepScanner(ctx: ScanContext): Promise<RawFinding[]> {
  if (!opengrepEnabled()) return [];
  const bin = resolveOpengrepBinary();
  if (!bin) return [];
  const packs = loadOpengrepPacks();
  if (packs.length === 0) {
    logger.warn("No OpenGrep rule packs found; rule-based SAST skipped");
    return [];
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-opengrep-"));
  const outputFile = path.join(tmp, "results.json");
  const jobs = Math.max(1, Math.min(4, os.cpus().length));
  const args = buildOpengrepArgs({ packs, targets: opengrepTargets(ctx), outputFile, jobs });
  const timeoutMs = Number(process.env.OPENGREP_TIMEOUT_SECONDS || 1200) * 1000;
  ctx.onProgress?.(`OpenGrep: running ${packs.map((p) => p.id).join(", ")} rule packs`);

  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(bin, args, {
        cwd: ctx.workDir,
        // OpenGrep crashes printing non-ASCII text without a UTF-8 locale.
        env: { ...process.env, LC_ALL: "C.UTF-8", LANG: "C.UTF-8" },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (d) => {
        stderr = (stderr + String(d)).slice(-4000);
      });
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`OpenGrep timed out after ${timeoutMs / 1000}s`));
      }, timeoutMs);
      const onAbort = () => child.kill("SIGKILL");
      ctx.signal?.addEventListener("abort", onAbort, { once: true });
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(timer);
        ctx.signal?.removeEventListener("abort", onAbort);
        // 0 = no findings, 1 = findings (with --error); anything else is a failure
        // unless results were still written.
        if (code === 0 || code === 1 || fs.existsSync(outputFile)) resolve();
        else reject(new Error(`OpenGrep exited with ${code}: ${stderr.trim().slice(-500)}`));
      });
    });

    if (!fs.existsSync(outputFile)) return [];
    const output = JSON.parse(fs.readFileSync(outputFile, "utf8")) as OpengrepOutput;
    const findings = mapOpengrepResults(output, ctx.workDir, indexRulePacks(packs));
    const errorCount = output.errors?.length ?? 0;
    logger.info(
      { findings: findings.length, errors: errorCount, scanned: output.paths?.scanned?.length },
      "OpenGrep scan complete",
    );
    ctx.onProgress?.(`OpenGrep: ${findings.length} findings`);
    return findings;
  } catch (err) {
    if (ctx.signal?.aborted) return [];
    logger.warn({ err: err instanceof Error ? err.message : String(err) }, "OpenGrep scan failed; continuing without rule-based SAST");
    return [];
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
