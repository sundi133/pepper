/**
 * Rule-based IaC scanning with `trivy config` (Trivy: Apache-2.0, checks: MIT).
 *
 * Covers Terraform, CloudFormation, Azure ARM, Kubernetes manifests (found
 * by content, anywhere in the repo), Helm charts (rendered with their
 * values) and Ansible. Runs offline with the checks embedded in the Trivy
 * binary, with telemetry and version checks disabled. Deterministic, so it
 * runs whether or not LLM analysis is enabled.
 *
 * Dockerfiles are left to the existing Dockerfile lint (container scanner).
 */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { logger } from "@/lib/logger";
import type { RawFinding, ScanContext, SeverityLevel } from "../types";

// ─── Policy ───────────────────────────────────────────────────────────

export interface IacGroup {
  id: string;
  checks: string[];
  title: string;
  severity: SeverityLevel;
  resolution: string;
}

export interface IacPolicy {
  minSeverity: SeverityLevel;
  misconfigScanners: string[];
  excludeChecks: Set<string>;
  groups: IacGroup[];
}

const ORDER: SeverityLevel[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** "KSV017" / "ksv-17" / "KSV-0017" → "KSV-0017". */
export function normalizeCheckId(id: string): string {
  const m = id.trim().toUpperCase().match(/^([A-Z]+)-?0*(\d+)$/);
  return m ? `${m[1]}-${m[2].padStart(4, "0")}` : id.trim().toUpperCase();
}

export function iacPolicyPath(): string {
  return process.env.IAC_POLICY_FILE?.trim() || path.join(process.cwd(), "rules", "trivy", "iac-policy.json");
}

export function loadIacPolicy(
  file = iacPolicyPath(),
  env: Record<string, string | undefined> = process.env,
): IacPolicy {
  const raw = fs.existsSync(file)
    ? (JSON.parse(fs.readFileSync(file, "utf8")) as {
        minSeverity?: string;
        misconfigScanners?: string[];
        excludeChecks?: Record<string, string> | string[];
        groups?: IacGroup[];
      })
    : {};
  const envMin = env.IAC_MIN_SEVERITY?.trim().toUpperCase();
  const min = (ORDER as string[]).includes(envMin ?? "")
    ? (envMin as SeverityLevel)
    : ((raw.minSeverity?.toUpperCase() as SeverityLevel) ?? "HIGH");
  const excluded = Array.isArray(raw.excludeChecks) ? raw.excludeChecks : Object.keys(raw.excludeChecks ?? {});
  const extra = (env.IAC_EXCLUDE_CHECKS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    minSeverity: (ORDER as string[]).includes(min) ? min : "HIGH",
    misconfigScanners: raw.misconfigScanners?.length
      ? raw.misconfigScanners
      : ["terraform", "cloudformation", "azure-arm", "kubernetes", "helm", "ansible"],
    excludeChecks: new Set([...excluded, ...extra].map(normalizeCheckId)),
    groups: (raw.groups ?? []).map((g) => ({ ...g, checks: g.checks.map(normalizeCheckId) })),
  };
}

// ─── Trivy JSON ───────────────────────────────────────────────────────

export interface TrivyMisconfig {
  ID: string;
  AVDID?: string;
  Title: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity: string;
  PrimaryURL?: string;
  References?: string[];
  Status?: string;
  CauseMetadata?: {
    Resource?: string;
    Provider?: string;
    Service?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: { Lines?: Array<{ Number: number; Content: string; IsCause?: boolean }> | null };
  };
}

export interface TrivyConfigOutput {
  Results?: Array<{ Target: string; Class?: string; Type?: string; Misconfigurations?: TrivyMisconfig[] | null }>;
}

const K8S_TYPES = new Set(["kubernetes", "helm"]);

function toSeverity(s: string): SeverityLevel {
  const up = s.toUpperCase();
  return (ORDER as string[]).includes(up) ? (up as SeverityLevel) : "MEDIUM";
}

function atLeast(sev: SeverityLevel, min: SeverityLevel): boolean {
  return ORDER.indexOf(sev) >= ORDER.indexOf(min);
}

function snippetOf(m: TrivyMisconfig): string | undefined {
  const lines = m.CauseMetadata?.Code?.Lines ?? [];
  const cause = lines.filter((l) => l.IsCause);
  const chosen = (cause.length ? cause : lines).slice(0, 8);
  if (!chosen.length) return undefined;
  return chosen.map((l) => `${l.Number}: ${l.Content}`).join("\n").slice(0, 1000);
}

function description(parts: Array<string | undefined>, resolution?: string): string {
  const body = parts.filter((p): p is string => !!p && !!p.trim()).join("\n\n");
  return resolution ? `${body}\n\n**Fix:** ${resolution}` : body;
}

/**
 * Map `trivy config` output to findings: failures only, at or above the
 * policy's minimum severity, minus excluded checks; related checks in a
 * group collapse into one finding per resource.
 */
export function mapTrivyConfigResults(output: TrivyConfigOutput, policy: IacPolicy): RawFinding[] {
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  const grouped = new Map<string, { group: IacGroup; target: string; type: string; hits: TrivyMisconfig[] }>();
  const groupOf = new Map<string, IacGroup>();
  for (const g of policy.groups) for (const c of g.checks) groupOf.set(c, g);

  for (const result of output.Results ?? []) {
    const type = (result.Type ?? "").toLowerCase();
    for (const m of result.Misconfigurations ?? []) {
      if (m.Status && m.Status !== "FAIL") continue;
      const checkId = normalizeCheckId(m.ID);
      if (policy.excludeChecks.has(checkId)) continue;

      const group = groupOf.get(checkId);
      if (group) {
        const key = `${group.id}|${result.Target}|${m.CauseMetadata?.Resource ?? ""}`;
        const g = grouped.get(key) ?? { group, target: result.Target, type, hits: [] };
        g.hits.push(m);
        grouped.set(key, g);
        continue;
      }

      const severity = toSeverity(m.Severity);
      if (!atLeast(severity, policy.minSeverity)) continue;
      const start = m.CauseMetadata?.StartLine || undefined;
      const key = `${checkId}|${result.Target}|${start ?? ""}|${m.CauseMetadata?.Resource ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        scanner: K8S_TYPES.has(type) ? "K8S" : "IAC",
        severity,
        title: m.Title,
        description: description([m.Description, m.Message], m.Resolution),
        filePath: result.Target,
        startLine: start,
        endLine: m.CauseMetadata?.EndLine || start,
        snippet: snippetOf(m),
        ruleId: checkId,
        confidence: 0.95,
        metadata: {
          detectionMethod: "Rule-based (Trivy config)",
          engine: "trivy",
          category: "IAC_MISCONFIG",
          weaknessClass: checkId,
          checkId,
          avdId: m.AVDID,
          iacType: type,
          resource: m.CauseMetadata?.Resource,
          provider: m.CauseMetadata?.Provider,
          service: m.CauseMetadata?.Service,
          references: m.References ?? (m.PrimaryURL ? [m.PrimaryURL] : undefined),
          remediation: m.Resolution,
        },
      });
    }
  }

  for (const { group, target, type, hits } of grouped.values()) {
    if (!atLeast(group.severity, policy.minSeverity)) continue;
    const starts = hits.map((h) => h.CauseMetadata?.StartLine).filter((n): n is number => !!n);
    const ends = hits.map((h) => h.CauseMetadata?.EndLine).filter((n): n is number => !!n);
    const checks = [...new Set(hits.map((h) => normalizeCheckId(h.ID)))].sort();
    findings.push({
      scanner: K8S_TYPES.has(type) ? "K8S" : "IAC",
      severity: group.severity,
      title: group.title,
      description: description(
        [`${checks.length} related check${checks.length === 1 ? "" : "s"} failed for ${hits[0].CauseMetadata?.Resource ?? "this resource"}:`,
          hits.map((h) => `- ${normalizeCheckId(h.ID)}: ${h.Title}`).join("\n")],
        group.resolution,
      ),
      filePath: target,
      startLine: starts.length ? Math.min(...starts) : undefined,
      endLine: ends.length ? Math.max(...ends) : undefined,
      snippet: snippetOf(hits[0]),
      ruleId: group.id.toUpperCase(),
      confidence: 0.95,
      metadata: {
        detectionMethod: "Rule-based (Trivy config)",
        engine: "trivy",
        category: "IAC_MISCONFIG",
        weaknessClass: group.id,
        checkIds: checks,
        iacType: type,
        resource: hits[0].CauseMetadata?.Resource,
        references: [...new Set(hits.flatMap((h) => h.References ?? []))].slice(0, 6),
        remediation: group.resolution,
      },
    });
  }
  return findings;
}

// ─── Runner ───────────────────────────────────────────────────────────

let trivyBin: string | null | undefined;

export function resolveTrivyBinary(): string | null {
  if (trivyBin !== undefined) return trivyBin;
  const candidate = process.env.TRIVY_BIN?.trim() || "trivy";
  trivyBin = spawnSync(candidate, ["--version"], { encoding: "utf8", timeout: 20_000 }).status === 0 ? candidate : null;
  if (!trivyBin) logger.warn({ candidate }, "Trivy not found; rule-based IaC scanning is disabled");
  return trivyBin;
}

export function trivyIacEnabled(): boolean {
  return (process.env.ENABLE_TRIVY_IAC ?? "true").toLowerCase() !== "false";
}

/** Which misconfig scanners to run for a scan type. */
export function misconfigScannersFor(scanType: string, policy: IacPolicy): string[] {
  if (scanType === "K8S_ONLY") return policy.misconfigScanners.filter((s) => K8S_TYPES.has(s));
  if (scanType === "IAC_ONLY") return policy.misconfigScanners.filter((s) => !K8S_TYPES.has(s));
  return policy.misconfigScanners;
}

export function buildTrivyConfigArgs(opts: { policy: IacPolicy; scanners: string[]; outputFile: string; target: string }): string[] {
  // Grouped checks can be rated LOW individually (e.g. AWS-0094), so request
  // down to LOW when groups exist; the mapping applies the real threshold.
  const floor: SeverityLevel = opts.policy.groups.length ? "LOW" : opts.policy.minSeverity;
  const requested = ORDER.filter((s) => s !== "INFO" && atLeast(s, floor));
  return [
    "config",
    "--quiet",
    "--format",
    "json",
    "--output",
    opts.outputFile,
    // Offline + no data leaves the network: embedded checks, no telemetry,
    // no update notices.
    "--skip-check-update",
    "--disable-telemetry",
    "--skip-version-check",
    "--severity",
    requested.join(","),
    "--misconfig-scanners",
    opts.scanners.join(","),
    "--skip-dirs",
    "**/node_modules",
    "--skip-dirs",
    "**/.git",
    "--skip-dirs",
    "**/.terraform",
    "--timeout",
    `${Number(process.env.IAC_TRIVY_TIMEOUT_SECONDS || 600)}s`,
    opts.target,
  ];
}

export async function runTrivyIacScanner(ctx: ScanContext): Promise<RawFinding[]> {
  if (!trivyIacEnabled()) return [];
  const bin = resolveTrivyBinary();
  if (!bin) return [];
  const policy = loadIacPolicy();
  const scanners = misconfigScannersFor(ctx.scanType, policy);
  if (!scanners.length) return [];

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-trivy-iac-"));
  const outputFile = path.join(tmp, "results.json");
  const args = buildTrivyConfigArgs({ policy, scanners, outputFile, target: "." });
  const timeoutMs = (Number(process.env.IAC_TRIVY_TIMEOUT_SECONDS || 600) + 60) * 1000;
  ctx.onProgress?.(`Trivy: checking ${scanners.join(", ")} configuration`);

  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(bin, args, { cwd: ctx.workDir, stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (d) => {
        stderr = (stderr + String(d)).slice(-4000);
      });
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`trivy config timed out after ${timeoutMs / 1000}s`));
      }, timeoutMs);
      const onAbort = () => child.kill("SIGKILL");
      ctx.signal?.addEventListener("abort", onAbort, { once: true });
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(timer);
        ctx.signal?.removeEventListener("abort", onAbort);
        if (code === 0) resolve();
        else reject(new Error(`trivy config exited with ${code}: ${stderr.trim().slice(-500)}`));
      });
    });
    if (!fs.existsSync(outputFile)) return [];
    const output = JSON.parse(fs.readFileSync(outputFile, "utf8")) as TrivyConfigOutput;
    const findings = mapTrivyConfigResults(output, policy);
    logger.info({ findings: findings.length, scanners }, "Trivy IaC scan complete");
    ctx.onProgress?.(`Trivy: ${findings.length} configuration findings`);
    return findings;
  } catch (err) {
    if (ctx.signal?.aborted) return [];
    logger.warn({ err: err instanceof Error ? err.message : String(err) }, "Trivy IaC scan failed; continuing without it");
    return [];
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** Rule-based IaC + Kubernetes/Helm misconfiguration scanner. */
export const iacRulesScanner = {
  name: "IAC_RULES",
  scan: runTrivyIacScanner,
};
