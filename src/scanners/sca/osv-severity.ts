/**
 * Severity and fix-version extraction from full OSV vulnerability records.
 *
 * OSV publishes CVSS as a *vector* (`CVSS:3.1/AV:N/AC:L/...`), not a number,
 * so the CVSS v3.x base score is computed here (FIRST CVSS v3.1 spec, §7).
 * When no v3 vector is present the GitHub advisory severity in
 * database_specific / ecosystem_specific is used.
 */
import type { SeverityLevel } from "../types";

export interface OsvRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    ecosystem_specific?: { severity?: string };
    database_specific?: { severity?: string };
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { cwe_ids?: string[]; severity?: string };
}

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/** CVSS v3.1 Roundup: smallest number, to 1 decimal place, >= input. */
function roundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** CVSS v3.0 / v3.1 base score from a vector string, or null if unparseable. */
export function cvss3BaseScore(vector: string): number | null {
  const parts = vector.trim().split("/");
  if (!/^CVSS:3\.[01]$/.test(parts[0] ?? "")) return null;
  const m: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(":");
    if (k && v) m[k] = v;
  }
  const scopeChanged = m.S === "C";
  const pr =
    m.PR === "N" ? 0.85 : m.PR === "L" ? (scopeChanged ? 0.68 : 0.62) : m.PR === "H" ? (scopeChanged ? 0.5 : 0.27) : undefined;
  const av = AV[m.AV];
  const ac = AC[m.AC];
  const ui = UI[m.UI];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined) || (m.S !== "U" && m.S !== "C")) {
    return null;
  }
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr! * ui;
  if (impact <= 0) return 0;
  return scopeChanged
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10));
}

export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
}

function labelToSeverity(label: string | undefined): SeverityLevel | null {
  switch ((label ?? "").trim().toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MODERATE":
    case "MEDIUM":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    default:
      return null;
  }
}

/**
 * Best available severity for a record:
 *   1. CVSS v3.x vector → computed base score (a plain numeric score is accepted too)
 *   2. GitHub advisory severity (database_specific / affected[].*_specific)
 *   3. MEDIUM when nothing is published (same as before)
 */
export function osvSeverity(vuln: OsvRecord): { severity: SeverityLevel; cvssScore: number | null } {
  for (const s of vuln.severity ?? []) {
    if (s.type !== "CVSS_V3") continue;
    const numeric = Number(s.score);
    const score = Number.isFinite(numeric) ? numeric : cvss3BaseScore(s.score);
    if (score !== null) return { severity: scoreToSeverity(score), cvssScore: score };
  }
  const label =
    labelToSeverity(vuln.database_specific?.severity) ??
    vuln.affected?.map((a) => labelToSeverity(a.database_specific?.severity ?? a.ecosystem_specific?.severity)).find(Boolean) ??
    null;
  return { severity: label ?? "MEDIUM", cvssScore: null };
}

/** Loose version ordering good enough to pick a fix version: 1.2.10 > 1.2.9, 2.0.0-rc1 < 2.0.0. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string): [string, string] => {
    const s = v.replace(/^v/i, "");
    const dash = s.indexOf("-");
    return dash === -1 ? [s, ""] : [s.slice(0, dash), s.slice(dash + 1)];
  };
  const [aMain, aPre] = split(a);
  const [bMain, bPre] = split(b);
  const ap = aMain.split(/[.+]/);
  const bp = bMain.split(/[.+]/);
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    const x = ap[i] ?? "0";
    const y = bp[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    const diff = Number.isFinite(nx) && Number.isFinite(ny) ? nx - ny : x.localeCompare(y);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  if (aPre === bPre) return 0;
  if (!aPre) return 1; // release > pre-release
  if (!bPre) return -1;
  return aPre.localeCompare(bPre, undefined, { numeric: true });
}

function samePackage(recordName: string | undefined, depName: string, ecosystem: string): boolean {
  if (!recordName) return false;
  const norm = (n: string) =>
    ecosystem === "PyPI" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n.toLowerCase();
  return norm(recordName) === norm(depName);
}

/**
 * The version that fixes this record for this dependency: the lowest `fixed`
 * above the installed version among this package's semver/ecosystem ranges
 * (git-commit ranges are ignored). Undefined when no fix is published.
 */
export function osvFixVersion(
  vuln: OsvRecord,
  dep: { name: string; version: string; ecosystem: string },
): string | undefined {
  const relevant = (vuln.affected ?? []).filter((a) => samePackage(a.package?.name, dep.name, dep.ecosystem));
  const pool = relevant.length ? relevant : (vuln.affected ?? []);
  const fixes = pool
    .flatMap((a) => a.ranges ?? [])
    .filter((r) => r.type !== "GIT")
    .flatMap((r) => r.events.map((e) => e.fixed))
    .filter((f): f is string => typeof f === "string" && f.length > 0);
  if (!fixes.length) return undefined;
  const above = fixes.filter((f) => compareVersions(f, dep.version) > 0).sort(compareVersions);
  return above[0] ?? fixes.sort(compareVersions)[fixes.length - 1];
}
