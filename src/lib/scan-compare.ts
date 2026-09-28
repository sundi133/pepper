/**
 * Compare the findings of two scan versions of the same repository.
 *
 * Matching runs in two passes so ordinary code movement does not show up as
 * "one fixed + one new":
 *   1. exact cross-scan fingerprint (scanner + rule + file + 5-line bucket);
 *   2. same scanner + rule + file, pairing the nearest remaining line.
 *
 * Suppressed findings (false positive / accepted risk) take part in matching
 * — so a suppression is never mistaken for a fix or a new issue — but are
 * reported separately instead of being counted as open work.
 */
import { findingRuleKey } from "@/lib/fix-verification";

export const COMPARE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type CompareSeverity = (typeof COMPARE_SEVERITIES)[number];

export interface CompareFinding {
  fingerprint: string;
  findingId?: string | null;
  scanner: string;
  severity: string;
  status: string;
  title: string;
  filePath: string | null;
  startLine: number | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
}

export interface PersistingPair {
  base: CompareFinding;
  target: CompareFinding;
  /** Matched by rule + file after the code moved (pass 2). */
  moved: boolean;
  /** Severity differs between the two versions. */
  severityChanged: boolean;
}

export interface CompareResult {
  fixed: CompareFinding[];
  introduced: CompareFinding[];
  persisting: PersistingPair[];
  /** Detected in the target but suppressed there (false positive / accepted risk). */
  suppressed: number;
  bySeverity: Record<CompareSeverity, { fixed: number; introduced: number; persisting: number }>;
  byFile: Array<{ filePath: string; fixed: number; introduced: number; net: number }>;
}

const SUPPRESSED = new Set(["FALSE_POSITIVE", "ACCEPTED_RISK"]);

function isSuppressed(f: CompareFinding): boolean {
  return SUPPRESSED.has(f.status);
}

function looseKey(f: CompareFinding): string {
  return `${f.scanner}|${findingRuleKey(f)}|${f.filePath ?? ""}`;
}

function lineDistance(a: CompareFinding, b: CompareFinding): number {
  return Math.abs((a.startLine ?? 0) - (b.startLine ?? 0));
}

const bySeverityThenLocation = (a: CompareFinding, b: CompareFinding) =>
  COMPARE_SEVERITIES.indexOf(a.severity as CompareSeverity) -
    COMPARE_SEVERITIES.indexOf(b.severity as CompareSeverity) ||
  (a.filePath ?? "").localeCompare(b.filePath ?? "") ||
  (a.startLine ?? 0) - (b.startLine ?? 0);

/** Pair each base finding with the nearest unmatched target finding sharing `keyOf`. */
function matchPass(
  base: CompareFinding[],
  target: CompareFinding[],
  keyOf: (f: CompareFinding) => string,
  moved: boolean,
  pairs: PersistingPair[],
): { base: CompareFinding[]; target: CompareFinding[] } {
  const pool = new Map<string, CompareFinding[]>();
  for (const t of target) pool.set(keyOf(t), [...(pool.get(keyOf(t)) ?? []), t]);
  const unmatchedBase: CompareFinding[] = [];
  for (const b of base) {
    const candidates = pool.get(keyOf(b));
    if (!candidates?.length) {
      unmatchedBase.push(b);
      continue;
    }
    let best = 0;
    for (let i = 1; i < candidates.length; i++) {
      if (lineDistance(b, candidates[i]) < lineDistance(b, candidates[best])) best = i;
    }
    const [t] = candidates.splice(best, 1);
    pairs.push({ base: b, target: t, moved, severityChanged: b.severity !== t.severity });
  }
  return { base: unmatchedBase, target: [...pool.values()].flat() };
}

export function compareFindingSets(
  baseFindings: CompareFinding[],
  targetFindings: CompareFinding[],
): CompareResult {
  const pairs: PersistingPair[] = [];
  const base = [...baseFindings].sort(bySeverityThenLocation);
  const target = [...targetFindings].sort(bySeverityThenLocation);

  const afterExact = matchPass(base, target, (f) => f.fingerprint, false, pairs);
  const afterLoose = matchPass(afterExact.base, afterExact.target, looseKey, true, pairs);

  // Only count work that was open: a suppressed finding disappearing is not a fix.
  const fixed = afterLoose.base.filter((f) => !isSuppressed(f)).sort(bySeverityThenLocation);
  const introduced = afterLoose.target.filter((f) => !isSuppressed(f)).sort(bySeverityThenLocation);
  const persisting = pairs
    .filter((p) => !isSuppressed(p.target))
    .sort((a, b) => bySeverityThenLocation(a.target, b.target));
  const suppressed =
    pairs.filter((p) => isSuppressed(p.target)).length +
    afterLoose.target.filter(isSuppressed).length;

  const bySeverity = Object.fromEntries(
    COMPARE_SEVERITIES.map((s) => [s, { fixed: 0, introduced: 0, persisting: 0 }]),
  ) as CompareResult["bySeverity"];
  const bump = (sev: string, key: "fixed" | "introduced" | "persisting") => {
    if (sev in bySeverity) bySeverity[sev as CompareSeverity][key]++;
  };
  fixed.forEach((f) => bump(f.severity, "fixed"));
  introduced.forEach((f) => bump(f.severity, "introduced"));
  persisting.forEach((p) => bump(p.target.severity, "persisting"));

  const files = new Map<string, { fixed: number; introduced: number }>();
  const fileRow = (path: string | null) => {
    const key = path ?? "(no file)";
    const row = files.get(key) ?? { fixed: 0, introduced: 0 };
    files.set(key, row);
    return row;
  };
  fixed.forEach((f) => fileRow(f.filePath).fixed++);
  introduced.forEach((f) => fileRow(f.filePath).introduced++);
  const byFile = [...files.entries()]
    .map(([filePath, v]) => ({ filePath, ...v, net: v.introduced - v.fixed }))
    .sort((a, b) => b.fixed + b.introduced - (a.fixed + a.introduced) || a.filePath.localeCompare(b.filePath))
    .slice(0, 10);

  return { fixed, introduced, persisting, suppressed, bySeverity, byFile };
}
