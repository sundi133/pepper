/**
 * Scoring for the AI SAST evaluation harness (see docs/AI_SAST_ACCURACY_SPEC.md).
 *
 * A finding counts as a hit when it is in the same file as an expected issue,
 * within its line range widened by LINE_SLACK, and of the same class (or one
 * of its accepted CWEs). Each expected issue is credited once; further hits
 * are duplicates. Findings on code labelled safe are false positives. Anything
 * else is "unlabelled": possibly a real issue the labels miss, so it is listed
 * for review instead of being counted as false straight away.
 */

export type VulnClass =
  | "authorization"
  | "business-logic"
  | "injection"
  | "ssrf"
  | "path-traversal"
  | "authentication"
  | "crypto"
  | "data-exposure"
  | "deserialization"
  | "config"
  | "hardening"
  | "reliability"
  | "other";

export interface TruthItem {
  id: string;
  file: string;
  lines: [number, number];
  class: VulnClass;
  cwe?: string[];
  severity?: string;
  note?: string;
  /** Other places a correct finding may point at (the same root cause seen from its caller or its data model). */
  alt?: Array<{ file: string; lines: [number, number] }>;
}

export interface SafeItem {
  id: string;
  file: string;
  lines: [number, number];
  reason?: string;
}

export interface Truth {
  app: string;
  language: string;
  include?: string[];
  expected: TruthItem[];
  must_not_report: SafeItem[];
  debatable: Array<SafeItem & { class?: VulnClass }>;
}

export interface EvalFinding {
  scanner: string;
  severity: string;
  title: string;
  cweId?: string | null;
  filePath?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  validation?: string;
  confidence?: number | null;
}

export type Outcome =
  | { kind: "hit"; id: string }
  | { kind: "duplicate"; id: string }
  | { kind: "safe-hit"; id: string }
  | { kind: "debatable"; id: string }
  | { kind: "unlabelled" };

export const LINE_SLACK = 10;

const CWE_CLASS: Record<string, VulnClass> = {};
const add = (cls: VulnClass, ids: number[]) => ids.forEach((n) => (CWE_CLASS[`CWE-${n}`] = cls));
add("authorization", [284, 285, 639, 862, 863, 266, 269, 425, 566, 602, 915, 732, 1220]);
add("business-logic", [840, 841, 837, 799, 362, 367, 1284, 601, 642]);
add("injection", [74, 77, 78, 79, 80, 83, 89, 90, 91, 93, 94, 95, 96, 97, 98, 113, 116, 117, 434, 611, 643, 652, 917, 943, 1236, 1336]);
add("ssrf", [918]);
add("path-traversal", [22, 23, 35, 36, 73, 59]);
add("authentication", [287, 288, 290, 294, 306, 307, 308, 347, 352, 384, 521, 522, 613, 620, 640, 798, 1390, 1391, 1392, 1393, 204, 203]);
add("crypto", [256, 257, 261, 295, 310, 326, 327, 328, 329, 330, 331, 338, 759, 760, 916]);
add("data-exposure", [200, 201, 209, 212, 213, 312, 319, 359, 497, 532, 538, 540, 548]);
add("deserialization", [502]);
add("config", [16, 489, 942, 1004, 614, 15, 250, 1188]);
add("hardening", [693, 1021, 1275]);
add("reliability", [400, 770, 1333, 674, 835, 404, 617]);

const TITLE_CLASS: Array<[RegExp, VulnClass]> = [
  [/\bidor\b|\bbola\b|\bbfla\b|object level|authori[sz]ation|access control|privilege|ownership|mass assignment/i, "authorization"],
  [/business logic|workflow|race condition|double spend|price|quantity|coupon|open redirect/i, "business-logic"],
  [/sql|nosql|command injection|code injection|\bxss\b|cross-site scripting|xxe|xml external|template injection|ldap|xpath|injection|file upload/i, "injection"],
  [/\bssrf\b|server-side request/i, "ssrf"],
  [/path traversal|directory traversal|file inclusion|\blfi\b|\brfi\b/i, "path-traversal"],
  [/authentication|\bjwt\b|token forgery|brute|credential|password|session|csrf|enumeration/i, "authentication"],
  [/crypto|hash|md5|sha1|random|cipher/i, "crypto"],
  [/exposure|leak|disclos|sensitive data/i, "data-exposure"],
  [/deserializ|pickle|yaml\.load/i, "deserialization"],
  [/header|csp|hsts|helmet|cookie flag/i, "hardening"],
  [/redos|denial of service|resource|unbounded/i, "reliability"],
  [/debug|cors|misconfig/i, "config"],
];

export function classOfCwe(cwe?: string | null): VulnClass | undefined {
  if (!cwe) return undefined;
  const norm = cwe.toUpperCase().replace(/^CWE[-\s]*/, "CWE-");
  return CWE_CLASS[norm];
}

export function classOf(f: Pick<EvalFinding, "cweId" | "title">): VulnClass {
  const byCwe = classOfCwe(f.cweId);
  if (byCwe) return byCwe;
  for (const [re, cls] of TITLE_CLASS) if (re.test(f.title)) return cls;
  return "other";
}

const norm = (p?: string | null) => (p || "").replace(/^\.?\//, "");

function near(f: EvalFinding, item: { file: string; lines: [number, number] }, slack: number): boolean {
  if (norm(f.filePath) !== norm(item.file)) return false;
  const start = f.startLine ?? 0;
  const end = f.endLine ?? start;
  return start <= item.lines[1] + slack && end >= item.lines[0] - slack;
}

/** Same kind of issue: same class, or one of the item's accepted CWEs. */
function sameKind(f: EvalFinding, item: TruthItem): boolean {
  const fc = f.cweId ? f.cweId.toUpperCase().replace(/^CWE[-\s]*/, "CWE-") : undefined;
  if (fc && item.cwe?.some((c) => c.toUpperCase() === fc)) return true;
  return classOf(f) === item.class;
}

export function scoreFindings(findings: EvalFinding[], truth: Truth): Array<EvalFinding & { outcome: Outcome; class: VulnClass }> {
  const credited = new Set<string>();
  return findings.map((f) => {
    const cls = classOf(f);
    const candidates = truth.expected.filter(
      (e) => (near(f, e, LINE_SLACK) || (e.alt ?? []).some((a) => near(f, a, LINE_SLACK))) && sameKind(f, e),
    );
    // Prefer an item not yet credited, then the closest one.
    candidates.sort((a, b) => {
      const ca = credited.has(a.id) ? 1 : 0;
      const cb = credited.has(b.id) ? 1 : 0;
      if (ca !== cb) return ca - cb;
      const d = (e: TruthItem) => Math.abs((f.startLine ?? 0) - e.lines[0]);
      return d(a) - d(b);
    });
    const hit = candidates[0];
    if (hit) {
      if (credited.has(hit.id)) return { ...f, class: cls, outcome: { kind: "duplicate", id: hit.id } };
      credited.add(hit.id);
      return { ...f, class: cls, outcome: { kind: "hit", id: hit.id } };
    }
    const safe = truth.must_not_report.find((s) => near(f, s, 3));
    if (safe) return { ...f, class: cls, outcome: { kind: "safe-hit", id: safe.id } };
    const deb = truth.debatable.find((d) => near(f, d, 3));
    if (deb) return { ...f, class: cls, outcome: { kind: "debatable", id: deb.id } };
    return { ...f, class: cls, outcome: { kind: "unlabelled" } };
  });
}

export interface ClassStats {
  expected: number;
  found: number;
  hits: number;
  safeHits: number;
  unlabelled: number;
  duplicates: number;
}

export interface AppScore {
  app: string;
  language: string;
  recall: number | null;
  /** Hits / (hits + safe hits + unlabelled): a lower bound until unlabelled findings are reviewed. */
  precisionLowerBound: number | null;
  /** Hits / (hits + safe hits): unlabelled findings excluded. */
  precisionLabelled: number | null;
  byClass: Record<string, ClassStats>;
  missed: TruthItem[];
  scored: ReturnType<typeof scoreFindings>;
}

const ratio = (a: number, b: number) => (b === 0 ? null : a / b);

export function scoreApp(findings: EvalFinding[], truth: Truth): AppScore {
  const scored = scoreFindings(findings, truth);
  const byClass: Record<string, ClassStats> = {};
  const stat = (c: string) => (byClass[c] ??= { expected: 0, found: 0, hits: 0, safeHits: 0, unlabelled: 0, duplicates: 0 });
  for (const e of truth.expected) stat(e.class).expected++;
  const hitIds = new Set<string>();
  for (const s of scored) {
    if (s.outcome.kind === "hit") {
      const item = truth.expected.find((e) => e.id === (s.outcome as { id: string }).id)!;
      stat(item.class).hits++;
      hitIds.add(item.id);
    } else if (s.outcome.kind === "duplicate") stat(s.class).duplicates++;
    else if (s.outcome.kind === "safe-hit") stat(s.class).safeHits++;
    else if (s.outcome.kind === "unlabelled") stat(s.class).unlabelled++;
    if (s.outcome.kind !== "debatable") stat(s.class).found++;
  }
  const hits = hitIds.size;
  const safeHits = scored.filter((s) => s.outcome.kind === "safe-hit").length;
  const unlabelled = scored.filter((s) => s.outcome.kind === "unlabelled").length;
  return {
    app: truth.app,
    language: truth.language,
    recall: ratio(hits, truth.expected.length),
    precisionLowerBound: ratio(hits, hits + safeHits + unlabelled),
    precisionLabelled: ratio(hits, hits + safeHits),
    byClass,
    missed: truth.expected.filter((e) => !hitIds.has(e.id)),
    scored,
  };
}
