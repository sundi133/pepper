/**
 * Incident-pattern pack (docs/LOGIC_FLAW_DETECTION_SPEC.md §5). Each pattern
 * asks one focused question, with an exploit test and a defence test, about
 * code regions the map pass tagged with the pattern's trait (or, for files the
 * map didn't read, regions a language-neutral keyword prefilter found).
 */
import type { RawFinding } from "../../types";
import { UNTRUSTED_CONTENT_GUARD } from "../../shared/prompts";
import { enrichFinding } from "../../shared/finding-normalize";
import { applySeverityCalibration, SEVERITY_CALIBRATION_PROMPT } from "@/lib/severity-calibration";
import type { Trait, TraitRegion } from "./map";
import { SourceFiles, resolveKnownFile, verifyQuote } from "./source";

export interface IncidentPattern {
  id: string;
  trait: Trait;
  cwe: string[];
  name: string;
  question: string;
  exploitTest: string;
  defenceTest: string;
  notFindings: string[];
  /** Language-neutral prefilter for files the map pass did not read. */
  keywords: RegExp;
}

export const PATTERNS: IncidentPattern[] = [
  {
    id: "P1",
    trait: "security-check-error-path",
    cwe: ["CWE-636", "CWE-280"],
    name: "Fail-open security check",
    question: "Does an error, exception or missing setting in this security check let the request through?",
    exploitTest: "The attacker makes the check fail (malformed or expired token, unreachable dependency, oversized or unexpected input) or relies on a missing setting, and the protected action still runs.",
    defenceTest: "Every error path denies (returns 401/403, rethrows, passes the error on) and a missing setting stops startup or denies.",
    notFindings: ["logging and rethrowing", "fallbacks in features that are not security checks", "an error path that returns a generic error and stops the request"],
    keywords: /\b(?:catch|except|rescue|recover)\b[\s\S]{0,400}\b(?:verify|valid|auth|token|permission|signature|allow|next\(\)|return true|pass\b)/i,
  },
  {
    id: "P2",
    trait: "external-event-side-effect",
    cwe: ["CWE-837", "CWE-294"],
    name: "Event processed twice",
    question: "Can the same external event (webhook, callback, payment notification, queue message) apply its side effect more than once?",
    exploitTest: "The same event is delivered twice — a provider retry or an attacker replaying a captured request — and the credit, refund, fulfilment, message or balance change happens twice.",
    defenceTest: "An event id or idempotency key is checked and recorded, a unique constraint prevents the second write, or a status is checked and changed in the same transaction.",
    notFindings: ["read-only handlers", "updates that set a fixed value and are naturally idempotent"],
    keywords: /\b(?:webhooks?|callbacks?|ipn|notifications?|events?|consumes?|onMessage|handle_?message)\b[\s\S]{0,600}\b(?:credit|refund|balance|fulfil|ship|paid|send|grant|increment|update)\w*/i,
  },
  {
    id: "P3",
    trait: "cache-or-shared-state",
    cwe: ["CWE-524", "CWE-488"],
    name: "Data shared across users or tenants",
    question: "Can one user or tenant receive data cached or stored for another?",
    exploitTest: "User B (or tenant B) gets a response built from data cached or kept in shared memory for user A, because the key leaves out the user or tenant, or request state lives in a module-level or global variable.",
    defenceTest: "The key includes the user or tenant id, the data is identical for everyone, or the state is scoped to one request.",
    notFindings: ["caches of public or global data (configuration, catalogs, exchange rates)", "constants"],
    keywords: /\b(?:cache|memo|memoize|lru_cache|redis|memcache|global|static)\b[\s\S]{0,400}\b(?:user|session|tenant|account|profile|token)\b/i,
  },
  {
    id: "P4",
    trait: "job-loads-by-payload-id",
    cwe: ["CWE-639", "CWE-862"],
    name: "Background job without the API's check",
    question: "Does this job or consumer act on records chosen by its payload without the ownership or tenant check the API applies?",
    exploitTest: "A user who can enqueue the job (directly, or through an API that forwards input) makes it read or change another user's or tenant's records.",
    defenceTest: "The job re-scopes by the owner or tenant captured when it was enqueued, or the API that enqueues it already constrained the id to the caller's records.",
    notFindings: ["system jobs that intentionally process all records", "ids produced by the server, never by a user"],
    keywords: /\b(?:job|task|worker|consumer|queue|process)\b[\s\S]{0,400}\b(?:payload|data|message|args)\b[\s\S]{0,200}\b(?:id|Id|_id)\b/,
  },
  {
    id: "P5",
    trait: "read-then-write-value",
    cwe: ["CWE-362", "CWE-367"],
    name: "Race on a value read then written",
    question: "Can two concurrent requests both pass the check on this value and both apply the change?",
    exploitTest: "Two requests sent at the same moment both read the same balance, stock, quota, credit or single-use flag, both pass the check, and both write — double spend, oversell, coupon reuse, quota bypass.",
    defenceTest: "Row locking in a transaction (SELECT … FOR UPDATE), an atomic conditional update (UPDATE … SET balance = balance - x WHERE balance >= x), an optimistic version check, or a unique constraint.",
    notFindings: ["values that are not security- or money-relevant", "single-user local state"],
    keywords: /\b(?:balance|stock|inventory|quantity|quota|credits?|remaining|redeemed|used|uses|count)\b[\s\S]{0,400}(?:save|update|commit|set|=)/i,
  },
  {
    id: "P6",
    trait: "money-arithmetic",
    cwe: ["CWE-1339", "CWE-681", "CWE-1284"],
    name: "Unsafe money arithmetic",
    question: "Can an attacker gain value through how amounts are parsed, validated or computed here?",
    exploitTest: "A negative or zero amount reverses a transfer or refund; a client-sent total, unit price or discount is trusted; floating-point rounding is exploited by repeating small operations.",
    defenceTest: "Amounts are integer minor units or a decimal type, validated as positive and bounded, and totals are recomputed on the server from stored prices.",
    notFindings: ["floats used only for display, logging or analytics", "amounts that are validated before use"],
    keywords: /\b(?:amount|price|total|fee|refund|balance|cost|discount)\b[\s\S]{0,300}(?:parseFloat|Number\(|float\(|double|Decimal|[-+*/]\s*\w)/i,
  },
];

export function patternSystemPrompt(p: IncidentPattern): string {
  return `You are a senior application security engineer reviewing code regions for ONE kind of flaw: ${p.name} (${p.cwe.join(", ")}).

Question: ${p.question}

${UNTRUSTED_CONTENT_GUARD}

For EACH region:
1. EXPLOIT TEST — ${p.exploitTest} Describe the concrete steps against THIS code. If you cannot, it is not a finding.
2. DEFENCE TEST — ${p.defenceTest} If such a control is present (in the region or in code it clearly calls), it is not a finding.
3. Not findings: ${p.notFindings.join("; ")}.

Report only regions where the exploit test succeeds and the defence test finds nothing. Cite the line where the flaw is, with a verbatim quote of that line; it must be inside the region.

Respond with JSON only:
{"findings":[{"region":"R1","title":"…","severity":"HIGH","confidence":0.85,"cweId":"${p.cwe[0]}","file":"…","line":0,"quote":"…","description":"what is wrong and its impact","exploit":"the concrete steps","defence":"what you looked for and did not find","recommendation":"the specific fix"}]}
If nothing qualifies: {"findings":[]}

confidence: 0.90–1.0 when the whole flaw is visible; 0.80–0.89 when one minor detail is inferred; below 0.80 do not report. Never invent code that is not shown.

${SEVERITY_CALIBRATION_PROMPT}`;
}

export interface Region { id: string; pattern: IncidentPattern; file: string; startLine: number; endLine: number }

/**
 * Regions for each pattern: the map's verified trait ranges first, then keyword
 * windows in files the map pass did not read. Overlaps are merged; caps apply
 * per pattern and per scan.
 */
export function selectRegions(src: SourceFiles, traits: TraitRegion[], unreadFiles: string[], perPattern: number, total: number): Region[] {
  const out: Region[] = [];
  for (const p of PATTERNS) {
    const mine: Array<{ file: string; startLine: number; endLine: number }> = traits.filter((t) => t.trait === p.trait).map((t) => ({ file: t.file, startLine: t.startLine, endLine: t.endLine }));
    for (const file of unreadFiles) {
      if (mine.length >= perPattern * 2) break;
      const lines = src.lines(file);
      if (!lines) continue;
      const text = lines.join("\n");
      const m = p.keywords.exec(text);
      if (!m) continue;
      const line = text.slice(0, m.index).split("\n").length;
      mine.push({ file, startLine: Math.max(1, line - 15), endLine: Math.min(lines.length, line + 35) });
    }
    const merged: typeof mine = [];
    for (const r of mine.sort((a, b) => a.file.localeCompare(b.file) || a.startLine - b.startLine)) {
      const last = merged[merged.length - 1];
      if (last && last.file === r.file && r.startLine <= last.endLine + 3) last.endLine = Math.max(last.endLine, r.endLine);
      else merged.push({ ...r });
    }
    for (const r of merged.slice(0, perPattern)) out.push({ id: "", pattern: p, ...r });
  }
  return out.slice(0, total).map((r, i) => ({ ...r, id: `R${i + 1}` }));
}

export function patternUserContent(src: SourceFiles, regions: Region[]): string {
  return regions
    .map((r) => `═══ REGION ${r.id} — ${r.file} lines ${r.startLine}-${r.endLine}\n\`\`\`\n${src.numbered(r.file, r.startLine, r.endLine)}\n\`\`\``)
    .join("\n\n");
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

export function findingsFromPatternAnswer(answer: unknown, regions: Region[], src: SourceFiles, known: Set<string>, minConfidence: number): { findings: RawFinding[]; evidenceFailed: number; lowConfidence: number } {
  const res = { findings: [] as RawFinding[], evidenceFailed: 0, lowConfidence: 0 };
  const list = Array.isArray((answer as { findings?: unknown })?.findings) ? (answer as { findings: unknown[] }).findings : [];
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const f = raw as Record<string, unknown>;
    const region = regions.find((r) => r.id === f.region);
    const file = resolveKnownFile(f.file, known);
    const line = Number(f.line);
    if (!region || !file || file !== region.file || line < region.startLine || line > region.endLine || !verifyQuote(src, file, line, f.quote)) {
      res.evidenceFailed++;
      continue;
    }
    const confidence = typeof f.confidence === "number" ? f.confidence : 0;
    if (confidence < minConfidence) {
      res.lowConfidence++;
      continue;
    }
    const p = region.pattern;
    const sev = String(f.severity || "").toUpperCase();
    const title = String(f.title || p.name).slice(0, 200);
    const lines = src.lines(file) ?? [];
    const snippet = lines.slice(Math.max(0, line - 3), Math.min(lines.length, line + 2)).map((l, i) => `${Math.max(1, line - 2) + i}: ${l}`).join("\n");
    const cwe = typeof f.cweId === "string" && /^CWE-\d+$/.test(f.cweId) ? f.cweId : p.cwe[0];
    const base = applySeverityCalibration({
      scanner: "ZERO_DAY",
      severity: (SEVERITIES.has(sev) ? sev : "MEDIUM") as RawFinding["severity"],
      title: `[Zero-Day] ${title}`,
      description: String(f.description || ""),
      filePath: file,
      startLine: line,
      endLine: line,
      snippet,
      cweId: cwe,
      confidence,
      ruleId: `ZD-PATTERN-${p.id}`,
      metadata: {
        category: "Business Logic",
        weaknessClass: p.id === "P5" ? "Race Condition" : p.id === "P3" ? "Multi-tenant" : p.id === "P4" ? "Authorization" : "Business Logic",
        pattern: p.id,
        remediation: String(f.recommendation || p.defenceTest),
        severityJustification: `${p.name}, confirmed with an exploit and a defence test`,
      },
    });
    res.findings.push(
      enrichFinding(base, base.metadata as Record<string, unknown>, {
        whatIsWrong: title,
        where: `${file}:${line}`,
        whyExploitable: String(f.exploit || f.description || ""),
        attackPath: String(f.exploit || ""),
        impact: String(f.description || ""),
        fix: String(f.recommendation || p.defenceTest),
        validation: `Reproduce the exploit test in a staging environment and confirm it fails after the fix.${f.defence ? ` Checked for: ${String(f.defence).slice(0, 300)}` : ""}`,
      }),
    );
  }
  return res;
}
