/** The minimal finding shape this gate needs; RawFinding satisfies it. */
export interface EvidenceCandidate {
  startLine?: number;
  title?: string;
  cweId?: string | null;
  metadata?: unknown;
}

/**
 * Weaknesses that are about a missing or wrong control rather than a call to
 * a dangerous API: broken access control (IDOR/BOLA/BFLA, missing ownership
 * or role checks), authentication and session flaws, and business-logic flaws
 * (workflow bypass, race conditions, mass assignment, price/quantity abuse).
 * The model describes these in words ("no ownership check before the
 * lookup"), so the identifiers it cites need not appear in the file. They are
 * a core part of what Pepper reports and are never dropped by this gate.
 */
const ABSENCE_CWES = new Set([
  // Access control
  "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-266", "CWE-269",
  "CWE-425", "CWE-566", "CWE-602", "CWE-472",
  // Authentication and sessions
  "CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-307", "CWE-384", "CWE-613",
  "CWE-620", "CWE-640", "CWE-352",
  // Business logic
  "CWE-840", "CWE-841", "CWE-837", "CWE-799", "CWE-770", "CWE-362", "CWE-367",
  "CWE-915", "CWE-1284",
]);

const ABSENCE_TITLE =
  /\b(?:idor|bola|bfla|insecure direct object|authori[sz]ation|access control|privilege|ownership|tenant|business[- ]logic|workflow|race condition|toctou|mass assignment|over-?posting|forced browsing|replay|double[- ]spend|price manipulation|negative (?:amount|quantity|price)|rate limit|brute[- ]force|missing (?:auth\w*|role|permission|ownership|check|validation|csrf))\b|auth(?:entication|orization)?\s+bypass/i;

const ABSENCE_WEAKNESS = /idor|auth bypass|authori[sz]ation|access control|business logic|privilege/i;

/** An authorization, authentication or business-logic finding (see ABSENCE_CWES). */
export function isAuthorizationOrLogicFinding(finding: EvidenceCandidate): boolean {
  const cwe = (finding.cweId || "").toUpperCase().replace(/^CWE[-\s]*/, "CWE-");
  if (ABSENCE_CWES.has(cwe)) return true;
  if (finding.title && ABSENCE_TITLE.test(finding.title)) return true;
  const weakness = ((finding.metadata || {}) as Record<string, unknown>).weaknessClass;
  return typeof weakness === "string" && ABSENCE_WEAKNESS.test(weakness);
}

/**
 * Deterministic anti-hallucination gate for AI SAST findings.
 *
 * The LLM names the exact sink/parameter it believes is vulnerable. Those
 * names are identifiers that must exist verbatim in the file it was shown. If
 * the model invented a sink (`userInput` when the code defines `payload`),
 * split a name that never appears, or cited a line beyond the end of the file,
 * the finding cannot be real. This check is deliberately conservative: it only
 * drops a finding when the specific identifiers it cites are absent from the
 * file entirely — it never judges severity, exploitability, or correctness of
 * the reasoning, which remain the job of the validation passes.
 */

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** Grammatical/structural words that carry no evidence value. Code-relevant
 * names (query, exec, input, request, data, …) are deliberately NOT stopped:
 * a real sink name is exactly the evidence we want to match against the file. */
const STOP_WORDS = new Set([
  "the", "and", "from", "with", "that", "this", "into", "null", "undefined",
  "true", "false", "string", "number", "object", "array", "function", "method",
  "call", "http", "https", "api", "parameter", "argument", "attribute",
  "property", "variable",
]);

export interface EvidenceVerification {
  /** False only when the finding is a clear hallucination. */
  ok: boolean;
  /** Why it was rejected. */
  reason?: string;
  /** Identifier anchors extracted from the finding's cited metadata. */
  anchors: string[];
  /** Anchors that were found verbatim in the file. */
  matched: string[];
}

/** Split a cited sink/parameter field into candidate identifier anchors. */
function normalizeAnchorTokens(value: string): string[] {
  const candidate = value.trim();
  if (!candidate || candidate.toLowerCase() === "null") return [];
  const tokens = new Set<string>();
  for (const part of candidate.split(/[^A-Za-z0-9_$]+/)) {
    if (part.length < 3) continue;
    if (!IDENTIFIER.test(part)) continue;
    if (STOP_WORDS.has(part.toLowerCase())) continue;
    tokens.add(part);
  }
  return [...tokens];
}

/**
 * Collect the exact identifiers the model claimed to observe: the sink, the
 * user-controlled parameter, and any named function. Route/method are excluded
 * because they are frequently inferred and are not stable identifiers.
 */
export function extractEvidenceAnchors(finding: EvidenceCandidate): string[] {
  const meta = (finding.metadata || {}) as Record<string, unknown>;
  const fields: unknown[] = [meta.sink, meta.parameter, meta.sinkFunction, meta.function];
  const anchors = new Set<string>();
  for (const v of fields) {
    if (typeof v !== "string") continue;
    for (const token of normalizeAnchorTokens(v)) anchors.add(token);
  }
  return [...anchors];
}

/**
 * Verify a finding's cited evidence against the source file it came from.
 *
 * Returns ok=true whenever the check cannot make a determination (no file
 * content, no identifiers cited, or at least one identifier present) so the
 * finding stays for the validation passes rather than being silently removed.
 */
export function verifyFindingEvidence(
  finding: EvidenceCandidate,
  fileContent: string | undefined,
): EvidenceVerification {
  const anchors = extractEvidenceAnchors(finding);

  if (!fileContent || fileContent.length === 0) {
    return { ok: true, anchors, matched: [] };
  }

  // Cited line must exist in the file; a startLine past EOF is invented.
  const lineCount = fileContent.split("\n").length;
  if (finding.startLine && finding.startLine > lineCount) {
    return {
      ok: false,
      reason: `cited line ${finding.startLine} is outside the ${lineCount}-line file`,
      anchors,
      matched: [],
    };
  }

  if (anchors.length === 0) {
    return { ok: true, anchors, matched: [] };
  }

  // Authorization and business-logic findings describe a missing control,
  // not a named sink: never dropped for their wording.
  if (isAuthorizationOrLogicFinding(finding)) {
    return { ok: true, anchors, matched: anchors.filter((a) => fileContent.includes(a)) };
  }

  const matched = anchors.filter((a) => fileContent.includes(a));
  if (matched.length === 0) {
    return {
      ok: false,
      reason: `none of the cited sink/parameter identifiers (${anchors.join(", ")}) appear in the file`,
      anchors,
      matched,
    };
  }

  return { ok: true, anchors, matched };
}
