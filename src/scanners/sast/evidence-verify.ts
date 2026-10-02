/** The minimal finding shape this gate needs; RawFinding satisfies it. */
export interface EvidenceCandidate {
  startLine?: number;
  metadata?: unknown;
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
