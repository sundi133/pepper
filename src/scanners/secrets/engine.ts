import { RawFinding } from "../types";
import { SECRET_PATTERNS } from "./patterns";
import { isHighEntropy, extractCandidateValues } from "./entropy";
import { maskSnippet } from "./masker";
import { isEnvFile, scanDotenvLine } from "./env-files";
import { SecretLineHit } from "./hits";

export type { SecretLineHit } from "./hits";

/** Generic / heuristic rules — skipped when a specific pattern already matched the line. */
const GENERIC_RULE_IDS = new Set([
  "GENERIC_API_KEY",
  "GENERIC_SECRET",
  "ENTROPY_SECRET",
  "DOTENV_SECRET",
]);

const SECRET_CONTEXT =
  /(?:key|secret|token|password|credential|auth|api|passwd|pwd)/i;

function buildSnippet(
  lines: string[],
  lineNum: number,
  maskPatterns: RegExp[],
): string {
  const snippetStart = Math.max(0, lineNum - 1);
  const snippetEnd = Math.min(lines.length, lineNum + 2);
  const rawSnippet = lines
    .slice(snippetStart, snippetEnd)
    .map((l, i) => `${snippetStart + i + 1}: ${l}`)
    .join("\n");
  return maskSnippet(rawSnippet, maskPatterns);
}

function isAllowlisted(line: string, allowlist?: RegExp[]): boolean {
  return allowlist?.some((al) => al.test(line)) ?? false;
}

/**
 * Scan line array for secrets (patterns + entropy). Shared by full scan and pre-commit.
 */
export function scanLinesForSecrets(
  lines: string[],
  filePath: string,
): SecretLineHit[] {
  const findings: SecretLineHit[] = [];
  const seen = new Set<string>();
  const linesWithSpecificHit = new Set<number>();
  const linesWithAnyPatternHit = new Set<number>();
  const envFile = isEnvFile(filePath);

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    if (!line) continue;

    if (envFile) {
      const dotenvHit = scanDotenvLine(line, lineNum);
      if (dotenvHit) {
        const dedupeKey = `${lineNum}:DOTENV_SECRET`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          linesWithAnyPatternHit.add(lineNum);
          linesWithSpecificHit.add(lineNum);
          findings.push(dotenvHit);
        }
      }
    }

    for (const pattern of SECRET_PATTERNS) {
      if (
        GENERIC_RULE_IDS.has(pattern.id) &&
        linesWithSpecificHit.has(lineNum)
      ) {
        continue;
      }

      if (!pattern.pattern.test(line)) {
        pattern.pattern.lastIndex = 0;
        continue;
      }
      pattern.pattern.lastIndex = 0;

      if (isAllowlisted(line, pattern.allowlist)) {
        continue;
      }

      const dedupeKey = `${lineNum}:${pattern.id}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      linesWithAnyPatternHit.add(lineNum);
      if (!GENERIC_RULE_IDS.has(pattern.id)) {
        linesWithSpecificHit.add(lineNum);
      }

      findings.push({
        ruleId: pattern.id,
        title: pattern.title,
        description: pattern.description,
        severity: pattern.severity,
        startLine: lineNum + 1,
        endLine: lineNum + 1,
        snippet: buildSnippet(lines, lineNum, [pattern.pattern]),
        confidence: 0.85,
        masked: true,
      });
    }

    if (linesWithAnyPatternHit.has(lineNum)) continue;

    if (!SECRET_CONTEXT.test(line)) continue;

    for (const candidate of extractCandidateValues(line, { isEnvFile: envFile })) {
      if (!isHighEntropy(candidate)) continue;

      const dedupeKey = `${lineNum}:ENTROPY_SECRET`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        ruleId: "ENTROPY_SECRET",
        title: "High-Entropy String in Secret Context",
        description:
          "A high-entropy string was found in a context suggesting it may be a secret or credential.",
        severity: "MEDIUM",
        startLine: lineNum + 1,
        endLine: lineNum + 1,
        snippet: `${lineNum + 1}: [MASKED HIGH-ENTROPY VALUE]`,
        confidence: 0.6,
        masked: true,
      });
      break;
    }
  }

  return findings;
}

export function secretHitsToRawFindings(
  hits: SecretLineHit[],
  filePath: string,
  scanner: RawFinding["scanner"] = "SECRETS_PATTERN",
): RawFinding[] {
  return hits.map((h) => ({
    scanner,
    severity: h.severity,
    title: h.title,
    description: h.description,
    filePath,
    startLine: h.startLine,
    endLine: h.endLine,
    snippet: h.snippet,
    ruleId: h.ruleId,
    cweId: "CWE-798",
    confidence: h.confidence,
    masked: h.masked,
  }));
}

/** Stable id for LLM classification — avoids index drift between prompt and response. */
export function secretCandidateId(f: RawFinding): string {
  return `${f.filePath ?? ""}:${f.startLine ?? 0}:${f.ruleId ?? "unknown"}`;
}
