import type { RawFinding, ScannerType } from "../types";
import {
  IAC_MIN_CONFIDENCE_DEFAULT,
  LLM_MIN_CONFIDENCE_DEFAULT,
  SECRETS_MIN_CONFIDENCE_DEFAULT,
  ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { isAuthorizationOrLogicFinding } from "../sast/evidence-verify";

// SAST_PATTERN is rule-based SAST (OpenGrep, curated packs). Its findings pass
// the gates below like any other scanner: LOW-confidence rules fall under the
// floor, test/fixture code is dropped, and a line number is required.
// SECRETS_PATTERN findings are fast, high-confidence detections; deduplication
// with SECRETS_LLM is handled in areRootCauseDuplicates.

const FAILURE_RULE_IDS = new Set([
  "CONTAINER-INVENTORY",
  "CONTAINER-SCAN-FAILED",
  "MAL-NEW-PKG",
  "MAL-NO-REPO",
]);

const PLACEHOLDER_TEXT =
  /(?:example|sample|dummy|fake|mock|placeholder|changeme|change-me|your[_-]?(?:key|secret|token|password)|<[^>]+>|\$\{|process\.env|os\.environ|getenv|localhost|127\.0\.0\.1|xxx+|test[_-]?key)/i;

const TEST_PATH =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

function confidenceFloor(scanner: ScannerType): number {
  switch (scanner) {
    case "SECRETS_LLM":
      return SECRETS_MIN_CONFIDENCE_DEFAULT;
    case "ZERO_DAY":
      return ZERO_DAY_MIN_CONFIDENCE_DEFAULT;
    case "IAC":
      return IAC_MIN_CONFIDENCE_DEFAULT;
    case "SAST_LLM":
    case "MALICIOUS_PKG":
    case "CONTAINER":
    case "SCA":
      return LLM_MIN_CONFIDENCE_DEFAULT;
    default:
      return 0.65;
  }
}

function hasRemediation(f: RawFinding): boolean {
  const meta = f.metadata || {};
  if (typeof meta.remediation === "string" && meta.remediation.trim()) return true;
  if (/\*\*Fix:\*\*/i.test(f.description)) return true;
  if (/^Fix:/im.test(f.description)) return true;
  if (/recommendation:/i.test(f.description)) return true;
  if (/remediation:/i.test(f.description)) return true;
  return false;
}

/**
 * An authorization or business-logic finding the second validation pass could
 * not judge (its answer failed or was cut off). These are the findings Pepper
 * exists to surface, so a validator outage must not remove them: they are
 * held to the AI's first-pass floor instead of the confirmed-finding floor.
 */
function isUnjudgedLogicFinding(f: RawFinding): boolean {
  return (
    f.scanner === "SAST_LLM" &&
    (f.metadata as Record<string, unknown> | undefined)?.validation === "unconfirmed" &&
    (f.confidence ?? 0) >= 0.65 &&
    isAuthorizationOrLogicFinding(f)
  );
}

export function applyQualityGates(findings: RawFinding[]): RawFinding[] {
  return findings.filter((f) => {
    if (f.severity === "INFO") return false;
    if (FAILURE_RULE_IDS.has(f.ruleId || "")) return false;
    const unjudgedLogic = isUnjudgedLogicFinding(f);

    // SCA findings are database-confirmed from OSV (confidence=1.0) and are
    // not LLM-generated — skip the LLM confidence floor so triaged findings
    // whose confidence was adjusted by the AI triage are never silently dropped.
    if (f.scanner !== "SCA" && !unjudgedLogic) {
      const floor = confidenceFloor(f.scanner);
      if ((f.confidence ?? 0) < floor) return false;
    }

    // Remediation is required for most findings, but ZERO_DAY and high-confidence
    // SAST_LLM findings with a valid CWE are exempt — business logic, race
    // condition, and trust boundary findings often describe the flaw without a
    // formulaic "Fix:" section.
    if (!hasRemediation(f)) {
      const hasCwe = Boolean(f.cweId);
      const isHighConfidence = (f.confidence ?? 0) >= 0.78;
      // Rule-based SAST findings carry the rule's guidance; a CWE is enough.
      const exemptScanner =
        f.scanner === "ZERO_DAY" || f.scanner === "SAST_LLM" || f.scanner === "SAST_PATTERN";
      // A rule's message is its guidance, so any CWE-tagged rule match counts
      // (the confidence floor above still applies).
      const ruleBased = f.scanner === "SAST_PATTERN";
      if (!(exemptScanner && hasCwe && (isHighConfidence || ruleBased || unjudgedLogic))) {
        return false;
      }
    }

    const text = `${f.title}\n${f.description}\n${f.snippet || ""}`;

    // Placeholder text filter: only apply to SECRETS_LLM (where placeholders
    // almost always mean a false positive). For SAST_LLM, legitimate findings
    // routinely reference process.env, localhost, or template syntax in their
    // descriptions — filtering on these tokens was dropping real injection,
    // trust boundary, and misconfiguration findings.
    if (
      f.scanner === "SECRETS_LLM" &&
      PLACEHOLDER_TEXT.test(text) &&
      (f.confidence ?? 0) < 0.92
    ) {
      return false;
    }

    // Missing line number: still required for SAST_LLM and SECRETS_LLM (these
    // analyze specific code locations). ZERO_DAY and IAC scanners can report
    // cross-file or config-level findings without a precise line.
    if (
      ["SAST_LLM", "SECRETS_LLM", "SAST_PATTERN"].includes(f.scanner) &&
      f.filePath &&
      (!f.startLine || f.startLine < 1)
    ) {
      return false;
    }

    if (f.scanner === "SCA" || f.scanner === "MALICIOUS_PKG") {
      const pkg =
        (f.metadata?.packageName as string) || (f.metadata?.package as string);
      if (!pkg && !f.cveId && !f.ruleId?.startsWith("MAL-")) return false;
    }

    if (f.scanner === "CONTAINER") {
      const image = f.metadata?.image as string;
      const category = f.metadata?.category as string | undefined;
      if (!image && category !== "CONTAINER_CONFIG" && category !== "DOCKERFILE_LINT") return false;
    }

    if (
      TEST_PATH.test(f.filePath || "") &&
      ["SAST_LLM", "SECRETS_LLM", "ZERO_DAY"].includes(f.scanner) &&
      (f.confidence ?? 0) < 0.9
    ) {
      return false;
    }

    // Rule matches in test / fixture / example code are almost always
    // deliberate or unreachable.
    if (f.scanner === "SAST_PATTERN" && TEST_PATH.test(f.filePath || "")) {
      return false;
    }

    return true;
  });
}
