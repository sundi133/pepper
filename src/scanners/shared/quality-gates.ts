import type { RawFinding, ScannerType } from "../types";
import {
  IAC_MIN_CONFIDENCE_DEFAULT,
  LLM_MIN_CONFIDENCE_DEFAULT,
  SECRETS_MIN_CONFIDENCE_DEFAULT,
  ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";

const PATTERN_SCANNERS = new Set(["SAST_PATTERN", "SECRETS_PATTERN"]);

const FAILURE_RULE_IDS = new Set([
  "DAST-UNAVAILABLE",
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
    case "DAST":
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
  if (/recommendation:/i.test(f.description)) return true;
  if (/remediation:/i.test(f.description)) return true;
  return false;
}

export function applyQualityGates(findings: RawFinding[]): RawFinding[] {
  return findings.filter((f) => {
    if (PATTERN_SCANNERS.has(f.scanner)) return false;
    if (f.severity === "INFO") return false;
    if (FAILURE_RULE_IDS.has(f.ruleId || "")) return false;

    const floor = confidenceFloor(f.scanner);
    if ((f.confidence ?? 0) < floor) return false;

    if (!hasRemediation(f)) return false;

    const text = `${f.title}\n${f.description}\n${f.snippet || ""}`;

    if (
      (f.scanner === "SECRETS_LLM" || f.scanner === "SAST_LLM") &&
      PLACEHOLDER_TEXT.test(text) &&
      (f.confidence ?? 0) < 0.92
    ) {
      return false;
    }

    if (
      ["SAST_LLM", "IAC", "ZERO_DAY", "SECRETS_LLM"].includes(f.scanner) &&
      f.filePath &&
      (!f.startLine || f.startLine < 1)
    ) {
      return false;
    }

    if (f.scanner === "DAST") {
      const url = (f.metadata?.url as string) || f.filePath;
      if (!url) return false;
    }

    if (f.scanner === "SCA" || f.scanner === "MALICIOUS_PKG") {
      const pkg =
        (f.metadata?.packageName as string) || (f.metadata?.package as string);
      if (!pkg && !f.cveId && !f.ruleId?.startsWith("MAL-")) return false;
    }

    if (f.scanner === "CONTAINER") {
      const image = f.metadata?.image as string;
      const isConfig = f.metadata?.category === "CONTAINER_CONFIG";
      if (!image && !isConfig) return false;
    }

    if (
      TEST_PATH.test(f.filePath || "") &&
      ["SAST_LLM", "SECRETS_LLM", "ZERO_DAY"].includes(f.scanner) &&
      (f.confidence ?? 0) < 0.9
    ) {
      return false;
    }

    return true;
  });
}
