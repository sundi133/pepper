import type { RawFinding } from "../types";

function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/\[zero-day\]/gi, "")
    .replace(/\[[^\]]+\]/g, "")
    .replace(/\b(?:potential|possible|detected|vulnerability|issue|risk)\b/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .slice(0, 80);
}

function lineBucket(line?: number): number {
  if (!line) return 0;
  return Math.floor(line / 5);
}

function scannerFamily(scanner: string): string {
  if (scanner.startsWith("SAST")) return "SAST";
  if (scanner.startsWith("SECRETS")) return "SECRETS";
  if (scanner === "ZERO_DAY") return "SAST";
  if (scanner === "SCA" || scanner === "MALICIOUS_PKG") return "SCA";
  if (scanner === "IAC" || scanner === "CONTAINER") return "IAC_CONTAINER";
  return scanner;
}

function weaknessKey(f: RawFinding): string {
  const meta = f.metadata || {};
  return (
    (meta.weaknessClass as string) ||
    f.cweId ||
    f.ruleId?.split("-")[0] ||
    normalizeTitle(f.title)
  );
}

/** Root-cause dedupe fingerprint for cross-scanner collapse. */
export function buildRootCauseKey(f: RawFinding): string {
  const meta = f.metadata || {};
  const parts = [
    scannerFamily(f.scanner),
    weaknessKey(f),
    f.filePath || "",
    lineBucket(f.startLine),
    (meta.route as string) || "",
    (meta.method as string) || "",
    (meta.parameter as string) || "",
    (meta.sink as string) || "",
    (meta.packageName as string) || (meta.package as string) || "",
    (meta.image as string) || "",
    (meta.credentialType as string) || "",
    normalizeTitle(f.title),
  ];
  return parts.join("|");
}

const SAST_LIKE_SCANNERS = new Set(["SAST_LLM", "ZERO_DAY", "SAST_PATTERN"]);

export function areRootCauseDuplicates(a: RawFinding, b: RawFinding): boolean {
  if (buildRootCauseKey(a) === buildRootCauseKey(b)) return true;

  if (SAST_LIKE_SCANNERS.has(a.scanner) && SAST_LIKE_SCANNERS.has(b.scanner)) {
    if (
      (a.filePath || "") === (b.filePath || "") &&
      lineBucket(a.startLine) === lineBucket(b.startLine) &&
      weaknessKey(a) === weaknessKey(b)
    ) {
      return true;
    }
  }

  if (scannerFamily(a.scanner) !== scannerFamily(b.scanner)) {
    if (
      (a.scanner === "SECRETS_LLM" && b.scanner === "IAC") ||
      (a.scanner === "IAC" && b.scanner === "SECRETS_LLM")
    ) {
      if (
        (a.filePath || "") === (b.filePath || "") &&
        lineBucket(a.startLine) === lineBucket(b.startLine)
      ) {
        return true;
      }
    }
  }

  return false;
}

const SEVERITY_RANK: Record<string, number> = {
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

export function compareFindingQuality(a: RawFinding, b: RawFinding): number {
  const score = (f: RawFinding) =>
    (SEVERITY_RANK[f.severity] || 0) * 100 +
    (f.confidence ?? 0) * 10 +
    (f.description?.length || 0) / 100;
  return score(a) - score(b);
}
