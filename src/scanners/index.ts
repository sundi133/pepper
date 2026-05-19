import { RawFinding, ScanContext, ScannerPlugin, ScanResult } from "./types";
import { sastLlmScanner, sastPatternScanner } from "./sast";
import { scaScanner, parseDependencies } from "./sca";
import { secretsLlmScanner, secretsPatternScanner } from "./secrets";
import { iacScanner } from "./iac";
import { maliciousPkgScanner } from "./sca/malicious-pkg";
import { zeroDayScanner } from "./zero-day";
import { containerScanner } from "./container";
import { dastScanner } from "./dast";
import { buildFindingFingerprint } from "@/lib/finding-fingerprint";
import { isEnvFile } from "./secrets/env-files";
import {
  IAC_MIN_CONFIDENCE_DEFAULT,
  LLM_MIN_CONFIDENCE_DEFAULT,
  ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";

const SEVERITY_RANK: Record<string, number> = {
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

const SCANNER_RANK: Record<string, number> = {
  SAST_PATTERN: 1,
  SECRETS_PATTERN: 1,
  SCA: 2,
  MALICIOUS_PKG: 3,
  IAC: 4,
  SAST_LLM: 5,
  SECRETS_LLM: 5,
  ZERO_DAY: 6,
};

const TEST_OR_EXAMPLE_PATH =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

const PLACEHOLDER_TEXT =
  /(?:example|sample|dummy|fake|mock|placeholder|changeme|change-me|your[_-]?(?:key|secret|token|password)|<[^>]+>|\$\{|process\.env|os\.environ|getenv|localhost|127\.0\.0\.1)/i;

const LOW_SIGNAL_RULES = new Set([
  "GEN-HARDCODE-001",
  "GEN-TODO-001",
  "GEN-DISABLE-001",
  "GEN-DEBUGGER-001",
  "GEN-DOCKERFILE-002",
  "STRIPE_PUBLISHABLE_KEY",
]);

export function getScanners(
  scanType: string,
  orgSettings: {
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    dastEnabled?: boolean;
  },
): ScannerPlugin[] {
  const scanners: ScannerPlugin[] = [];

  const includeSast = ["FULL", "SAST_ONLY"].includes(scanType);
  const includeSca = ["FULL", "SCA_ONLY"].includes(scanType);
  const includeSecrets = ["FULL", "SECRETS_ONLY"].includes(scanType);
  const includeContainer = ["FULL", "CONTAINER_ONLY"].includes(scanType);
  const includeDast = ["FULL", "DAST_ONLY"].includes(scanType);
  const includeFull = scanType === "FULL";

  if (includeSast) {
    if (orgSettings.enableLlmSast) {
      scanners.push(sastLlmScanner);
    } else {
      scanners.push(sastPatternScanner);
    }
  }

  if (includeSca) {
    scanners.push(scaScanner);
    scanners.push(maliciousPkgScanner);
  }

  if (includeSecrets) {
    scanners.push(
      orgSettings.enableLlmSecrets ? secretsLlmScanner : secretsPatternScanner,
    );
  }

  // IaC is a separate concern from application SAST; only run on full scans.
  if (includeFull) {
    scanners.push(iacScanner);
  }

  if (includeFull && orgSettings.enableLlmSast) {
    scanners.push(zeroDayScanner);
  }

  if (includeContainer) {
    scanners.push(containerScanner);
  }

  if (includeDast && orgSettings.dastEnabled) {
    scanners.push(dastScanner);
  }

  return scanners;
}

/**
 * Stateful deduplicator that tracks seen findings across scanners,
 * so each scanner's callback only receives net-new findings.
 */
export class FindingDeduplicator {
  private seen = new Map<string, RawFinding>();
  private ordered: RawFinding[] = [];

  private key(f: RawFinding): string {
    if (["SAST_LLM", "IAC", "ZERO_DAY"].includes(f.scanner)) {
      return `${f.scanner}:${buildFindingFingerprint(f)}`;
    }

    if (f.cveId || f.ruleId?.startsWith("GHSA-") || f.ruleId?.startsWith("CVE-")) {
      return `${f.scanner}:${f.cveId || f.ruleId}:${packageIdentity(f)}`;
    }

    if (f.scanner.startsWith("SECRETS")) {
      return `secret:${f.filePath || ""}:${f.startLine || 0}:${f.ruleId || ""}`;
    }

    return [
      scannerGroup(f.scanner),
      f.filePath || "",
      lineBucket(f.startLine),
      f.cweId || "",
      normalizeTitle(f.title),
    ].join(":");
  }

  /** Deduplicate a batch, returning only net-new findings. */
  dedupe(findings: RawFinding[]): RawFinding[] {
    const novel: RawFinding[] = [];
    for (const f of filterFalsePositives(findings)) {
      const exactKey = this.key(f);
      const fuzzyKey = this.findSimilarKey(f);
      const k = fuzzyKey || exactKey;
      const existing = this.seen.get(k);
      if (!existing) {
        this.seen.set(k, f);
        this.ordered.push(f);
        novel.push(f);
      } else if (isBetterFinding(f, existing)) {
        this.replaceFinding(k, existing, f);
        // The earlier duplicate may already be persisted via incremental flush.
        // Keep the best version for final artifacts without inserting duplicates.
      }
    }
    return novel;
  }

  allFindings(): RawFinding[] {
    return this.ordered;
  }

  private findSimilarKey(f: RawFinding): string | undefined {
    for (const [key, existing] of this.seen) {
      if (areSimilarFindings(existing, f)) return key;
    }
    return undefined;
  }

  private replaceFinding(key: string, previous: RawFinding, next: RawFinding) {
    this.seen.set(key, next);
    const idx = this.ordered.indexOf(previous);
    if (idx >= 0) this.ordered[idx] = next;
  }
}

function filterFalsePositives(findings: RawFinding[]): RawFinding[] {
  return findings.filter((finding) => {
    const text = `${finding.title}\n${finding.description}\n${finding.snippet || ""}`;
    const filePath = finding.filePath || "";

    if (
      LOW_SIGNAL_RULES.has(finding.ruleId || "") &&
      TEST_OR_EXAMPLE_PATH.test(filePath)
    ) {
      return false;
    }

    if (
      finding.scanner.startsWith("SECRETS") &&
      finding.severity !== "CRITICAL" &&
      !isEnvFile(filePath) &&
      PLACEHOLDER_TEXT.test(text)
    ) {
      return false;
    }

    if (
      finding.scanner === "SAST_PATTERN" &&
      finding.severity === "LOW" &&
      TEST_OR_EXAMPLE_PATH.test(filePath)
    ) {
      return false;
    }

    if (
      (finding.scanner === "SAST_LLM" ||
        finding.scanner === "IAC" ||
        finding.scanner === "ZERO_DAY") &&
      (finding.confidence ?? 0) < confidenceFloor(finding.scanner)
    ) {
      return false;
    }

    if (
      (finding.scanner === "IAC" || finding.scanner === "ZERO_DAY") &&
      TEST_OR_EXAMPLE_PATH.test(filePath) &&
      (finding.confidence ?? 0) < 0.95
    ) {
      return false;
    }

    return true;
  });
}

function confidenceFloor(scanner: string): number {
  if (scanner === "ZERO_DAY") return ZERO_DAY_MIN_CONFIDENCE_DEFAULT;
  if (scanner === "SAST_LLM") return LLM_MIN_CONFIDENCE_DEFAULT;
  if (scanner === "IAC") return IAC_MIN_CONFIDENCE_DEFAULT;
  return 0;
}

function isBetterFinding(candidate: RawFinding, current: RawFinding): boolean {
  const candidateScore =
    SEVERITY_RANK[candidate.severity] * 100 +
    (candidate.confidence ?? 0.7) * 10 +
    (SCANNER_RANK[candidate.scanner] || 0);
  const currentScore =
    SEVERITY_RANK[current.severity] * 100 +
    (current.confidence ?? 0.7) * 10 +
    (SCANNER_RANK[current.scanner] || 0);
  return candidateScore > currentScore;
}

function areSimilarFindings(a: RawFinding, b: RawFinding): boolean {
  if (
    ["SAST_LLM", "IAC", "ZERO_DAY"].includes(a.scanner) ||
    ["SAST_LLM", "IAC", "ZERO_DAY"].includes(b.scanner)
  ) {
    return false;
  }

  if ((a.filePath || "") !== (b.filePath || "")) return false;
  if (Math.abs((a.startLine || 0) - (b.startLine || 0)) > 5) return false;

  if (a.cweId && b.cweId && a.cweId === b.cweId) return true;
  if (normalizeTitle(a.title) === normalizeTitle(b.title)) return true;
  if (scannerGroup(a.scanner) === scannerGroup(b.scanner) && sameRuleFamily(a, b)) {
    return true;
  }

  return false;
}

function sameRuleFamily(a: RawFinding, b: RawFinding): boolean {
  const aFamily = (a.ruleId || a.title).split(/[-_:]/)[0];
  const bFamily = (b.ruleId || b.title).split(/[-_:]/)[0];
  return aFamily.length > 2 && aFamily === bFamily;
}

function scannerGroup(scanner: string): string {
  if (scanner.startsWith("SAST")) return "SAST";
  if (scanner.startsWith("SECRETS")) return "SECRETS";
  if (scanner === "SCA" || scanner === "MALICIOUS_PKG") return "SCA";
  return scanner;
}

function lineBucket(line?: number): number {
  if (!line) return 0;
  return Math.floor(line / 5);
}

function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/\[[^\]]+\]/g, "")
    .replace(/\b(?:potential|possible|detected|vulnerability|issue|risk)\b/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .slice(0, 80);
}

function packageIdentity(finding: RawFinding): string {
  const metadata = finding.metadata || {};
  const name = metadata.packageName || metadata.package || "";
  const version = metadata.packageVersion || metadata.version || "";
  const ecosystem = metadata.ecosystem || "";
  return `${ecosystem}:${name}:${version}`;
}

export async function runScanners(ctx: ScanContext): Promise<ScanResult> {
  const scanners = getScanners(ctx.scanType, ctx.orgSettings);

  await ctx.waitIfPaused?.();
  ctx.onProgress?.(
    `Running ${scanners.length} scanners: ${scanners.map((s) => s.name).join(", ")}`,
  );

  const deduplicator = new FindingDeduplicator();

  // Wrap onBatchFindings through the deduplicator so intermediate
  // LLM results are deduped before DB insert
  const wrappedCtx: ScanContext = {
    ...ctx,
    onBatchFindings: ctx.onBatchFindings
      ? async (scannerName: string, findings: RawFinding[]) => {
          const deduped = deduplicator.dedupe(findings);
          if (deduped.length > 0) {
            await ctx.onBatchFindings!(scannerName, deduped);
          }
        }
      : undefined,
  };

  // Run all scanners in parallel, calling onScannerComplete as each resolves
  await Promise.allSettled(
    scanners.map(async (scanner) => {
      await ctx.waitIfPaused?.();
      const rawFindings = await scanner.scan(wrappedCtx);
      await ctx.waitIfPaused?.();
      // For scanners that use onBatchFindings (LLM), rawFindings are already
      // flushed — dedupe returns only unflushed leftovers
      const deduped = deduplicator.dedupe(rawFindings);
      if (ctx.onScannerComplete) {
        await ctx.onScannerComplete(scanner.name, deduped);
      }
    }),
  );

  // Get dependency info for SBOM
  await ctx.waitIfPaused?.();
  const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);

  return {
    findings: deduplicator.allFindings(),
    dependencies,
    filesScanned: ctx.fileList.length,
    depsScanned: dependencies.length,
  };
}
