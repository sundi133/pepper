import { RawFinding, ScanContext, ScannerPlugin, ScanResult } from "./types";
import { sastLlmScanner } from "./sast";
import { scaScanner, parseDependencies } from "./sca";
import { secretsLlmScanner } from "./secrets";
import { iacScanner } from "./iac";
import { maliciousPkgScanner } from "./sca/malicious-pkg";
import { zeroDayScanner } from "./zero-day";
import { containerScanner } from "./container";
import { dastScanner } from "./dast";
import {
  buildRootCauseKey,
  areRootCauseDuplicates,
  compareFindingQuality,
} from "./shared/dedupe";
import { applyQualityGates } from "./shared/quality-gates";

export function getScanners(
  scanType: string,
  orgSettings: {
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    dastEnabled?: boolean;
  },
): ScannerPlugin[] {
  const scanners: ScannerPlugin[] = [];

  // INCREMENTAL: PR/MR webhooks only — no diff engine yet; run fast PR checks.
  const includeSast = ["FULL", "SAST_ONLY", "INCREMENTAL"].includes(scanType);
  const includeSca = ["FULL", "SCA_ONLY", "INCREMENTAL"].includes(scanType);
  const includeSecrets = ["FULL", "SECRETS_ONLY", "INCREMENTAL"].includes(
    scanType,
  );
  const includeIac = ["FULL", "IAC_ONLY"].includes(scanType);
  const includeZeroDay = ["FULL", "ZERO_DAY_ONLY"].includes(scanType);
  const includeContainer = ["FULL", "CONTAINER_ONLY"].includes(scanType);
  const includeDast = ["FULL", "DAST_ONLY"].includes(scanType);

  if (includeSast && orgSettings.enableLlmSast) {
    scanners.push(sastLlmScanner);
  }

  if (includeSca) {
    scanners.push(scaScanner);
    scanners.push(maliciousPkgScanner);
  }

  if (includeSecrets && orgSettings.enableLlmSecrets) {
    scanners.push(secretsLlmScanner);
  }

  if (includeIac && orgSettings.enableLlmSast) {
    scanners.push(iacScanner);
  }

  if (includeZeroDay && orgSettings.enableLlmSast) {
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
 * Root-cause deduplicator across scanners.
 */
export class FindingDeduplicator {
  private seen = new Map<string, RawFinding>();
  private ordered: RawFinding[] = [];

  dedupe(findings: RawFinding[]): RawFinding[] {
    const gated = applyQualityGates(findings);
    const novel: RawFinding[] = [];

    for (const f of gated) {
      const key = buildRootCauseKey(f);
      let matchKey: string | undefined = key;
      for (const [existingKey, existing] of this.seen) {
        if (areRootCauseDuplicates(existing, f)) {
          matchKey = existingKey;
          break;
        }
      }

      const existing = this.seen.get(matchKey);
      if (!existing) {
        this.seen.set(matchKey, f);
        this.ordered.push(f);
        novel.push(f);
      } else if (compareFindingQuality(f, existing) > 0) {
        this.seen.set(matchKey, f);
        const idx = this.ordered.indexOf(existing);
        if (idx >= 0) this.ordered[idx] = f;
      }
    }
    return novel;
  }

  allFindings(): RawFinding[] {
    return this.ordered;
  }
}

export async function runScanners(ctx: ScanContext): Promise<ScanResult> {
  const scanners = getScanners(ctx.scanType, ctx.orgSettings);

  await ctx.waitIfPaused?.();
  ctx.onProgress?.(
    `Running ${scanners.length} scanners: ${scanners.map((s) => s.name).join(", ")}`,
  );

  const deduplicator = new FindingDeduplicator();

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

  await Promise.allSettled(
    scanners.map(async (scanner) => {
      await ctx.waitIfPaused?.();
      const rawFindings = await scanner.scan(wrappedCtx);
      await ctx.waitIfPaused?.();
      const deduped = deduplicator.dedupe(rawFindings);
      if (ctx.onScannerComplete) {
        await ctx.onScannerComplete(scanner.name, deduped);
      }
    }),
  );

  await ctx.waitIfPaused?.();
  const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);

  return {
    findings: deduplicator.allFindings(),
    dependencies,
    filesScanned: ctx.fileList.length,
    depsScanned: dependencies.length,
  };
}
