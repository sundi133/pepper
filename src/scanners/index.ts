import { RawFinding, ScanContext, ScannerPlugin, ScanResult } from "./types";
import { sanitizeFindingForEvent } from "./scan-events";
import { sastPatternScanner, sastLlmScanner } from "./sast";
import { scaScanner, parseDependencies } from "./sca";
import { secretsPatternScanner, secretsLlmScanner } from "./secrets";
import { iacScanner } from "./iac";
import { maliciousPkgScanner } from "./sca/malicious-pkg";
import { zeroDayScanner } from "./zero-day";

export function getScanners(
  scanType: string,
  orgSettings: {
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    llmApiKey?: string;
    llmProvider?: string;
  },
): ScannerPlugin[] {
  const scanners: ScannerPlugin[] = [];
  const llmEnabled = orgSettings.enableLlmSast || orgSettings.enableLlmSecrets;
  const useAiSast =
    orgSettings.enableLlmSast &&
    (Boolean(orgSettings.llmApiKey) ||
      orgSettings.llmProvider?.toLowerCase() === "ollama");

  const includeSast = ["FULL", "SAST_ONLY"].includes(scanType);
  const includeSca = ["FULL", "SCA_ONLY"].includes(scanType);
  const includeSecrets = ["FULL", "SECRETS_ONLY"].includes(scanType);
  const includeFull = scanType === "FULL";

  if (includeSast) {
    if (useAiSast) {
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
    if (orgSettings.enableLlmSecrets) {
      scanners.push(secretsLlmScanner);
    } else {
      scanners.push(secretsPatternScanner);
    }
  }

  if (includeFull || includeSast) {
    scanners.push(iacScanner);
  }

  if (includeFull && llmEnabled) {
    scanners.push(zeroDayScanner);
  }

  return scanners;
}

/**
 * Stateful deduplicator that tracks seen findings across scanners,
 * so each scanner's callback only receives net-new findings.
 */
export class FindingDeduplicator {
  private seen = new Map<string, RawFinding>();

  private key(f: RawFinding): string {
    return `${f.filePath}:${f.startLine}:${f.ruleId || f.title}`;
  }

  /** Deduplicate a batch, returning only net-new findings. */
  dedupe(findings: RawFinding[]): RawFinding[] {
    const novel: RawFinding[] = [];
    for (const f of findings) {
      const k = this.key(f);
      const existing = this.seen.get(k);
      if (!existing) {
        this.seen.set(k, f);
        novel.push(f);
      } else if ((f.confidence ?? 0) > (existing.confidence ?? 0)) {
        this.seen.set(k, f);
        // Already reported — skip from novel set to avoid double-insert
      }
    }
    return novel;
  }

  allFindings(): RawFinding[] {
    return Array.from(this.seen.values());
  }
}

export async function runScanners(ctx: ScanContext): Promise<ScanResult> {
  const scanners = getScanners(ctx.scanType, ctx.orgSettings);

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
    onEvent: ctx.onEvent
      ? async (event) => {
          if (event.type === "finding_found") {
            await ctx.onEvent!({
              ...event,
              finding: sanitizeFindingForEvent(event.finding),
            });
          } else {
            await ctx.onEvent!(event);
          }
        }
      : undefined,
  };

  // Run all scanners in parallel, calling onScannerComplete as each resolves
  await Promise.allSettled(
    scanners.map(async (scanner) => {
      const rawFindings = await scanner.scan(wrappedCtx);
      // For scanners that use onBatchFindings (LLM), rawFindings are already
      // flushed — dedupe returns only unflushed leftovers
      const deduped = deduplicator.dedupe(rawFindings);
      if (ctx.onScannerComplete) {
        await ctx.onScannerComplete(scanner.name, deduped);
      }
    }),
  );

  // Get dependency info for SBOM
  const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);

  return {
    findings: deduplicator.allFindings(),
    dependencies,
    filesScanned: ctx.fileList.length,
    depsScanned: dependencies.length,
  };
}
