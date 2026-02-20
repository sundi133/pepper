import { RawFinding, ScanContext, ScannerPlugin, ScanResult } from "./types";
import { sastPatternScanner, sastLlmScanner } from "./sast";
import { scaScanner, parseDependencies } from "./sca";
import { secretsPatternScanner, secretsLlmScanner } from "./secrets";

export function getScanners(
  scanType: string,
  llmEnabled: boolean
): ScannerPlugin[] {
  const scanners: ScannerPlugin[] = [];

  const includeSast = ["FULL", "SAST_ONLY"].includes(scanType);
  const includeSca = ["FULL", "SCA_ONLY"].includes(scanType);
  const includeSecrets = ["FULL", "SECRETS_ONLY"].includes(scanType);

  if (includeSast) {
    scanners.push(sastPatternScanner);
    if (llmEnabled) scanners.push(sastLlmScanner);
  }

  if (includeSca) {
    scanners.push(scaScanner);
  }

  if (includeSecrets) {
    scanners.push(secretsPatternScanner);
    // LLM secrets scanner runs its own pattern detection + classification
    // so we don't add it alongside pattern scanner; use one or the other
    // If LLM is enabled, replace pattern with LLM
    if (llmEnabled) {
      // Remove pattern scanner and replace with LLM version
      const idx = scanners.indexOf(secretsPatternScanner);
      if (idx >= 0) {
        scanners.splice(idx, 1, secretsLlmScanner);
      }
    }
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

export async function runScanners(
  ctx: ScanContext
): Promise<ScanResult> {
  const scanners = getScanners(
    ctx.scanType,
    ctx.orgSettings.enableLlmSast || ctx.orgSettings.enableLlmSecrets
  );

  ctx.onProgress?.(
    `Running ${scanners.length} scanners: ${scanners.map((s) => s.name).join(", ")}`
  );

  const deduplicator = new FindingDeduplicator();

  // Run all scanners in parallel, calling onScannerComplete as each resolves
  await Promise.allSettled(
    scanners.map(async (scanner) => {
      const rawFindings = await scanner.scan(ctx);
      const deduped = deduplicator.dedupe(rawFindings);
      if (ctx.onScannerComplete) {
        await ctx.onScannerComplete(scanner.name, deduped);
      }
    })
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
