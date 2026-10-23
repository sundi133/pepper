import {
  RawFinding,
  ScanContext,
  ScannerPlugin,
  ScanResult,
  SuppressedVulnerability,
} from "./types";
import { sastLlmScanner, sastPatternScanner } from "./sast";
import { mobileLlmScanner } from "./mobile";
import { mobileAgentScanner } from "./mobile-agent";
import { scaScanner, parseDependencies } from "./sca";
import { secretsPatternScanner, secretsLlmScanner } from "./secrets";
import { iacScanner } from "./iac";
import { iacRulesScanner } from "./iac/trivy-config";
import { maliciousPkgScanner } from "./sca/malicious-pkg";
import { zeroDayScanner } from "./zero-day";
import { containerScanner } from "./container";
import { k8sScanner } from "./k8s";
import {
  buildRootCauseKey,
  areRootCauseDuplicates,
  compareFindingQuality,
} from "./shared/dedupe";
import { applyQualityGates } from "./shared/quality-gates";
import { fetchVersionInfoBatch } from "./sca/deps-dev-client";
import { attachLicenses } from "./sca/license-findings";
import { ENABLE_DEPS_DEV } from "@/lib/constants";
import { logger } from "@/lib/logger";

/** Scanners that also review source decompiled from compiled artifacts. */
export const COMPILED_CODE_SCANNERS = new Set([
  "SAST_PATTERN",
  "SAST_LLM",
  "SECRETS_PATTERN",
  "SECRETS_LLM",
  // Mobile review reads decompiled Android source + the decoded manifest.
  "mobile-llm",
]);

export function getScanners(
  scanType: string,
  orgSettings: {
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
  },
): ScannerPlugin[] {
  const scanners: ScannerPlugin[] = [];

  // INCREMENTAL: PR/MR webhooks — changed files only, plus the rest of any
  // IaC stack they touch (see incremental-scan-files).
  const includeSast = ["FULL", "SAST_ONLY", "INCREMENTAL"].includes(scanType);
  const includeSca = ["FULL", "SCA_ONLY", "INCREMENTAL"].includes(scanType);
  const includeSecrets = ["FULL", "SECRETS_ONLY", "INCREMENTAL"].includes(
    scanType,
  );
  const includeIac = ["FULL", "IAC_ONLY", "INCREMENTAL"].includes(scanType);
  const includeZeroDay = ["FULL", "ZERO_DAY_ONLY", "INCREMENTAL"].includes(scanType);
  const includeContainer = ["FULL", "CONTAINER_ONLY", "INCREMENTAL"].includes(scanType);
  const includeK8s = ["FULL", "K8S_ONLY", "INCREMENTAL"].includes(scanType);

  if (includeSast) {
    // Rule-based SAST (OpenGrep) is deterministic and offline: always run it.
    scanners.push(sastPatternScanner);
  }

  if (includeSast && orgSettings.enableLlmSast) {
    scanners.push(sastLlmScanner);
    // Mobile review: no-ops unless the scan has a decompiled AndroidManifest
    // (uploaded .apk) and OPENROUTER_API_KEY is set, so non-mobile scans are
    // unaffected.
    scanners.push(mobileLlmScanner);
    // Mobile agent deep scan (opt-in): no-ops unless ENABLE_MOBILE_AGENT_SCAN is
    // set with E2B + OpenRouter keys AND the scan has an uploaded mobile app, so
    // non-mobile scans — and mobile scans with the mode off — are untouched.
    scanners.push(mobileAgentScanner);
  }

  if (includeSca) {
    scanners.push(scaScanner);
    scanners.push(maliciousPkgScanner);
  }

  if (includeSecrets) {
    // Always run pattern scanner for fast, high-confidence detections
    scanners.push(secretsPatternScanner);
    // Also run LLM scanner if enabled for deeper analysis
    if (orgSettings.enableLlmSecrets) {
      scanners.push(secretsLlmScanner);
    }
  }

  if (includeIac || includeK8s) {
    // Rule-based IaC / Kubernetes / Helm checks (trivy config): deterministic
    // and offline, so they run whether or not LLM analysis is enabled.
    scanners.push(iacRulesScanner);
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

  if (includeK8s && orgSettings.enableLlmSast) {
    scanners.push(k8sScanner);
  }

  return scanners;
}

/**
 * Root-cause deduplicator across scanners.
 */
export class FindingDeduplicator {
  private seen = new Map<string, RawFinding>();
  private ordered: RawFinding[] = [];
  private replacements: Array<{ superseded: RawFinding; replacement: RawFinding }> = [];

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
        this.replacements.push({ superseded: existing, replacement: f });
      }
    }
    return novel;
  }

  drainReplacements(): Array<{ superseded: RawFinding; replacement: RawFinding }> {
    const r = [...this.replacements];
    this.replacements = [];
    return r;
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
  const suppressed: SuppressedVulnerability[] = [];

  const wrappedCtx: ScanContext = {
    ...ctx,
    onSuppressedVulnerabilities: (entries) => {
      suppressed.push(...entries);
      ctx.onSuppressedVulnerabilities?.(entries);
    },
    onBatchFindings: ctx.onBatchFindings
      ? async (scannerName: string, findings: RawFinding[]) => {
          const deduped = deduplicator.dedupe(findings);
          const replacements = deduplicator.drainReplacements();
          if (replacements.length > 0 && ctx.onFindingsReplaced) {
            await ctx.onFindingsReplaced(replacements);
          }
          if (deduped.length > 0) {
            await ctx.onBatchFindings!(scannerName, deduped);
          }
        }
      : undefined,
  };

  // Decompiled source from compiled artifacts is reviewed by the source
  // scanners only; SCA, IaC, container and zero-day keep the original list.
  const decompiled = ctx.decompiledFileList ?? [];
  const sourceCtx: ScanContext =
    decompiled.length > 0 ? { ...wrappedCtx, fileList: [...ctx.fileList, ...decompiled] } : wrappedCtx;
  const ctxFor = (scanner: ScannerPlugin) =>
    COMPILED_CODE_SCANNERS.has(scanner.name) ? sourceCtx : wrappedCtx;

  const hasLlmSast = scanners.some((s) => s.name === "SAST_LLM");
  let resolveLlmSastDone: () => void = () => {};
  const llmSastDonePromise = hasLlmSast
    ? new Promise<void>((resolve) => {
        resolveLlmSastDone = resolve;
      })
    : Promise.resolve();

  const allScanners = Promise.allSettled(
    scanners.map(async (scanner) => {
      try {
        await ctx.waitIfPaused?.();
        const rawFindings = await scanner.scan(ctxFor(scanner));
        await ctx.waitIfPaused?.();

        // Give first priority to AI: if this is a pattern/regex scanner,
        // wait for LLM SAST to finish so LLM findings are registered first.
        // Pattern findings then only fill gaps not covered by AI.
        if (scanner.name === "SAST_PATTERN" && hasLlmSast) {
          await llmSastDonePromise;
        }

        const deduped = deduplicator.dedupe(rawFindings);
        const replacements = deduplicator.drainReplacements();
        if (replacements.length > 0 && ctx.onFindingsReplaced) {
          await ctx.onFindingsReplaced(replacements);
        }
        if (ctx.onScannerComplete) {
          await ctx.onScannerComplete(scanner.name, deduped);
        }
      } finally {
        if (scanner.name === "SAST_LLM") {
          resolveLlmSastDone();
        }
      }
    }),
  );
  // A stopped or cancelled scan does not wait for slow scanners: they are
  // told to stop through the same signal (external tools are killed), and the
  // job ends now so its worker slot is free for the next scan.
  const aborted = new Promise<"aborted">((resolve) => {
    if (ctx.signal?.aborted) return resolve("aborted");
    ctx.signal?.addEventListener("abort", () => resolve("aborted"), { once: true });
  });
  if ((await Promise.race([allScanners, aborted])) === "aborted") {
    return {
      findings: deduplicator.allFindings(),
      dependencies: [],
      filesScanned: ctx.fileList.length,
      depsScanned: 0,
      suppressed,
    };
  }

  await ctx.waitIfPaused?.();
  const scaFiles = ctx.scaFileList ?? ctx.fileList;
  let { dependencies } = parseDependencies(ctx.workDir, scaFiles);

  // Attach declared licenses so the SBOM reports real licenses instead of
  // NOASSERTION. The SCA scanner has usually already fetched these, so this
  // normally resolves from the deps.dev cache without further network calls.
  if (
    dependencies.length > 0 &&
    ENABLE_DEPS_DEV &&
    ctx.orgSettings.vulnDbMode !== "offline"
  ) {
    try {
      const infoByKey = await fetchVersionInfoBatch(dependencies, {
        signal: ctx.signal,
      });
      dependencies = attachLicenses(dependencies, infoByKey);
    } catch (err) {
      logger.warn({ err }, "SBOM license enrichment failed (non-blocking)");
    }
  }

  const filesScanned = new Set([
    ...ctx.fileList,
    ...(ctx.scaFileList ?? []),
    ...decompiled,
  ]).size;

  return {
    findings: deduplicator.allFindings(),
    dependencies,
    filesScanned,
    depsScanned: dependencies.length,
    suppressed,
  };
}
