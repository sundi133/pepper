import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { Dependency, RawFinding, ScanContext, ScannerPlugin } from "../types";
import { parseDependencies } from "./index";
import {
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { enrichFinding } from "../shared/finding-normalize";
import { MALICIOUS_VALIDATION_PROMPT } from "../shared/prompts";

// ─── OSV Malware Advisory Query (Batch) ───────────────────────────────
// OSV tracks malicious packages (MAL-*) reported by OpenSSF and others.
// Uses batch API for efficiency, then filters for malware-specific advisories.

interface OsvMalwareHit {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
}

interface OsvBatchResult {
  results: Array<{
    vulns?: OsvMalwareHit[];
  }>;
}

/**
 * Batch query OSV for malware advisories.
 * Returns a map of dep index -> malware hits.
 */
async function batchQueryOsvForMalware(
  deps: Dependency[],
  apiUrl: string,
): Promise<Map<number, OsvMalwareHit[]>> {
  const results = new Map<number, OsvMalwareHit[]>();
  const BATCH_SIZE = 1000;

  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    const batch = deps.slice(i, i + BATCH_SIZE);
    const queries = batch.map((dep) => ({
      package: { name: dep.name, ecosystem: dep.ecosystem },
      version: dep.version,
    }));

    try {
      const response = await fetch(`${apiUrl}/v1/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) continue;

      const data: OsvBatchResult = await response.json();

      for (let j = 0; j < (data.results?.length || 0); j++) {
        const vulns = data.results[j]?.vulns;
        if (!vulns || vulns.length === 0) continue;

        // Filter for malware-specific advisories
        const malwareHits = vulns.filter(
          (v) =>
            v.id.startsWith("MAL-") ||
            v.summary?.toLowerCase().includes("malicious") ||
            v.summary?.toLowerCase().includes("malware") ||
            v.details?.toLowerCase().includes("malicious"),
        );

        if (malwareHits.length > 0) {
          results.set(i + j, malwareHits);
        }
      }
    } catch {
      // OSV batch failed, continue
    }
  }

  return results;
}

// ─── Registry Metadata Checks (Multi-Ecosystem) ──────────────────────
// Fast, deterministic checks using public registry APIs

interface PkgMetadata {
  ecosystem: string;
  hasInstallScripts: boolean;
  installScripts: Record<string, string>;
  ageInDays?: number;
  hasRepository: boolean;
}

async function fetchPkgMetadata(dep: Dependency): Promise<PkgMetadata | null> {
  switch (dep.ecosystem) {
    case "npm":
      return fetchNpmMeta(dep.name, dep.version);
    case "PyPI":
      return fetchPypiMeta(dep.name, dep.version);
    case "Maven":
      return fetchMavenMeta(dep.name, dep.version);
    case "Go":
      return fetchGoMeta(dep.name, dep.version);
    case "crates.io":
      return fetchCratesMeta(dep.name, dep.version);
    case "RubyGems":
      return fetchRubyGemsMeta(dep.name, dep.version);
    default:
      return null;
  }
}

async function fetchNpmMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  try {
    const response = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/${version}`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!response.ok) return null;

    const data = await response.json();
    const scripts = data.scripts || {};
    const dangerousKeys = [
      "preinstall",
      "install",
      "postinstall",
      "preuninstall",
      "postuninstall",
    ];
    const installScripts: Record<string, string> = {};
    for (const key of dangerousKeys) {
      if (scripts[key]) installScripts[key] = scripts[key];
    }

    let ageInDays: number | undefined;
    let hasRepository = !!data.repository;
    try {
      const pkgRes = await fetch(
        `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`,
        { signal: AbortSignal.timeout(5000) },
      );
      if (pkgRes.ok) {
        const pkgData = await pkgRes.json();
        if (pkgData.time?.created) {
          ageInDays = Math.floor(
            (Date.now() - new Date(pkgData.time.created).getTime()) / 86400000,
          );
        }
        hasRepository = hasRepository || !!pkgData.repository;
      }
    } catch {
      /* ignore */
    }

    return {
      ecosystem: "npm",
      hasInstallScripts: Object.keys(installScripts).length > 0,
      installScripts,
      ageInDays,
      hasRepository,
    };
  } catch {
    return null;
  }
}

async function fetchPypiMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  try {
    const response = await fetch(
      `https://pypi.org/pypi/${encodeURIComponent(pkgName)}/${version}/json`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!response.ok) return null;

    const data = await response.json();
    const info = data.info;
    let ageInDays: number | undefined;

    // Check first release date
    const releases = data.releases || {};
    const allVersions = Object.keys(releases);
    if (allVersions.length > 0) {
      const firstRelease = releases[allVersions[0]];
      if (firstRelease?.[0]?.upload_time) {
        ageInDays = Math.floor(
          (Date.now() - new Date(firstRelease[0].upload_time).getTime()) /
            86400000,
        );
      }
    }

    // Python packages can have setup.py install hooks — flag if setup.py exists
    return {
      ecosystem: "PyPI",
      hasInstallScripts: false, // Can't detect from API; checked via file analysis
      installScripts: {},
      ageInDays,
      hasRepository: !!(info.project_urls?.Repository || info.home_page),
    };
  } catch {
    return null;
  }
}

async function fetchMavenMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  void version;
  try {
    const [groupId, artifactId] = pkgName.split(":");
    if (!groupId || !artifactId) return null;

    const response = await fetch(
      `https://search.maven.org/solrsearch/select?q=g:"${encodeURIComponent(groupId)}"+AND+a:"${encodeURIComponent(artifactId)}"&rows=1&wt=json`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!response.ok) return null;

    const data = await response.json();
    const doc = data?.response?.docs?.[0];
    if (!doc) return null;

    let ageInDays: number | undefined;
    if (doc.timestamp) {
      ageInDays = Math.floor((Date.now() - doc.timestamp) / 86400000);
    }

    return {
      ecosystem: "Maven",
      hasInstallScripts: false,
      installScripts: {},
      ageInDays,
      hasRepository: true,
    };
  } catch {
    return null;
  }
}

async function fetchGoMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  try {
    const vStr = version.startsWith("v") ? version : `v${version}`;
    const response = await fetch(
      `https://proxy.golang.org/${encodeURIComponent(pkgName)}/@v/${encodeURIComponent(vStr)}.info`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!response.ok) return null;

    const data = await response.json();
    let ageInDays: number | undefined;
    if (data.Time) {
      ageInDays = Math.floor(
        (Date.now() - new Date(data.Time).getTime()) / 86400000,
      );
    }

    return {
      ecosystem: "Go",
      hasInstallScripts: false,
      installScripts: {},
      ageInDays,
      hasRepository: true,
    };
  } catch {
    return null;
  }
}

async function fetchCratesMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  void version;
  try {
    const response = await fetch(
      `https://crates.io/api/v1/crates/${encodeURIComponent(pkgName)}`,
      {
        signal: AbortSignal.timeout(5000),
        headers: { "User-Agent": "Pepper-SCA/1.0" },
      },
    );
    if (!response.ok) return null;

    const data = await response.json();
    const crate = data?.crate;
    if (!crate) return null;

    let ageInDays: number | undefined;
    if (crate.created_at) {
      ageInDays = Math.floor(
        (Date.now() - new Date(crate.created_at).getTime()) / 86400000,
      );
    }

    return {
      ecosystem: "crates.io",
      hasInstallScripts: false,
      installScripts: {},
      ageInDays,
      hasRepository: !!crate.repository,
    };
  } catch {
    return null;
  }
}

async function fetchRubyGemsMeta(
  pkgName: string,
  version: string,
): Promise<PkgMetadata | null> {
  void version;
  try {
    const response = await fetch(
      `https://rubygems.org/api/v1/gems/${encodeURIComponent(pkgName)}.json`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!response.ok) return null;

    const data = await response.json();
    let ageInDays: number | undefined;
    if (data.created_at) {
      ageInDays = Math.floor(
        (Date.now() - new Date(data.created_at).getTime()) / 86400000,
      );
    }

    return {
      ecosystem: "RubyGems",
      hasInstallScripts: false,
      installScripts: {},
      ageInDays,
      hasRepository: !!(data.source_code_uri || data.homepage_uri),
    };
  } catch {
    return null;
  }
}

// ─── LLM Prompts ─────────────────────────────────────────────────────

const TYPOSQUAT_SYSTEM_PROMPT = `You are a supply chain security expert analyzing software dependencies for malicious indicators.

For each batch of package names and versions, analyze for:

1. **TYPOSQUATTING**: Is this package name suspiciously similar to a well-known, popular package?
   - Character substitution (e.g., "reqeusts" for "requests")
   - Character omission/addition (e.g., "lodassh" for "lodash")
   - Hyphen/underscore confusion
   - Combosquatting (appending -dev, -util, -js to popular names)
   - IMPORTANT: Legitimate extensions (e.g., "express-validator", "lodash-es", "react-dom") are NOT typosquats
   - If the package IS the well-known package itself, it is NOT a typosquat

2. **SUSPICIOUS NAMES**: Names mimicking system utilities, random/obfuscated strings, or impersonating organizations

STRICT RULES:
- Only flag packages with confidence >= 0.65
- Do NOT flag legitimate popular packages or their well-known extensions
- If uncertain, do NOT report

Respond with:
{
  "findings": [
    {
      "packageName": "the suspicious package",
      "version": "its version",
      "type": "TYPOSQUAT|SUSPICIOUS_NAME",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "similarTo": "legitimate package it mimics",
      "description": "Why this package is suspicious",
      "confidence": <0.65 to 1.0>,
      "recommendation": "What to do"
    }
  ]
}

If no suspicious packages, return: {"findings": []}`;

const SCRIPT_ANALYSIS_SYSTEM_PROMPT = `You are a supply chain security expert analyzing install scripts for malicious behavior.

Analyze these install scripts (preinstall, install, postinstall) for:

1. **DATA EXFILTRATION**: Reading .ssh, .aws, .env, /etc/passwd, or sending data to external servers
2. **CODE EXECUTION**: Downloading and executing remote code (curl|sh, wget|bash, eval of remote content)
3. **OBFUSCATION**: base64 encoding, hex-encoded strings, String.fromCharCode
4. **SUSPICIOUS NETWORK CALLS**: Requests to unknown domains (.ru, .cn, .tk), Discord webhooks, Telegram bots
5. **PROCESS MANIPULATION**: Background processes, system file modification

IMPORTANT: Common build tools (node-gyp, cmake, make) are NOT suspicious.

Respond with:
{
  "findings": [
    {
      "title": "Brief description of the malicious behavior",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "description": "What the script does and why it's dangerous",
      "scriptKey": "preinstall|install|postinstall",
      "confidence": <0.65 to 1.0>,
      "recommendation": "What to do"
    }
  ]
}

If no malicious scripts, return: {"findings": []}`;

interface PkgLlmFinding {
  packageName: string;
  version: string;
  type: string;
  severity: string;
  similarTo?: string;
  description: string;
  confidence?: number;
  recommendation?: string;
}

interface ScriptLlmFinding {
  title: string;
  severity: string;
  description: string;
  scriptKey?: string;
  confidence?: number;
  recommendation?: string;
}

// ─── Scanner Plugin ───────────────────────────────────────────────────

export const maliciousPkgScanner: ScannerPlugin = {
  name: "MALICIOUS_PKG",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    await ctx.waitIfPaused?.();
    const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);
    if (dependencies.length === 0) return [];

    const findings: RawFinding[] = [];
    const supplyChainEvidence: Array<Record<string, unknown>> = [];
    const osvApiUrl = ctx.orgSettings.osvApiUrl || "https://api.osv.dev";
    const useVulnerabilityDb = ctx.orgSettings.vulnDbMode !== "offline";

    // ────────────────────────────────────────────────────────────────────
    // PHASE 1: OSV Malware Advisory Check (batch API — fast, free, authoritative)
    // ────────────────────────────────────────────────────────────────────
    if (useVulnerabilityDb) {
      ctx.onProgress?.(
        `Supply Chain: batch-checking ${dependencies.length} packages against OSV malware database...`,
      );

      await ctx.waitIfPaused?.();
      const malwareMap = await batchQueryOsvForMalware(dependencies, osvApiUrl);

      for (const [depIdx, hits] of malwareMap) {
        const dep = dependencies[depIdx];
        for (const hit of hits) {
          findings.push({
            scanner: "MALICIOUS_PKG",
            severity: "CRITICAL",
            title: `Known malicious package: ${dep.name}@${dep.version} (${hit.id})`,
            description: `${hit.summary || hit.details || "This package has been flagged as malicious by the OpenSSF Malicious Packages database."}\n\nAdvisory: ${hit.id}\nPackage: ${dep.name}@${dep.version} (${dep.ecosystem})\n\nRecommendation: Remove this package immediately and audit any systems where it was installed.`,
            ruleId: hit.id,
            cweId: "CWE-506",
            confidence: 1.0,
            metadata: {
              ecosystem: dep.ecosystem,
              version: dep.version,
              osvId: hit.id,
              source: "osv-malware-db",
            },
          });
        }
      }
    } else {
      ctx.onProgress?.(
        "Supply Chain: vulnerability database is offline; skipping OSV malware advisory lookup",
      );
    }

    const phase1Count = findings.length;
    if (phase1Count > 0) {
      logger.info({ count: phase1Count }, "OSV malware advisories found");
    }

    // ────────────────────────────────────────────────────────────────────
    // PHASE 2: Registry Metadata Checks (all ecosystems — fast, deterministic)
    // ────────────────────────────────────────────────────────────────────
    ctx.onProgress?.(
      `Supply Chain: checking registry metadata for ${dependencies.length} packages...`,
    );

    const REG_CONCURRENCY = 10;
    const depsWithScripts: { dep: Dependency; meta: PkgMetadata }[] = [];

    for (let i = 0; i < dependencies.length; i += REG_CONCURRENCY) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = dependencies.slice(i, i + REG_CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map((dep) => fetchPkgMetadata(dep)),
      );

      for (let j = 0; j < results.length; j++) {
        if (results[j].status !== "fulfilled") continue;
        const meta = (results[j] as PromiseFulfilledResult<PkgMetadata | null>)
          .value;
        if (!meta) continue;
        const dep = batch[j];

        // Collect evidence for LLM validation (no direct heuristic findings)
        supplyChainEvidence.push({
          packageName: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          ageInDays: meta.ageInDays,
          hasRepository: meta.hasRepository,
          hasInstallScripts: meta.hasInstallScripts,
          installScripts: meta.installScripts,
        });

        // Collect npm deps with install scripts for LLM analysis in Phase 3
        if (meta.hasInstallScripts) {
          depsWithScripts.push({ dep, meta });
        }
      }
    }

    // ────────────────────────────────────────────────────────────────────
    // PHASE 3: LLM Deep Analysis (typosquatting + script behavior)
    // ────────────────────────────────────────────────────────────────────

    if (!ctx.orgSettings.enableLlmSast) {
      ctx.onProgress?.(
        `Supply Chain: ${findings.length} issues found (LLM disabled, skipping deep analysis)`,
      );
      return findings;
    }

    const client = createLlmClient({
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      apiKey: ctx.orgSettings.llmApiKey,
      model: ctx.orgSettings.llmModel,
    });

    const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
    const maxResponseTokens = isOllama
      ? OLLAMA_MAX_RESPONSE_TOKENS
      : LLM_MAX_RESPONSE_TOKENS;

    // 3a. Typosquatting detection via LLM (batch)
    ctx.onProgress?.(
      `Supply Chain: LLM analyzing ${dependencies.length} packages for typosquatting...`,
    );

    const BATCH_SIZE = 26;
    for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = dependencies.slice(i, i + BATCH_SIZE);
      const depList = batch
        .map((d) => `- ${d.name}@${d.version} (${d.ecosystem})`)
        .join("\n");

      try {
        const raw = await analyzeWithLlm(
          client,
          ctx.orgSettings.llmModel,
          TYPOSQUAT_SYSTEM_PROMPT,
          `Analyze these ${batch.length} packages:\n\n${depList}`,
          { maxTokens: maxResponseTokens },
        );

        const parsed = parseLlmJsonResponse<{ findings: PkgLlmFinding[] }>(
          raw,
          { findings: [] },
        );

        for (const f of parsed.findings || []) {
          if (
            !f.packageName ||
            !f.severity ||
            (f.confidence ?? 0) < MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT
          )
            continue;

          findings.push({
            scanner: "MALICIOUS_PKG",
            severity: normalizeSeverity(f.severity),
            title: `${f.type === "TYPOSQUAT" ? "Potential typosquat" : "Suspicious package"}: ${f.packageName}${f.similarTo ? ` (similar to ${f.similarTo})` : ""}`,
            description: f.recommendation
              ? `${f.description}\n\nRecommendation: ${f.recommendation}`
              : f.description,
            ruleId: `MAL-${f.type || "PKG"}`,
            cweId: f.type === "TYPOSQUAT" ? "CWE-506" : "CWE-829",
            confidence:
              f.confidence ?? MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT,
            metadata: {
              ecosystem: batch.find((d) => d.name === f.packageName)?.ecosystem,
              version: f.version,
              type: f.type,
              similarTo: f.similarTo,
              source: "llm-analysis",
            },
          });
        }
      } catch (err) {
        logger.warn({ err }, "LLM typosquat batch analysis failed");
      }
    }

    // 3b. Install script deep analysis via LLM
    if (depsWithScripts.length > 0) {
      ctx.onProgress?.(
        `Supply Chain: LLM analyzing ${depsWithScripts.length} packages with install scripts...`,
      );

      for (const { dep, meta } of depsWithScripts) {
        await ctx.waitIfPaused?.();
        if (ctx.signal?.aborted) break;

        const scriptEntries = Object.entries(meta.installScripts)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");

        try {
          const raw = await analyzeWithLlm(
            client,
            ctx.orgSettings.llmModel,
            SCRIPT_ANALYSIS_SYSTEM_PROMPT,
            `Package: ${dep.name}@${dep.version} (npm)\n\nInstall scripts:\n${scriptEntries}`,
            { maxTokens: maxResponseTokens },
          );

          const parsed = parseLlmJsonResponse<{
            findings: ScriptLlmFinding[];
          }>(raw, { findings: [] });

          for (const f of parsed.findings || []) {
            if (
              !f.title ||
              !f.severity ||
              (f.confidence ?? 0) < MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT
            )
              continue;

            findings.push({
              scanner: "MALICIOUS_PKG",
              severity: normalizeSeverity(f.severity),
              title: `${f.title} in ${dep.name}@${dep.version}`,
              description: f.recommendation
                ? `${f.description}\n\nRecommendation: ${f.recommendation}`
                : f.description,
              ruleId: `MAL-SCRIPT-${f.scriptKey || "INSTALL"}`,
              cweId: "CWE-506",
              confidence:
                f.confidence ?? MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT,
              metadata: {
                ecosystem: "npm",
                version: dep.version,
                scriptKey: f.scriptKey,
                source: "llm-script-analysis",
              },
            });
          }
        } catch (err) {
          logger.warn(
            { err, pkg: dep.name },
            "LLM install script analysis failed",
          );
        }
      }
    }

    // 3c. Also check local package.json scripts (for repos that don't publish to npm)
    for (const filePath of ctx.fileList) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;
      if (path.basename(filePath) !== "package.json") continue;
      if (filePath.includes("node_modules")) continue;

      try {
        const content = fs.readFileSync(
          path.join(ctx.workDir, filePath),
          "utf-8",
        );
        const pkg = JSON.parse(content);
        const scripts = pkg.scripts || {};

        const dangerousKeys = [
          "preinstall",
          "install",
          "postinstall",
          "preuninstall",
          "postuninstall",
        ];

        const scriptEntries = dangerousKeys
          .filter((k) => scripts[k])
          .map((k) => `${k}: ${scripts[k]}`);

        if (scriptEntries.length === 0) continue;

        const raw = await analyzeWithLlm(
          client,
          ctx.orgSettings.llmModel,
          SCRIPT_ANALYSIS_SYSTEM_PROMPT,
          `File: ${filePath}\n\nInstall scripts:\n${scriptEntries.join("\n")}`,
          { maxTokens: maxResponseTokens },
        );

        const parsed = parseLlmJsonResponse<{
          findings: ScriptLlmFinding[];
        }>(raw, { findings: [] });

        for (const f of parsed.findings || []) {
          if (
            !f.title ||
            !f.severity ||
            (f.confidence ?? 0) < MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT
          )
            continue;

          findings.push({
            scanner: "MALICIOUS_PKG",
            severity: normalizeSeverity(f.severity),
            title: f.title,
            description: f.recommendation
              ? `${f.description}\n\nRecommendation: ${f.recommendation}`
              : f.description,
            filePath,
            ruleId: `MAL-SCRIPT-${f.scriptKey || "INSTALL"}`,
            cweId: "CWE-506",
            confidence:
              f.confidence ?? MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT,
            metadata: { source: "llm-local-script-analysis" },
          });
        }
      } catch {
        continue;
      }
    }

    // Phase 4: LLM validation of registry metadata evidence (no heuristic-only findings)
    if (supplyChainEvidence.length > 0 && ctx.orgSettings.enableLlmSast) {
      ctx.onProgress?.(
        `Supply Chain: LLM validating ${supplyChainEvidence.length} metadata evidence items...`,
      );
      const EVIDENCE_BATCH = 30;
      for (let i = 0; i < supplyChainEvidence.length; i += EVIDENCE_BATCH) {
        const batch = supplyChainEvidence.slice(i, i + EVIDENCE_BATCH);
        try {
          const raw = await analyzeWithLlm(
            client,
            ctx.orgSettings.llmModel,
            MALICIOUS_VALIDATION_PROMPT,
            JSON.stringify({ evidence: batch }, null, 2),
            { maxTokens: maxResponseTokens },
          );
          const parsed = parseLlmJsonResponse<{
            findings: Array<{
              packageName: string;
              version: string;
              title: string;
              severity: string;
              suspiciousBehavior: string;
              evidence: string;
              whyNotBenign: string;
              installImpact: string;
              remediation: string;
              confidence: number;
            }>;
          }>(raw, { findings: [] });

          for (const f of parsed.findings || []) {
            if (
              !f.packageName ||
              (f.confidence ?? 0) < MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT
            ) {
              continue;
            }
            const dep = dependencies.find(
              (d) => d.name === f.packageName && d.version === f.version,
            );
            findings.push(
              enrichFinding(
                {
                  scanner: "MALICIOUS_PKG",
                  severity: normalizeSeverity(f.severity),
                  title: f.title,
                  description: "",
                  ruleId: "MAL-LLM-VALIDATED",
                  cweId: "CWE-506",
                  confidence: f.confidence,
                  metadata: {
                    packageName: f.packageName,
                    packageVersion: f.version,
                    ecosystem: dep?.ecosystem,
                    suspiciousBehavior: f.suspiciousBehavior,
                    evidence: f.evidence,
                    source: "llm-validation",
                  },
                },
                {
                  remediation: f.remediation,
                  impact: f.installImpact,
                  confidenceReason: f.whyNotBenign,
                },
                {
                  whatIsWrong: f.suspiciousBehavior,
                  where: `${f.packageName}@${f.version}`,
                  whyExploitable: f.whyNotBenign,
                  impact: f.installImpact,
                  fix: f.remediation,
                },
              ),
            );
          }
        } catch (err) {
          logger.warn({ err }, "Supply chain LLM validation batch failed");
        }
      }
    }

    ctx.onProgress?.(
      `Supply Chain: ${findings.length} validated issues (${phase1Count} from OSV malware DB)`,
    );
    return findings;
  },
};

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}
