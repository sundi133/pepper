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
} from "@/lib/constants";
import { logger } from "@/lib/logger";

// ─── OSV Malware Advisory Query ───────────────────────────────────────
// OSV tracks malicious packages (MAL-*) reported by OpenSSF and others.
// Query individual packages against OSV to catch known-malicious advisories
// that the batch SCA scanner might miss (different query granularity).

interface OsvMalwareHit {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
}

async function queryOsvForMalware(
  dep: Dependency,
  apiUrl: string,
): Promise<OsvMalwareHit[]> {
  try {
    const response = await fetch(`${apiUrl}/v1/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: dep.name, ecosystem: dep.ecosystem },
        version: dep.version,
      }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return [];

    const data = await response.json();
    const vulns: OsvMalwareHit[] = data.vulns || [];

    // Filter for malware-specific advisories (MAL-*, PYSEC-malware, etc.)
    return vulns.filter(
      (v) =>
        v.id.startsWith("MAL-") ||
        v.summary?.toLowerCase().includes("malicious") ||
        v.summary?.toLowerCase().includes("malware") ||
        v.details?.toLowerCase().includes("malicious"),
    );
  } catch {
    return [];
  }
}

// ─── NPM Registry Metadata Checks ────────────────────────────────────
// Fast, deterministic checks using public registry metadata

interface NpmMetadata {
  hasInstallScripts: boolean;
  installScripts: Record<string, string>;
  ageInDays?: number;
  weeklyDownloads?: number;
  hasRepository: boolean;
}

async function fetchNpmMetadata(
  pkgName: string,
  version: string,
): Promise<NpmMetadata | null> {
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

    // Fetch package-level metadata for age
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
          const created = new Date(pkgData.time.created);
          ageInDays = Math.floor(
            (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24),
          );
        }
        hasRepository = hasRepository || !!pkgData.repository;
      }
    } catch {
      // ignore
    }

    return {
      hasInstallScripts: Object.keys(installScripts).length > 0,
      installScripts,
      ageInDays,
      hasRepository,
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
- Only flag packages with confidence >= 0.7
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
      "confidence": <0.7 to 1.0>,
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
      "confidence": <0.7 to 1.0>,
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
    const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);
    if (dependencies.length === 0) return [];

    const findings: RawFinding[] = [];
    const osvApiUrl = ctx.orgSettings.osvApiUrl || "https://api.osv.dev";

    // ────────────────────────────────────────────────────────────────────
    // PHASE 1: OSV Malware Advisory Check (fast, free, authoritative)
    // ────────────────────────────────────────────────────────────────────
    ctx.onProgress?.(
      `Supply Chain: checking ${dependencies.length} packages against OSV malware database...`,
    );

    const OSV_CONCURRENCY = 10;
    for (let i = 0; i < dependencies.length; i += OSV_CONCURRENCY) {
      if (ctx.signal?.aborted) break;

      const batch = dependencies.slice(i, i + OSV_CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map((dep) => queryOsvForMalware(dep, osvApiUrl)),
      );

      for (let j = 0; j < results.length; j++) {
        const result = results[j];
        if (result.status !== "fulfilled" || result.value.length === 0)
          continue;

        const dep = batch[j];
        for (const hit of result.value) {
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
    }

    const phase1Count = findings.length;
    if (phase1Count > 0) {
      logger.info({ count: phase1Count }, "OSV malware advisories found");
    }

    // ────────────────────────────────────────────────────────────────────
    // PHASE 2: NPM Registry Metadata Checks (fast, deterministic)
    // ────────────────────────────────────────────────────────────────────
    ctx.onProgress?.(`Supply Chain: checking npm registry metadata...`);

    const npmDeps = dependencies.filter((d) => d.ecosystem === "npm");
    const NPM_CONCURRENCY = 5;

    const depsWithScripts: { dep: Dependency; meta: NpmMetadata }[] = [];

    for (let i = 0; i < npmDeps.length; i += NPM_CONCURRENCY) {
      if (ctx.signal?.aborted) break;

      const batch = npmDeps.slice(i, i + NPM_CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map((dep) => fetchNpmMetadata(dep.name, dep.version)),
      );

      for (let j = 0; j < results.length; j++) {
        if (results[j].status !== "fulfilled") continue;
        const meta = (results[j] as PromiseFulfilledResult<NpmMetadata | null>)
          .value;
        if (!meta) continue;
        const dep = batch[j];

        // Flag very new packages (< 7 days) with install scripts
        if (
          meta.ageInDays !== undefined &&
          meta.ageInDays < 7 &&
          meta.hasInstallScripts
        ) {
          findings.push({
            scanner: "MALICIOUS_PKG",
            severity: "HIGH",
            title: `New package with install scripts: ${dep.name}@${dep.version} (${meta.ageInDays} days old)`,
            description: `Package "${dep.name}" was published only ${meta.ageInDays} days ago and contains install scripts. New packages with install scripts are a common vector for supply chain attacks.\n\nRecommendation: Verify this package is legitimate before using it. Consider running with --ignore-scripts.`,
            ruleId: "MAL-NEW-SCRIPT",
            cweId: "CWE-829",
            confidence: 0.75,
            metadata: {
              ecosystem: "npm",
              version: dep.version,
              ageInDays: meta.ageInDays,
              installScripts: Object.keys(meta.installScripts),
              source: "npm-registry",
            },
          });
        }

        // Collect deps with install scripts for LLM analysis in Phase 3
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

    const BATCH_SIZE = 30;
    for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
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
          if (!f.packageName || !f.severity || (f.confidence ?? 0) < 0.7)
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
            confidence: f.confidence ?? 0.7,
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
            if (!f.title || !f.severity || (f.confidence ?? 0) < 0.7) continue;

            findings.push({
              scanner: "MALICIOUS_PKG",
              severity: normalizeSeverity(f.severity),
              title: `${f.title} in ${dep.name}@${dep.version}`,
              description: f.recommendation
                ? `${f.description}\n\nRecommendation: ${f.recommendation}`
                : f.description,
              ruleId: `MAL-SCRIPT-${f.scriptKey || "INSTALL"}`,
              cweId: "CWE-506",
              confidence: f.confidence ?? 0.7,
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
          if (!f.title || !f.severity || (f.confidence ?? 0) < 0.7) continue;

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
            confidence: f.confidence ?? 0.7,
            metadata: { source: "llm-local-script-analysis" },
          });
        }
      } catch {
        continue;
      }
    }

    ctx.onProgress?.(
      `Supply Chain: ${findings.length} issues (${phase1Count} from OSV, ${findings.length - phase1Count} from deep analysis)`,
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
