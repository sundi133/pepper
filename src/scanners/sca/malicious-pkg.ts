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

const MALICIOUS_PKG_SYSTEM_PROMPT = `You are a supply chain security expert analyzing software dependencies for malicious indicators.

For each batch of package names and versions, analyze for:

1. **TYPOSQUATTING**: Is this package name suspiciously similar to a well-known, popular package?
   - Character substitution (e.g., "reqeusts" for "requests")
   - Character omission/addition (e.g., "lodassh" for "lodash")
   - Hyphen/underscore confusion (e.g., "python-dateutil" vs "python_dateutil")
   - Combosquatting (appending -dev, -util, -js to popular names)
   - IMPORTANT: Legitimate extensions of popular packages (e.g., "express-validator", "lodash-es", "react-dom") are NOT typosquats
   - If the package IS the well-known package itself, it is NOT a typosquat

2. **SUSPICIOUS NAMES**: Does the package name contain patterns associated with malware?
   - Names mimicking system utilities or core modules
   - Names with random/obfuscated strings
   - Names impersonating well-known organizations

3. **VERSION ANOMALIES**: Is the version suspicious?
   - Very high major version numbers for new packages
   - Pre-release versions that shouldn't be in production

STRICT RULES:
- Only flag packages you are CONFIDENT (>= 0.7) are suspicious
- Do NOT flag legitimate popular packages or their well-known extensions
- If uncertain, do NOT report (prefer false negatives over false positives)

Respond with:
{
  "findings": [
    {
      "packageName": "the suspicious package",
      "version": "its version",
      "type": "TYPOSQUAT|SUSPICIOUS_NAME|VERSION_ANOMALY",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "similarTo": "legitimate package it mimics (for typosquats)",
      "description": "Why this package is suspicious",
      "confidence": <0.7 to 1.0>,
      "recommendation": "What to do about it"
    }
  ]
}

If no suspicious packages, return: {"findings": []}`;

const INSTALL_SCRIPT_SYSTEM_PROMPT = `You are a supply chain security expert analyzing npm/pip install scripts for malicious behavior.

Analyze the install scripts (preinstall, install, postinstall) for:

1. **DATA EXFILTRATION**: Scripts that read sensitive files (.ssh, .aws, .env, /etc/passwd) or send data to external servers
2. **CODE EXECUTION**: Scripts that download and execute remote code (curl|sh, wget|bash, eval of remote content)
3. **OBFUSCATION**: Scripts with base64 encoding, hex-encoded strings, String.fromCharCode, or other obfuscation
4. **NETWORK CALLS**: Suspicious outbound network requests to unknown domains (especially .ru, .cn, .tk domains, Discord webhooks, Telegram bots)
5. **PROCESS MANIPULATION**: Scripts that spawn background processes, modify system files, or install rootkits

STRICT RULES:
- Common build tools (node-gyp, cmake, make) are NOT suspicious
- Running tests during install is NOT suspicious
- Only report genuinely dangerous patterns

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

export const maliciousPkgScanner: ScannerPlugin = {
  name: "MALICIOUS_PKG",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    if (!ctx.orgSettings.enableLlmSast) return [];

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

    const { dependencies } = parseDependencies(ctx.workDir, ctx.fileList);
    if (dependencies.length === 0) return [];

    const findings: RawFinding[] = [];

    // 1. Analyze package names for typosquatting and suspicious patterns (in batches)
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
          MALICIOUS_PKG_SYSTEM_PROMPT,
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
            },
          });
        }
      } catch (err) {
        logger.warn({ err }, "Malicious package batch analysis failed");
      }
    }

    // 2. Analyze install scripts in package.json files
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
          INSTALL_SCRIPT_SYSTEM_PROMPT,
          `File: ${filePath}\n\nInstall scripts:\n${scriptEntries.join("\n")}`,
          { maxTokens: maxResponseTokens },
        );

        const parsed = parseLlmJsonResponse<{ findings: ScriptLlmFinding[] }>(
          raw,
          { findings: [] },
        );

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
          });
        }
      } catch {
        continue;
      }
    }

    ctx.onProgress?.(
      `Supply Chain: analyzed ${dependencies.length} packages, found ${findings.length} issues`,
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
