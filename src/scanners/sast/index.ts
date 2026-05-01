import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { getRulesForLanguage } from "./pattern-rules";
import { runLlmSastScanner } from "./llm-analyzer";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_FILE_SIZE_BYTES,
} from "@/lib/constants";
import { scanSensitivePaths } from "./sensitive-files";
import {
  detectFramework,
  extractRoute,
  maskSecrets,
} from "@/scanners/reports/finding-report-generator";

export const sastPatternScanner: ScannerPlugin = {
  name: "SAST_PATTERN",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const scanId = ctx.scanId ?? "";
    const ts = () => new Date().toISOString();

    ctx.onEvent?.({
      type: "scanner_started",
      scanId,
      scanner: "SAST_PATTERN",
      timestamp: ts(),
    });

    const scannable = ctx.fileList.filter((filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) return false;
      const language = FILE_EXTENSIONS[ext];
      if (!language) return false;
      const parts = filePath.split(path.sep);
      if (parts.some((p) => SKIP_DIRECTORIES.has(p))) return false;
      return true;
    });

    const totalScanFiles = scannable.length;
    let currentFile = 0;

    for (const filePath of scannable) {
      if (ctx.signal?.aborted) break;

      currentFile++;
      ctx.onEvent?.({
        type: "file_scanning",
        scanId,
        scanner: "SAST_PATTERN",
        filePath,
        currentFile,
        totalFiles: Math.max(totalScanFiles, 1),
        timestamp: ts(),
      });

      const ext = path.extname(filePath).toLowerCase();
      const language = FILE_EXTENSIONS[ext]!;

      const fullPath = path.join(ctx.workDir, filePath);

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE_BYTES) continue;

        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split("\n");
        const rules = getRulesForLanguage(language);

        for (const rule of rules) {
          for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];
            if (rule.pattern.test(line)) {
              if (rule.negative && rule.negative.test(line)) continue;

              const snippetStart = Math.max(0, lineNum - 2);
              const snippetEnd = Math.min(lines.length, lineNum + 3);
              const snippet = maskSecrets(
                lines
                .slice(snippetStart, snippetEnd)
                .map((l, i) => `${snippetStart + i + 1}: ${l}`)
                  .join("\n"),
              );

              const finding: RawFinding = {
                scanner: "SAST_PATTERN",
                severity: rule.severity,
                title: rule.title,
                description: rule.description,
                filePath,
                startLine: lineNum + 1,
                endLine: lineNum + 1,
                snippet,
                ruleId: rule.id,
                cweId: rule.cweId,
                confidence: 0.9,
                metadata: buildSastMetadata({
                  filePath,
                  language,
                  snippet,
                  ruleId: rule.id,
                  cweId: rule.cweId,
                  title: rule.title,
                  description: rule.description,
                }),
              };

              findings.push(finding);

              ctx.onEvent?.({
                type: "finding_found",
                scanId,
                scanner: "SAST_PATTERN",
                finding,
                timestamp: ts(),
              });

              // Reset lastIndex for global regexes
              rule.pattern.lastIndex = 0;
            }
            rule.pattern.lastIndex = 0;
          }
        }
      } catch {
        continue;
      }
    }

    const sensitive = scanSensitivePaths(ctx).map((finding) => ({
      ...finding,
      snippet: finding.snippet ? maskSecrets(finding.snippet) : finding.snippet,
      metadata: {
        ...(finding.metadata || {}),
        category: "HARDCODED_SECRET",
        language: finding.filePath ? languageFromPath(finding.filePath) : undefined,
        owasp: "A02:2021 Cryptographic Failures",
        fix:
          "Rotate the exposed value and move the replacement secret into a protected secret manager or environment variable.",
      },
      masked: true,
    }));
    for (const f of sensitive) {
      findings.push(f);
      ctx.onEvent?.({
        type: "finding_found",
        scanId,
        scanner: "SAST_PATTERN",
        finding: f,
        timestamp: ts(),
      });
    }

    ctx.onEvent?.({
      type: "scanner_completed",
      scanId,
      scanner: "SAST_PATTERN",
      findingCount: findings.length,
      timestamp: ts(),
    });

    ctx.onProgress?.(
      `SAST Pattern: found ${findings.length} issues in ${ctx.fileList.length} files`,
    );
    return findings;
  },
};

export const sastLlmScanner: ScannerPlugin = {
  name: "SAST_LLM",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    return runLlmSastScanner(ctx);
  },
};

function buildSastMetadata(input: {
  filePath: string;
  language: string;
  snippet: string;
  ruleId: string;
  cweId?: string;
  title: string;
  description: string;
}): Record<string, unknown> {
  const category = categoryFromFinding(input.title, input.description, input.ruleId, input.cweId);
  return {
    category,
    owasp: owaspFor(category, input.cweId),
    language: input.language,
    framework: detectFramework(input.filePath, input.snippet, {}),
    route: extractRoute(input.snippet, {}),
    fix: fixFor(category),
    references: referencesFor(input.cweId),
    sourceSinkEvidence: sourceSinkEvidence(input.snippet, category),
  };
}

function categoryFromFinding(
  title: string,
  description: string,
  ruleId?: string,
  cweId?: string,
): string {
  const text = `${title} ${description} ${ruleId || ""} ${cweId || ""}`.toLowerCase();
  if (/cwe-352|csrf|cross-site request forgery/.test(text)) return "CSRF";
  if (/cwe-1004|cwe-614|cookie|httponly|same.?site/.test(text)) return "COOKIE_SECURITY";
  if (/cwe-78|command|exec|shell/.test(text)) return "COMMAND_INJECTION";
  if (/cwe-79|xss|html/.test(text)) return "XSS";
  if (/cwe-89|sql/.test(text)) return "SQL_INJECTION";
  if (/cwe-918|ssrf/.test(text)) return "SSRF";
  if (/cwe-22|path traversal|directory traversal/.test(text)) return "PATH_TRAVERSAL";
  if (/cwe-601|open redirect|redirect/.test(text)) return "OPEN_REDIRECT";
  if (/cwe-502|deserialize/.test(text)) return "INSECURE_DESERIALIZATION";
  if (/cwe-611|xxe|xml external/.test(text)) return "XXE";
  if (/prototype pollution|cwe-1321/.test(text)) return "PROTOTYPE_POLLUTION";
  if (/crypto|md5|sha1|random|cwe-327|cwe-338/.test(text)) return "CRYPTO_WEAKNESS";
  if (/auth|idor|access control|cwe-862|cwe-863|cwe-639/.test(text)) return "AUTHZ_BYPASS";
  if (/upload|cwe-434/.test(text)) return "DANGEROUS_FILE_UPLOAD";
  if (/secret|credential|password|token|api key|cwe-798/.test(text)) return "HARDCODED_SECRET";
  if (/redos|regular expression/.test(text)) return "REDOS";
  return "GENERIC";
}

function owaspFor(category: string, cweId?: string): string | undefined {
  if (["COMMAND_INJECTION", "XSS", "SQL_INJECTION", "NOSQL_INJECTION", "TEMPLATE_INJECTION"].includes(category) || cweId === "CWE-79" || cweId === "CWE-89") {
    return "A03:2021 Injection";
  }
  if (["AUTHZ_BYPASS", "AUTHN_WEAKNESS", "OPEN_REDIRECT"].includes(category)) return "A01:2021 Broken Access Control";
  if (["HARDCODED_SECRET", "CRYPTO_WEAKNESS", "INFO_DISCLOSURE"].includes(category)) return "A02:2021 Cryptographic Failures";
  if (["INSECURE_CONFIG", "XXE"].includes(category)) return "A05:2021 Security Misconfiguration";
  if (category === "SSRF") return "A10:2021 Server-Side Request Forgery";
  return undefined;
}

function fixFor(category: string): string | undefined {
  const fixes: Record<string, string> = {
    COMMAND_INJECTION: "Avoid shell parsing. Use a fixed executable with argument arrays and allowlist user-controlled values.",
    XSS: "Use framework autoescaping or contextual output encoding. Never concatenate untrusted input into HTML.",
    SQL_INJECTION: "Use parameterized queries, prepared statements, or safe ORM APIs instead of string-built SQL.",
    SSRF: "Allowlist outbound destinations and block private/link-local IP ranges after URL parsing and DNS resolution.",
    PATH_TRAVERSAL: "Normalize and resolve paths under a fixed base directory, or use opaque server-side file IDs.",
    HARDCODED_SECRET: "Rotate the secret and load replacements from a secret manager or protected environment variable.",
  };
  return fixes[category];
}

function referencesFor(cweId?: string): string[] | undefined {
  if (!cweId?.startsWith("CWE-")) return undefined;
  return [`https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`];
}

function sourceSinkEvidence(snippet: string, category: string): string | undefined {
  const lines = snippet.split(/\r?\n/).map((line) => line.replace(/^\s*\d+:\s?/, ""));
  const source = lines.find((line) => /(?:req\.|request\.|\$_GET|\$_POST|params|query|body|args|getParameter)/i.test(line));
  const sink = lines.find((line) => sinkRegex(category).test(line));
  if (source && sink) return `User-controlled input in \`${source.trim()}\` reaches sensitive operation \`${sink.trim()}\`.`;
  if (sink) return `Sensitive operation evidence: \`${sink.trim()}\`.`;
  return undefined;
}

function sinkRegex(category: string): RegExp {
  if (category === "COMMAND_INJECTION") return /(?:exec|spawn|system|subprocess|shell_exec|passthru)/i;
  if (category === "XSS") return /(?:innerHTML|dangerouslySetInnerHTML|return\s+["'`].*<|render_template_string)/i;
  if (category === "SQL_INJECTION") return /(?:query|execute|raw|select|insert|update|delete)/i;
  if (category === "SSRF") return /(?:fetch|axios|requests\.|http\.get|curl)/i;
  if (category === "PATH_TRAVERSAL") return /(?:readFile|open|createReadStream|path\.join|file_get_contents)/i;
  return /(?:exec|query|open|redirect|fetch|innerHTML|return)/i;
}

function languageFromPath(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return FILE_EXTENSIONS[ext] || "text";
}
