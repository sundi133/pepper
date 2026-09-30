/**
 * Secret detectors and file selection, shared by the SECRETS_PATTERN scanner,
 * the LLM secrets pass and the pre-commit endpoint.
 */
import * as path from "path";

export const PATTERN_DETECTORS: Record<string, { patterns: RegExp[]; severity: "CRITICAL" | "HIGH" }> = {
  AWS_ACCESS_KEY: { patterns: [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g], severity: "CRITICAL" },
  GITHUB_TOKEN: { patterns: [/\b(ghp|ghu|gho|ghs)_[a-zA-Z0-9_]{36,}\b/g], severity: "CRITICAL" },
  GITLAB_TOKEN: { patterns: [/\bglpat-[a-zA-Z0-9_-]{20,}\b/g], severity: "CRITICAL" },
  SLACK_TOKEN: { patterns: [/\b(xox[bap])-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g], severity: "CRITICAL" },
  STRIPE_KEY: { patterns: [/\b(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}\b/g], severity: "CRITICAL" },
  PRIVATE_KEY: { patterns: [/-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/gi], severity: "CRITICAL" },
  JWT_TOKEN: { patterns: [/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*\b/g], severity: "HIGH" },
  GOOGLE_API_KEY: { patterns: [/\bAIza[0-9A-Za-z_-]{35}\b/g], severity: "CRITICAL" },
  SENDGRID_KEY: { patterns: [/\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g], severity: "CRITICAL" },
  DATABASE_URL: { patterns: [/(?:postgres|mysql|mongodb)(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/gi], severity: "HIGH" },
  NPM_TOKEN: { patterns: [/\bnpm_[a-zA-Z0-9]{36}\b/g], severity: "CRITICAL" },
  OPENAI_API_KEY: { patterns: [/\bsk-[a-zA-Z0-9]{20,}(?:T3BlbkFJ[a-zA-Z0-9]{20,})?\b/g], severity: "CRITICAL" },
  // Generic named-key literals (api_key = "…", secret_key=…, client_secret=…).
  // These are deliberately conservative: a quoted value that does not look like
  // a mask (uniform chars below) is flagged HIGH and left for the LLM pass /
  // human to confirm, so we never add shape-only noise for docs or examples.
  API_KEY: {
    patterns: [/\b(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-$+/=]{12,}["']/gi],
    severity: "HIGH",
  },
  SECRET_KEY: {
    patterns: [/\b(?:secret[_-]?key|secretkey|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-$+/=]{12,}["']/gi],
    severity: "HIGH",
  },
};

/**
 * Mask-like values (xxxx…, aaaa…, 1234… repeated) are never real credentials.
 * Applies to every pattern match as a final anti-false-positive gate.
 */
export function isUniformSecretValue(value: string): boolean {
  const alnum = value.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  if (alnum.length < 8) return false;
  const unique = new Set(alnum).size;
  return unique <= 1 || unique / alnum.length < 0.1;
}

/** Examples, placeholders and test values that single-line matches skip. */
export function isLikelyPlaceholderSecret(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    lower.includes("example") ||
    lower.includes("placeholder") ||
    lower.includes("test") ||
    /^(xxx|yyy|zzz|aaa|bbb|ccc|ddd|eee|fff|000|111|222)[\-_]/.test(value) ||
    isUniformSecretValue(value)
  );
}

// ─── Which files are scanned ─────────────────────────────────────────────────

/** Source and config file types scanned by both the pattern and LLM passes. */
const SECRET_SCAN_EXTENSIONS = new Set([
  // JavaScript / TypeScript
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
  // JVM / Android
  ".java", ".kt", ".kts", ".scala", ".groovy", ".gradle",
  // Apple
  ".swift", ".m", ".mm", ".h", ".plist", ".xcconfig",
  // .NET
  ".cs", ".vb", ".config",
  // Other languages
  ".py", ".go", ".rb", ".php", ".rs", ".sh", ".ps1", ".psm1",
  // Config
  ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".tf", ".tfvars",
  // Key material
  ".pem", ".key",
]);

/**
 * XML is everywhere in Java / Android / .NET repos (layouts, build files), so
 * the LLM pass only reads the XML files that commonly hold credentials; the
 * cheap pattern pass reads all of them.
 */
const XML_CREDENTIAL_FILES = new Set([
  "settings.xml", // Maven server passwords
  "context.xml", // Tomcat JNDI resources
  "server.xml",
  "tomcat-users.xml",
  "persistence.xml",
  "hibernate.cfg.xml",
  "applicationcontext.xml",
  "androidmanifest.xml",
  "strings.xml", // Android API keys
  "nuget.config",
]);

/** Files matched by exact (lower-cased) name. */
const SECRET_FILE_NAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.test",
  ".env.staging",
  ".env.ci",
  ".env.production.local",
  "credentials.json",
  "secrets.json",
  "config.json",
  "appsettings.json",
  "serviceaccountkey.json",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".pypirc",
  ".netrc",
  ".git-credentials",
  ".htpasswd",
  ".dockercfg",
  "gradle.properties",
  "local.properties",
]);

/**
 * Whether a repository file should be read for secrets. `pass` is "pattern"
 * (regex detectors, cheap) or "llm" (the model reads the file).
 */
export function isSecretScanCandidate(filePath: string, pass: "pattern" | "llm"): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (SECRET_SCAN_EXTENSIONS.has(ext) || SECRET_FILE_NAMES.has(base) || base.includes(".env")) return true;
  if (ext === ".xml") return pass === "pattern" || XML_CREDENTIAL_FILES.has(base);
  return false;
}
