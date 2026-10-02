/**
 * Secret detectors and file selection, shared by the SECRETS_PATTERN scanner,
 * the LLM secrets pass and the pre-commit endpoint.
 */
import * as path from "path";

export const PATTERN_DETECTORS: Record<string, { patterns: RegExp[]; severity: "CRITICAL" | "HIGH" }> = {
  AWS_ACCESS_KEY: { patterns: [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g], severity: "CRITICAL" },
  // Only with its name next to it: 40 base64 characters alone match hashes and identifiers.
  AWS_SECRET_ACCESS_KEY: {
    patterns: [/\baws_?secret_?(?:access_?)?key\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/gi],
    severity: "CRITICAL",
  },
  GITHUB_TOKEN: {
    patterns: [/\b(ghp|ghu|gho|ghs|ghr)_[a-zA-Z0-9_]{36,}\b/g, /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g],
    severity: "CRITICAL",
  },
  GITLAB_TOKEN: { patterns: [/\bglpat-[a-zA-Z0-9_-]{20,}\b/g], severity: "CRITICAL" },
  SLACK_TOKEN: { patterns: [/\b(xox[bap])-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g], severity: "CRITICAL" },
  // Secret and restricted keys only: publishable keys (pk_…) are public by design.
  SLACK_WEBHOOK: {
    patterns: [/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g],
    severity: "HIGH",
  },
  AZURE_STORAGE_KEY: { patterns: [/\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}/g], severity: "CRITICAL" },
  ANTHROPIC_API_KEY: { patterns: [/\bsk-ant-[A-Za-z0-9_-]{40,}/g], severity: "CRITICAL" },
  STRIPE_KEY: { patterns: [/\b(sk|rk)_(live|test)_[a-zA-Z0-9]{24,}\b/g], severity: "CRITICAL" },
  // Includes PKCS#8 ("BEGIN PRIVATE KEY"). A header alone is not a finding:
  // isPrivateKeyBlock() requires real key material after it.
  PRIVATE_KEY: { patterns: [/-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP) )?PRIVATE KEY(?: BLOCK)?-----/gi], severity: "CRITICAL" },
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
  // Any other secret-named setting holding a long random literal
  // (master_enc_key = "73ad…", jwt_secret: "…", db_password = "…").
  // Kept last: a more specific detector on the same text wins. The value must
  // pass isGeneratedSecretLiteral(), which is what keeps this from being noise.
  GENERIC_SECRET: {
    patterns: [
      /\b[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|passwd|token|[_-]key|apikey)["']?\s*[:=]\s*["'][A-Za-z0-9+/=_-]{20,}["']/gi,
    ],
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

/**
 * Examples, placeholders and test values that single-line matches skip.
 * Also decides what LLM secret masking leaves unmasked, so it stays narrow:
 * the wider checks for reporting are in isCredibleSecretMatch().
 */
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

// ─── Is this match a credential, or does it only look like one? ──────────────
//
// A detector matching is not enough to report. Most "secrets" a regex finds in
// a real repository are format strings, shell variables, documentation
// examples, local development defaults and descriptive placeholder text.
// Reporting those as Critical is what makes a scan unusable, so each match is
// checked for evidence that a real value is present.

/** Words that mark a value as documentation or a stand-in rather than a credential. */
const STAND_IN_WORD =
  /sample|dummy|fake|changeme|change[_-]me|invalid|nonexistent|redacted|foobar|lorem|your[_-]?(?:api|key|secret|token|pass)/i;

function isStandIn(value: string): boolean {
  return isLikelyPlaceholderSecret(value) || STAND_IN_WORD.test(value) || TEMPLATE_SYNTAX.test(value);
}

/** Format-string, template and shell-variable syntax: the value is filled in elsewhere. */
const TEMPLATE_SYNTAX = /[{}<>]|\$[A-Za-z_({]|%[sdv(]|\*{3,}/;

/** The line itself says this is an example. */
const EXAMPLE_LINE = /\bexamples?\b|\bsample\b|placeholder|\bdummy\b/i;

function entropyOf(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * A value assigned to an api_key / secret name that could be a generated
 * credential: it mixes letters and digits, isn't a description of itself
 * ("paypal_secret_key") and isn't plain words ("MyMerchantName").
 */
export function looksLikeGeneratedSecret(value: string): boolean {
  if (isStandIn(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) return false;
  if (/secret|passw(?:or)?d|api[_-]?key|token/i.test(value)) return false;
  return entropyOf(value) >= 3.0;
}

/** Setting names that end in "key"/"token" but hold an identifier, a name or a location. */
const NOT_A_SECRET_SETTING =
  /public|(?:^|[_.-])(?:pub|primary|foreign|partition|sort|cache|lock|idempotency|dedup|group|row|map|object|storage|sse|kms)[_-]?key|key[_-]?(?:id|name|path|file|type|prefix|ring|vault)|token[_-]?(?:url|uri|endpoint|type|name|path|file|ttl|expir)/i;

/** The value is one short unit repeated ("0123456789abcdef0123456789abcdef"). */
function repeatsShortUnit(value: string): boolean {
  for (let n = 1; n <= 16 && n * 2 <= value.length; n++) {
    if (value.length % n === 0 && value.slice(0, n).repeat(value.length / n) === value) return true;
  }
  return false;
}

/** Tests, API examples and docs are full of made-up tokens; only provider formats are reported there. */
const TEST_OR_DOC_PATH =
  /(?:^|\/)(?:tests?|specs?|__tests__|fixtures?|mocks?|examples?|samples?|docs?|api-reference|postman|e2e|cypress[^/]*)(?:\/|$)|\.(?:test|spec)\.[a-z]+$|openapi|swagger|postman_collection/i;

/**
 * The bar for GENERIC_SECRET: key material (32+ characters of hex or base64)
 * assigned to a setting whose name says it is secret. Not identifiers (UUIDs,
 * prefixed ids like pm_0199…), not test, example or documentation files.
 * Shorter passwords are left to the AI secrets pass, which reads the context.
 */
export function isGeneratedSecretLiteral(matched: string, filePath?: string): boolean {
  const m = /^(.*?)["']?\s*[:=]\s*["']([^"']+)["']$/.exec(matched);
  if (!m) return false;
  const [, name, value] = m;
  if (NOT_A_SECRET_SETTING.test(name)) return false;
  if (filePath && (TEST_OR_DOC_PATH.test(filePath) || /example|sample|template/i.test(path.basename(filePath)))) return false;
  if (value.length < 32 || !looksLikeGeneratedSecret(value) || repeatsShortUnit(value)) return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return false; // UUID
  // A Google API key has its own detector, which knows the client files that must carry one.
  if (/^AIza[0-9A-Za-z_-]{35}$/.test(value)) return false;
  if (/^[A-Za-z]{2,10}[_-]/.test(value)) return false; // prefixed identifier (pm_…, cus_…) or words-joined-like-this
  return entropyOf(value) >= 3.5;
}

/** Hosts that are this machine or a placeholder, not a database someone could reach. */
const LOCAL_OR_PLACEHOLDER_HOST =
  /^(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|host|hostname|server|db[_-]?host|your[_-].*)$/i;

/** Passwords that are defaults or stand-ins. */
const STAND_IN_PASSWORDS = new Set([
  "password", "pass", "passwd", "pwd", "secret", "changeme", "postgres", "mysql", "mongo", "mongodb", "root",
  "admin", "user", "guest", "default", "db_pass", "dbpass", "db_password", "dbpassword", "1234", "12345",
  "123456", "12345678", "qwerty", "letmein",
]);

/**
 * A connection URL that carries real credentials for a database someone could
 * reach. Not: format strings (postgres://{}:{}@{}), shell variables, local
 * development databases, and stand-in passwords on a compose service name.
 * A weak password on a real host is still reported.
 */
export function isRealDatabaseUrl(match: string): boolean {
  const m = /:\/\/([^:@/\s]+):([^@\s]+)@([^\s:/'"?,)]+)/.exec(match);
  if (!m) return false;
  const [, user, password, host] = m;
  if ([user, password, host].some(isStandIn)) return false;
  if (LOCAL_OR_PLACEHOLDER_HOST.test(host)) return false;
  const standIn = STAND_IN_PASSWORDS.has(password.toLowerCase()) || password.toLowerCase() === user.toLowerCase();
  // "db", "postgres", "mongo": a compose service name, i.e. a local stack.
  const serviceName = !host.includes(".");
  if (standIn && serviceName) return false;
  if (["password", "pass", "secret", "changeme"].includes(password.toLowerCase())) return false;
  return true;
}

/**
 * Real key material follows the BEGIN line. Rejects a header quoted in
 * documentation, a format string ("-----BEGIN RSA PRIVATE KEY-----\n{key}")
 * and truncated examples.
 */
export function isPrivateKeyBlock(content: string, index: number): boolean {
  const rest = content.slice(index, index + 12000);
  const headerEnd = rest.indexOf("-----", 10);
  const end = rest.search(/-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/);
  if (headerEnd < 0 || end < 0) return false;
  // Source files hold keys as string literals: drop escapes, quotes and joins.
  const body = rest.slice(headerEnd + 5, end).replace(/\\[nrt]/g, "").replace(/[\s"'`,\\]/g, "");
  if (TEMPLATE_SYNTAX.test(body)) return false;
  return (body.match(/[A-Za-z0-9+/=]/g) ?? []).length >= 40;
}

/** A JWT whose header really decodes to a JOSE header, not just three dotted segments. */
export function isJwt(token: string): boolean {
  try {
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8")) as Record<string, unknown>;
    return typeof header === "object" && header !== null && ("alg" in header || "typ" in header);
  } catch {
    return false;
  }
}

/** The whole value is a reference to where the secret really lives. */
const WHOLE_VALUE_REFERENCE =
  /^(?:\$\{?[\w.:-]+\}?|\{\{.*\}\}|\{[\w.]*\}|<[^>]+>|%\w+%|%[sdv]|(?:process\.env|os\.environ|System\.getenv|env\(|getenv\(|secrets\.|vault:).*)$/;

/**
 * A value the AI secrets pass reported that cannot be a credential: a variable
 * reference, a template, a stand-in ("changeme", "your_api_key"), a repeated
 * character, or a connection string for a local or placeholder database.
 * Deliberately narrower than the pattern checks: a real password may contain
 * braces or the word "test".
 */
export function isObviousNonSecret(value: string): boolean {
  const v = value.trim().replace(/^["'`]|["'`]$/g, "");
  if (!v) return false;
  if (WHOLE_VALUE_REFERENCE.test(v)) return true;
  if (/example|placeholder/i.test(v) || STAND_IN_WORD.test(v) || isUniformSecretValue(v)) return true;
  if (/^[a-z][a-z0-9+]*:\/\/[^:@/\s]+:[^@\s]+@/i.test(v)) return !isRealDatabaseUrl(v);
  return false;
}

/**
 * The match sits in test-only code inside a source file: a Rust
 * `#[cfg(test)]` module, which (unlike a tests/ directory) the file path
 * doesn't reveal. Still reported, one severity level lower.
 */
export function isInlineTestCode(filePath: string, content: string, index: number): boolean {
  if (!filePath.endsWith(".rs")) return false;
  const marker = content.lastIndexOf("#[cfg(test)]", index);
  return marker >= 0 && /^\s*(?:pub\s+)?mod\s+\w+\s*\{/.test(content.slice(marker + 12, marker + 200));
}

/** Client configuration files whose Google API key is public by design. */
const PUBLIC_GOOGLE_CONFIG = new Set(["google-services.json", "googleservice-info.plist"]);

/**
 * Whether a detector match is worth reporting. `line` is the source line the
 * match is on and `filePath` the file, when known.
 */
export function isCredibleSecretMatch(
  credentialType: string,
  matched: string,
  line: string,
  filePath?: string,
): boolean {
  if (isLikelyPlaceholderSecret(matched)) return false;
  if (EXAMPLE_LINE.test(line)) return false;
  if (credentialType === "PRIVATE_KEY") return true; // body checked by isPrivateKeyBlock()
  if (STAND_IN_WORD.test(matched)) return false;
  switch (credentialType) {
    case "DATABASE_URL":
      return isRealDatabaseUrl(matched);
    case "API_KEY":
    case "SECRET_KEY": {
      const value = /["']([^"']+)["']\s*$/.exec(matched)?.[1];
      return value ? looksLikeGeneratedSecret(value) : false;
    }
    case "GENERIC_SECRET":
      return isGeneratedSecretLiteral(matched, filePath);
    case "JWT_TOKEN":
      return isJwt(matched);
    case "GOOGLE_API_KEY":
      return !(filePath && PUBLIC_GOOGLE_CONFIG.has(path.basename(filePath).toLowerCase()));
    default:
      return true;
  }
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
