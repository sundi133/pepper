import path from "path";
import { SecretLineHit } from "./hits";
import { isHighEntropy } from "./entropy";

const DOTENV_LINE =
  /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/;

const SECRET_KEY_NAME =
  /(?:password|passwd|pwd|secret|token|credential|auth|api[_-]?key|private[_-]?key|database|db_|_url$|connection|mongodb|redis|postgres|mysql)/i;

const PLACEHOLDER_VALUE =
  /^(?:xxx+|changeme|change-me|replace-me|your[_-]|insert[_-]|todo|tbd|none|null|undefined|dummy|example|test|fake|placeholder|<[^>]+>)$/i;

export function isEnvFile(filePath: string): boolean {
  const base = path.basename(filePath.replace(/\\/g, "/"));
  if (base === ".env" || base.startsWith(".env.")) return true;
  if (base.endsWith(".env")) return true;
  return false;
}

function unquoteValue(raw: string): string {
  const v = raw.trim();
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    return v.slice(1, -1);
  }
  return v;
}

function isPlaceholderValue(value: string): boolean {
  if (!value || value.length < 4) return true;
  if (PLACEHOLDER_VALUE.test(value)) return true;
  if (/^\$\{[^}]+\}$/.test(value)) return true;
  return false;
}

/**
 * Detect secret assignments in .env / dotenv files (unquoted KEY=value).
 */
export function scanDotenvLine(
  line: string,
  lineNum: number,
): SecretLineHit | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;

  const match = trimmed.match(DOTENV_LINE);
  if (!match) return null;

  const key = match[1];
  const value = unquoteValue(match[2]);
  if (isPlaceholderValue(value)) return null;
  if (!SECRET_KEY_NAME.test(key)) return null;

  const minLen = /password|passwd|pwd/i.test(key) ? 6 : 8;
  if (value.length < minLen && !isHighEntropy(value, 3.8, 6)) return null;

  const masked = `${lineNum + 1}: ${key}=[MASKED]`;

  return {
    ruleId: "DOTENV_SECRET",
    title: "Secret in Environment File",
    description: `Sensitive value for "${key}" is stored in a dotenv file. Use a secrets manager and keep .env out of version control.`,
    severity: /password|secret|private|token/i.test(key) ? "HIGH" : "MEDIUM",
    startLine: lineNum + 1,
    endLine: lineNum + 1,
    snippet: masked,
    confidence: 0.8,
    masked: true,
  };
}
