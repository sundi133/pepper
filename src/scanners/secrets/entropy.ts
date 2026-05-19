/**
 * Calculate Shannon entropy of a string.
 * High entropy (>4.5) on long strings (>16 chars) suggests random/secret data.
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a string looks like a high-entropy secret.
 */
export function isHighEntropy(
  str: string,
  minEntropy = 4.5,
  minLength = 16,
): boolean {
  if (str.length < minLength) return false;
  return shannonEntropy(str) >= minEntropy;
}

/**
 * Extract candidate secret values from a line of code.
 * Looks for quoted strings and assignment values.
 */
const ENV_REFERENCE =
  /(?:process\.env|os\.environ|getenv|ENV\[|\$\{|import\.meta\.env)/i;

const DOTENV_LINE =
  /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+?)\s*$/;

export function extractCandidateValues(
  line: string,
  options?: { isEnvFile?: boolean },
): string[] {
  if (!options?.isEnvFile && ENV_REFERENCE.test(line)) return [];

  const candidates: string[] = [];
  const seen = new Set<string>();

  const add = (value: string) => {
    if (value.length < 16 || seen.has(value)) return;
    seen.add(value);
    candidates.push(value);
  };

  const quotedRegex = /['"]([^'"]{16,})['"]/g;
  let match: RegExpExecArray | null;
  while ((match = quotedRegex.exec(line)) !== null) {
    add(match[1]);
  }

  const assignRegex = /[:=]\s*['"]?([A-Za-z0-9_\-/.+=!@#$%^&*]{16,})['"]?/g;
  while ((match = assignRegex.exec(line)) !== null) {
    add(match[1]);
  }

  if (options?.isEnvFile) {
    const dotenv = line.trim().match(DOTENV_LINE);
    if (dotenv) {
      let v = dotenv[1].trim();
      if (
        (v.startsWith('"') && v.endsWith('"')) ||
        (v.startsWith("'") && v.endsWith("'"))
      ) {
        v = v.slice(1, -1);
      }
      add(v);
    }
  }

  return candidates;
}
