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
  minLength = 16
): boolean {
  if (str.length < minLength) return false;
  return shannonEntropy(str) >= minEntropy;
}

/**
 * Extract candidate secret values from a line of code.
 * Looks for quoted strings and assignment values.
 */
export function extractCandidateValues(line: string): string[] {
  const candidates: string[] = [];

  // Quoted strings
  const quotedRegex = /['"]([^'"]{16,})['"]/g;
  let match;
  while ((match = quotedRegex.exec(line)) !== null) {
    candidates.push(match[1]);
  }

  // Assignment values (after = or :)
  const assignRegex = /[:=]\s*['"]?([A-Za-z0-9_\-/.+=!@#$%^&*]{16,})['"]?/g;
  while ((match = assignRegex.exec(line)) !== null) {
    if (!candidates.includes(match[1])) {
      candidates.push(match[1]);
    }
  }

  return candidates;
}
