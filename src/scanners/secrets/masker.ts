/**
 * Mask a secret value, showing only first 4 and last 4 characters.
 */
export function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  const prefix = value.substring(0, 4);
  const suffix = value.substring(value.length - 4);
  const masked = "*".repeat(Math.min(value.length - 8, 20));
  return `${prefix}${masked}${suffix}`;
}

/**
 * Mask secret values in a code snippet.
 */
export function maskSnippet(
  snippet: string,
  secretPatterns: RegExp[]
): string {
  let masked = snippet;
  for (const pattern of secretPatterns) {
    masked = masked.replace(pattern, (match) => maskSecret(match));
  }
  return masked;
}
