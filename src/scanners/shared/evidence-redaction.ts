const SECRET_PATTERNS = [
  /(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /(?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*['"]?[^\s'"]{8,}/gi,
  /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
  /ghp_[A-Za-z0-9_]{20,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  /(?:Cookie|Set-Cookie):\s*[^\n]+/gi,
];

const MASK = "[REDACTED]";

export function redactSensitiveText(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, MASK);
  }
  return out;
}

export function maskSecretValue(value: string, visibleChars = 4): string {
  const trimmed = value.trim();
  if (trimmed.length <= visibleChars * 2) return "*".repeat(Math.min(8, trimmed.length));
  return `${trimmed.slice(0, visibleChars)}…${trimmed.slice(-visibleChars)}`;
}
