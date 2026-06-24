// Entropy-based secret validation to reduce false positives
// Uses Shannon entropy and known credential format patterns

export interface EntropyAnalysis {
  shannonEntropy: number; // 0-8 (bits per character)
  isHighEntropy: boolean; // > 4.0
  matchesKnownFormat: boolean;
  credentialType: string | null;
  confidence: number; // 0-1
}

// Known credential format patterns (case-insensitive)
const CREDENTIAL_PATTERNS: Record<string, RegExp[]> = {
  AWS_ACCESS_KEY: [
    /^AKIA[0-9A-Z]{16}$/i, // AWS Access Key ID format
    /^ASIA[0-9A-Z]{16}$/i, // AWS Temp Access Key
  ],
  AWS_SECRET_KEY: [
    /^[a-zA-Z0-9+/]{40}(==)?$/i, // 40-char base64-ish
  ],
  GITHUB_TOKEN: [
    /^ghp_[a-zA-Z0-9_]{36}$/i, // GitHub personal access token
    /^ghu_[a-zA-Z0-9_]{36}$/i, // GitHub user token
    /^gho_[a-zA-Z0-9_]{36}$/i, // GitHub OAuth token
    /^ghs_[a-zA-Z0-9_]{36}$/i, // GitHub app token
  ],
  GITHUB_PAT: [
    /^github_pat_[a-zA-Z0-9_]{82}$/i,
  ],
  GITLAB_TOKEN: [
    /^glpat-[a-zA-Z0-9_-]{20,}$/i,
  ],
  SLACK_TOKEN: [
    /^xox[bap]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}$/i,
  ],
  STRIPE_KEY: [
    /^(sk|pk)_live_[a-zA-Z0-9]{24,}$/i,
    /^(sk|pk)_test_[a-zA-Z0-9]{24,}$/i,
  ],
  PRIVATE_KEY: [
    /BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY/i,
    /BEGIN ENCRYPTED PRIVATE KEY/i,
  ],
  JWT_TOKEN: [
    /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.([a-zA-Z0-9_-]+)?$/i,
  ],
  GOOGLE_API_KEY: [
    /AIza[0-9A-Za-z_-]{35}/i,
  ],
  SENDGRID_KEY: [
    /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/i,
  ],
  TWILIO_KEY: [
    /AC[a-zA-Z0-9]{32}/i,
  ],
  DATABRICKS_TOKEN: [
    /dapi[a-z0-9]{32}[a-z0-9_-]+/i,
  ],
};

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  // Count frequency of each character
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  // Calculate Shannon entropy
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const probability = count / str.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

export function detectCredentialFormat(
  value: string,
): { type: string | null; matches: boolean } {
  for (const [type, patterns] of Object.entries(CREDENTIAL_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(value.trim())) {
        return { type, matches: true };
      }
    }
  }
  return { type: null, matches: false };
}

export function isCommonHash(value: string): boolean {
  const trimmed = value.trim();

  // Common hash lengths
  const hashPatterns = [
    /^[a-f0-9]{32}$/i, // MD5
    /^[a-f0-9]{40}$/i, // SHA1
    /^[a-f0-9]{64}$/i, // SHA256
    /^[a-f0-9]{128}$/i, // SHA512
  ];

  for (const pattern of hashPatterns) {
    if (pattern.test(trimmed)) {
      return true;
    }
  }

  // UUID pattern
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
    return true;
  }

  return false;
}

export function validateSecretCandidate(
  value: string,
  credentialType?: string,
  additionalContext?: string,
): EntropyAnalysis {
  if (!value || value.length < 8) {
    return {
      shannonEntropy: 0,
      isHighEntropy: false,
      matchesKnownFormat: false,
      credentialType: null,
      confidence: 0,
    };
  }

  const entropy = calculateShannonEntropy(value);
  const format = detectCredentialFormat(value);
  const isHash = isCommonHash(value);

  // Confidence calculation
  let confidence = 0;

  // Format match is strong signal
  if (format.matches) {
    confidence = 0.95;
  }
  // High entropy (>4.0) is moderate signal
  else if (entropy > 4.0) {
    confidence = 0.75;
    // Additional signals
    if (value.length >= 32) confidence += 0.1;
    if (/[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value)) {
      confidence += 0.1;
    }
  }
  // Very high entropy with length
  else if (entropy > 3.5 && value.length >= 64) {
    confidence = 0.7;
  }
  // Low entropy unless it matches a known format
  else if (!format.matches) {
    confidence = 0;
  }

  // Reduce confidence if it looks like a hash or UUID
  if (isHash) {
    confidence *= 0.3; // Hashes are not credentials
  }

  // Adjust based on credential type hint
  if (credentialType && format.type && format.type.includes(credentialType)) {
    confidence = Math.min(1.0, confidence + 0.1);
  }

  // Check context (if LLM mentioned specific keywords)
  if (additionalContext) {
    const contextLower = additionalContext.toLowerCase();
    if (contextLower.includes("test") || contextLower.includes("example")) {
      confidence *= 0.5;
    }
    if (contextLower.includes("dev") || contextLower.includes("mock")) {
      confidence *= 0.6;
    }
  }

  return {
    shannonEntropy: Math.round(entropy * 100) / 100,
    isHighEntropy: entropy > 4.0,
    matchesKnownFormat: format.matches,
    credentialType: format.type,
    confidence: Math.round(confidence * 100) / 100,
  };
}

export function getEntropyLabel(entropy: number): string {
  if (entropy > 6.0) return "Very High Entropy (likely credential)";
  if (entropy > 4.0) return "High Entropy (probable credential)";
  if (entropy > 2.5) return "Medium Entropy (possible credential)";
  return "Low Entropy (unlikely credential)";
}
