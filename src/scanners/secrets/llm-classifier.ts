import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding } from "../types";
import { logger } from "@/lib/logger";

export const SYSTEM_PROMPT = `You are a security expert classifying potential secret/credential findings in source code.

For each finding, determine if it's a TRUE POSITIVE (real leaked secret) or FALSE POSITIVE (test value, placeholder, hash, encoded data, etc.).

Judge from the full context (file path, line, snippet, credential type, and the candidate's own "whyReal" evidence) — not just the value shape.

Treat these as HIGH-RISK TRUE POSITIVES when the context suggests real application use:
- Cloud/API credentials (AWS AKIA/ASIA access keys, Azure/Google service-account keys, GCP client secrets), OAuth client secrets, webhook signing secrets, JWT/session signing secrets, private keys (RSA/EC/Ed25519/OpenSSH/PGP), database connection strings with passwords, Redis/AMQP URIs with passwords, CI/CD tokens (GitLab CI_JOB_TOKEN, GITHUB_TOKEN, Vault tokens), MCP/agent/tool credentials, LLM provider API keys (OpenAI sk-, Anthropic sk-ant-, Google AIza…), npm/pypi publish tokens, SMTP credentials
- Tokens embedded in Terraform, Kubernetes, Docker, GitHub Actions, GitLab CI, Helm values, application config, or deployment scripts
- Long-lived keys in code paths reachable by production builds, even if masked partially
- A high-entropy literal that matches a provider's live format AND sits next to real usage (client that consumes it, server that starts it, config referenced by deploy manifests)
- Obfuscated secrets: base64/hex-wrapped real keys, split literals rejoined at runtime, or PEM private-key blocks ("BEGIN [RSA|EC] PRIVATE KEY") in committed files — the obfuscation itself plus surrounding usage marks it as real

Treat these as LIKELY FALSE POSITIVES:
- Documented examples, test fixtures (jest/mocha/seed scripts), obvious placeholders (example/dummy/test/placeholder/todo/fake), local-only defaults, hashes/checksums/commit SHAs, public IDs, public keys (not private), publishable-only keys, redacted values, randomly generated test data, and values that only appear as environment variable names (process.env.X) with no literal
- Low-entropy or short values that do not match any provider format and are not in a file that looks like real config
- Certificate PUBLIC keys or public key material (BEGIN PUBLIC KEY, .pub files) — public by design, not a secret

Do NOT lower confidence merely because a value is base64 or looks "encoded" — if the context is a real credential use site, it is still a leak. Conversely, do NOT raise confidence for a plausible-looking value that clearly lives in docs/examples.

For each finding, output isSecret true/false and a confidence that reflects context strength, not just shape. When a finding is a true secret but you are unsure it is reachable, keep confidence >= 0.80 (reachability is assessed elsewhere).

Respond with JSON:
{
  "classifications": [
    {
      "index": 0,
      "isSecret": true,
      "confidence": 0.95,
      "reasoning": "This is a real AWS key matching the AKIA pattern in a production client file"
    }
  ]
}`;

interface Classification {
  index: number;
  isSecret: boolean;
  confidence: number;
  reasoning?: string;
}

export async function classifySecrets(
  findings: RawFinding[],
  llmConfig: {
    provider: string;
    baseUrl: string;
    apiKey?: string;
    model: string;
  },
): Promise<RawFinding[]> {
  if (findings.length === 0) return [];

  logger.info(
    {
      provider: llmConfig.provider,
      baseUrl: llmConfig.baseUrl,
      model: llmConfig.model,
      findingCount: findings.length,
    },
    "Secrets LLM classifier invoked",
  );

  const client = createLlmClient(llmConfig);

  // Build context for LLM
  const context = findings.map((f, i) => {
    const meta = (f.metadata || {}) as Record<string, unknown>;
    return {
      index: i,
      type: f.ruleId,
      credentialType: meta.credentialType,
      file: f.filePath,
      line: f.startLine,
      snippet: f.snippet?.substring(0, 900),
      whyReal: meta.evidence,
      maskedValue: meta.maskedValue,
    };
  });

  try {
    logger.info(
      { findingCount: findings.length },
      "Sending secrets to LLM for classification",
    );
    const raw = await analyzeWithLlm(
      client,
      llmConfig.model,
      SYSTEM_PROMPT,
      JSON.stringify({ findings: context }),
    );

    const parsed = parseLlmJsonResponse<{ classifications: Classification[] }>(
      raw,
      { classifications: [] },
    );

    const classMap = new Map<number, Classification>();
    for (const c of parsed.classifications || []) {
      classMap.set(c.index, c);
    }

    return findings.filter((_, i) => {
      const classification = classMap.get(i);
      if (!classification) return true; // keep if LLM didn't classify
      return classification.isSecret;
    });
  } catch (err) {
    logger.error(
      { err, findingCount: findings.length },
      "Secrets LLM classification failed — keeping all findings unfiltered",
    );
    return findings;
  }
}
