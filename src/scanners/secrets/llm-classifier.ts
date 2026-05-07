import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding } from "../types";
import { logger } from "@/lib/logger";

const SYSTEM_PROMPT = `You are a security expert classifying potential secret/credential findings in source code.

For each finding, determine if it's a TRUE POSITIVE (real leaked secret) or FALSE POSITIVE (test value, placeholder, hash, encoded data, etc.).

Treat these as high-risk true positives when the context suggests real application use:
- Cloud/API credentials, OAuth client secrets, webhook signing secrets, JWT signing keys, session secrets, database URLs, private keys, CI/CD tokens, MCP/agent/tool credentials, LLM provider API keys
- Tokens embedded in Terraform, Kubernetes, Docker, GitHub Actions, GitLab CI, Helm values, application config, or deployment scripts
- Long-lived keys in code paths reachable by production builds, even if masked partially

Treat these as likely false positives:
- Documented examples, test fixtures, obvious placeholders, local-only defaults, hashes/checksums, public IDs, publishable-only keys, redacted values, and randomly generated test data

Respond with JSON:
{
  "classifications": [
    {
      "index": 0,
      "isSecret": true,
      "confidence": 0.95,
      "reasoning": "This is a real AWS key matching the AKIA pattern"
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
  const context = findings.map((f, i) => ({
    index: i,
    type: f.ruleId,
    file: f.filePath,
    line: f.startLine,
    snippet: f.snippet?.substring(0, 500),
  }));

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
