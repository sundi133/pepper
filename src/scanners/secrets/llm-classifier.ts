import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding } from "../types";
import { logger } from "@/lib/logger";
import { secretCandidateId } from "./engine";

const BATCH_SIZE = 20;

/** Only these rule types may be dropped — and only on a high-confidence LLM false positive. */
const DROPPABLE_RULE_IDS = new Set(["ENTROPY_SECRET"]);

const FALSE_POSITIVE_DROP_CONFIDENCE = 0.88;

const SYSTEM_PROMPT = `You are a security expert reviewing secret/credential findings already detected by static patterns.

Your job is to CLASSIFY each finding — not to discard safe-looking code. Pattern matches in .env files, config files, and application source are usually real issues unless clearly a placeholder.

Default to isSecret: true when:
- Dotenv files (.env, .env.local) with password, secret, token, API key, or database URL variables
- Hardcoded API keys, passwords, tokens, connection strings, cloud credentials, private keys
- Values that look like real credentials (length, entropy, known token prefixes)

Only set isSecret: false when you are confident it is a placeholder, example, test fixture, hash/checksum, or public/non-sensitive value (e.g. publishable key only).

IMPORTANT: Each finding has a unique "id". Echo that exact "id" in every classification.

Respond with JSON only:
{
  "classifications": [
    {
      "id": "<exact id from input>",
      "isSecret": true,
      "confidence": 0.92,
      "reasoning": "brief reason"
    }
  ]
}`;

interface Classification {
  id?: string;
  index?: number;
  isSecret: boolean;
  confidence: number;
  reasoning?: string;
}

function buildClassMap(
  classifications: Classification[],
  idToIndex: Map<string, number>,
  batchLength: number,
): Map<number, Classification> {
  const classMap = new Map<number, Classification>();

  const indexOnly = classifications.filter(
    (c) => c.id == null && typeof c.index === "number",
  );
  const looksOneBased =
    indexOnly.length > 0 &&
    indexOnly.every((c) => (c.index ?? 0) >= 1 && (c.index ?? 0) <= batchLength) &&
    !indexOnly.some((c) => c.index === 0);

  for (const c of classifications) {
    let idx: number | undefined;

    if (c.id && idToIndex.has(c.id)) {
      idx = idToIndex.get(c.id);
    } else if (typeof c.index === "number") {
      idx = looksOneBased ? c.index - 1 : c.index;
    }

    if (idx === undefined || idx < 0 || idx >= batchLength) continue;
    if (!classMap.has(idx)) {
      classMap.set(idx, c);
    }
  }

  return classMap;
}

function shouldDropFinding(f: RawFinding, classification: Classification): boolean {
  if (classification.isSecret) return false;
  if ((classification.confidence ?? 0) < FALSE_POSITIVE_DROP_CONFIDENCE) return false;
  return DROPPABLE_RULE_IDS.has(f.ruleId ?? "");
}

function applyClassification(
  finding: RawFinding,
  classification: Classification | undefined,
): RawFinding {
  if (!classification) return finding;

  const base = finding.confidence ?? 0.85;
  const confidence = classification.isSecret
    ? Math.min(0.98, Math.max(base, classification.confidence))
    : Math.max(0.5, base * 0.85);

  return {
    ...finding,
    confidence,
    metadata: {
      ...(finding.metadata ?? {}),
      llmIsSecret: classification.isSecret,
      llmConfidence: classification.confidence,
      llmReasoning: classification.reasoning,
    },
  };
}

async function classifyBatch(
  findings: RawFinding[],
  llmConfig: {
    provider: string;
    baseUrl: string;
    apiKey?: string;
    model: string;
  },
): Promise<RawFinding[]> {
  const idToIdx = new Map<string, number>();
  const context = findings.map((f, i) => {
    const id = secretCandidateId(f);
    idToIdx.set(id, i);
    return {
      id,
      type: f.ruleId,
      file: f.filePath,
      line: f.startLine,
      snippet: f.snippet?.substring(0, 900),
    };
  });

  const client = createLlmClient(llmConfig);
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

  const classMap = buildClassMap(
    parsed.classifications || [],
    idToIdx,
    findings.length,
  );

  const enriched: RawFinding[] = [];
  let dropped = 0;

  for (let i = 0; i < findings.length; i++) {
    const classification = classMap.get(i);
    if (classification && shouldDropFinding(findings[i], classification)) {
      dropped++;
      continue;
    }
    enriched.push(applyClassification(findings[i], classification));
  }

  if (dropped > 0) {
    logger.info({ dropped, kept: enriched.length }, "LLM dropped low-signal secret candidates");
  }

  return enriched;
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

  try {
    const kept: RawFinding[] = [];

    for (let offset = 0; offset < findings.length; offset += BATCH_SIZE) {
      const batch = findings.slice(offset, offset + BATCH_SIZE);
      logger.info(
        { batchStart: offset, batchSize: batch.length },
        "Sending secrets batch to LLM for classification",
      );
      kept.push(...(await classifyBatch(batch, llmConfig)));
    }

    if (kept.length < findings.length * 0.75 && findings.length >= 4) {
      logger.warn(
        {
          patternCount: findings.length,
          keptCount: kept.length,
        },
        "LLM removed too many secret candidates — keeping all pattern findings with metadata",
      );
      return findings.map((f, i) =>
        applyClassification(f, undefined),
      );
    }

    return kept;
  } catch (err) {
    logger.error(
      { err, findingCount: findings.length },
      "Secrets LLM classification failed — keeping all findings unfiltered",
    );
    return findings;
  }
}
