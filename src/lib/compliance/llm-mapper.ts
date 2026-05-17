/**
 * LLM-based compliance mapping engine.
 *
 * For each finding, sends the finding context + full control catalog
 * to the LLM to get accurate, contextual control mappings.
 *
 * Architecture:
 * - Findings are batched (10 per LLM call) to reduce API calls
 * - Each batch includes the FULL control catalog for reference
 * - Results are cached per scan in the DB (never re-computed)
 * - Mapping quality > cost optimization
 */
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
  LlmConfig,
} from "@/lib/llm-gateway";
import { ComplianceFramework } from "./pdf-parser";
import { logger } from "@/lib/logger";

export interface FindingForMapping {
  id: string;
  title: string;
  description: string;
  severity: string;
  scanner: string;
  cweId?: string | null;
  ruleId?: string | null;
  filePath?: string | null;
}

export interface ControlMapping {
  controlId: string;
  title: string;
  theme: string;
  relevance: "direct" | "supporting" | "related";
  reasoning: string;
}

export interface FindingComplianceResult {
  findingId: string;
  controls: ControlMapping[];
}

const SYSTEM_PROMPT = `You are an expert compliance auditor specializing in mapping security vulnerabilities to compliance framework controls.

Given a set of security findings from a SAST/SCA scan and a compliance framework control catalog, your task is to map EACH finding to the most relevant controls.

MAPPING RULES:
1. For each finding, identify ALL controls that are relevant — be thorough, not conservative
2. Classify each mapping as:
   - "direct": The finding directly violates or relates to this control (e.g., SQL injection → Secure coding)
   - "supporting": The finding indicates a gap in this supporting control (e.g., SQL injection → Security testing, Application security requirements)
   - "related": The finding is tangentially related (e.g., SQL injection → Logging, if it could enable undetected data breach)
3. Provide a brief reasoning for each mapping explaining WHY this control is relevant
4. Prioritize accuracy — include a control only if you can justify it
5. Each finding should map to 2-5 controls typically (1 direct, 1-3 supporting, 0-2 related)
6. Consider the FULL context: the finding description, CWE, severity, and what the control actually requires

IMPORTANT: Only map to controls that exist in the provided catalog. Use the exact ControlID from the catalog.`;

/**
 * Map a batch of findings to compliance controls using LLM.
 * Processes in batches of 10 findings per LLM call.
 */
export async function mapFindingsToControls(
  findings: FindingForMapping[],
  framework: ComplianceFramework,
  llmConfig: LlmConfig,
  onProgress?: (message: string) => void,
): Promise<FindingComplianceResult[]> {
  const client = createLlmClient(llmConfig);
  const results: FindingComplianceResult[] = [];
  const BATCH_SIZE = 15; // 15 findings per batch — balances accuracy vs. API calls

  onProgress?.(
    `Mapping ${findings.length} findings to ${framework.name} controls...`,
  );

  for (let i = 0; i < findings.length; i += BATCH_SIZE) {
    const batch = findings.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(findings.length / BATCH_SIZE);

    onProgress?.(
      `Compliance mapping: batch ${batchNum}/${totalBatches} (${batch.length} findings)...`,
    );

    try {
      const batchResults = await mapBatch(
        client,
        llmConfig.model,
        batch,
        framework,
      );
      results.push(...batchResults);
    } catch (err) {
      logger.error({ err, batchNum }, "Compliance mapping batch failed");
      // Add empty results for failed findings so we don't lose them
      for (const f of batch) {
        results.push({ findingId: f.id, controls: [] });
      }
    }
  }

  onProgress?.(
    `Compliance mapping complete: ${results.length} findings mapped to ${framework.name}`,
  );

  return results;
}

async function mapBatch(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  findings: FindingForMapping[],
  framework: ComplianceFramework,
): Promise<FindingComplianceResult[]> {
  // Build the finding descriptions
  const findingList = findings
    .map(
      (f, i) =>
        `[Finding ${i + 1}] ID: ${f.id}
Title: ${f.title}
Severity: ${f.severity}
Scanner: ${f.scanner}
CWE: ${f.cweId || "N/A"}
File: ${f.filePath || "N/A"}
Description: ${f.description.substring(0, 300)}`,
    )
    .join("\n\n");

  const userPrompt = `## Compliance Framework: ${framework.name}

## Control Catalog (ControlID | Title | Summary):
${framework.controlCatalog}

## Security Findings to Map:
${findingList}

## Task:
For each finding above, identify the most relevant controls from the catalog.

Return STRICT JSON:
{
  "mappings": [
    {
      "findingId": "<exact finding ID>",
      "controls": [
        {
          "controlId": "<exact ControlID from catalog>",
          "title": "<control title>",
          "theme": "<Organizational|People|Physical|Technological>",
          "relevance": "direct|supporting|related",
          "reasoning": "<1-2 sentence explanation of why this control applies>"
        }
      ]
    }
  ]
}

Map EVERY finding. Be thorough and accurate.`;

  const raw = await analyzeWithLlm(client, model, SYSTEM_PROMPT, userPrompt, {
    maxTokens: 8192,
    temperature: 0.1,
  });

  logger.info(
    { responseLength: raw.length, preview: raw.substring(0, 200) },
    "Compliance LLM raw response",
  );

  interface LlmMapping {
    findingId: string;
    controls: ControlMapping[];
  }

  // Try multiple parsing strategies — LLMs return varied formats
  let mappings: LlmMapping[] = [];

  // Strategy 1: Standard JSON parse with markdown stripping
  const parsed = parseLlmJsonResponse<{
    mappings?: LlmMapping[];
  }>(raw, {});

  if (parsed.mappings && parsed.mappings.length > 0) {
    mappings = parsed.mappings;
  }

  // Strategy 2: Response might be the array directly (no wrapper)
  if (mappings.length === 0) {
    const asArray = parseLlmJsonResponse<LlmMapping[]>(raw, []);
    if (Array.isArray(asArray) && asArray.length > 0 && asArray[0]?.findingId) {
      mappings = asArray;
    }
  }

  // Strategy 3: Extract JSON from text that has extra content around it
  if (mappings.length === 0) {
    const jsonMatch = raw.match(/\{[\s\S]*"mappings"\s*:\s*\[[\s\S]*\]\s*\}/);
    if (jsonMatch) {
      try {
        const extracted = JSON.parse(jsonMatch[0]);
        if (extracted.mappings && extracted.mappings.length > 0) {
          mappings = extracted.mappings;
        }
      } catch {
        // ignore parse error
      }
    }
  }

  // Strategy 4: Find array of objects with findingId
  if (mappings.length === 0) {
    const arrayMatch = raw.match(/\[\s*\{[\s\S]*?"findingId"[\s\S]*?\}\s*\]/);
    if (arrayMatch) {
      try {
        const extracted = JSON.parse(arrayMatch[0]);
        if (Array.isArray(extracted) && extracted.length > 0) {
          mappings = extracted;
        }
      } catch {
        // ignore
      }
    }
  }

  if (mappings.length === 0) {
    logger.warn(
      { rawPreview: raw.substring(0, 500) },
      "LLM returned no parseable compliance mappings",
    );
    return findings.map((f) => ({ findingId: f.id, controls: [] }));
  }

  logger.info(
    { mappingsCount: mappings.length },
    "Compliance mappings parsed successfully",
  );

  // Validate and clean up results
  const validControlIds = new Set(framework.controls.map((c) => c.controlId));

  return mappings.map((m) => ({
    findingId: m.findingId,
    controls: (m.controls || [])
      .filter((c) => c.controlId && validControlIds.has(c.controlId))
      .map((c) => ({
        controlId: c.controlId,
        title:
          c.title ||
          framework.controls.find((fc) => fc.controlId === c.controlId)
            ?.title ||
          c.controlId,
        theme: c.theme || "Unknown",
        relevance: c.relevance || "related",
        reasoning: c.reasoning || "",
      })),
  }));
}
