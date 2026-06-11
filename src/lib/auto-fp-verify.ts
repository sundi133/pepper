import { prisma } from "@/lib/prisma";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import type { ScanJobData } from "@/lib/queue";
import type { Logger } from "pino";

const BATCH_SIZE = 40;
const CONFIDENCE_THRESHOLD = 0.85;

const SYSTEM_PROMPT = `You are a senior application security engineer performing automated false positive triage on a batch of vulnerability findings from SAST, SCA, and secrets scanners.

For each finding, determine whether it is a TRUE POSITIVE (real, exploitable vulnerability) or FALSE POSITIVE (not exploitable, test code, dead code, already mitigated, or misidentified pattern).

Consider for each finding:
- Is the vulnerable code reachable in production?
- Are there sanitization, validation, or encoding steps the scanner may have missed?
- Is this test, example, documentation, or generated code?
- Does the code context show this is already mitigated (e.g. parameterized queries, CSP headers)?
- For secrets: is this a placeholder, example, test fixture, hash, or public identifier?
- For SCA: is the vulnerable function actually called, or is it unused?

Respond with JSON only:
{
  "classifications": [
    {
      "index": 0,
      "isFalsePositive": true,
      "confidence": 0.92,
      "reasoning": "Brief explanation with evidence"
    }
  ]
}

Rules:
- Return one classification per finding, matching by index
- Only mark as false positive when confidence >= 0.80
- Be conservative: when in doubt, keep the finding as a true positive`;

interface Classification {
  index: number;
  isFalsePositive: boolean;
  confidence: number;
  reasoning?: string;
}

export async function autoVerifyFalsePositives(
  scanId: string,
  orgSettings: ScanJobData["orgSettings"],
  log: Logger,
): Promise<{ analyzed: number; marked: number }> {
  // Only run if LLM is configured
  const apiKey = orgSettings.llmApiKey?.trim();
  if (!apiKey) {
    log.info("Skipping auto FP verification — no LLM API key configured");
    return { analyzed: 0, marked: 0 };
  }

  // Only verify SAST and secrets findings (pattern-based are most FP-prone)
  const findings = await prisma.finding.findMany({
    where: {
      scanId,
      status: "OPEN",
      scanner: {
        in: [
          "SAST_PATTERN",
          "SECRETS_PATTERN",
          "IAC",
          "SAST_LLM",
          "SECRETS_LLM",
        ],
      },
    },
    select: {
      id: true,
      scanner: true,
      severity: true,
      title: true,
      description: true,
      filePath: true,
      startLine: true,
      snippet: true,
      ruleId: true,
      cweId: true,
    },
    orderBy: { severity: "asc" }, // process lower-severity first (more likely FP)
  });

  if (findings.length === 0) {
    return { analyzed: 0, marked: 0 };
  }

  log.info(
    { findingCount: findings.length },
    "Starting auto FP verification",
  );

  const client = createLlmClient({
    provider: orgSettings.llmProvider,
    baseUrl: orgSettings.llmBaseUrl,
    apiKey,
    model: orgSettings.llmModel,
  });

  let totalMarked = 0;

  // Process in batches
  for (let i = 0; i < findings.length; i += BATCH_SIZE) {
    const batch = findings.slice(i, i + BATCH_SIZE);
    const context = batch.map((f, idx) => ({
      index: idx,
      scanner: f.scanner,
      severity: f.severity,
      title: f.title,
      description: f.description?.substring(0, 400),
      file: f.filePath,
      line: f.startLine,
      snippet: f.snippet?.substring(0, 800),
      ruleId: f.ruleId,
      cweId: f.cweId,
    }));

    try {
      const raw = await analyzeWithLlm(
        client,
        orgSettings.llmModel,
        SYSTEM_PROMPT,
        JSON.stringify({ findings: context }),
        { temperature: 0.1, maxTokens: 4096 },
      );

      const parsed = parseLlmJsonResponse<{
        classifications: Classification[];
      }>(raw, { classifications: [] });

      const fpIds: string[] = [];
      for (const c of parsed.classifications || []) {
        if (
          c.isFalsePositive &&
          c.confidence >= CONFIDENCE_THRESHOLD &&
          batch[c.index]
        ) {
          fpIds.push(batch[c.index].id);
        }
      }

      if (fpIds.length > 0) {
        await prisma.finding.updateMany({
          where: { id: { in: fpIds } },
          data: {
            status: "FALSE_POSITIVE",
            statusNote: "Auto-verified as false positive by AI after scan completion",
            statusUpdatedAt: new Date(),
          },
        });
        totalMarked += fpIds.length;
      }

      log.info(
        {
          batch: Math.floor(i / BATCH_SIZE) + 1,
          batchSize: batch.length,
          fpFound: fpIds.length,
        },
        "Auto FP verification batch complete",
      );
    } catch (batchErr) {
      log.warn(
        { batchErr, batchStart: i },
        "Auto FP verification batch failed — continuing with next batch",
      );
    }
  }

  // Recount severity totals after marking FPs
  if (totalMarked > 0) {
    const counts = await prisma.finding.groupBy({
      by: ["severity"],
      where: { scanId, status: { not: "FALSE_POSITIVE" } },
      _count: true,
    });

    const countMap: Record<string, number> = {};
    for (const c of counts) {
      countMap[c.severity] = c._count;
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        criticalCount: countMap["CRITICAL"] ?? 0,
        highCount: countMap["HIGH"] ?? 0,
        mediumCount: countMap["MEDIUM"] ?? 0,
        lowCount: countMap["LOW"] ?? 0,
        infoCount: countMap["INFO"] ?? 0,
      },
    });
  }

  return { analyzed: findings.length, marked: totalMarked };
}
