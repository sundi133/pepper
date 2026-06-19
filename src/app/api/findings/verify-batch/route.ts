import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { z } from "zod";

const MAX_BATCH = 50;

const SYSTEM = `You are a senior application security engineer performing false positive triage on a batch of vulnerability findings from automated SAST, SCA, and secrets scanners.

For each finding, determine whether it is a TRUE POSITIVE (real, exploitable vulnerability) or FALSE POSITIVE (not exploitable, test code, dead code, already mitigated, or misidentified pattern).

Consider for each finding:
- Is the vulnerable code reachable in production?
- Are there sanitization/validation steps the scanner may have missed?
- Is this test, example, documentation, or generated code?
- Does the code context show this is already mitigated?
- For secrets: is this a placeholder, example, test fixture, hash, or public identifier?

Respond with JSON only:
{
  "classifications": [
    {
      "index": 0,
      "isFalsePositive": true,
      "confidence": 0.92,
      "reasoning": "Brief explanation with evidence from the code",
      "recommendation": "MARK_FP"
    }
  ]
}

Rules:
- Return one classification per finding, matching by index
- Use MARK_FP only when confidence >= 0.80
- Use NEEDS_REVIEW when confidence is between 0.50 and 0.80
- Use KEEP_OPEN when the finding appears to be a true positive`;

const batchSchema = z.object({
  findingIds: z.array(z.string()).min(1).max(MAX_BATCH),
  autoApply: z.boolean().optional().default(false),
});

interface Classification {
  index: number;
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  recommendation: "MARK_FP" | "KEEP_OPEN" | "NEEDS_REVIEW";
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  let body;
  try {
    body = batchSchema.parse(await req.json());
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  const findings = await prisma.finding.findMany({
    where: {
      id: { in: body.findingIds },
      scan: { project: { organizationId: orgId } },
    },
    select: {
      id: true,
      scanner: true,
      severity: true,
      title: true,
      description: true,
      filePath: true,
      startLine: true,
      endLine: true,
      snippet: true,
      ruleId: true,
      cweId: true,
      cveId: true,
      confidence: true,
      status: true,
    },
  });

  if (findings.length === 0) {
    return NextResponse.json({ error: "No findings found" }, { status: 404 });
  }

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  const apiKey =
    orgSettings?.llmApiKey?.trim() ||
    process.env.LLM_API_KEY?.trim() ||
    process.env.OPENAI_API_KEY?.trim();

  if (!apiKey) {
    return NextResponse.json(
      {
        error:
          "No LLM API key configured. Set the organization LLM key in Settings, or set LLM_API_KEY / OPENAI_API_KEY in the server environment.",
      },
      { status: 503 },
    );
  }

  const provider = orgSettings?.llmProvider || "openai";
  const baseUrl =
    orgSettings?.llmBaseUrl ||
    (provider.toLowerCase() === "ollama"
      ? process.env.OLLAMA_HOST || "http://localhost:11434"
      : "https://api.openai.com/v1");
  const model = orgSettings?.llmModel || "gpt-4o-mini";

  // Build indexed context for LLM
  const context = findings.map((f, i) => ({
    index: i,
    scanner: f.scanner,
    severity: f.severity,
    title: f.title,
    description: f.description?.substring(0, 500),
    file: f.filePath,
    line: f.startLine,
    snippet: f.snippet?.substring(0, 900),
    ruleId: f.ruleId,
    cweId: f.cweId,
    cveId: f.cveId,
  }));

  try {
    const client = createLlmClient({ provider, baseUrl, apiKey, model });

    const raw = await analyzeWithLlm(
      client,
      model,
      SYSTEM,
      JSON.stringify({ findings: context }),
      { temperature: 0.1, maxTokens: 4096 },
    );

    const parsed = parseLlmJsonResponse<{
      classifications: Classification[];
    }>(raw, { classifications: [] });

    const classMap = new Map<number, Classification>();
    for (const c of parsed.classifications || []) {
      classMap.set(c.index, c);
    }

    // Build results mapped back to finding IDs
    const results = findings.map((f, i) => {
      const c = classMap.get(i);
      return {
        findingId: f.id,
        isFalsePositive: c?.isFalsePositive ?? false,
        confidence: c?.confidence ?? 0.5,
        reasoning: c?.reasoning ?? "Not classified",
        recommendation: c?.recommendation ?? "NEEDS_REVIEW",
      };
    });

    // Auto-apply if requested
    let appliedCount = 0;
    if (body.autoApply) {
      const toMark = results.filter(
        (r) => r.isFalsePositive && r.confidence >= 0.85,
      );
      if (toMark.length > 0) {
        const markIds = toMark.map((r) => r.findingId);
        const updateResult = await prisma.finding.updateMany({
          where: {
            id: { in: markIds },
            scan: { project: { organizationId: orgId } },
          },
          data: {
            status: "FALSE_POSITIVE",
            statusNote: "AI batch verification — marked as false positive",
            statusUpdatedBy: auth.session.user.id,
            statusUpdatedAt: new Date(),
          },
        });
        appliedCount = updateResult.count;
      }
    }

    const fpCount = results.filter((r) => r.isFalsePositive).length;

    return NextResponse.json({
      total: results.length,
      falsePositives: fpCount,
      truePositives: results.length - fpCount,
      appliedCount,
      results,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("Batch FP verification LLM error:", msg, e instanceof Error ? e.stack : "");
    return NextResponse.json(
      { error: `Failed to verify findings: ${msg}` },
      { status: 500 },
    );
  }
}
