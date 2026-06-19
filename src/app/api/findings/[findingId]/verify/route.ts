import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";

const SYSTEM = `You are a senior application security engineer performing false positive triage on vulnerability findings from automated SAST, SCA, and secrets scanners.

Given a finding, determine whether it is a TRUE POSITIVE (real, exploitable vulnerability) or FALSE POSITIVE (not exploitable, test code, dead code, already mitigated, or misidentified pattern).

Consider carefully:
- Is the vulnerable code reachable in production?
- Are there sanitization, validation, or encoding steps the scanner may have missed?
- Is this test, example, documentation, or generated code?
- Does the surrounding code context show this is already mitigated (e.g. parameterized queries, CSP headers, auth middleware)?
- For secrets: is this a placeholder, example value, test fixture, hash, or public identifier?
- For SCA: is the vulnerable function actually called, or is it an unused transitive dependency?

Respond with JSON only:
{
  "isFalsePositive": boolean,
  "confidence": 0.0 to 1.0,
  "reasoning": "2-4 sentences explaining your assessment with specific evidence from the code",
  "recommendation": "MARK_FP | KEEP_OPEN | NEEDS_REVIEW"
}

Rules:
- Use MARK_FP only when confidence >= 0.80
- Use NEEDS_REVIEW when confidence is between 0.50 and 0.80
- Use KEEP_OPEN when the finding appears to be a true positive
- Ground every claim in the provided evidence`;

type VerifyResult = {
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  recommendation: "MARK_FP" | "KEEP_OPEN" | "NEEDS_REVIEW";
};

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { findingId } = await params;

  let autoApply = false;
  try {
    const body = await req.json();
    autoApply = body?.autoApply === true;
  } catch {
    // No body or invalid JSON — that's fine, defaults apply
  }

  const finding = await prisma.finding.findFirst({
    where: {
      id: findingId,
      scan: { project: { organizationId: orgId } },
    },
    include: {
      scan: {
        select: {
          id: true,
          branch: true,
          commitSha: true,
          sourceType: true,
          project: { select: { repoUrl: true, name: true } },
        },
      },
    },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
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

  const userPayload = {
    projectName: finding.scan.project?.name,
    repoUrl: finding.scan.project?.repoUrl,
    branch: finding.scan.branch,
    sourceType: finding.scan.sourceType,
    finding: {
      scanner: finding.scanner,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      filePath: finding.filePath,
      startLine: finding.startLine,
      endLine: finding.endLine,
      snippet: finding.snippet,
      ruleId: finding.ruleId,
      cweId: finding.cweId,
      cveId: finding.cveId,
      confidence: finding.confidence,
      metadata: finding.metadata,
    },
  };

  try {
    const client = createLlmClient({ provider, baseUrl, apiKey, model });

    const raw = await analyzeWithLlm(
      client,
      model,
      SYSTEM,
      JSON.stringify(userPayload, null, 2),
      { temperature: 0.1, maxTokens: 2048 },
    );

    const parsed = parseLlmJsonResponse<Partial<VerifyResult>>(raw, {});
    const result: VerifyResult = {
      isFalsePositive: parsed.isFalsePositive === true,
      confidence:
        typeof parsed.confidence === "number"
          ? Math.max(0, Math.min(1, parsed.confidence))
          : 0.5,
      reasoning:
        typeof parsed.reasoning === "string" && parsed.reasoning.trim()
          ? parsed.reasoning.trim()
          : "The model did not provide reasoning.",
      recommendation:
        parsed.recommendation === "MARK_FP" ||
        parsed.recommendation === "KEEP_OPEN" ||
        parsed.recommendation === "NEEDS_REVIEW"
          ? parsed.recommendation
          : "NEEDS_REVIEW",
    };

    // Auto-apply if requested and confidence is high enough
    if (
      autoApply &&
      result.isFalsePositive &&
      result.confidence >= 0.85
    ) {
      await prisma.finding.update({
        where: { id: findingId },
        data: {
          status: "FALSE_POSITIVE",
          statusNote: `AI verification (${Math.round(result.confidence * 100)}% confidence): ${result.reasoning}`,
          statusUpdatedBy: auth.session.user.id,
          statusUpdatedAt: new Date(),
        },
      });
      return NextResponse.json({ ...result, applied: true });
    }

    return NextResponse.json({ ...result, applied: false });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("FP verification LLM error:", msg, e instanceof Error ? e.stack : "");
    return NextResponse.json(
      { error: `Failed to verify finding: ${msg}` },
      { status: 500 },
    );
  }
}
