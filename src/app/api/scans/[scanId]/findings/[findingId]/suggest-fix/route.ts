import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";

const SYSTEM = `You are a senior application security engineer helping a developer fix one finding.

Respond with JSON only (no markdown outside JSON strings) matching this shape:
{
  "summary": "2-4 sentences: what is wrong and why it matters",
  "developerFix": "Markdown allowed. Concrete code-level steps, suggested replacement patterns, and fenced code blocks where helpful. Do not assume files not shown.",
  "verificationSteps": ["short bullet as string", "..."],
  "optionalUnifiedDiff": "unified diff string or null if you cannot produce a safe minimal patch from the evidence"
}

Rules:
- Ground every claim in the provided evidence; if unsure, say what to verify locally.
- Prefer minimal, safe fixes over large refactors.
- Do not include real secrets, tokens, or working exploit payloads — use placeholders like YOUR_TOKEN or example.com.
- When an HTTP route and method are visible, include one fenced bash block with a curl example using 127.0.0.1 or example.com and safe placeholder data inside developerFix or verificationSteps.`;

type SuggestFixBody = {
  summary: string;
  developerFix: string;
  verificationSteps: string[];
  optionalUnifiedDiff: string | null;
};

export async function POST(
  _req: NextRequest,
  {
    params,
  }: { params: Promise<{ scanId: string; findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId, findingId } = await params;

  const finding = await prisma.finding.findFirst({
    where: {
      id: findingId,
      scanId,
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
          "No LLM API key configured. Set the organization LLM key in Settings → LLM, or set LLM_API_KEY / OPENAI_API_KEY in the server environment.",
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
    commitSha: finding.scan.commitSha,
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
      metadata: finding.metadata,
    },
  };

  try {
    const client = createLlmClient({
      provider,
      baseUrl,
      apiKey,
      model,
    });

    const raw = await analyzeWithLlm(
      client,
      model,
      SYSTEM,
      JSON.stringify(userPayload, null, 2),
      { temperature: 0.15, maxTokens: 6144 },
    );

    const parsed = parseLlmJsonResponse<Partial<SuggestFixBody>>(raw, {});
    const result: SuggestFixBody = {
      summary:
        typeof parsed.summary === "string" && parsed.summary.trim()
          ? parsed.summary.trim()
          : "The model did not return a summary; try again or shorten the finding context.",
      developerFix:
        typeof parsed.developerFix === "string"
          ? parsed.developerFix.trim()
          : "",
      verificationSteps: Array.isArray(parsed.verificationSteps)
        ? parsed.verificationSteps.filter(
            (s): s is string => typeof s === "string" && s.trim().length > 0,
          )
        : [],
      optionalUnifiedDiff:
        typeof parsed.optionalUnifiedDiff === "string" &&
        parsed.optionalUnifiedDiff.trim()
          ? parsed.optionalUnifiedDiff.trim()
          : null,
    };

    return NextResponse.json(result);
  } catch (e) {
    console.error("suggest-fix LLM error:", e);
    return NextResponse.json(
      { error: "Failed to generate fix suggestion" },
      { status: 500 },
    );
  }
}
