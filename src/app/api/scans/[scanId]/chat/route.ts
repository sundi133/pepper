import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { createLlmClient, streamChatWithLlm, type ChatMessage } from "@/lib/llm-gateway";
import { z } from "zod";

const MAX_FINDINGS_IN_CONTEXT = 60;

const chatSchema = z.object({
  message: z.string().min(1).max(2000),
  history: z
    .array(
      z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string().max(4000),
      }),
    )
    .max(20)
    .default([]),
});

function buildSystemPrompt(
  scan: {
    id: string;
    scanType: string;
    status: string;
    branch: string | null;
    prNumber: number | null;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    project: { name: string } | null;
  },
  findings: Array<{
    severity: string;
    scanner: string;
    title: string;
    filePath: string | null;
    startLine: number | null;
    ruleId: string | null;
    cweId: string | null;
    status: string;
    riskScore: number | null;
  }>,
): string {
  const projectName = scan.project?.name ?? "Unknown project";
  const scanContext = [
    `Project: ${projectName}`,
    `Scan type: ${scan.scanType}`,
    scan.branch ? `Branch: ${scan.branch}` : null,
    scan.prNumber ? `PR #${scan.prNumber}` : null,
    `Status: ${scan.status}`,
    `Findings: ${scan.criticalCount} critical, ${scan.highCount} high, ${scan.mediumCount} medium, ${scan.lowCount} low, ${scan.infoCount} info`,
  ]
    .filter(Boolean)
    .join(" | ");

  const findingList = findings
    .map((f, i) => {
      const parts = [
        `${i + 1}. [${f.severity}] ${f.title}`,
        f.filePath
          ? `   File: ${f.filePath}${f.startLine ? `:${f.startLine}` : ""}`
          : null,
        `   Scanner: ${f.scanner}${f.ruleId ? ` (${f.ruleId})` : ""}${f.cweId ? ` | ${f.cweId}` : ""}`,
        f.riskScore != null ? `   Risk score: ${f.riskScore}/100` : null,
        f.status !== "OPEN" ? `   Status: ${f.status}` : null,
      ]
        .filter(Boolean)
        .join("\n");
      return parts;
    })
    .join("\n\n");

  return `You are a security triage assistant helping developers understand and prioritise findings from a SAST/SCA/secrets scan.

Scan context: ${scanContext}

Findings (${findings.length} shown, ordered by risk score):
${findingList || "No findings."}

Guidelines:
- Be concise and actionable. Developers want to know what to fix, not lengthy explanations.
- Reference findings by number or title when discussing them.
- When asked to prioritise, use severity and risk score together.
- Suggest concrete remediation steps when relevant.
- If asked about a finding not in the list, say so rather than guessing.
- Format responses as plain text with clear structure. Use bullet lists for multiple items.`;
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId } = await params;

  // Verify scan belongs to org
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      scanType: true,
      status: true,
      branch: true,
      prNumber: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      project: { select: { name: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Parse request
  let body: z.infer<typeof chatSchema>;
  try {
    body = chatSchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid input", details: e.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  // Get org LLM config
  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: { llmApiKey: true, llmProvider: true, llmBaseUrl: true, llmModel: true },
  });

  const apiKey = orgSettings?.llmApiKey?.trim();
  if (!apiKey) {
    return NextResponse.json(
      { error: "LLM not configured. Add an API key under Settings → LLM Config." },
      { status: 422 },
    );
  }

  // Fetch findings for context (top N by risk score)
  const findings = await prisma.finding.findMany({
    where: { scanId, status: { not: "FALSE_POSITIVE" } },
    select: {
      severity: true,
      scanner: true,
      title: true,
      filePath: true,
      startLine: true,
      ruleId: true,
      cweId: true,
      status: true,
      riskScore: true,
    },
    orderBy: [{ riskScore: "desc" }, { severity: "asc" }],
    take: MAX_FINDINGS_IN_CONTEXT,
  });

  const llmClient = createLlmClient({
    provider: orgSettings?.llmProvider ?? "openai",
    baseUrl: orgSettings?.llmBaseUrl ?? "https://api.openai.com/v1",
    apiKey,
    model: orgSettings?.llmModel ?? "gpt-4o-mini",
  });

  const systemPrompt = buildSystemPrompt(scan, findings);

  // Build message history: system + history + new user message
  const messages: ChatMessage[] = [
    { role: "system", content: systemPrompt },
    ...body.history.map((m) => ({ role: m.role, content: m.content })),
    { role: "user", content: body.message },
  ];

  // Stream the response as SSE
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      try {
        const gen = streamChatWithLlm(llmClient, messages, {
          temperature: 0.7,
          maxTokens: 1024,
        });
        for await (const chunk of gen) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
        }
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "LLM error";
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: msg })}\n\n`));
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
