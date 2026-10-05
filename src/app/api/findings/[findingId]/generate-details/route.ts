import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import {
  getLlmConfig,
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> }
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  // Get finding with scan context
  const finding = await prisma.finding.findFirst({
    where: { id: findingId },
    include: {
      scan: {
        select: {
          projectId: true,
          project: {
            select: {
              organizationId: true,
              organization: {
                select: {
                  settings: true,
                },
              },
            },
          },
        },
      },
    },
  });

  if (!finding || finding.scan?.project?.organizationId !== orgId) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  const config = getLlmConfig(
    finding.scan?.project?.organization?.settings as Record<string, unknown> | null
  );

  if (!config.apiKey && config.provider !== "ollama") {
    return NextResponse.json(
      { error: "LLM API key is not configured. Please check Settings → LLM." },
      { status: 400 }
    );
  }

  try {
    const appContext = `${finding.filePath ? `File: ${finding.filePath}` : ""}${finding.startLine ? `:${finding.startLine}` : ""}${finding.endLine ? `-${finding.endLine}` : ""}`;

    const prompt = `Vulnerability: ${finding.title}
${finding.cweId ? `CWE: ${finding.cweId}` : ""}
Severity: ${finding.severity}
${appContext}

Context:
${finding.description}

Return EXACTLY this JSON structure — no extra fields, no missing fields:

{
  "summary": "One paragraph describing what the vulnerability is and how it works. Direct and specific.",
  "vulnerabilityDetails": "Markdown bullet list with key technical details. Each bullet has a bold label then value. Example:\\n* **Endpoint:** \\\`POST /api/login\\\`\\n* **Affected Parameters:** \\\`email\\\`, \\\`password\\\`\\n* **Vulnerable Function:** \\\`pool.query()\\\`\\n* **Issue:** Short description of the root cause.",
  "stepsToReproduce": "Numbered steps (1. 2. 3.) as markdown. Each step's description and its code block MUST be a single list item, with the fenced code block indented under its numbered line with NO blank line between. Format each step as:\\n1. Description of the step\\n   \`\`\`bash\\n   curl command here\\n   \`\`\`\\n2. Next step description with its indented code block",
  "impact": "Markdown bullet list of 3-6 specific consequences. Each bullet is a complete sentence.",
  "remediation": "Markdown bullet list of 3-6 specific fixes. Each bullet is a complete actionable sentence.",
  "references": "Markdown bullet list. Include the CWE and OWASP Top 10 mapping if applicable. Example:\\n* CWE-89 – SQL Injection\\n* OWASP Top 10: A03:2021 – Injection"
}

RULES:
- vulnerabilityDetails MUST be a markdown bullet list with bold labels
- NEVER use "What is wrong", "Where", "Why it is exploitable", "Impact" as labels
- NO generic text — be specific to this exact vulnerability and code context
- references: ALWAYS include at least the CWE reference
- Each bullet in impact and remediation is a complete sentence
- stepsToReproduce: each numbered step is a SINGLE list item with its code block indented directly under it (no blank line between the step text and its code block)
- DO NOT put code blocks as separate paragraphs between numbered items — they must be part of the step`;

    const client = createLlmClient(config);
    const responseText = await analyzeWithLlm(
      client,
      config.model,
      "You are a security engineer writing a vulnerability report. Output ONLY valid JSON. No markdown, no code fences.",
      prompt,
      { maxTokens: 4096 }
    );

    // Parse JSON response
    let details: Record<string, any> = {};
    try {
      details = parseLlmJsonResponse<Record<string, any>>(responseText, {});
      if (!details || Object.keys(details).length === 0) {
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          details = JSON.parse(jsonMatch[0]);
        }
      }
    } catch (parseError) {
      console.error("Failed to parse AI response:", responseText);
      return NextResponse.json(
        { error: "Failed to parse vulnerability details" },
        { status: 500 }
      );
    }

    if (!details || Object.keys(details).length === 0) {
      console.error("AI returned empty or unparseable response:", responseText);
      return NextResponse.json(
        { error: "Failed to parse vulnerability details" },
        { status: 500 }
      );
    }

    // Update finding metadata with generated details
    const updatedMetadata = {
      ...((finding.metadata as Record<string, unknown>) || {}),
      generatedDetails: {
        summary: details.summary || "",
        vulnerabilityDetails: details.vulnerabilityDetails || "",
        stepsToReproduce:
          typeof details.stepsToReproduce === "string"
            ? details.stepsToReproduce
            : Array.isArray(details.stepsToReproduce)
              ? details.stepsToReproduce
              : [],
        impact: details.impact || "",
        remediation:
          typeof details.remediation === "string"
            ? details.remediation
            : Array.isArray(details.remediation)
              ? details.remediation
              : [],
        references: details.references || "",
        generatedAt: new Date().toISOString(),
      },
    };

    // Save to database
    await prisma.finding.update({
      where: { id: findingId },
      data: { metadata: updatedMetadata as object },
    });

    return NextResponse.json(updatedMetadata.generatedDetails);
  } catch (error) {
    console.error("Error generating vulnerability details:", error);
    return NextResponse.json(
      { error: "Failed to generate details" },
      { status: 500 }
    );
  }
}
