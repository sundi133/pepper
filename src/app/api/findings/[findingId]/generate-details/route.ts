import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  apiKey: process.env.LLM_API_KEY,
  baseURL: process.env.LLM_BASE_URL,
});

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

  // Get finding with scan context
  const finding = await prisma.finding.findFirst({
    where: { id: findingId },
    include: {
      scan: {
        select: { projectId: true, project: { select: { organizationId: true } } },
      },
    },
  });

  if (!finding || finding.scan?.project?.organizationId !== orgId) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  try {
    // Generate fresh vulnerability details from AI
    const prompt = `Generate a professional vulnerability report. Output ONLY valid JSON, no markdown.

Title: ${finding.title}
CWE: ${finding.cweId || "Unknown"}
Severity: ${finding.severity}
File: ${finding.filePath}
Lines: ${finding.startLine}-${finding.endLine}

Original Description:
${finding.description}

Return this JSON structure:

{
  "summary": "2-3 sentences max. Clear vulnerability overview.",
  "vulnerabilityDetails": "2-3 sentences max. Combine: what is wrong + where + why exploitable. ONE paragraph only. NO labels. NO subheadings.",
  "stepsToReproduce": ["Step 1: Clear, actionable step to reproduce", "Step 2: Next step", "Step 3: Final step to trigger the vulnerability"],
  "impact": "2-3 bullet points max. Business and technical consequences.",
  "remediation": ["Fix 1", "Fix 2", "Fix 3"]
}

RULES:
- vulnerabilityDetails: EXACTLY 2-3 lines, ONE paragraph
- stepsToReproduce: Generate 3-5 clear, actionable steps that a developer can follow to reproduce the vulnerability in the code
- NEVER use "What is wrong:" or "Where:" or "Why it is exploitable:" labels
- NO generic filler text
- Specific to this vulnerability type
- Concise and direct`;

    const message = await client.messages.create({
      model: process.env.LLM_MODEL || "anthropic/claude-opus-4-8",
      max_tokens: 1024,
      messages: [
        {
          role: "user",
          content: prompt,
        },
      ],
    });

    const responseText =
      message.content[0].type === "text" ? message.content[0].text : "";

    // Parse JSON response
    let details;
    try {
      // Extract JSON from response (may be wrapped in markdown code blocks)
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error("No JSON found in response");
      }
      details = JSON.parse(jsonMatch[0]);
    } catch (parseError) {
      console.error("Failed to parse AI response:", responseText);
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
        stepsToReproduce: Array.isArray(details.stepsToReproduce)
          ? details.stepsToReproduce
          : [],
        impact: details.impact || "",
        remediation: Array.isArray(details.remediation)
          ? details.remediation
          : [],
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
