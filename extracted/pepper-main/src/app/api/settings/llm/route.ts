import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  if (!settings) {
    return NextResponse.json({
      llmProvider: "openai",
      llmBaseUrl: "https://api.openai.com/v1",
      llmModel: "gpt-4o-mini",
      hasApiKey: false,
      enableLlmSast: true,
      enableLlmSecrets: true,
      osvApiUrl: "https://api.osv.dev",
      vulnDbMode: "online",
    });
  }

  return NextResponse.json({
    llmProvider: settings.llmProvider,
    llmBaseUrl: settings.llmBaseUrl,
    llmModel: settings.llmModel,
    hasApiKey: !!settings.llmApiKey,
    enableLlmSast: settings.enableLlmSast,
    enableLlmSecrets: settings.enableLlmSecrets,
    osvApiUrl: settings.osvApiUrl,
    vulnDbMode: settings.vulnDbMode,
  });
}

const updateSchema = z.object({
  llmProvider: z.string().optional(),
  llmBaseUrl: z.string().url().optional(),
  llmModel: z.string().optional(),
  llmApiKey: z.string().optional(),
  enableLlmSast: z.boolean().optional(),
  enableLlmSecrets: z.boolean().optional(),
  osvApiUrl: z.string().url().optional(),
  vulnDbMode: z.string().optional(),
});

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  try {
    const body = await req.json();
    const data = updateSchema.parse(body);

    // Don't update llmApiKey if empty string (means "keep existing")
    const updateData: Record<string, unknown> = { ...data };
    if (data.llmApiKey === "") delete updateData.llmApiKey;

    await prisma.orgSettings.upsert({
      where: { organizationId: orgId },
      update: updateData,
      create: {
        organizationId: orgId,
        ...updateData,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update settings" },
      { status: 500 },
    );
  }
}
