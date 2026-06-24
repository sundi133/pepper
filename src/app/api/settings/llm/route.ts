import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

export async function GET() {
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
      enableLlmPrDiff: false,
      enableLlmSca: false,
      enableLlmIac: false,
      enableLlmZeroDay: false,
      enableLlmContainer: false,
      osvApiUrl: "https://api.osv.dev",
      vulnDbMode: "online",
    });
  }

  return NextResponse.json({
    llmProvider: settings.llmProvider,
    llmBaseUrl: settings.llmBaseUrl,
    llmModel: settings.llmModel,
    hasApiKey: !!settings.llmApiKey,
    enableLlmSast: settings.enableLlmSast ?? true,
    enableLlmSecrets: settings.enableLlmSecrets ?? true,
    enableLlmPrDiff: settings.enableLlmPrDiff ?? false,
    enableLlmSca: settings.enableLlmSca ?? false,
    enableLlmIac: settings.enableLlmIac ?? false,
    enableLlmZeroDay: settings.enableLlmZeroDay ?? false,
    enableLlmContainer: settings.enableLlmContainer ?? false,
    osvApiUrl: settings.osvApiUrl,
    vulnDbMode: settings.vulnDbMode,
  });
}

const updateSchema = z.object({
  llmProvider: z
    .enum(["ollama", "openai", "anthropic", "openrouter", "azure", "vllm", "custom"])
    .optional(),
  llmBaseUrl: z.string().min(1).optional(),
  llmModel: z.string().min(1).optional(),
  llmApiKey: z.string().optional(),
  enableLlmSast: z.boolean().optional(),
  enableLlmSecrets: z.boolean().optional(),
  enableLlmPrDiff: z.boolean().optional(),
  enableLlmSca: z.boolean().optional(),
  enableLlmIac: z.boolean().optional(),
  enableLlmZeroDay: z.boolean().optional(),
  enableLlmContainer: z.boolean().optional(),
  osvApiUrl: z.string().min(1).optional(),
  vulnDbMode: z.enum(["online", "mirror", "offline"]).optional(),
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

    // Build updateData, filtering out empty values and undefined
    const updateData: Record<string, unknown> = {};
    Object.entries(data).forEach(([key, value]) => {
      if (key === "llmApiKey" && value === "") {
        // Skip empty llmApiKey (means "keep existing")
        return;
      }
      if (value !== undefined) {
        updateData[key] = value;
      }
    });

    const createData = {
      organizationId: orgId,
      llmProvider: data.llmProvider ?? "openai",
      llmBaseUrl: data.llmBaseUrl ?? "https://api.openai.com/v1",
      llmModel: data.llmModel ?? "gpt-4o-mini",
      enableLlmSast: data.enableLlmSast ?? true,
      enableLlmSecrets: data.enableLlmSecrets ?? true,
      enableLlmPrDiff: data.enableLlmPrDiff ?? false,
      enableLlmSca: data.enableLlmSca ?? false,
      enableLlmIac: data.enableLlmIac ?? false,
      enableLlmZeroDay: data.enableLlmZeroDay ?? false,
      enableLlmContainer: data.enableLlmContainer ?? false,
      osvApiUrl: data.osvApiUrl ?? "https://api.osv.dev",
      vulnDbMode: data.vulnDbMode ?? "online",
    };

    await prisma.orgSettings.upsert({
      where: { organizationId: orgId },
      update: updateData,
      create: createData,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    console.error("Failed to update settings:", error);
    return NextResponse.json(
      { error: "Failed to update settings" },
      { status: 500 },
    );
  }
}
