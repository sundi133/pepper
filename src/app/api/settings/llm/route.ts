import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { encryptSecret } from "@/lib/token-encryption";
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

// Hosted providers that always need their own key.
const KEYED_PROVIDERS = new Set([
  "openai",
  "anthropic",
  "openrouter",
  "azure",
  "azure-foundry",
  "opencode",
]);

const updateSchema = z.object({
  llmProvider: z
    .enum(["ollama", "openai", "anthropic", "openrouter", "azure", "azure-foundry", "vllm", "opencode", "custom"])
    .optional(),
  llmBaseUrl: z.string().url().optional(),
  llmModel: z.string().min(1).optional(),
  llmApiKey: z.string().optional(),
  enableLlmSast: z.boolean().optional(),
  enableLlmSecrets: z.boolean().optional(),
  osvApiUrl: z.string().url().optional(),
  vulnDbMode: z.enum(["online", "mirror", "offline"]).optional(),
});

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  try {
    const body = await req.json();
    const data = updateSchema.parse(body);

    // Empty key normally means "keep existing" — but NOT across a provider
    // change: the stored key belongs to the old provider (e.g. an OpenRouter
    // sk-or-… key sent to Anthropic → 401, every scan returns 0 findings).
    const existing = await prisma.orgSettings.findUnique({
      where: { organizationId: orgId },
      select: { llmProvider: true, llmApiKey: true },
    });
    const providerChanged =
      !!data.llmProvider &&
      !!existing?.llmProvider &&
      data.llmProvider !== existing.llmProvider;
    if (providerChanged && !data.llmApiKey && existing?.llmApiKey) {
      if (KEYED_PROVIDERS.has(data.llmProvider!)) {
        return NextResponse.json(
          {
            error: `Enter the API key for ${data.llmProvider} — the saved key belongs to ${existing.llmProvider} and won't work with the new provider.`,
            code: "API_KEY_REQUIRED_FOR_PROVIDER",
          },
          { status: 400 },
        );
      }
      // Keyless/local providers (ollama, vllm, custom): drop the stale key.
      data.llmApiKey = undefined;
    }

    const updateData: Record<string, unknown> = { ...data };
    if (providerChanged && !data.llmApiKey && existing?.llmApiKey) {
      updateData.llmApiKey = null;
    } else if (data.llmApiKey === "" || data.llmApiKey === undefined) {
      delete updateData.llmApiKey;
    } else if (data.llmApiKey) {
      // Encrypt before storing — use "enc:" prefix so readers can distinguish
      // encrypted keys from legacy plaintext values still in the database.
      updateData.llmApiKey = "enc:" + encryptSecret(data.llmApiKey);
    }

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

  return NextResponse.json({ error: "Method not allowed" }, { status: 405 });
}

const DEFAULTS = {
  llmProvider: "openai",
  llmBaseUrl: "https://api.openai.com/v1",
  llmModel: "gpt-4o-mini",
  llmApiKey: null,
  enableLlmSast: true,
  enableLlmSecrets: true,
  osvApiUrl: "https://api.osv.dev",
  vulnDbMode: "online",
};

export async function DELETE() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  try {
    await prisma.orgSettings.upsert({
      where: { organizationId: orgId },
      update: DEFAULTS,
      create: { organizationId: orgId, ...DEFAULTS },
    });
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json(
      { error: "Failed to reset settings" },
      { status: 500 },
    );
  }
}
