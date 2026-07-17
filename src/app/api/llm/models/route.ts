import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { createLlmClient, LlmConfig } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";

/**
 * GET /api/llm/models
 *
 * Lists the models available for the org's configured LLM provider so the UI
 * can offer a per-report model picker. Queries the provider live (OpenAI /
 * OpenRouter /models, Anthropic /models, Ollama tags) and falls back to a small
 * curated preset if the provider can't be reached. The configured default model
 * is always included.
 */

// Safe fallbacks used only when the provider's model list can't be fetched.
const PRESETS: Record<string, string[]> = {
  openai: ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o4-mini"],
  anthropic: [
    "claude-opus-4-1",
    "claude-sonnet-4-5",
    "claude-3-5-haiku-latest",
  ],
  openrouter: [],
  ollama: [],
};

async function listModels(cfg: LlmConfig): Promise<string[]> {
  const c = createLlmClient(cfg);

  if (c.type === "ollama") {
    const res = await c.client.list();
    return (res.models || []).map((m) => m.name).filter(Boolean);
  }

  if (c.type === "anthropic") {
    const res = await c.client.models.list({ limit: 100 });
    return (res.data || []).map((m) => m.id).filter(Boolean);
  }

  // openai / openrouter / any OpenAI-compatible endpoint
  const ids: string[] = [];
  const page = await c.client.models.list();
  for await (const m of page) {
    if (m?.id) ids.push(m.id);
    if (ids.length >= 300) break;
  }
  return ids;
}

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  const cfg: LlmConfig = {
    provider: orgSettings?.llmProvider || "openai",
    baseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
    apiKey: orgSettings?.llmApiKey || undefined,
    model: orgSettings?.llmModel || "gpt-4o-mini",
  };
  const provider = cfg.provider.toLowerCase();
  const defaultModel = cfg.model;

  let models: string[] = [];
  let source: "live" | "fallback" = "live";
  try {
    models = await listModels(cfg);
  } catch (err) {
    logger.warn({ err, provider }, "Could not list provider models; using presets");
  }
  if (models.length === 0) {
    source = "fallback";
    models = PRESETS[provider] || [];
  }

  // Always offer the configured default, and sort for a stable, scannable list.
  const set = new Set<string>([defaultModel, ...models].filter(Boolean));
  const sorted = Array.from(set).sort((a, b) =>
    a === defaultModel ? -1 : b === defaultModel ? 1 : a.localeCompare(b),
  );

  return NextResponse.json({
    provider,
    defaultModel,
    source,
    models: sorted,
  });
}
