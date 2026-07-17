import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-guard";
import { z } from "zod";

const querySchema = z.object({
  provider: z.string().min(1),
  baseUrl: z.string().url(),
  apiKey: z.string().optional(),
});

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { searchParams } = new URL(req.url);
  const parsed = querySchema.safeParse({
    provider: searchParams.get("provider"),
    baseUrl: searchParams.get("baseUrl"),
    apiKey: searchParams.get("apiKey") || undefined,
  });
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid parameters", details: parsed.error.issues },
      { status: 400 },
    );
  }

  const { provider, baseUrl, apiKey } = parsed.data;

  try {
    let models: string[];

    if (provider === "ollama") {
      const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/api/tags`);
      if (!res.ok) throw new Error(`Ollama returned ${res.status}`);
      const data = await res.json();
      models = (data.models || []).map((m: { name: string }) => m.name);
    } else if (provider === "anthropic") {
      const modelsUrl = `${baseUrl.replace(/\/+$/, "")}/models`;
      const res = await fetch(modelsUrl, {
        headers: {
          "x-api-key": apiKey || "",
          "anthropic-version": "2024-10-22",
        },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = body.error?.message || `Anthropic returned ${res.status}`;
        throw new Error(`${msg} — try typing the model name manually`);
      }
      const data = await res.json();
      models = (data.data || []).map((m: { id: string }) => m.id);
    } else {
      // OpenAI-compatible
      const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/models`, {
        headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error?.message || `API returned ${res.status}`);
      }
      const data = await res.json();
      models = (data.data || []).map((m: { id: string }) => m.id);
    }

    return NextResponse.json({ models });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to fetch models";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
