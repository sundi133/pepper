import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-guard";
import Anthropic from "@anthropic-ai/sdk";
import { createLlmClient } from "@/lib/llm-gateway";
import { z } from "zod";

const testSchema = z.object({
  llmProvider: z.enum(["ollama", "openai", "anthropic", "openrouter", "azure", "azure-foundry", "vllm", "opencode", "custom"]),
  llmBaseUrl: z.string().url(),
  llmModel: z.string().min(1),
  llmApiKey: z.string().optional(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = testSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid input", details: parsed.error.issues },
      { status: 400 },
    );
  }

  const { llmProvider, llmBaseUrl, llmModel, llmApiKey } = parsed.data;

  try {
    const client = createLlmClient({
      provider: llmProvider,
      baseUrl: llmBaseUrl,
      apiKey: llmApiKey,
      model: llmModel,
    });

    if (client.type === "ollama") {
      const models = await client.client.list();
      const modelExists = models.models?.some(
        (m) => m.name === llmModel || m.name.startsWith(llmModel + ":"),
      );
      if (!modelExists) {
        return NextResponse.json(
          { error: `Model "${llmModel}" not found. Available: ${models.models?.map((m) => m.name).join(", ") || "none"}` },
          { status: 400 },
        );
      }
    } else if (client.type === "anthropic") {
      try {
        // Small but not 1: models that think by default need a little room.
        await client.client.messages.create({
          model: llmModel,
          max_tokens: 64,
          messages: [{ role: "user", content: "Reply with: ok" }],
        });
      } catch (err) {
        if (err instanceof Anthropic.NotFoundError) {
          return NextResponse.json(
            {
              error: `Anthropic returned 404 for model "${llmModel}". Check the model ID (e.g. claude-opus-5, claude-sonnet-5, claude-haiku-4-5) and that Base URL is the API root, e.g. https://api.anthropic.com.`,
            },
            { status: 400 },
          );
        }
        if (err instanceof Anthropic.AuthenticationError) {
          return NextResponse.json(
            { error: "Anthropic rejected the API key (401). Check or regenerate it." },
            { status: 400 },
          );
        }
        throw err;
      }
    } else {
      await client.client.chat.completions.create({
        model: llmModel,
        max_tokens: 1,
        messages: [{ role: "user", content: "ok" }],
      });
    }

    return NextResponse.json({ success: true });
  } catch (error: unknown) {
    const message =
      error instanceof Error ? stripApiKey(error.message) : "Connection failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

function stripApiKey(msg: string): string {
  // Covers OpenAI (sk-…) and Anthropic (sk-ant-api03-…) keys, which contain
  // '-' and '_' — the old [a-zA-Z0-9] class never matched Anthropic keys.
  return msg.replace(/sk-[A-Za-z0-9_-]{10,}/g, "sk-...");
}
