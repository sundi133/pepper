import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-guard";
import { createLlmClient } from "@/lib/llm-gateway";
import { z } from "zod";

const testSchema = z.object({
  llmProvider: z.enum(["ollama", "openai", "anthropic", "openrouter", "azure", "vllm", "opencode", "custom"]),
  llmBaseUrl: z.string().url(),
  llmModel: z.string().min(1),
  llmApiKey: z.string().min(1, "API key cannot be empty").optional(),
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
      await client.client.messages.create({
        model: llmModel,
        max_tokens: 1,
        messages: [{ role: "user", content: "ok" }],
      });
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
  return msg.replace(/(sk-[a-zA-Z0-9]{10,})/g, "sk-...");
}
