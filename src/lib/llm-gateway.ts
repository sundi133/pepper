import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { Ollama } from "ollama";
import { logger } from "@/lib/logger";
import { decryptSecret } from "@/lib/token-encryption";

export interface LlmConfig {
  provider: string;
  baseUrl: string;
  apiKey?: string;
  model: string;
}

function decryptLlmApiKey(stored: string | null | undefined): string | undefined {
  if (!stored) return undefined;
  if (stored.startsWith("enc:")) {
    try {
      return decryptSecret(stored.slice(4));
    } catch {
      return undefined;
    }
  }
  return stored;
}

/**
 * Build LLM config from org settings + env vars.
 *
 * If the user has stored an API key in Settings → LLM, use DB settings
 * for everything (with env fallback for provider/baseUrl/model).
 *
 * If no API key in DB, use .env only.
 */
export function getLlmConfig(orgSettings?: Record<string, unknown> | null): { provider: string; baseUrl: string; apiKey: string; model: string } {
  const envProvider = process.env.LLM_PROVIDER || "openai";
  const envBaseUrl = process.env.LLM_BASE_URL || "https://api.openai.com/v1";
  const envApiKey = process.env.LLM_API_KEY?.trim() || process.env.OPENAI_API_KEY?.trim() || "";
  const envModel = process.env.LLM_MODEL || "gpt-4o-mini";

  const str = (k: string) => {
    const v = orgSettings?.[k];
    return typeof v === "string" ? v : undefined;
  };
  const dbApiKey = decryptLlmApiKey(str("llmApiKey"));

  if (dbApiKey) {
    return {
      provider: str("llmProvider") || envProvider,
      baseUrl: str("llmBaseUrl") || envBaseUrl,
      apiKey: dbApiKey,
      model: str("llmModel") || envModel,
    };
  }

  return {
    provider: envProvider,
    baseUrl: envBaseUrl,
    apiKey: envApiKey,
    model: envModel,
  };
}

// ─── Ollama Client (native SDK) ───────────────────────────────────────

const OLLAMA_HOST = process.env.OLLAMA_HOST || "http://localhost:11434";

// Custom fetch with extended timeout for CPU-based LLM inference
// Analysis prompts can be 1000+ tokens, requiring 10-15 minutes on CPU
const ollamaFetch: typeof fetch = (url, options) => {
  return fetch(url, {
    ...options,
    signal: AbortSignal.timeout(900000), // 15 minutes timeout for CPU inference
  });
};

let _ollamaClient: Ollama | undefined;

function getOllamaClient(host?: string): Ollama {
  const targetHost = host || OLLAMA_HOST;
  if (!_ollamaClient || (host && host !== OLLAMA_HOST)) {
    _ollamaClient = new Ollama({
      host: targetHost,
      fetch: ollamaFetch,
    });
  }
  return _ollamaClient;
}

// ─── OpenAI-compatible Client ─────────────────────────────────────────

function createOpenAIClient(config: LlmConfig): OpenAI {
  const provider = config.provider.toLowerCase();

  // OpenRouter requires specific headers and base URL
  if (provider === "openrouter") {
    return new OpenAI({
      apiKey: config.apiKey || "",
      baseURL: config.baseUrl || "https://openrouter.ai/api/v1",
      defaultHeaders: {
        "HTTP-Referer": process.env.OPENROUTER_REFERER || "https://pepper.dev",
        "X-Title": process.env.OPENROUTER_TITLE || "Pepper SAST",
      },
    });
  }

  return new OpenAI({
    apiKey: config.apiKey || process.env.LLM_API_KEY || "",
    baseURL: config.baseUrl,
  });
}

// ─── Unified Client Type ──────────────────────────────────────────────

export type LlmClient =
  | { type: "ollama"; client: Ollama; model: string }
  | { type: "anthropic"; client: Anthropic; model: string }
  | { type: "openrouter"; client: OpenAI; model: string }
  | { type: "openai"; client: OpenAI; model: string };

export function createLlmClient(config: LlmConfig): LlmClient {
  const provider = (config.provider || "openai").toLowerCase();

  if (provider === "ollama") {
    return {
      type: "ollama",
      client: getOllamaClient(config.baseUrl || OLLAMA_HOST),
      model: config.model,
    };
  }

  if (provider === "anthropic") {
    return {
      type: "anthropic",
      client: new Anthropic({
        apiKey: config.apiKey || "",
        ...(config.baseUrl ? { baseURL: config.baseUrl } : {}),
      }),
      model: config.model,
    };
  }

  if (provider === "openrouter") {
    return {
      type: "openrouter",
      client: createOpenAIClient(config),
      model: config.model,
    };
  }

  // OpenAI, Azure, vLLM, and any OpenAI-compatible provider
  return {
    type: "openai",
    client: createOpenAIClient(config),
    model: config.model,
  };
}

// ─── Unified Analysis Function ────────────────────────────────────────

export async function analyzeWithLlm(
  llmClient: LlmClient,
  model: string,
  systemPrompt: string,
  userContent: string,
  options?: { temperature?: number; maxTokens?: number },
): Promise<string> {
  const temperature = options?.temperature ?? 0.1;

  if (llmClient.type === "ollama") {
    const response = await llmClient.client.chat({
      model: model || llmClient.model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent },
      ],
      format: "json",
      options: {
        temperature,
        num_predict: options?.maxTokens ?? 8192,
      },
    });
    return response.message?.content || "{}";
  }

  // Anthropic path — uses native Messages API
  if (llmClient.type === "anthropic") {
    try {
      const response = await llmClient.client.messages.create({
        model: model || llmClient.model,
        system: systemPrompt,
        messages: [{ role: "user", content: userContent }],
        temperature,
        max_tokens: options?.maxTokens ?? 8192,
      });
      const block = response.content[0];
      return block.type === "text" ? block.text : "{}";
    } catch {
      return "{}";
    }
  }

  // OpenRouter path — many models don't support response_format, so we
  // enforce JSON via the prompt and parse the response manually.
  if (llmClient.type === "openrouter") {
    try {
      const jsonSystemPrompt = `${systemPrompt}\n\nIMPORTANT: You MUST respond with valid JSON only. No markdown, no explanation, no code fences — just raw JSON.`;
      const response = await llmClient.client.chat.completions.create({
        model: model || llmClient.model,
        messages: [
          { role: "system", content: jsonSystemPrompt },
          { role: "user", content: userContent },
        ],
        temperature,
        max_tokens: options?.maxTokens ?? 8192,
      });
      return response.choices[0]?.message?.content || "{}";
    } catch {
      return "{}";
    }
  }

  // OpenAI-compatible path
  try {
    const response = await llmClient.client.chat.completions.create({
      model: model || llmClient.model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent },
      ],
      temperature,
      max_tokens: options?.maxTokens ?? 8192,
      response_format: { type: "json_object" },
    });
    return response.choices[0]?.message?.content || "{}";
  } catch {
    return "{}";
  }
}

// ─── Streaming Chat ───────────────────────────────────────────────────
//
// Unlike analyzeWithLlm (which forces JSON output), this returns a plain-text
// async generator suitable for chat interfaces. Each yielded value is a text
// chunk to append to the response.

export type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

export async function* streamChatWithLlm(
  llmClient: LlmClient,
  messages: ChatMessage[],
  options?: { temperature?: number; maxTokens?: number },
): AsyncGenerator<string> {
  const temperature = options?.temperature ?? 0.7;
  const maxTokens = options?.maxTokens ?? 2048;

  if (llmClient.type === "ollama") {
    const stream = await llmClient.client.chat({
      model: llmClient.model,
      messages,
      stream: true,
      options: { temperature, num_predict: maxTokens },
    });
    for await (const chunk of stream) {
      const text = chunk.message?.content;
      if (text) yield text;
    }
    return;
  }

  // Anthropic streaming
  if (llmClient.type === "anthropic") {
    const systemMsg = messages.find((m) => m.role === "system");
    const nonSystemMsgs = messages
      .filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role as "user" | "assistant", content: m.content }));
    const stream = llmClient.client.messages.stream({
      model: llmClient.model,
      system: systemMsg?.content,
      messages: nonSystemMsgs,
      temperature,
      max_tokens: maxTokens,
    });
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        yield event.delta.text;
      }
    }
    return;
  }

  // OpenAI-compatible (openai + openrouter)
  const stream = await llmClient.client.chat.completions.create({
    model: llmClient.model,
    messages,
    temperature,
    max_tokens: maxTokens,
    stream: true,
  });
  for await (const chunk of stream) {
    const text = chunk.choices[0]?.delta?.content;
    if (text) yield text;
  }
}

// ─── JSON Response Parser ─────────────────────────────────────────────

export function parseLlmJsonResponse<T>(raw: string, fallback: T): T {
  try {
    // Handle cases where LLM wraps JSON in markdown code blocks
    let cleaned = raw.trim();
    if (cleaned.startsWith("```json")) {
      cleaned = cleaned.slice(7);
    } else if (cleaned.startsWith("```")) {
      cleaned = cleaned.slice(3);
    }
    if (cleaned.endsWith("```")) {
      cleaned = cleaned.slice(0, -3);
    }
    return JSON.parse(cleaned.trim()) as T;
  } catch (err) {
    logger.warn(
      {
        err,
        rawLength: raw?.length,
        rawPrefix: raw?.slice(0, 120),
      },
      "parseLlmJsonResponse: failed to parse LLM JSON response — returning fallback",
    );
    return fallback;
  }
}
