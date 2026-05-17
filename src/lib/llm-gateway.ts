import OpenAI from "openai";
import { Ollama } from "ollama";

export interface LlmConfig {
  provider: string;
  baseUrl: string;
  apiKey?: string;
  model: string;
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
    apiKey: config.apiKey || "not-needed",
    baseURL: config.baseUrl,
  });
}

// ─── Unified Client Type ──────────────────────────────────────────────

export type LlmClient =
  | { type: "ollama"; client: Ollama; model: string }
  | { type: "openrouter"; client: OpenAI; model: string }
  | { type: "openai"; client: OpenAI; model: string };

export function createLlmClient(config: LlmConfig): LlmClient {
  const provider = config.provider.toLowerCase();

  if (provider === "ollama") {
    return {
      type: "ollama",
      client: getOllamaClient(config.baseUrl || OLLAMA_HOST),
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

  // OpenRouter path — many models don't support response_format, so we
  // enforce JSON via the prompt and parse the response manually.
  if (llmClient.type === "openrouter") {
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
  }

  // OpenAI-compatible path
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
  } catch {
    return fallback;
  }
}
