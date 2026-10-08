import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { Ollama } from "ollama";
import { logger } from "@/lib/logger";
import { decryptSecret } from "@/lib/token-encryption";
import {
  createRedactionSession,
  llmMaskingEnabled,
  MASKED_SECRETS_NOTE,
  type RedactionSession,
} from "@/lib/llm-redaction";

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
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  // Provider inference: an explicit LLM_PROVIDER always wins; otherwise the
  // presence of an OpenRouter key implies OpenRouter, and OpenAI is the default.
  const envProvider =
    process.env.LLM_PROVIDER || (openrouterKey ? "openrouter" : "openai");
  const isOpenRouter = envProvider.toLowerCase() === "openrouter";
  const envBaseUrl =
    process.env.LLM_BASE_URL ||
    (isOpenRouter ? "https://openrouter.ai/api/v1" : "https://api.openai.com/v1");
  const envApiKey =
    process.env.LLM_API_KEY?.trim() ||
    process.env.OPENAI_API_KEY?.trim() ||
    openrouterKey ||
    "";
  const envModel =
    process.env.LLM_MODEL ||
    (isOpenRouter ? process.env.OPENROUTER_MODEL || "google/gemini-2.5-flash" : "gpt-4o-mini");

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
      apiKey:
        config.apiKey ||
        process.env.OPENROUTER_API_KEY?.trim() ||
        process.env.LLM_API_KEY?.trim() ||
        "",
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

// ─── Anthropic helpers ────────────────────────────────────────────────

/**
 * The Anthropic SDK's baseURL is the API *root*; it appends `/v1/messages`
 * itself. A configured `https://api.anthropic.com/v1` therefore produced
 * `/v1/v1/messages` → 404 not_found_error on every call. Strip a trailing
 * `/v1` (and slashes) so both forms work. Returns undefined for "use default".
 */
export function normalizeAnthropicBaseUrl(url?: string | null): string | undefined {
  const trimmed = url?.trim().replace(/\/+$/, "");
  if (!trimmed) return undefined;
  return trimmed.replace(/\/v1$/i, "");
}

/**
 * Sampling parameters (`temperature`/`top_p`/`top_k`) are rejected with a 400
 * on Claude Sonnet 5, Opus 5 / 5.5, Opus 4.7 / 4.8, and Fable. Only send them
 * to the older families known to accept them; unknown (newer) models get none.
 */
export function anthropicAcceptsTemperature(model: string): boolean {
  return /^claude-(3[-.]|haiku-4-5|sonnet-4-[56]|opus-4-[156]|(sonnet|opus)-4-20\d{6})/.test(
    model,
  );
}

/**
 * Concatenate the text blocks of a Messages response. Current models think by
 * default, so content[0] is often a `thinking` block — reading only the first
 * block returned "{}" even when the model answered.
 */
export function anthropicResponseText(
  content: ReadonlyArray<{ type: string; text?: string }>,
): string {
  return content
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("");
}

// Thinking tokens count toward max_tokens on models that think by default, so
// a small ceiling can be consumed before any JSON is written. Raising the
// ceiling costs nothing (billing is on tokens actually generated).
const ANTHROPIC_MIN_MAX_TOKENS = 16000;

// ─── Unified Client Type ──────────────────────────────────────────────

export type LlmClient =
  | { type: "ollama"; client: Ollama; model: string }
  | { type: "anthropic"; client: Anthropic; model: string }
  | { type: "openrouter"; client: OpenAI; model: string }
  | { type: "azure"; client: OpenAI; model: string }
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
    const baseURL = normalizeAnthropicBaseUrl(config.baseUrl);
    return {
      type: "anthropic",
      client: new Anthropic({
        apiKey: config.apiKey || "",
        ...(baseURL ? { baseURL } : {}),
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

  // Azure AI Foundry: OpenAI-compatible endpoint (…/services.ai.azure.com/
  // openai/v1) with Bearer auth, hosting a heterogeneous model catalog
  // (gpt, grok, glm, qwen, kimi, …). Kept separate from the classic "azure"
  // (Azure OpenAI) option, which uses a different URL/protocol, so neither
  // changes the other.
  if (provider === "azure-foundry" || provider === "azure_foundry") {
    return {
      type: "azure",
      client: createOpenAIClient(config),
      model: config.model,
    };
  }

  // OpenAI, classic Azure OpenAI, vLLM, and any OpenAI-compatible provider
  return {
    type: "openai",
    client: createOpenAIClient(config),
    model: config.model,
  };
}

/**
 * Chat call tolerant of Azure AI Foundry's heterogeneous model catalog.
 *
 * Foundry serves many model families behind one OpenAI-compatible endpoint and
 * they disagree on parameters, so a single fixed request 400s on some of them.
 * Send the modern parameters and, on a parameter error, adapt and retry rather
 * than failing the scan:
 *   - max_completion_tokens ↔ max_tokens — newer models (gpt-6, o-series) reject
 *     the old name; some third-party models reject the new one.
 *   - drop temperature — reasoning models allow only the default.
 * JSON is enforced through the prompt, not response_format, because not every
 * Foundry-hosted model supports response_format.
 *
 * `create` is injected so the retry logic is unit-testable without a network.
 */
export async function foundryChat(
  create: (params: Record<string, unknown>) => Promise<{
    choices?: Array<{ message?: { content?: string | null } }>;
  }>,
  args: {
    model: string;
    system: string;
    user: string;
    maxTokens: number;
    temperature: number;
  },
): Promise<string> {
  const messages = [
    {
      role: "system",
      content: `${args.system}\n\nIMPORTANT: respond with valid JSON only. No markdown, no code fences, no prose.`,
    },
    { role: "user", content: args.user },
  ];
  let params: Record<string, unknown> = {
    model: args.model,
    messages,
    max_completion_tokens: args.maxTokens,
    temperature: args.temperature,
  };

  // At most one retry per adaptable parameter.
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await create(params);
      return res.choices?.[0]?.message?.content || "{}";
    } catch (err) {
      const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
      if (
        "max_completion_tokens" in params &&
        /max_tokens/.test(msg) &&
        /unsupported|unknown|not supported|unrecognized|use ['"]?max_tokens|instead/.test(msg)
      ) {
        const { max_completion_tokens, ...rest } = params;
        params = { ...rest, max_tokens: max_completion_tokens };
        continue;
      }
      if ("max_tokens" in params && /max_completion_tokens/.test(msg)) {
        const { max_tokens, ...rest } = params;
        params = { ...rest, max_completion_tokens: max_tokens };
        continue;
      }
      if ("temperature" in params && /temperature/.test(msg)) {
        const { temperature, ...rest } = params;
        params = rest;
        continue;
      }
      // Any other error degrades to "{}" like the other provider paths.
      return "{}";
    }
  }
  return "{}";
}

// ─── Secret masking ───────────────────────────────────────────────────

/**
 * Mask secrets in a prompt before it leaves the process. Pass a session to
 * keep tokens consistent across calls or to restore values in the answer
 * (code-fix flows); otherwise each call masks on its own and the answer keeps
 * the tokens.
 */
function maskPrompt(
  system: string,
  contents: string[],
  session: RedactionSession | undefined,
): { system: string; contents: string[] } {
  if (!llmMaskingEnabled()) return { system, contents };
  const s = session ?? createRedactionSession();
  const before = s.count;
  const maskedSystem = s.redact(system);
  const maskedContents = contents.map((c) => s.redact(c));
  const masked = s.count > before || /\[\[SECRET_\d+/.test(maskedContents.join("\n"));
  return {
    system: masked ? `${maskedSystem}\n\n${MASKED_SECRETS_NOTE}` : maskedSystem,
    contents: maskedContents,
  };
}

// ─── Unified Analysis Function ────────────────────────────────────────

export async function analyzeWithLlm(
  llmClient: LlmClient,
  model: string,
  rawSystemPrompt: string,
  rawUserContent: string,
  options?: {
    temperature?: number;
    maxTokens?: number;
    /** Share or restore masked secrets (see maskPrompt). */
    redaction?: RedactionSession;
  },
): Promise<string> {
  const temperature = options?.temperature ?? 0.1;
  const {
    system: systemPrompt,
    contents: [userContent],
  } = maskPrompt(rawSystemPrompt, [rawUserContent], options?.redaction);

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
    const useModel = model || llmClient.model;
    try {
      const response = await llmClient.client.messages.create({
        model: useModel,
        system: systemPrompt,
        messages: [{ role: "user", content: userContent }],
        ...(anthropicAcceptsTemperature(useModel) ? { temperature } : {}),
        max_tokens: Math.max(options?.maxTokens ?? 0, ANTHROPIC_MIN_MAX_TOKENS),
      });
      if (response.stop_reason === "refusal" || response.stop_reason === "max_tokens") {
        logger.warn(
          {
            model: useModel,
            stopReason: response.stop_reason,
            stopDetails: response.stop_details ?? undefined,
          },
          "Anthropic response did not complete normally",
        );
      }
      return anthropicResponseText(response.content) || "{}";
    } catch (err) {
      // Degrade to "{}" like the other providers, but never silently — a bad
      // model ID, base URL, or key must be visible in the worker logs.
      if (err instanceof Anthropic.APIError) {
        logger.warn(
          { model: useModel, status: err.status, error: err.message },
          "Anthropic API call failed",
        );
      } else {
        logger.warn({ model: useModel, err }, "Anthropic call failed");
      }
      return "{}";
    }
  }

  // Azure AI Foundry path — tolerant of its heterogeneous model catalog.
  if (llmClient.type === "azure") {
    return foundryChat(
      (params) => llmClient.client.chat.completions.create(params as never),
      {
        model: model || llmClient.model,
        system: systemPrompt,
        user: userContent,
        maxTokens: options?.maxTokens ?? 8192,
        temperature,
      },
    );
  }

  // OpenRouter path — many models don't support response_format, so we
  // enforce JSON via the prompt and parse the response manually.
  if (llmClient.type === "openrouter") {
    const useModel = model || llmClient.model;
    try {
      const jsonSystemPrompt = `${systemPrompt}\n\nIMPORTANT: You MUST respond with valid JSON only. No markdown, no explanation, no code fences — just raw JSON.`;
      const response = await llmClient.client.chat.completions.create({
        model: useModel,
        messages: [
          { role: "system", content: jsonSystemPrompt },
          { role: "user", content: userContent },
        ],
        temperature,
        max_tokens: options?.maxTokens ?? 8192,
      });
      return response.choices[0]?.message?.content || "{}";
    } catch (err) {
      // Degrade to "{}" like the other providers, but log: a bad key, base URL,
      // model slug (e.g. a missing vendor prefix), or credit balance must be
      // visible in the worker logs instead of silently producing 0 findings.
      const status = (err as { status?: number })?.status;
      logger.warn(
        { model: useModel, status, err: err instanceof Error ? err.message : err },
        "OpenRouter API call failed",
      );
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
  rawMessages: ChatMessage[],
  options?: { temperature?: number; maxTokens?: number; redaction?: RedactionSession },
): AsyncGenerator<string> {
  const temperature = options?.temperature ?? 0.7;
  const maxTokens = options?.maxTokens ?? 2048;
  const systemIdx = rawMessages.findIndex((m) => m.role === "system");
  const masked = maskPrompt(
    systemIdx >= 0 ? rawMessages[systemIdx].content : "",
    rawMessages.map((m, i) => (i === systemIdx ? "" : m.content)),
    options?.redaction,
  );
  const messages: ChatMessage[] = rawMessages.map((m, i) => ({
    ...m,
    content: i === systemIdx ? masked.system : masked.contents[i],
  }));
  if (systemIdx < 0 && masked.system) messages.unshift({ role: "system", content: masked.system.trim() });

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
      ...(anthropicAcceptsTemperature(llmClient.model) ? { temperature } : {}),
      // Streaming has no HTTP-timeout concern; leave room for default thinking.
      max_tokens: Math.max(maxTokens, ANTHROPIC_MIN_MAX_TOKENS),
    });
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        yield event.delta.text;
      }
    }
    return;
  }

  // OpenAI-compatible (openai + openrouter + azure foundry).
  // Foundry's newer models use max_completion_tokens; older ones and the other
  // providers use max_tokens. Send both is invalid, so pick by client type.
  const tokenParam =
    llmClient.type === "azure"
      ? { max_completion_tokens: maxTokens }
      : { max_tokens: maxTokens };
  const stream = await llmClient.client.chat.completions.create({
    model: llmClient.model,
    messages,
    temperature,
    ...tokenParam,
    stream: true,
  });
  for await (const chunk of stream) {
    const text = chunk.choices[0]?.delta?.content;
    if (text) yield text;
  }
}

// ─── JSON Response Parser ─────────────────────────────────────────────

/**
 * Every complete object of the response's "findings" array, from a response
 * that was cut off (output budget exhausted, often by a reasoning model's
 * hidden reasoning). Walks the text tracking strings and nesting, so a cut
 * inside a finding loses only that finding, not the ones before it.
 */
export function recoverCompleteFindings(text: string): unknown[] | null {
  const key = text.indexOf('"findings"');
  if (key < 0) return null;
  const open = text.indexOf("[", key);
  if (open < 0) return null;
  const items: unknown[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = open + 1; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{" || ch === "[") {
      if (depth === 0 && ch === "{") start = i;
      depth++;
    } else if (ch === "}" || ch === "]") {
      if (depth === 0) break; // end of the findings array
      depth--;
      if (depth === 0 && ch === "}" && start >= 0) {
        try {
          items.push(JSON.parse(text.slice(start, i + 1)));
        } catch {
          /* skip a malformed item */
        }
        start = -1;
      }
    }
  }
  return items;
}

export type LlmJsonParse<T> = { value: T; status: "ok" | "recovered" | "failed" };

/**
 * Parse a model's JSON answer and say how complete it was: "recovered" means
 * the answer was cut off and only its complete findings were kept; "failed"
 * means nothing could be read and `fallback` was returned.
 */
export function parseLlmJsonResponseDetailed<T>(raw: string, fallback: T): LlmJsonParse<T> {
  let cleaned = (raw || "").trim();
  if (cleaned.startsWith("```json")) cleaned = cleaned.slice(7);
  else if (cleaned.startsWith("```")) cleaned = cleaned.slice(3);
  if (cleaned.endsWith("```")) cleaned = cleaned.slice(0, -3);
  cleaned = cleaned.trim();
  try {
    return { value: JSON.parse(cleaned) as T, status: "ok" };
  } catch (err) {
    const items = recoverCompleteFindings(cleaned);
    if (items && items.length > 0) {
      logger.warn(
        { recovered: items.length, rawLength: raw?.length },
        "parseLlmJsonResponse: answer was cut off; kept the complete findings",
      );
      return { value: { findings: items } as T, status: "recovered" };
    }
    logger.warn(
      { err, rawLength: raw?.length, rawPrefix: raw?.slice(0, 120) },
      "parseLlmJsonResponse: failed to parse LLM JSON response — returning fallback",
    );
    return { value: fallback, status: "failed" };
  }
}

export function parseLlmJsonResponse<T>(raw: string, fallback: T): T {
  let cleaned = (raw || "").trim();
  try {
    // Handle cases where LLM wraps JSON in markdown code blocks
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
    // Truncated response (e.g. max_tokens cutoff): keep every complete finding.
    const items = recoverCompleteFindings(cleaned);
    if (items && items.length > 0) {
      logger.warn({ recovered: items.length, rawLength: raw?.length }, "parseLlmJsonResponse: answer was cut off; kept the complete findings");
      return { findings: items } as T;
    }
    if (cleaned.includes('"findings"')) {
      const lastObjEnd = cleaned.lastIndexOf("}");
      if (lastObjEnd !== -1) {
        const candidate = cleaned.slice(0, lastObjEnd + 1).trim();
        for (const suffix of ["]}", "}", "\n]}", "\n}"]) {
          try {
            const recovered = JSON.parse(candidate + suffix) as T;
            logger.info("parseLlmJsonResponse: successfully recovered truncated JSON array");
            return recovered;
          } catch {}
        }
      }
    }

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
