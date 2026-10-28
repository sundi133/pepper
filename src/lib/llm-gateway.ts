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

/**
 * When a model rejects a chat parameter, adapt the params and return a new set
 * to retry with; return null when the error isn't one we can adapt. Reasoning
 * models (o-series, gpt-6 / astra) require `max_completion_tokens` instead of
 * `max_tokens`, allow only the default temperature, and some reject
 * `response_format`. Mirrors the retry logic in foundryChat so every
 * OpenAI-SDK path tolerates these models.
 */
function adaptChatParamsForError<T extends Record<string, unknown>>(
  params: T,
  err: unknown,
): T | null {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if ("max_tokens" in params && /max_completion_tokens/.test(msg)) {
    const { max_tokens, ...rest } = params as Record<string, unknown>;
    return { ...rest, max_completion_tokens: max_tokens } as unknown as T;
  }
  if (
    "max_completion_tokens" in params &&
    /max_tokens/.test(msg) &&
    /unsupported|unknown|not supported|unrecognized|instead/.test(msg)
  ) {
    const { max_completion_tokens, ...rest } = params as Record<string, unknown>;
    return { ...rest, max_tokens: max_completion_tokens } as unknown as T;
  }
  if ("temperature" in params && /temperature/.test(msg)) {
    const { temperature, ...rest } = params as Record<string, unknown>;
    return rest as unknown as T;
  }
  if ("response_format" in params && /response_format/.test(msg)) {
    const { response_format, ...rest } = params as Record<string, unknown>;
    return rest as unknown as T;
  }
  return null;
}

/**
 * Streams an OpenAI-compatible chat call, accumulating the answer and feeding
 * reasoning-token deltas to onReasoning. Reasoning only fires when the model
 * actually emits it (delta.reasoning / reasoning_details), so a non-reasoning
 * model just returns its content. Adapts params for reasoning models that
 * reject max_tokens/temperature, then throws on any other transport error so
 * the caller can fall back to the normal non-streaming request.
 */
async function streamChatCaptureReasoning(
  client: OpenAI,
  params: OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming,
  onReasoning: (delta: string) => void,
): Promise<string> {
  let attemptParams: Record<string, unknown> = { ...params };
  let stream: AsyncIterable<OpenAI.Chat.Completions.ChatCompletionChunk>;
  for (let attempt = 0; ; attempt++) {
    try {
      stream = (await client.chat.completions.create({
        ...attemptParams,
        stream: true,
      } as OpenAI.Chat.Completions.ChatCompletionCreateParamsStreaming)) as unknown as AsyncIterable<OpenAI.Chat.Completions.ChatCompletionChunk>;
      break;
    } catch (err) {
      const adapted = attempt < 3 ? adaptChatParamsForError(attemptParams, err) : null;
      if (!adapted) throw err;
      attemptParams = adapted;
    }
  }
  let content = "";
  for await (const chunk of stream) {
    const delta = chunk.choices?.[0]?.delta as
      | { content?: string; reasoning?: string; reasoning_details?: unknown }
      | undefined;
    if (!delta) continue;
    if (delta.content) content += delta.content;
    let r = typeof delta.reasoning === "string" ? delta.reasoning : "";
    if (!r && Array.isArray(delta.reasoning_details)) {
      r = (delta.reasoning_details as unknown[])
        .map((d) =>
          d && typeof d === "object"
            ? ((d as Record<string, unknown>).text as string) ||
              ((d as Record<string, unknown>).summary as string) ||
              ""
            : "",
        )
        .join("");
    }
    if (r) onReasoning(r);
  }
  return content;
}

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
    /**
     * Called with reasoning-token deltas as they stream, when the chosen model
     * emits them. Opt-in: only the OpenAI-SDK paths (OpenRouter / OpenAI-
     * compatible) honor it, and only by switching to a streamed request that
     * falls back to the normal call on any error — so a non-reasoning model (or
     * a provider that can't stream) is never affected, and this is simply never
     * called when no reasoning tokens arrive.
     */
    onReasoning?: (delta: string) => void;
  },
): Promise<string> {
  const temperature = options?.temperature ?? 0.1;
  const {
    system: systemPrompt,
    contents: [userContent],
  } = maskPrompt(rawSystemPrompt, [rawUserContent], options?.redaction);

  if (llmClient.type === "ollama") {
    const useModel = model || llmClient.model;
    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent },
    ];
    const ollamaOptions = {
      temperature,
      num_predict: options?.maxTokens ?? 8192,
    };
    // Opt-in reasoning: ask the model to think and stream, capturing
    // `message.thinking` deltas. Any error (the model can't think or can't
    // stream) falls back to the normal non-streaming JSON call below, so a
    // non-reasoning model is never affected and this is inert without onReasoning.
    if (options?.onReasoning) {
      try {
        const stream = await llmClient.client.chat({
          model: useModel,
          messages,
          format: "json",
          think: true,
          stream: true,
          options: ollamaOptions,
        });
        let content = "";
        for await (const part of stream) {
          if (part.message?.thinking) options.onReasoning(part.message.thinking);
          if (part.message?.content) content += part.message.content;
        }
        return content || "{}";
      } catch (err) {
        logger.warn(
          { model: useModel, err: err instanceof Error ? err.message : err },
          "Ollama reasoning stream failed; using non-streaming call",
        );
      }
    }
    const response = await llmClient.client.chat({
      model: useModel,
      messages,
      format: "json",
      options: ollamaOptions,
    });
    return response.message?.content || "{}";
  }

  // Anthropic path — uses native Messages API
  if (llmClient.type === "anthropic") {
    const useModel = model || llmClient.model;
    // Opt-in extended thinking: stream `thinking_delta`s to onReasoning. This
    // changes cost (thinking tokens are billed) and forces temperature to its
    // default (thinking requires temperature 1), so it only ever runs when a
    // caller asked for reasoning. Any error falls back to the normal
    // non-streaming call below, leaving the default (non-thinking) path exactly
    // as it was.
    if (options?.onReasoning) {
      try {
        const answerBudget = Math.max(options?.maxTokens ?? 0, ANTHROPIC_MIN_MAX_TOKENS);
        const thinkingBudget = Math.max(1024, Math.floor(answerBudget / 2));
        let content = "";
        const stream = llmClient.client.messages.stream({
          model: useModel,
          system: systemPrompt,
          messages: [{ role: "user", content: userContent }],
          // Omit temperature: thinking requires the default (1), and newer
          // models reject any sampling parameter outright.
          max_tokens: answerBudget + thinkingBudget,
          thinking: { type: "enabled", budget_tokens: thinkingBudget },
        });
        for await (const event of stream) {
          if (event.type === "content_block_delta") {
            if (event.delta.type === "thinking_delta") {
              options.onReasoning(event.delta.thinking);
            } else if (event.delta.type === "text_delta") {
              content += event.delta.text;
            }
          }
        }
        return content || "{}";
      } catch (err) {
        if (err instanceof Anthropic.APIError) {
          logger.warn(
            { model: useModel, status: err.status, error: err.message },
            "Anthropic reasoning stream failed; using non-streaming call",
          );
        } else {
          logger.warn({ model: useModel, err }, "Anthropic reasoning stream failed; using non-streaming call");
        }
      }
    }
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
    const useModel = model || llmClient.model;
    // Best-effort opt-in reasoning: try a streamed call that captures reasoning
    // deltas (the same delta.reasoning / reasoning_details shape as OpenRouter).
    // On any error — a model that won't stream, or rejects max_tokens — fall
    // back to the tolerant non-streaming foundryChat, so default behavior and
    // Foundry's parameter negotiation are unchanged.
    if (options?.onReasoning) {
      try {
        const params = {
          model: useModel,
          messages: [
            {
              role: "system",
              content: `${systemPrompt}\n\nIMPORTANT: respond with valid JSON only. No markdown, no code fences, no prose.`,
            },
            { role: "user", content: userContent },
          ],
          max_tokens: options?.maxTokens ?? 8192,
          temperature,
        } satisfies OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming;
        const content = await streamChatCaptureReasoning(
          llmClient.client,
          params,
          options.onReasoning,
        );
        return content || "{}";
      } catch (err) {
        logger.warn(
          { model: useModel, err: err instanceof Error ? err.message : err },
          "Azure Foundry reasoning stream failed; using foundryChat",
        );
      }
    }
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
      const params = {
        model: useModel,
        messages: [
          { role: "system", content: jsonSystemPrompt },
          { role: "user", content: userContent },
        ],
        temperature,
        max_tokens: options?.maxTokens ?? 8192,
      } satisfies OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming;
      // When we capture reasoning, run reasoning models (e.g. glm-5.3) at high
      // effort. `reasoning` is an OpenRouter passthrough field; non-reasoning
      // models ignore it, so default behavior is unchanged.
      const callParams = options?.onReasoning
        ? ({ ...params, reasoning: { enabled: true, effort: "high" } } as typeof params)
        : params;
      if (options?.onReasoning) {
        try {
          const content = await streamChatCaptureReasoning(
            llmClient.client,
            callParams,
            options.onReasoning,
          );
          return content || "{}";
        } catch (err) {
          // Streaming/reasoning unsupported for this model — fall back to the
          // normal call below so a non-reasoning model is never broken.
          logger.warn(
            { model: useModel, err: err instanceof Error ? err.message : err },
            "OpenRouter reasoning stream failed; using non-streaming call",
          );
        }
      }
      let attemptParams: OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming =
        callParams;
      for (let attempt = 0; attempt < 4; attempt++) {
        try {
          const response = await llmClient.client.chat.completions.create(attemptParams);
          return response.choices[0]?.message?.content || "{}";
        } catch (err) {
          const adapted = adaptChatParamsForError(
            attemptParams as unknown as Record<string, unknown>,
            err,
          );
          if (!adapted) throw err; // outer catch logs + returns "{}"
          attemptParams =
            adapted as unknown as OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming;
        }
      }
      return "{}";
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
  const params = {
    model: model || llmClient.model,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent },
    ],
    temperature,
    max_tokens: options?.maxTokens ?? 8192,
    response_format: { type: "json_object" as const },
  } satisfies OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming;
  if (options?.onReasoning) {
    try {
      const content = await streamChatCaptureReasoning(
        llmClient.client,
        params,
        options.onReasoning,
      );
      return content || "{}";
    } catch {
      // Streaming/reasoning unsupported — fall through to the normal call so a
      // non-reasoning model (or endpoint) behaves exactly as before.
    }
  }
  // Retry loop so reasoning models (which reject max_tokens / temperature) are
  // adapted instead of silently degrading to "{}".
  let attemptParams: OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming =
    params;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const response = await llmClient.client.chat.completions.create(attemptParams);
      return response.choices[0]?.message?.content || "{}";
    } catch (err) {
      const adapted = adaptChatParamsForError(
        attemptParams as unknown as Record<string, unknown>,
        err,
      );
      if (!adapted) return "{}";
      attemptParams =
        adapted as unknown as OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming;
    }
  }
  return "{}";
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

/**
 * Make a model's almost-JSON object parseable: escape raw control characters
 * inside strings (models often emit literal newlines in Markdown values) and,
 * when the answer was cut off, drop the unfinished tail and close every open
 * string, array and object.
 */
export function repairJsonObject(text: string): string {
  let out = "";
  const stack: string[] = [];
  let inString = false;
  let escaped = false;
  // Last non-whitespace character outside strings, to tell a value string
  // (after ":" or inside an array) from a key.
  let lastSignificant = "";
  let stringIsValue = false;
  // Output length at the last point where everything before it is complete
  // values, so the tail can be dropped and the containers closed.
  let safeLength = -1;
  let safeStack: string[] = [];
  const markSafe = () => {
    safeLength = out.length;
    safeStack = [...stack];
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
        out += ch;
      } else if (ch === "\\") {
        escaped = true;
        out += ch;
      } else if (ch === '"') {
        inString = false;
        out += ch;
        lastSignificant = '"';
        if (stringIsValue) markSafe();
      } else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch < " ") out += `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`;
      else out += ch;
      continue;
    }
    out += ch;
    if (ch === '"') {
      inString = true;
      stringIsValue = lastSignificant === ":" || stack[stack.length - 1] === "[";
    } else if (ch === "{" || ch === "[") {
      stack.push(ch);
    } else if (ch === "}" || ch === "]") {
      stack.pop();
      markSafe();
      if (stack.length === 0) return out;
    } else if (/[0-9a-z.]/i.test(ch) && /^[,}\]\s]$/.test(text[i + 1] ?? "")) {
      // Last character of a complete number / true / false / null.
      markSafe();
    }
    if (!/\s/.test(ch)) lastSignificant = ch;
  }

  if (stack.length === 0 && !inString) return out;
  // Cut off: keep everything up to the last complete value, then close.
  if (safeLength < 0) return out;
  let repaired = out.slice(0, safeLength).replace(/,\s*$/, "");
  for (let i = safeStack.length - 1; i >= 0; i--) {
    repaired += safeStack[i] === "{" ? "}" : "]";
  }
  return repaired;
}

/**
 * Parse a model's answer that must be ONE JSON object (not a findings list).
 * Strips code fences and prose around it, then repairs raw newlines and a
 * cut-off ending. Null when no object can be recovered.
 */
export function parseLlmJsonObject<T extends object>(
  raw: string,
): { value: T; status: "ok" | "recovered" } | null {
  const text = (raw || "").trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = text.indexOf("{");
  if (start < 0) return null;
  const body = text.slice(start);
  try {
    const parsed = JSON.parse(body.slice(0, body.lastIndexOf("}") + 1));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return { value: parsed as T, status: "ok" };
    }
  } catch {
    /* fall through to repair */
  }
  try {
    const parsed = JSON.parse(repairJsonObject(body));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return { value: parsed as T, status: "recovered" };
    }
  } catch {
    /* unrecoverable */
  }
  return null;
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
