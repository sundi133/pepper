/**
 * Dedicated GLM-via-OpenRouter review call for the mobile scanner (chosen over
 * the shared LLM gateway so the mobile pipeline matches the validated prototype
 * and can be tuned independently). Reuses the OpenAI SDK (already a dependency)
 * pointed at OpenRouter's OpenAI-compatible endpoint.
 */
import OpenAI from "openai";
import { MOBILE_REVIEW_SYSTEM } from "./prompt";

export interface MobileReviewConfig {
  apiKey: string;
  model: string;
  baseUrl: string;
}

/** Reads config from the environment; returns null when no key is set (scanner then no-ops). */
export function mobileReviewConfigFromEnv(): MobileReviewConfig | null {
  const apiKey = process.env.OPENROUTER_API_KEY?.trim();
  if (!apiKey) return null;
  return {
    apiKey,
    model: process.env.OPENROUTER_MOBILE_MODEL?.trim() || "z-ai/glm-5.3",
    baseUrl:
      process.env.OPENROUTER_BASE_URL?.trim() || "https://openrouter.ai/api/v1",
  };
}

export interface MobileReviewResult {
  /** The model's answer (JSON string to parse into findings). */
  content: string;
  /** The full streamed reasoning trace, for storage + developer display. */
  reasoning: string;
}

export interface MobileReviewOptions {
  signal?: AbortSignal;
  /** Called with each reasoning delta as it streams, for live display. */
  onReasoning?: (delta: string) => void;
}

/**
 * Streams the review from GLM, capturing both the answer and the reasoning
 * trace as they arrive. Parsing/validation of `content` is the caller's job
 * (reuses parseLlmJsonResponse).
 */
export async function reviewMobileBundle(
  bundle: string,
  cfg: MobileReviewConfig,
  opts: MobileReviewOptions = {},
): Promise<MobileReviewResult> {
  const client = new OpenAI({ apiKey: cfg.apiKey, baseURL: cfg.baseUrl });
  const params: OpenAI.Chat.Completions.ChatCompletionCreateParamsStreaming = {
    model: cfg.model,
    stream: true,
    messages: [
      { role: "system", content: MOBILE_REVIEW_SYSTEM },
      {
        role: "user",
        content:
          "Decoded and decompiled sources from an app I own are below. " +
          "Return the findings JSON per your instructions.\n\n" +
          bundle,
      },
    ],
  };
  // `reasoning` is an OpenRouter passthrough field, not in the OpenAI types.
  const stream = await client.chat.completions.create(
    { ...params, reasoning: { enabled: true, effort: "high" } } as typeof params,
    { signal: opts.signal },
  );

  let content = "";
  let reasoning = "";
  for await (const chunk of stream) {
    const delta = chunk.choices[0]?.delta as
      | { content?: string; reasoning?: string; reasoning_details?: unknown }
      | undefined;
    if (!delta) continue;
    if (delta.content) content += delta.content;
    let r = typeof delta.reasoning === "string" ? delta.reasoning : "";
    if (!r && Array.isArray(delta.reasoning_details)) {
      r = delta.reasoning_details
        .map((d) =>
          d && typeof d === "object"
            ? ((d as Record<string, unknown>).text as string) ||
              ((d as Record<string, unknown>).summary as string) ||
              ""
            : "",
        )
        .join("");
    }
    if (r) {
      reasoning += r;
      opts.onReasoning?.(r);
    }
  }
  return { content, reasoning };
}
