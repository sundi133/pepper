import { createLlmClient, type LlmConfig } from "@/lib/llm-gateway";
import { LLM_MAX_RESPONSE_TOKENS } from "@/lib/constants";

export type LlmPreflight = { ok: true } | { ok: false; status?: number; reason: string };

/** Refusals that fail every request until someone changes the settings or the account. */
const BLOCKING_STATUS: Record<number, string> = {
  401: "the API key was rejected",
  402: "the account has no credit left",
  403: "the API key is not allowed to use this model",
  404: "the model or endpoint was not found",
};

/**
 * One tiny request to the configured model before a scan's AI passes run.
 * The AI gateway turns a refused request into an empty answer (so a scanner
 * never crashes), which also makes "no credit" look exactly like "no
 * findings". This tells the two apart: a provider that refuses outright is
 * reported so the scan can say its AI analysis did not run. Rate limits,
 * server errors and timeouts are transient and are not reported here.
 */
export async function checkLlmAvailable(config: LlmConfig): Promise<LlmPreflight> {
  const client = createLlmClient(config);
  if (client.type === "ollama") return { ok: true }; // local model: no account to run out of
  const model = config.model || client.model;
  const signal = AbortSignal.timeout(30_000);
  // Ask for the same output budget as a scan request: providers such as
  // OpenRouter refuse a request when the balance can't cover its maximum cost,
  // so a 1-token probe would pass while every real request is refused. The
  // model is told to answer in one word, so the call itself costs next to nothing.
  const maxTokens = LLM_MAX_RESPONSE_TOKENS;
  const messages = [{ role: "user" as const, content: "Reply with the single word OK." }];
  try {
    if (client.type === "anthropic") {
      await client.client.messages.create(
        { model, max_tokens: Math.max(maxTokens, 16000), messages },
        { signal },
      );
    } else {
      await client.client.chat.completions.create(
        { model, max_tokens: maxTokens, messages },
        { signal },
      );
    }
    return { ok: true };
  } catch (err) {
    const status = (err as { status?: number })?.status;
    const message = err instanceof Error ? err.message : String(err);
    // Anthropic reports an empty balance as 400, OpenAI as 429 insufficient_quota.
    if (/credit balance|insufficient[_ ](?:credits|quota|funds)|billing/i.test(message)) {
      return { ok: false, status, reason: `the account has no credit left (${status ?? "error"}: ${message.slice(0, 200)})` };
    }
    if (status && BLOCKING_STATUS[status]) {
      return { ok: false, status, reason: `${BLOCKING_STATUS[status]} (${status}: ${message.slice(0, 200)})` };
    }
    return { ok: true };
  }
}

/** The note stored on a scan whose AI analysis could not run. */
export function aiUnavailableNote(provider: string, model: string, reason: string): string {
  return (
    `AI analysis did not run: ${provider} refused requests to ${model} because ${reason}. ` +
    "Only rule-based findings (patterns, secrets, dependencies, IaC, containers) are included. " +
    "Fix the provider account or key under LLM Config, then rescan."
  );
}
