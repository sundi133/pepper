import { beforeEach, describe, expect, it, vi } from "vitest";

const chatCreate = vi.fn();
const messagesCreate = vi.fn();
let type = "openrouter";
vi.mock("@/lib/llm-gateway", () => ({
  createLlmClient: () =>
    type === "anthropic"
      ? { type, model: "m", client: { messages: { create: messagesCreate } } }
      : { type, model: "m", client: { chat: { completions: { create: chatCreate } } } },
}));

import { aiUnavailableNote, checkLlmAvailable } from "./llm-preflight";

const cfg = { provider: "openrouter", baseUrl: "", apiKey: "k", model: "moonshotai/kimi-k3" };
const apiError = (status: number, message: string) => Object.assign(new Error(message), { status });

beforeEach(() => {
  vi.clearAllMocks();
  type = "openrouter";
});

describe("checkLlmAvailable", () => {
  it("passes when the model answers", async () => {
    chatCreate.mockResolvedValue({ choices: [] });
    expect(await checkLlmAvailable(cfg)).toEqual({ ok: true });
    // Same output budget as a scan request, or OpenRouter would accept it while refusing real ones.
    expect(chatCreate.mock.calls[0][0]).toMatchObject({ model: "moonshotai/kimi-k3", max_tokens: 8192 });
  });

  it("reports no credit, a rejected key, a forbidden or unknown model", async () => {
    for (const [status, message, words] of [
      [402, "Insufficient credits. Add more using https://openrouter.ai/settings/credits", "no credit"],
      [401, "No auth credentials found", "key was rejected"],
      [403, "Key not permitted for this model", "not allowed"],
      [404, "No endpoints found for moonshotai/kimi-k9", "not found"],
    ] as const) {
      chatCreate.mockRejectedValueOnce(apiError(status, message));
      const r = await checkLlmAvailable(cfg);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.status).toBe(status);
        expect(r.reason).toContain(words);
      }
    }
  });

  it("does not report rate limits, server errors or timeouts", async () => {
    for (const err of [apiError(429, "slow down"), apiError(503, "busy"), new Error("timeout")]) {
      chatCreate.mockRejectedValueOnce(err);
      expect(await checkLlmAvailable(cfg)).toEqual({ ok: true });
    }
  });

  it("recognises an empty account however the provider reports it, and skips local Ollama", async () => {
    type = "anthropic";
    messagesCreate.mockRejectedValueOnce(apiError(400, "Your credit balance is too low to access the Anthropic API."));
    const r = await checkLlmAvailable(cfg);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("no credit");
    messagesCreate.mockRejectedValueOnce(apiError(400, "max_tokens: invalid"));
    expect(await checkLlmAvailable(cfg)).toEqual({ ok: true }); // other 400s are not about the account
    type = "openai";
    chatCreate.mockRejectedValueOnce(apiError(429, "You exceeded your current quota: insufficient_quota"));
    expect((await checkLlmAvailable(cfg)).ok).toBe(false);
    type = "ollama";
    expect(await checkLlmAvailable(cfg)).toEqual({ ok: true });
  });

  it("explains what the scan is missing", () => {
    expect(aiUnavailableNote("openrouter", "moonshotai/kimi-k3", "the account has no credit left (402)")).toMatch(
      /AI analysis did not run: openrouter refused requests to moonshotai\/kimi-k3 because the account has no credit left.*Only rule-based findings/,
    );
  });
});
