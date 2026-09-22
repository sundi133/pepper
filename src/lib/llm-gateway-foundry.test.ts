import { describe, it, expect, vi } from "vitest";
import { foundryChat, createLlmClient } from "./llm-gateway";

function ok(content: string) {
  return { choices: [{ message: { content } }] };
}

const args = {
  model: "grok-4.6",
  system: "You are a scanner.",
  user: "analyze this",
  maxTokens: 8192,
  temperature: 0.1,
};

describe("foundryChat parameter fallback", () => {
  it("returns content on the first successful call", async () => {
    const create = vi.fn().mockResolvedValue(ok('{"findings":[]}'));
    expect(await foundryChat(create, args)).toBe('{"findings":[]}');
    expect(create).toHaveBeenCalledTimes(1);
    // Sends the modern parameter first.
    expect(create.mock.calls[0][0]).toHaveProperty("max_completion_tokens", 8192);
  });

  it("swaps to max_tokens when the model rejects max_completion_tokens", async () => {
    // Some third-party Foundry models only accept the old name.
    const create = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("Unsupported parameter: 'max_completion_tokens'. Use 'max_tokens' instead."),
      )
      .mockResolvedValue(ok("{}"));

    await foundryChat(create, args);

    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1][0]).toHaveProperty("max_tokens", 8192);
    expect(create.mock.calls[1][0]).not.toHaveProperty("max_completion_tokens");
  });

  it("swaps to max_completion_tokens when the model rejects max_tokens", async () => {
    // The reverse: gpt-6/o-series reject max_tokens. Prime the retry by starting
    // from a max_tokens error, then a max_completion_tokens error is impossible,
    // so simulate a model that wants the new name after the old is sent.
    const create = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("Unsupported parameter: 'max_completion_tokens'. Use 'max_tokens'."),
      )
      .mockRejectedValueOnce(
        new Error("Unsupported value: 'max_tokens' is not supported; use 'max_completion_tokens'."),
      )
      .mockResolvedValue(ok("{}"));

    await foundryChat(create, args);

    // First sent max_completion_tokens → error → max_tokens → error → back.
    expect(create).toHaveBeenCalledTimes(3);
    expect(create.mock.calls[2][0]).toHaveProperty("max_completion_tokens");
  });

  it("drops temperature when the model only allows the default", async () => {
    const create = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("temperature does not support 0.1 with this model; only the default is allowed"),
      )
      .mockResolvedValue(ok("{}"));

    await foundryChat(create, args);

    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1][0]).not.toHaveProperty("temperature");
  });

  it("adapts more than one parameter in sequence", async () => {
    const create = vi
      .fn()
      .mockRejectedValueOnce(new Error("temperature is not supported"))
      .mockRejectedValueOnce(
        new Error("Unsupported parameter 'max_completion_tokens', use max_tokens instead"),
      )
      .mockResolvedValue(ok('{"ok":true}'));

    const out = await foundryChat(create, args);

    expect(out).toBe('{"ok":true}');
    const final = create.mock.calls[2][0];
    expect(final).not.toHaveProperty("temperature");
    expect(final).toHaveProperty("max_tokens");
  });

  it("degrades to {} on a non-parameter error, like the other provider paths", async () => {
    const create = vi.fn().mockRejectedValue(new Error("503 upstream unavailable"));
    expect(await foundryChat(create, args)).toBe("{}");
    // Not retried for a non-parameter error.
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("enforces JSON through the prompt, not response_format", async () => {
    const create = vi.fn().mockResolvedValue(ok("{}"));
    await foundryChat(create, args);
    const sent = create.mock.calls[0][0];
    expect(sent).not.toHaveProperty("response_format");
    const system = sent.messages[0];
    expect(system.role).toBe("system");
    expect(system.content).toMatch(/valid JSON only/i);
  });

  it("stops after a bounded number of retries", async () => {
    // Always erroring on temperature would loop; the loop is bounded.
    const create = vi.fn().mockRejectedValue(new Error("temperature not supported"));
    expect(await foundryChat(create, args)).toBe("{}");
    expect(create.mock.calls.length).toBeLessThanOrEqual(4);
  });
});

describe("createLlmClient dispatch", () => {
  it("routes azure-foundry to the azure client type", () => {
    const c = createLlmClient({
      provider: "azure-foundry",
      baseUrl: "https://r.services.ai.azure.com/openai/v1",
      apiKey: "k",
      model: "grok-4.6",
    });
    expect(c.type).toBe("azure");
  });

  it("accepts the underscore spelling too", () => {
    const c = createLlmClient({
      provider: "azure_foundry",
      baseUrl: "https://r.services.ai.azure.com/openai/v1",
      apiKey: "k",
      model: "x",
    });
    expect(c.type).toBe("azure");
  });

  // Regression guard: adding azure-foundry must not change existing routing.
  it("leaves the existing providers mapped as before", () => {
    const base = { baseUrl: "", apiKey: "k", model: "m" };
    expect(createLlmClient({ ...base, provider: "ollama" }).type).toBe("ollama");
    expect(createLlmClient({ ...base, provider: "anthropic" }).type).toBe("anthropic");
    expect(createLlmClient({ ...base, provider: "openrouter" }).type).toBe("openrouter");
    expect(createLlmClient({ ...base, provider: "openai" }).type).toBe("openai");
    // classic azure stays on the generic openai path, unchanged.
    expect(createLlmClient({ ...base, provider: "azure" }).type).toBe("openai");
    expect(createLlmClient({ ...base, provider: "vllm" }).type).toBe("openai");
  });
});
