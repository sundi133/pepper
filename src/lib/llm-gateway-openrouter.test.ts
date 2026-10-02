import { describe, it, expect, vi, afterEach } from "vitest";
import { createLlmClient, getLlmConfig } from "./llm-gateway";

/**
 * OpenRouter is an OpenAI-compatible provider with its own default base URL and
 * required attribution headers. These guards cover provider routing and the
 * instance-level env fallback (OPENROUTER_API_KEY / OPENROUTER_MODEL), which
 * .env.example and the docs promise.
 */
describe("OpenRouter integration", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("routes provider 'openrouter' to the openrouter client type", () => {
    const c = createLlmClient({
      provider: "openrouter",
      baseUrl: "",
      apiKey: "k",
      model: "m",
    });
    expect(c.type).toBe("openrouter");
  });

  it("defaults the base URL to openrouter.ai/api/v1", () => {
    const c = createLlmClient({
      provider: "openrouter",
      baseUrl: "",
      apiKey: "k",
      model: "m",
    });
    const baseURL = (c.client as unknown as { baseURL?: string }).baseURL || "";
    expect(baseURL).toContain("openrouter.ai/api/v1");
  });

  it("infers openrouter from OPENROUTER_API_KEY when no LLM_PROVIDER is set", () => {
    vi.stubEnv("LLM_PROVIDER", "");
    vi.stubEnv("LLM_BASE_URL", "");
    vi.stubEnv("LLM_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("LLM_MODEL", "");
    vi.stubEnv("OPENROUTER_MODEL", "");
    vi.stubEnv("OPENROUTER_API_KEY", "sk-or-test");

    const cfg = getLlmConfig(null);
    expect(cfg.provider).toBe("openrouter");
    expect(cfg.baseUrl).toBe("https://openrouter.ai/api/v1");
    expect(cfg.apiKey).toBe("sk-or-test");
    expect(cfg.model).toBe("google/gemini-2.5-flash");
  });

  it("honors OPENROUTER_MODEL for the default model", () => {
    vi.stubEnv("LLM_PROVIDER", "openrouter");
    vi.stubEnv("LLM_MODEL", "");
    vi.stubEnv("OPENROUTER_MODEL", "deepseek/deepseek-chat");

    expect(getLlmConfig(null).model).toBe("deepseek/deepseek-chat");
  });

  it("keeps the OpenAI default when only LLM_API_KEY is set", () => {
    vi.stubEnv("LLM_PROVIDER", "");
    vi.stubEnv("LLM_BASE_URL", "");
    vi.stubEnv("LLM_MODEL", "");
    vi.stubEnv("OPENROUTER_API_KEY", "");
    vi.stubEnv("LLM_API_KEY", "sk-openai");

    const cfg = getLlmConfig(null);
    expect(cfg.provider).toBe("openai");
    expect(cfg.baseUrl).toBe("https://api.openai.com/v1");
  });

  it("lets an explicit LLM_PROVIDER override the OpenRouter key inference", () => {
    vi.stubEnv("LLM_PROVIDER", "anthropic");
    vi.stubEnv("OPENROUTER_API_KEY", "sk-or-test");

    expect(getLlmConfig(null).provider).toBe("anthropic");
  });
});
