import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// config reads the ENABLE_/timeout/steps constants (which snapshot process.env
// at import time), so each case resets modules and re-imports with env set.
const SAVED = { ...process.env };

async function loadConfig() {
  vi.resetModules();
  return import("./config");
}

const ORG_OPENROUTER = {
  llmProvider: "openrouter",
  llmBaseUrl: "https://openrouter.ai/api/v1",
  llmApiKey: "sk-or-ORG",
};

beforeEach(() => {
  for (const k of [
    "ENABLE_AGENT_SCAN",
    "ENABLE_MOBILE_AGENT_SCAN",
    "OPENROUTER_API_KEY",
    "OPENROUTER_BASE_URL",
    "E2B_API_KEY",
    "OPENROUTER_MOBILE_MODEL",
    "AGENT_SCAN_MAX_STEPS",
    "MOBILE_AGENT_MAX_STEPS",
    "AGENT_SCAN_TIMEOUT_MINUTES",
    "MOBILE_AGENT_TIMEOUT_MINUTES",
    "WEB_SEARCH_API_KEY",
    "WEB_SEARCH_PROVIDER",
  ]) {
    delete process.env[k];
  }
});

afterEach(() => {
  process.env = { ...SAVED };
});

describe("agentScanConfig", () => {
  it("returns null when the mode is off (even with keys)", async () => {
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    const { agentScanConfig } = await loadConfig();
    expect(agentScanConfig(ORG_OPENROUTER)).toBeNull();
  });

  it("returns null when enabled but the E2B key is missing", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.OPENROUTER_API_KEY = "sk-or"; // no E2B key
    const { agentScanConfig } = await loadConfig();
    expect(agentScanConfig(ORG_OPENROUTER)).toBeNull();
  });

  it("returns null when enabled with E2B but no OpenRouter key (org or env)", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    const { agentScanConfig } = await loadConfig();
    expect(agentScanConfig(undefined)).toBeNull();
    // org on a non-openrouter provider does not supply an OpenRouter key
    expect(agentScanConfig({ llmProvider: "openai", llmApiKey: "sk-openai" })).toBeNull();
  });

  it("PREFERS the org's OpenRouter key (LLM Config) over the env key", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_API_KEY = "sk-or-ENV";
    const { agentScanConfig } = await loadConfig();
    const c = agentScanConfig({
      llmProvider: "openrouter",
      llmBaseUrl: "https://proxy.example/api/v1",
      llmApiKey: "sk-or-ORG",
    });
    expect(c).not.toBeNull();
    expect(c!.openRouterApiKey).toBe("sk-or-ORG");
    expect(c!.baseUrl).toBe("https://proxy.example/api/v1");
    expect(c!.keySource).toBe("org");
    // the model is always the sandbox-driver model, never the org's llmModel
    expect(c!.model).toBe("z-ai/glm-5.3");
  });

  it("falls back to the env OpenRouter key when the org has none", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_API_KEY = "sk-or-ENV";
    const { agentScanConfig } = await loadConfig();
    const c = agentScanConfig({ llmProvider: "openai", llmApiKey: "sk-openai" });
    expect(c!.openRouterApiKey).toBe("sk-or-ENV");
    expect(c!.keySource).toBe("env");
    expect(c!.baseUrl).toBe("https://openrouter.ai/api/v1");
  });

  it("still honors the deprecated ENABLE_MOBILE_AGENT_SCAN alias and env-only helper", async () => {
    process.env.ENABLE_MOBILE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_API_KEY = "sk-or-ENV";
    const { agentScanConfigFromEnv } = await loadConfig();
    expect(agentScanConfigFromEnv()?.keySource).toBe("env");
  });

  it("honors step/timeout overrides (new + legacy env names)", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.MOBILE_AGENT_MAX_STEPS = "12"; // legacy still works
    process.env.AGENT_SCAN_TIMEOUT_MINUTES = "5";
    const { agentScanConfig } = await loadConfig();
    const c = agentScanConfig();
    expect(c!.maxSteps).toBe(12);
    expect(c!.sandboxTimeoutMs).toBe(5 * 60_000);
    expect(c!.cmdTimeoutMs).toBe(5 * 60_000);
  });
});

describe("agentScanUnavailableReason", () => {
  it("is null when the feature is off (stay quiet)", async () => {
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    const { agentScanUnavailableReason } = await loadConfig();
    expect(agentScanUnavailableReason(ORG_OPENROUTER)).toBeNull();
  });

  it("names the E2B key when enabled but E2B is missing", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    const { agentScanUnavailableReason } = await loadConfig();
    expect(agentScanUnavailableReason(ORG_OPENROUTER)).toContain("E2B_API_KEY");
  });

  it("names the OpenRouter key when enabled with E2B but no OpenRouter key", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    const { agentScanUnavailableReason } = await loadConfig();
    const reason = agentScanUnavailableReason(undefined);
    expect(reason).toContain("OpenRouter");
    expect(reason).toContain("LLM Config");
  });

  it("is null when the agent is fully available", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    const { agentScanUnavailableReason } = await loadConfig();
    expect(agentScanUnavailableReason(ORG_OPENROUTER)).toBeNull();
  });
});

describe("web search config (self-gated)", () => {
  it("is undefined when no WEB_SEARCH_API_KEY is set", async () => {
    const { webSearchConfigFromEnv } = await loadConfig();
    expect(webSearchConfigFromEnv()).toBeUndefined();
  });

  it("defaults to the tavily provider when a key is set", async () => {
    process.env.WEB_SEARCH_API_KEY = "ws-key";
    const { webSearchConfigFromEnv } = await loadConfig();
    expect(webSearchConfigFromEnv()).toEqual({ apiKey: "ws-key", provider: "tavily" });
  });

  it("honors WEB_SEARCH_PROVIDER=brave", async () => {
    process.env.WEB_SEARCH_API_KEY = "ws-key";
    process.env.WEB_SEARCH_PROVIDER = "brave";
    const { webSearchConfigFromEnv } = await loadConfig();
    expect(webSearchConfigFromEnv()?.provider).toBe("brave");
  });

  it("attaches web search to the agent config only when the key is present", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_API_KEY = "sk-or";
    let { agentScanConfig } = await loadConfig();
    expect(agentScanConfig()!.webSearch).toBeUndefined();

    process.env.WEB_SEARCH_API_KEY = "ws-key";
    ({ agentScanConfig } = await loadConfig());
    expect(agentScanConfig()!.webSearch).toEqual({ apiKey: "ws-key", provider: "tavily" });
  });
});
