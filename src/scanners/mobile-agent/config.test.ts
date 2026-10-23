import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// config reads the ENABLE_/timeout/steps constants (which snapshot process.env
// at import time), so each case resets modules and re-imports with env set.
const SAVED = { ...process.env };

async function loadConfig() {
  vi.resetModules();
  const mod = await import("./config");
  return mod.agentScanConfigFromEnv;
}

beforeEach(() => {
  for (const k of [
    "ENABLE_AGENT_SCAN",
    "ENABLE_MOBILE_AGENT_SCAN",
    "OPENROUTER_API_KEY",
    "E2B_API_KEY",
    "OPENROUTER_MOBILE_MODEL",
    "AGENT_SCAN_MAX_STEPS",
    "MOBILE_AGENT_MAX_STEPS",
    "AGENT_SCAN_TIMEOUT_MINUTES",
    "MOBILE_AGENT_TIMEOUT_MINUTES",
  ]) {
    delete process.env[k];
  }
});

afterEach(() => {
  process.env = { ...SAVED };
});

describe("agentScanConfigFromEnv", () => {
  it("returns null when the mode is off (even with both keys)", async () => {
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    const cfg = await loadConfig();
    expect(cfg()).toBeNull();
  });

  it("returns null when enabled but a key is missing", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.OPENROUTER_API_KEY = "sk-or"; // no E2B_API_KEY
    const cfg = await loadConfig();
    expect(cfg()).toBeNull();
  });

  it("returns config when enabled with both keys", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    const cfg = await loadConfig();
    const c = cfg();
    expect(c).not.toBeNull();
    expect(c!.model).toBe("z-ai/glm-5.3");
    expect(c!.baseUrl).toBe("https://openrouter.ai/api/v1");
    expect(c!.maxSteps).toBe(50);
    expect(c!.sandboxTimeoutMs).toBe(30 * 60_000);
    // per-command timeout is bounded to 10 min even though the VM lives longer
    expect(c!.cmdTimeoutMs).toBe(10 * 60_000);
  });

  it("still honors the deprecated ENABLE_MOBILE_AGENT_SCAN alias", async () => {
    process.env.ENABLE_MOBILE_AGENT_SCAN = "true";
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    const cfg = await loadConfig();
    expect(cfg()).not.toBeNull();
  });

  it("honors overrides for model and step/timeout tuning (new + legacy env names)", async () => {
    process.env.ENABLE_AGENT_SCAN = "true";
    process.env.OPENROUTER_API_KEY = "sk-or";
    process.env.E2B_API_KEY = "e2b";
    process.env.OPENROUTER_MOBILE_MODEL = "z-ai/glm-5.3-air";
    process.env.MOBILE_AGENT_MAX_STEPS = "12"; // legacy name still works
    process.env.AGENT_SCAN_TIMEOUT_MINUTES = "5";
    const cfg = await loadConfig();
    const c = cfg();
    expect(c!.model).toBe("z-ai/glm-5.3-air");
    expect(c!.maxSteps).toBe(12);
    expect(c!.sandboxTimeoutMs).toBe(5 * 60_000);
    expect(c!.cmdTimeoutMs).toBe(5 * 60_000); // below the 10-min cap
  });
});
