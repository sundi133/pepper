/**
 * Config for the agent deep scan. The OpenRouter key the agent authenticates
 * with is resolved per-org: the organization's own LLM Config OpenRouter key
 * (decrypted by buildOrgSettingsForJob) wins, and the server-wide
 * OPENROUTER_API_KEY env var is only a fallback — so a multi-tenant instance
 * drives each org's agent with that org's token. E2B is genuinely platform
 * infra, so its key stays env-only. Returns null (agent unavailable) unless the
 * feature flag, the E2B key, and some OpenRouter key are all present.
 */
import {
  ENABLE_AGENT_SCAN,
  AGENT_SCAN_MAX_STEPS,
  AGENT_SCAN_TIMEOUT_MINUTES,
} from "@/lib/constants";

const DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

/** The slice of ctx.orgSettings this module reads to resolve the OpenRouter key. */
export interface AgentKeySource {
  llmProvider?: string;
  llmBaseUrl?: string;
  llmApiKey?: string;
}

export type WebSearchProvider = "tavily" | "brave";

export interface WebSearchConfig {
  apiKey: string;
  provider: WebSearchProvider;
}

export interface AgentScanConfig {
  /** OpenRouter key the glm-5.3 function-calling loop authenticates with (org key or env). */
  openRouterApiKey: string;
  /** E2B cloud key the sandbox is created under (platform env). */
  e2bApiKey: string;
  model: string;
  baseUrl: string;
  /** Where the OpenRouter key came from, for status/diagnostics. */
  keySource: "org" | "env";
  /**
   * Optional web search for advisory lookups. Present only when
   * WEB_SEARCH_API_KEY is set; when absent the agent is offered no web_search
   * tool (no behavior change, no regression).
   */
  webSearch?: WebSearchConfig;
  /** Max model turns before the loop stops. */
  maxSteps: number;
  /** How long the E2B VM is kept alive (ms). */
  sandboxTimeoutMs: number;
  /** Per-command timeout inside the VM (ms). */
  cmdTimeoutMs: number;
}

/** Reads the optional web search config from the env (WEB_SEARCH_API_KEY / WEB_SEARCH_PROVIDER). */
export function webSearchConfigFromEnv(): WebSearchConfig | undefined {
  const apiKey = process.env.WEB_SEARCH_API_KEY?.trim();
  if (!apiKey) return undefined;
  const provider: WebSearchProvider =
    process.env.WEB_SEARCH_PROVIDER?.trim().toLowerCase() === "brave" ? "brave" : "tavily";
  return { apiKey, provider };
}

/** Max per-command timeout — long enough for an install/decompile, bounded so one command can't hog the VM lease. */
const MAX_CMD_TIMEOUT_MS = 10 * 60_000;

/**
 * Resolve the OpenRouter credentials: the org's LLM Config OpenRouter key wins,
 * else the OPENROUTER_API_KEY env var. Returns null when neither is set.
 */
function resolveOpenRouter(
  org?: AgentKeySource,
): { apiKey: string; baseUrl: string; keySource: "org" | "env" } | null {
  if (org?.llmProvider === "openrouter" && org.llmApiKey?.trim()) {
    return {
      apiKey: org.llmApiKey.trim(),
      baseUrl: org.llmBaseUrl?.trim() || DEFAULT_OPENROUTER_BASE_URL,
      keySource: "org",
    };
  }
  const envKey = process.env.OPENROUTER_API_KEY?.trim();
  if (envKey) {
    return {
      apiKey: envKey,
      baseUrl: process.env.OPENROUTER_BASE_URL?.trim() || DEFAULT_OPENROUTER_BASE_URL,
      keySource: "env",
    };
  }
  return null;
}

/**
 * Builds the agent config, preferring the org's OpenRouter key. Returns null
 * when the feature is off, the E2B key is missing, or no OpenRouter key is
 * available (org or env). The model is always OPENROUTER_MOBILE_MODEL (a
 * sandbox-driver model), never the org's llmModel.
 */
export function agentScanConfig(org?: AgentKeySource): AgentScanConfig | null {
  if (!ENABLE_AGENT_SCAN) return null;
  const e2bApiKey = process.env.E2B_API_KEY?.trim();
  if (!e2bApiKey) return null;
  const or = resolveOpenRouter(org);
  if (!or) return null;

  const timeoutMin =
    Number.isFinite(AGENT_SCAN_TIMEOUT_MINUTES) && AGENT_SCAN_TIMEOUT_MINUTES > 0
      ? AGENT_SCAN_TIMEOUT_MINUTES
      : 30;
  const sandboxTimeoutMs = timeoutMin * 60_000;

  return {
    openRouterApiKey: or.apiKey,
    e2bApiKey,
    model: process.env.OPENROUTER_MOBILE_MODEL?.trim() || "z-ai/glm-5.3",
    baseUrl: or.baseUrl,
    keySource: or.keySource,
    webSearch: webSearchConfigFromEnv(),
    maxSteps:
      Number.isFinite(AGENT_SCAN_MAX_STEPS) && AGENT_SCAN_MAX_STEPS > 0
        ? AGENT_SCAN_MAX_STEPS
        : 50,
    sandboxTimeoutMs,
    // A single command should never outlast the VM lease.
    cmdTimeoutMs: Math.min(sandboxTimeoutMs, MAX_CMD_TIMEOUT_MS),
  };
}

/** Whether the agent deep scan can run for this org (flag + E2B key + an OpenRouter key). */
export function isAgentScanConfigured(org?: AgentKeySource): boolean {
  return agentScanConfig(org) !== null;
}

/**
 * A human reason the agent can't run — but only when the feature is ENABLED and
 * misconfigured, so a silent misconfiguration becomes visible on the scan.
 * Returns null when the agent is available OR the feature is simply off (stay
 * quiet — the instance isn't using the agent).
 */
export function agentScanUnavailableReason(org?: AgentKeySource): string | null {
  if (!ENABLE_AGENT_SCAN) return null;
  if (!process.env.E2B_API_KEY?.trim()) {
    return "agent deep scan unavailable: no E2B key — set E2B_API_KEY on the worker";
  }
  if (!resolveOpenRouter(org)) {
    return "agent deep scan unavailable: no OpenRouter key — set one in LLM Config or OPENROUTER_API_KEY";
  }
  return null;
}

/** @deprecated use {@link agentScanConfig} (now org-aware); this reads env only. */
export const agentScanConfigFromEnv = (): AgentScanConfig | null => agentScanConfig();
/** @deprecated renamed to {@link agentScanConfig}. */
export const mobileAgentConfigFromEnv = agentScanConfigFromEnv;
/** @deprecated renamed to {@link AgentScanConfig}. */
export type MobileAgentConfig = AgentScanConfig;
