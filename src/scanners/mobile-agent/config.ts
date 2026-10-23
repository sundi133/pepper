/**
 * Environment-driven config for the agent deep scan. Returns null unless the
 * feature is explicitly enabled AND both the E2B and OpenRouter keys are
 * present — which is how the processor decides "agent-only" vs. the fallback
 * pipeline, and how the scanner self-gates to a no-op.
 */
import {
  ENABLE_AGENT_SCAN,
  AGENT_SCAN_MAX_STEPS,
  AGENT_SCAN_TIMEOUT_MINUTES,
} from "@/lib/constants";

export interface AgentScanConfig {
  /** OpenRouter key the glm-5.3 function-calling loop authenticates with. */
  openRouterApiKey: string;
  /** E2B cloud key the sandbox is created under. */
  e2bApiKey: string;
  model: string;
  baseUrl: string;
  /** Max model turns before the loop stops. */
  maxSteps: number;
  /** How long the E2B VM is kept alive (ms). */
  sandboxTimeoutMs: number;
  /** Per-command timeout inside the VM (ms). */
  cmdTimeoutMs: number;
}

/** Max per-command timeout — long enough for an install/decompile, bounded so one command can't hog the VM lease. */
const MAX_CMD_TIMEOUT_MS = 10 * 60_000;

/**
 * Reads config from the environment. Returns null when the mode is off or a
 * required key is missing.
 */
export function agentScanConfigFromEnv(): AgentScanConfig | null {
  if (!ENABLE_AGENT_SCAN) return null;
  const openRouterApiKey = process.env.OPENROUTER_API_KEY?.trim();
  const e2bApiKey = process.env.E2B_API_KEY?.trim();
  if (!openRouterApiKey || !e2bApiKey) return null;

  const timeoutMin =
    Number.isFinite(AGENT_SCAN_TIMEOUT_MINUTES) && AGENT_SCAN_TIMEOUT_MINUTES > 0
      ? AGENT_SCAN_TIMEOUT_MINUTES
      : 30;
  const sandboxTimeoutMs = timeoutMin * 60_000;

  return {
    openRouterApiKey,
    e2bApiKey,
    model: process.env.OPENROUTER_MOBILE_MODEL?.trim() || "z-ai/glm-5.3",
    baseUrl:
      process.env.OPENROUTER_BASE_URL?.trim() || "https://openrouter.ai/api/v1",
    maxSteps:
      Number.isFinite(AGENT_SCAN_MAX_STEPS) && AGENT_SCAN_MAX_STEPS > 0
        ? AGENT_SCAN_MAX_STEPS
        : 50,
    sandboxTimeoutMs,
    // A single command should never outlast the VM lease.
    cmdTimeoutMs: Math.min(sandboxTimeoutMs, MAX_CMD_TIMEOUT_MS),
  };
}

/** Cheap "is the agent deep scan available on this instance?" check (flag + both keys). */
export function isAgentScanConfigured(): boolean {
  return agentScanConfigFromEnv() !== null;
}

/** @deprecated renamed to {@link agentScanConfigFromEnv}. */
export const mobileAgentConfigFromEnv = agentScanConfigFromEnv;
/** @deprecated renamed to {@link AgentScanConfig}. */
export type MobileAgentConfig = AgentScanConfig;
