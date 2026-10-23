/**
 * Environment-driven config for the mobile agent deep scan. Returns null unless
 * the feature is explicitly enabled AND both the E2B and OpenRouter keys are
 * present — which is how the scanner self-gates to no-op (so non-mobile and
 * existing mobile scans are byte-for-byte unchanged when the mode is off).
 */
import {
  ENABLE_MOBILE_AGENT_SCAN,
  MOBILE_AGENT_MAX_STEPS,
  MOBILE_AGENT_TIMEOUT_MINUTES,
} from "@/lib/constants";

export interface MobileAgentConfig {
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
 * required key is missing, so the scanner no-ops.
 */
export function mobileAgentConfigFromEnv(): MobileAgentConfig | null {
  if (!ENABLE_MOBILE_AGENT_SCAN) return null;
  const openRouterApiKey = process.env.OPENROUTER_API_KEY?.trim();
  const e2bApiKey = process.env.E2B_API_KEY?.trim();
  if (!openRouterApiKey || !e2bApiKey) return null;

  const timeoutMin =
    Number.isFinite(MOBILE_AGENT_TIMEOUT_MINUTES) && MOBILE_AGENT_TIMEOUT_MINUTES > 0
      ? MOBILE_AGENT_TIMEOUT_MINUTES
      : 30;
  const sandboxTimeoutMs = timeoutMin * 60_000;

  return {
    openRouterApiKey,
    e2bApiKey,
    model: process.env.OPENROUTER_MOBILE_MODEL?.trim() || "z-ai/glm-5.3",
    baseUrl:
      process.env.OPENROUTER_BASE_URL?.trim() || "https://openrouter.ai/api/v1",
    maxSteps:
      Number.isFinite(MOBILE_AGENT_MAX_STEPS) && MOBILE_AGENT_MAX_STEPS > 0
        ? MOBILE_AGENT_MAX_STEPS
        : 50,
    sandboxTimeoutMs,
    // A single command should never outlast the VM lease.
    cmdTimeoutMs: Math.min(sandboxTimeoutMs, MAX_CMD_TIMEOUT_MS),
  };
}
