import { decryptSecret } from "@/lib/token-encryption";
import { getLlmConfig } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";
import type { ScanJobData } from "@/lib/queue";

type RawOrgSettings = {
  llmProvider?: string | null;
  llmBaseUrl?: string | null;
  llmModel?: string | null;
  llmApiKey?: string | null;
  enableLlmSast?: boolean | null;
  enableLlmSecrets?: boolean | null;
  osvApiUrl?: string | null;
  vulnDbMode?: string | null;
  containerRegistryType?: string | null;
  containerRegistryUsernameEnc?: string | null;
  containerRegistryPasswordEnc?: string | null;
  containerRegistryRegion?: string | null;
} | null;

/**
 * Build the slimmed-down `orgSettings` blob that gets serialised onto a
 * BullMQ job.
 */
export function buildOrgSettingsForJob(
  orgSettings: RawOrgSettings,
  organizationId: string,
): ScanJobData["orgSettings"] {
  let containerRegistryUsername: string | undefined;
  if (orgSettings?.containerRegistryUsernameEnc) {
    try {
      containerRegistryUsername = decryptSecret(
        orgSettings.containerRegistryUsernameEnc,
      );
    } catch {
      containerRegistryUsername = undefined;
    }
  }
  let containerRegistryPassword: string | undefined;
  if (orgSettings?.containerRegistryPasswordEnc) {
    try {
      containerRegistryPassword = decryptSecret(
        orgSettings.containerRegistryPasswordEnc,
      );
    } catch {
      containerRegistryPassword = undefined;
    }
  }

  function decryptLlmApiKey(stored: string | null | undefined): string | undefined {
    if (!stored) return undefined;
    if (stored.startsWith("enc:")) {
      try {
        return decryptSecret(stored.slice(4));
      } catch (err) {
        // A saved customer secret that won't decrypt usually means the service
        // building the job has a different TOKEN_ENCRYPTION_KEY/NEXTAUTH_SECRET
        // than the one that saved it. Silently falling back to the env key hides
        // this; log it (never the key) so the misconfiguration is visible.
        logger.warn(
          {
            organizationId,
            err: err instanceof Error ? err.message : String(err),
          },
          "Could not decrypt the org LLM API key; falling back to env (check TOKEN_ENCRYPTION_KEY/NEXTAUTH_SECRET match between web and worker)",
        );
        return undefined;
      }
    }
    // Legacy plaintext value — still usable
    return stored;
  }

  const dbKey = decryptLlmApiKey(orgSettings?.llmApiKey);
  // Without an org key, use the same environment fallback as the web app
  // (getLlmConfig): LLM_* first, then OPENROUTER_API_KEY / OPENROUTER_MODEL.
  // A separate fallback here used to send scans to OpenAI with no key while
  // the web app used OpenRouter, so every AI scanner call failed.
  const env = getLlmConfig(null);

  return {
    llmProvider: dbKey ? (orgSettings?.llmProvider || env.provider) : env.provider,
    llmBaseUrl: dbKey ? (orgSettings?.llmBaseUrl || env.baseUrl) : env.baseUrl,
    llmModel: dbKey ? (orgSettings?.llmModel || env.model) : env.model,
    llmApiKey: dbKey || env.apiKey || undefined,
    enableLlmSast: orgSettings?.enableLlmSast ?? true,
    enableLlmSecrets: orgSettings?.enableLlmSecrets ?? true,
    osvApiUrl: orgSettings?.osvApiUrl || "https://api.osv.dev",
    vulnDbMode: (orgSettings?.vulnDbMode || "online") as
      | "online"
      | "mirror"
      | "offline",
    orgId: organizationId,
    containerRegistryType: orgSettings?.containerRegistryType || undefined,
    containerRegistryUsername,
    containerRegistryPassword,
    containerRegistryRegion: orgSettings?.containerRegistryRegion || undefined,
  };
}
