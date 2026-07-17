import { decryptSecret } from "@/lib/token-encryption";
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
      } catch {
        return undefined;
      }
    }
    // Legacy plaintext value — still usable
    return stored;
  }

  const dbKey = decryptLlmApiKey(orgSettings?.llmApiKey);

  return {
    llmProvider: dbKey ? (orgSettings?.llmProvider || process.env.LLM_PROVIDER || "openai") : (process.env.LLM_PROVIDER || "openai"),
    llmBaseUrl: dbKey ? (orgSettings?.llmBaseUrl || process.env.LLM_BASE_URL || "https://api.openai.com/v1") : (process.env.LLM_BASE_URL || "https://api.openai.com/v1"),
    llmModel: dbKey ? (orgSettings?.llmModel || process.env.LLM_MODEL || "gpt-4o-mini") : (process.env.LLM_MODEL || "gpt-4o-mini"),
    llmApiKey: dbKey || process.env.LLM_API_KEY,
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
