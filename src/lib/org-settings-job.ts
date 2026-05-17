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
  dastEnabled?: boolean | null;
  dastEndpoint?: string | null;
  dastApiKeyEnc?: string | null;
} | null;

/**
 * Build the slimmed-down `orgSettings` blob that gets serialised onto a
 * BullMQ job, including resolved DAST configuration.
 */
export function buildOrgSettingsForJob(
  orgSettings: RawOrgSettings,
  organizationId: string,
): ScanJobData["orgSettings"] {
  let dastApiKey: string | undefined;
  if (orgSettings?.dastApiKeyEnc) {
    try {
      dastApiKey = decryptSecret(orgSettings.dastApiKeyEnc);
    } catch {
      dastApiKey = undefined;
    }
  }

  return {
    llmProvider: orgSettings?.llmProvider || "openai",
    llmBaseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
    llmModel: orgSettings?.llmModel || "gpt-4o-mini",
    llmApiKey: orgSettings?.llmApiKey || undefined,
    enableLlmSast: orgSettings?.enableLlmSast ?? true,
    enableLlmSecrets: orgSettings?.enableLlmSecrets ?? true,
    osvApiUrl: orgSettings?.osvApiUrl || "https://api.osv.dev",
    vulnDbMode: (orgSettings?.vulnDbMode || "online") as
      | "online"
      | "mirror"
      | "offline",
    orgId: organizationId,
    dastEnabled: orgSettings?.dastEnabled ?? false,
    dastEndpoint: orgSettings?.dastEndpoint || undefined,
    dastApiKey,
  };
}
