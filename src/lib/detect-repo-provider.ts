import { parseAzureDevOpsRepoInput } from "@/lib/parse-azure-devops-repo-input";
import { parseBitbucketRepoInput } from "@/lib/parse-bitbucket-repo-input";
import { parseGithubRepoInput } from "@/lib/parse-github-repo-input";

export type RepoProviderHint =
  | "github"
  | "bitbucket"
  | "azure"
  | "generic"
  | null;

/** Guess provider from repository URL or slug for smart connect UI. */
export function detectRepoProviderFromInput(
  input: string,
  azureDefaultOrg?: string | null,
): RepoProviderHint {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const host = new URL(trimmed).hostname.toLowerCase();
      if (host.includes("github.com")) return "github";
      if (host.includes("bitbucket.org")) return "bitbucket";
      if (host.includes("dev.azure.com")) return "azure";
    }
  } catch {
    /* fall through */
  }

  if (parseBitbucketRepoInput(trimmed)) return "bitbucket";
  if (parseAzureDevOpsRepoInput(trimmed, azureDefaultOrg ?? undefined)) {
    return "azure";
  }
  if (parseGithubRepoInput(trimmed)) return "github";

  return "generic";
}

export const PROVIDER_HINT_LABEL: Record<
  Exclude<RepoProviderHint, null>,
  string
> = {
  github: "GitHub",
  bitbucket: "Bitbucket",
  azure: "Azure DevOps",
  generic: "Git",
};
