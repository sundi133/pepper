/**
 * Where a remediation run pushes its branch and opens its pull request.
 *
 * Resolution is provider-agnostic: the agent works in a real git clone and
 * pushes with the org's stored credentials, so only PR creation differs per
 * provider (GitHub, Azure DevOps Services / Server, Bitbucket Cloud).
 */
import { parseGithubRepo } from "@/lib/github-source-link";
import { parseBitbucketRepoInput } from "@/lib/parse-bitbucket-repo-input";
import { parseAzureDevOpsRepoInput } from "@/lib/parse-azure-devops-repo-input";
import {
  withAzureDevOpsCredentials,
  withBitbucketCredentials,
  withGitCredentials,
} from "@/lib/git-repo-url";
import { createPullRequest, humanizeGithubApiError } from "@/lib/github-api";
import {
  azureApiBase,
  azurePost,
  parseAzureErrorBody,
  type AzureDevOpsAuth,
} from "@/lib/azure-devops-api";
import {
  bitbucketPost,
  parseBitbucketErrorBody,
  type BitbucketAuth,
} from "@/lib/bitbucket-api";

export type RemediationProvider = "github" | "azure_devops" | "bitbucket";

export const PROVIDER_LABELS: Record<RemediationProvider, string> = {
  github: "GitHub",
  azure_devops: "Azure DevOps",
  bitbucket: "Bitbucket",
};

export interface RemediationRepoInput {
  scan: {
    sourceType: string;
    sourceRef: string | null;
    branch: string | null;
  };
  project: {
    repoUrl: string | null;
    defaultBranch: string | null;
    connectedViaGithub: boolean;
    connectedViaBitbucket: boolean;
    connectedViaAzure: boolean;
  };
}

export type ResolvedRemediationRepo =
  | {
      ok: true;
      provider: RemediationProvider;
      /** Credential-free clone URL — safe to store and display. */
      repoUrl: string;
      /** Preferred base branch (may not exist remotely; the clone falls back). */
      baseBranch: string | null;
    }
  | { ok: false; error: string; code: string };

function isHttpUrl(s: string | null | undefined): s is string {
  return !!s && /^https?:\/\//i.test(s.trim());
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/** Pick the repository and provider a scan's fixes should go to. */
export function resolveRemediationRepo(
  input: RemediationRepoInput,
): ResolvedRemediationRepo {
  const { scan, project } = input;
  const fromScan =
    (scan.sourceType === "GIT_CLONE" || scan.sourceType === "WEBHOOK") &&
    isHttpUrl(scan.sourceRef)
      ? scan.sourceRef.trim()
      : null;
  const repoUrl = fromScan ?? (isHttpUrl(project.repoUrl) ? project.repoUrl.trim() : null);

  if (!repoUrl) {
    return {
      ok: false,
      code: "REPO_REQUIRED",
      error:
        "This scan is not linked to a git repository. AI remediation needs a GitHub, Azure DevOps or Bitbucket repo — scan from a connected repository, or set the project repository URL.",
    };
  }

  const host = hostOf(repoUrl);
  let provider: RemediationProvider | null = null;
  if (host === "github.com" || host === "www.github.com") provider = "github";
  else if (host === "bitbucket.org") provider = "bitbucket";
  else if (host === "dev.azure.com" || host.endsWith(".visualstudio.com")) {
    provider = "azure_devops";
  } else if (project.connectedViaAzure) provider = "azure_devops";
  else if (project.connectedViaBitbucket) provider = "bitbucket";
  else if (project.connectedViaGithub) provider = "github";

  if (!provider) {
    return {
      ok: false,
      code: "PROVIDER_UNSUPPORTED",
      error: `AI remediation can open pull requests on GitHub, Azure DevOps and Bitbucket; ${host || "this repository"} is not one of them.`,
    };
  }

  const baseBranch =
    scan.branch?.trim() || project.defaultBranch?.trim() || null;
  return { ok: true, provider, repoUrl, baseBranch };
}

export type ProviderCredentials =
  | { provider: "github"; token: string }
  | { provider: "azure_devops"; auth: AzureDevOpsAuth }
  | { provider: "bitbucket"; auth: BitbucketAuth };

/** Load the org's stored credentials for a provider (null when not connected). */
export async function loadProviderCredentials(
  organizationId: string,
  provider: RemediationProvider,
): Promise<ProviderCredentials | null> {
  if (provider === "github") {
    const { getOrgGithubAccessToken } = await import("@/lib/github-connection");
    const token = (await getOrgGithubAccessToken(organizationId))?.trim();
    return token ? { provider, token } : null;
  }
  if (provider === "azure_devops") {
    const { getOrgAzureDevOpsAuth } = await import("@/lib/azure-devops-connection");
    const auth = await getOrgAzureDevOpsAuth(organizationId);
    return auth ? { provider, auth } : null;
  }
  const { getOrgBitbucketAuth } = await import("@/lib/bitbucket-connection");
  const auth = await getOrgBitbucketAuth(organizationId);
  return auth ? { provider, auth } : null;
}

export function missingCredentialsMessage(provider: RemediationProvider): string {
  return `${PROVIDER_LABELS[provider]} is not connected for this organization. Connect it under Settings → Integrations (with write access) so the agent can push a branch and open a pull request.`;
}

/** Clone/push URL with credentials embedded. Never persist or log this. */
export function authenticatedRepoUrl(
  repoUrl: string,
  creds: ProviderCredentials,
): string {
  if (creds.provider === "github") {
    // Token as the password (`x-access-token:<token>@`) is accepted for OAuth
    // tokens, PATs and app tokens alike, and never makes git prompt — which a
    // non-interactive push would otherwise fail on.
    try {
      const u = new URL(repoUrl);
      if (u.protocol === "https:" || u.protocol === "http:") {
        u.username = "x-access-token";
        u.password = encodeURIComponent(creds.token);
        return u.toString();
      }
    } catch {
      /* fall through */
    }
    return withGitCredentials(repoUrl, creds.token);
  }
  if (creds.provider === "azure_devops") {
    return withAzureDevOpsCredentials(repoUrl, creds.auth.pat);
  }
  return withBitbucketCredentials(repoUrl, creds.auth.username, creds.auth.appPassword);
}

export interface OpenPrInput {
  repoUrl: string;
  head: string;
  base: string;
  title: string;
  body: string;
}

export type OpenPrResult =
  | { ok: true; url: string; number: number | null }
  | { ok: false; error: string };

/** Azure DevOps caps PR descriptions at 4000 characters. */
const ADO_DESCRIPTION_LIMIT = 4000;

export async function openProviderPullRequest(
  creds: ProviderCredentials,
  input: OpenPrInput,
): Promise<OpenPrResult> {
  if (creds.provider === "github") {
    const parsed = parseGithubRepo(input.repoUrl);
    if (!parsed) return { ok: false, error: `Not a GitHub repository URL: ${input.repoUrl}` };
    const pr = await createPullRequest(creds.token, parsed.owner, parsed.repo, {
      title: input.title,
      head: input.head,
      base: input.base,
      body: input.body.slice(0, 60_000),
    });
    if (!pr.ok || !pr.html_url) {
      return {
        ok: false,
        error: humanizeGithubApiError(
          pr.message,
          parsed.owner,
          parsed.repo,
          "GitHub rejected the pull request",
        ),
      };
    }
    return { ok: true, url: pr.html_url, number: pr.number ?? null };
  }

  if (creds.provider === "azure_devops") {
    const parsed = parseAzureDevOpsRepoInput(
      input.repoUrl,
      creds.auth.organization,
      creds.auth.serverUrl,
    );
    if (!parsed) {
      return { ok: false, error: `Not an Azure DevOps repository URL: ${input.repoUrl}` };
    }
    const project = encodeURIComponent(parsed.project);
    const repo = encodeURIComponent(parsed.repo);
    const description =
      input.body.length > ADO_DESCRIPTION_LIMIT
        ? `${input.body.slice(0, ADO_DESCRIPTION_LIMIT - 40)}\n\n_(truncated — see commits)_`
        : input.body;
    const r = await azurePost<{ pullRequestId?: number }>(
      creds.auth,
      `/${project}/_apis/git/repositories/${repo}/pullrequests`,
      {
        sourceRefName: `refs/heads/${input.head}`,
        targetRefName: `refs/heads/${input.base}`,
        title: input.title.slice(0, 400),
        description,
      },
    );
    if (!r.ok || !r.data.pullRequestId) {
      return {
        ok: false,
        error: `Azure DevOps rejected the pull request (${r.status}): ${parseAzureErrorBody(r.data, r.raw) || "unknown error"}`,
      };
    }
    const id = r.data.pullRequestId;
    return {
      ok: true,
      url: `${azureApiBase(creds.auth)}/${project}/_git/${repo}/pullrequest/${id}`,
      number: id,
    };
  }

  const parsed = parseBitbucketRepoInput(input.repoUrl);
  if (!parsed) return { ok: false, error: `Not a Bitbucket repository URL: ${input.repoUrl}` };
  const r = await bitbucketPost<{ id?: number; links?: { html?: { href?: string } } }>(
    creds.auth,
    `/repositories/${encodeURIComponent(parsed.workspace)}/${encodeURIComponent(parsed.slug)}/pullrequests`,
    {
      title: input.title.slice(0, 255),
      description: input.body.slice(0, 30_000),
      source: { branch: { name: input.head } },
      destination: { branch: { name: input.base } },
      close_source_branch: true,
    },
  );
  const href = r.data.links?.html?.href;
  if (!r.ok || !href) {
    return {
      ok: false,
      error: `Bitbucket rejected the pull request (${r.status}): ${parseBitbucketErrorBody(r.data, r.raw) || "unknown error"}`,
    };
  }
  return { ok: true, url: href, number: r.data.id ?? null };
}
