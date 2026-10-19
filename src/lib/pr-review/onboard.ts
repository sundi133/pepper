/**
 * Zero-setup onboarding (docs/PR_REVIEW_BOT_SPEC.md §2): the first event the
 * GitHub App delivers for a repository creates its Pepper project in the
 * installation's organization. Only the repository's identity is taken from
 * the (App-signed) payload; the clone URL is built from owner and name.
 */
import { prisma } from "@/lib/prisma";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { githubHttpsCloneUrl } from "@/lib/parse-github-repo-input";

export interface RepoPayload {
  id?: number;
  name?: string;
  full_name?: string;
  default_branch?: string;
  owner?: { login?: string };
  language?: string | null;
}

const SAFE_SEGMENT = /^[A-Za-z0-9_.-]{1,100}$/;

export async function ensureProjectForGithubRepo(organizationId: string, repo: RepoPayload): Promise<{ id: string; created: boolean } | null> {
  const owner = repo.owner?.login ?? repo.full_name?.split("/")[0];
  const name = repo.name ?? repo.full_name?.split("/")[1];
  if (!owner || !name || !SAFE_SEGMENT.test(owner) || !SAFE_SEGMENT.test(name) || typeof repo.id !== "number") return null;
  const cloneUrl = githubHttpsCloneUrl(owner, name);

  const existing = await prisma.project.findFirst({
    where: { organizationId, OR: [{ githubRepoId: repo.id }, { repoUrl: cloneUrl }] },
    select: { id: true },
  });
  if (existing) return { id: existing.id, created: false };

  const project = await createProjectWithBuildGate({
    organizationId,
    name: `${owner}/${name}`,
    repoUrl: cloneUrl,
    defaultBranch: repo.default_branch || "main",
  });
  await prisma.project.update({
    where: { id: project.id },
    data: {
      githubRepoId: repo.id,
      githubOwner: owner,
      githubRepoName: name,
      primaryLanguage: repo.language ?? null,
      connectedViaGithub: true,
    },
  });
  return { id: project.id, created: true };
}
