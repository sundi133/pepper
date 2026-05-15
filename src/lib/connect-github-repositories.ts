import { prisma } from "@/lib/prisma";
import {
  getOrgGithubAccessTokenOrThrow,
  GithubTokenInvalidError,
} from "@/lib/github-connection";
import { listGithubRepositoriesForUser } from "@/lib/github-repos";
import { connectGithubRepositoryRecord } from "@/lib/github-repository-connect";

export type ConnectGithubRepoResult = {
  connected: Array<{ projectId: string; fullName: string; scanId: string }>;
  skipped: Array<{ repoId: number; reason: string }>;
};

export async function connectGithubRepositories(params: {
  organizationId: string;
  userId: string;
  repoIds: number[];
}): Promise<ConnectGithubRepoResult> {
  const token = await getOrgGithubAccessTokenOrThrow(params.organizationId);

  const existing = await prisma.project.findMany({
    where: {
      organizationId: params.organizationId,
      githubRepoId: { not: null },
    },
    select: { githubRepoId: true },
  });
  const connectedIds = new Set(
    existing.map((p) => p.githubRepoId).filter((id): id is number => id != null),
  );

  let available;
  try {
    available = await listGithubRepositoriesForUser(token, connectedIds);
  } catch (e) {
    if (e instanceof Error && /401|403|Bad credentials/i.test(e.message)) {
      throw new GithubTokenInvalidError();
    }
    throw e;
  }

  const byId = new Map(available.map((r) => [r.id, r]));
  const connected: ConnectGithubRepoResult["connected"] = [];
  const skipped: ConnectGithubRepoResult["skipped"] = [];

  for (const repoId of params.repoIds) {
    const repo = byId.get(repoId);
    if (!repo) {
      skipped.push({ repoId, reason: "Repository not found or not accessible" });
      continue;
    }
    if (repo.alreadyConnected) {
      skipped.push({ repoId, reason: "Already connected" });
      continue;
    }

    const record = await connectGithubRepositoryRecord({
      organizationId: params.organizationId,
      userId: params.userId,
      owner: repo.owner,
      repo: repo.name,
      githubRepoId: repo.id,
      cloneUrl: repo.cloneUrl,
      defaultBranch: repo.defaultBranch,
      language: repo.language,
      connectedViaGithub: true,
    });

    connected.push({
      projectId: record.projectId,
      fullName: record.fullName,
      scanId: record.scanId,
    });
    connectedIds.add(repoId);
  }

  return { connected, skipped };
}
