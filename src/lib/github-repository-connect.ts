import { prisma } from "@/lib/prisma";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { queueProjectScan } from "@/lib/queue-project-scan";
import { githubHttpsCloneUrl } from "@/lib/parse-github-repo-input";

export type ConnectGithubRepoRecord = {
  projectId: string;
  fullName: string;
  scanId: string;
  created: boolean;
};

export async function connectGithubRepositoryRecord(params: {
  organizationId: string;
  userId: string;
  owner: string;
  repo: string;
  githubRepoId: number;
  cloneUrl: string;
  defaultBranch: string;
  language: string | null;
  /** True when linked via OAuth import; false for manual URL-only project link. */
  connectedViaGithub: boolean;
  branch?: string;
}): Promise<ConnectGithubRepoRecord> {
  const fullName = `${params.owner}/${params.repo}`;
  const cloneUrl = params.cloneUrl.trim() || githubHttpsCloneUrl(params.owner, params.repo);

  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      OR: [{ githubRepoId: params.githubRepoId }, { repoUrl: cloneUrl }],
    },
  });

  if (existing) {
    await prisma.project.update({
      where: { id: existing.id },
      data: {
        repoUrl: cloneUrl,
        defaultBranch: params.branch?.trim() || params.defaultBranch,
        githubRepoId: params.githubRepoId,
        githubOwner: params.owner,
        githubRepoName: params.repo,
        primaryLanguage: params.language,
        connectedViaGithub: params.connectedViaGithub || existing.connectedViaGithub,
      },
    });
    const { scanId } = await queueProjectScan({
      projectId: existing.id,
      organizationId: params.organizationId,
      userId: params.userId,
      branch: params.branch?.trim() || params.defaultBranch,
      useOrgGithubToken: true,
    });
    return {
      projectId: existing.id,
      fullName,
      scanId,
      created: false,
    };
  }

  const project = await createProjectWithBuildGate({
    organizationId: params.organizationId,
    name: fullName,
    repoUrl: cloneUrl,
    defaultBranch: params.branch?.trim() || params.defaultBranch,
  });

  await prisma.project.update({
    where: { id: project.id },
    data: {
      githubRepoId: params.githubRepoId,
      githubOwner: params.owner,
      githubRepoName: params.repo,
      primaryLanguage: params.language,
      connectedViaGithub: params.connectedViaGithub,
    },
  });

  const { scanId } = await queueProjectScan({
    projectId: project.id,
    organizationId: params.organizationId,
    userId: params.userId,
    branch: params.branch?.trim() || params.defaultBranch,
    useOrgGithubToken: true,
  });

  return {
    projectId: project.id,
    fullName,
    scanId,
    created: true,
  };
}
