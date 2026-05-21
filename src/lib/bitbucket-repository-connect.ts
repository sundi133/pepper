import { prisma } from "@/lib/prisma";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { queueProjectScan } from "@/lib/queue-project-scan";
import { bitbucketHttpsCloneUrl } from "@/lib/parse-bitbucket-repo-input";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";

export type ConnectBitbucketRepoRecord = {
  projectId: string;
  fullName: string;
  scanId: string;
  created: boolean;
};

export async function connectBitbucketRepositoryRecord(params: {
  organizationId: string;
  userId: string;
  workspace: string;
  slug: string;
  bitbucketRepoUuid: string;
  cloneUrl: string;
  defaultBranch: string;
  language: string | null;
  connectedViaBitbucket: boolean;
  branch?: string;
  /** Queue an initial scan (import / manual connect). Reconnects skip unless true. */
  queueInitialScan?: boolean;
}): Promise<ConnectBitbucketRepoRecord> {
  const fullName = `${params.workspace}/${params.slug}`;
  const repoUuid = normalizeBitbucketUuid(params.bitbucketRepoUuid);
  const cloneUrl =
    params.cloneUrl.trim() ||
    bitbucketHttpsCloneUrl(params.workspace, params.slug);

  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      OR: [{ bitbucketRepoUuid: repoUuid }, { repoUrl: cloneUrl }],
    },
  });

  if (existing) {
    await prisma.project.update({
      where: { id: existing.id },
      data: {
        repoUrl: cloneUrl,
        defaultBranch: params.branch?.trim() || params.defaultBranch,
        bitbucketWorkspace: params.workspace,
        bitbucketRepoSlug: params.slug,
        bitbucketRepoUuid: repoUuid,
        primaryLanguage: params.language,
        connectedViaBitbucket:
          params.connectedViaBitbucket || existing.connectedViaBitbucket,
      },
    });
    let scanId = "";
    if (params.queueInitialScan) {
      const queued = await queueProjectScan({
        projectId: existing.id,
        organizationId: params.organizationId,
        userId: params.userId,
        branch: params.branch?.trim() || params.defaultBranch,
        useOrgBitbucketToken: true,
      });
      scanId = queued.scanId;
    }
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
      bitbucketWorkspace: params.workspace,
      bitbucketRepoSlug: params.slug,
      bitbucketRepoUuid: repoUuid,
      primaryLanguage: params.language,
      connectedViaBitbucket: params.connectedViaBitbucket,
    },
  });

  let scanId = "";
  if (params.queueInitialScan !== false) {
    const queued = await queueProjectScan({
      projectId: project.id,
      organizationId: params.organizationId,
      userId: params.userId,
      branch: params.branch?.trim() || params.defaultBranch,
      useOrgBitbucketToken: true,
    });
    scanId = queued.scanId;
  }

  return {
    projectId: project.id,
    fullName,
    scanId,
    created: true,
  };
}
