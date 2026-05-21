import { prisma } from "@/lib/prisma";
import {
  getOrgBitbucketAuthOrThrow,
  BitbucketCredentialsInvalidError,
} from "@/lib/bitbucket-connection";
import { listBitbucketRepositoriesInWorkspace } from "@/lib/bitbucket-repos";
import { connectBitbucketRepositoryRecord } from "@/lib/bitbucket-repository-connect";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";

export type ConnectBitbucketRepoResult = {
  connected: Array<{ projectId: string; fullName: string; scanId: string }>;
  skipped: Array<{ repoUuid: string; reason: string }>;
};

export async function connectBitbucketRepositories(params: {
  organizationId: string;
  userId: string;
  repoUuids: string[];
  workspace: string;
}): Promise<ConnectBitbucketRepoResult> {
  const auth = await getOrgBitbucketAuthOrThrow(params.organizationId);
  const workspace = params.workspace.trim();
  if (!workspace) {
    throw new Error(
      "Bitbucket workspace is required. Set it when connecting Bitbucket under Settings → Integrations.",
    );
  }

  const existing = await prisma.project.findMany({
    where: {
      organizationId: params.organizationId,
      bitbucketRepoUuid: { not: null },
    },
    select: { bitbucketRepoUuid: true },
  });
  const connectedUuids = new Set(
    existing
      .map((p) => p.bitbucketRepoUuid)
      .filter((id): id is string => id != null)
      .map(normalizeBitbucketUuid),
  );

  let available;
  try {
    available = await listBitbucketRepositoriesInWorkspace(
      auth,
      workspace,
      connectedUuids,
    );
  } catch (e) {
    if (e instanceof Error && /401|403/i.test(e.message)) {
      throw new BitbucketCredentialsInvalidError();
    }
    throw e;
  }

  const byUuid = new Map(available.map((r) => [r.uuid, r]));
  const connected: ConnectBitbucketRepoResult["connected"] = [];
  const skipped: ConnectBitbucketRepoResult["skipped"] = [];

  for (const rawUuid of params.repoUuids) {
    const repoUuid = normalizeBitbucketUuid(rawUuid);
    const repo = byUuid.get(repoUuid);
    if (!repo) {
      skipped.push({
        repoUuid,
        reason: "Repository not found or not accessible in this workspace",
      });
      continue;
    }
    if (repo.alreadyConnected) {
      skipped.push({ repoUuid, reason: "Already connected" });
      continue;
    }

    const record = await connectBitbucketRepositoryRecord({
      organizationId: params.organizationId,
      userId: params.userId,
      workspace: repo.workspace,
      slug: repo.slug,
      bitbucketRepoUuid: repo.uuid,
      cloneUrl: repo.cloneUrl,
      defaultBranch: repo.defaultBranch,
      language: repo.language,
      connectedViaBitbucket: true,
      queueInitialScan: true,
    });

    connected.push({
      projectId: record.projectId,
      fullName: record.fullName,
      scanId: record.scanId,
    });
    connectedUuids.add(repoUuid);
  }

  return { connected, skipped };
}
