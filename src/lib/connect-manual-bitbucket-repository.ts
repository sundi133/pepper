import { prisma } from "@/lib/prisma";
import {
  getOrgBitbucketAuthOrThrow,
  BitbucketCredentialsInvalidError,
} from "@/lib/bitbucket-connection";
import { bitbucketGet, parseBitbucketErrorBody } from "@/lib/bitbucket-api";
import {
  bitbucketHttpsCloneUrl,
  normalizeBitbucketUuid,
  parseBitbucketRepoInput,
} from "@/lib/parse-bitbucket-repo-input";
import { connectBitbucketRepositoryRecord } from "@/lib/bitbucket-repository-connect";

type BitbucketApiRepo = {
  uuid?: string;
  slug?: string;
  full_name?: string;
  language?: string;
  mainbranch?: { name?: string };
  links?: { clone?: Array<{ name?: string; href?: string }> };
};

export async function connectManualBitbucketRepository(params: {
  organizationId: string;
  userId: string;
  repoInput: string;
  branch?: string;
}) {
  const parsed = parseBitbucketRepoInput(params.repoInput);
  if (!parsed) {
    throw new Error(
      "Enter a Bitbucket repository as workspace/repo-slug or https://bitbucket.org/workspace/repo-slug",
    );
  }

  const auth = await getOrgBitbucketAuthOrThrow(params.organizationId);

  const meta = await bitbucketGet<BitbucketApiRepo>(
    auth,
    `/repositories/${encodeURIComponent(parsed.workspace)}/${encodeURIComponent(parsed.slug)}`,
  );

  if (!meta.ok) {
    const detail = parseBitbucketErrorBody(meta.data, meta.raw);
    if (meta.status === 404) {
      throw new Error(
        `Repository ${parsed.workspace}/${parsed.slug} was not found or your Bitbucket account cannot access it.`,
      );
    }
    if (meta.status === 401 || meta.status === 403) {
      throw new BitbucketCredentialsInvalidError(
        detail ||
          "Bitbucket denied access. Reconnect Bitbucket under Settings → Integrations and try again.",
      );
    }
    throw new Error(detail || "Could not load repository from Bitbucket");
  }

  const repo = meta.data;
  if (!repo?.uuid || !repo.slug) {
    throw new Error("Unexpected response from Bitbucket");
  }

  const clones = repo.links?.clone;
  const httpsClone = Array.isArray(clones)
    ? clones.find((c) => c.name === "https" && c.href)?.href
    : null;

  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      OR: [
        { bitbucketRepoUuid: normalizeBitbucketUuid(repo.uuid) },
        {
          repoUrl: {
            contains: `${parsed.workspace}/${repo.slug}`,
          },
        },
      ],
    },
    select: { id: true },
  });

  const record = await connectBitbucketRepositoryRecord({
    organizationId: params.organizationId,
    userId: params.userId,
    workspace: parsed.workspace,
    slug: repo.slug,
    bitbucketRepoUuid: normalizeBitbucketUuid(repo.uuid),
    cloneUrl:
      httpsClone?.trim() ||
      bitbucketHttpsCloneUrl(parsed.workspace, parsed.slug),
    defaultBranch: repo.mainbranch?.name || "main",
    language: repo.language ?? null,
    connectedViaBitbucket: true,
    branch: params.branch,
    queueInitialScan: !existing,
  });

  return record;
}
