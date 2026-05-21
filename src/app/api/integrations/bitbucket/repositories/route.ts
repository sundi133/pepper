import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import {
  getOrgBitbucketAuthOrThrow,
  getBitbucketConnectionStatus,
  BitbucketCredentialsInvalidError,
} from "@/lib/bitbucket-connection";
import { listBitbucketRepositoriesInWorkspace } from "@/lib/bitbucket-repos";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const status = await getBitbucketConnectionStatus(orgId);
    const workspace = status.workspace?.trim();
    if (!workspace) {
      return NextResponse.json(
        {
          error:
            "Set your Bitbucket workspace when connecting (Settings → Integrations → Bitbucket) to browse repositories.",
          code: "BITBUCKET_WORKSPACE_REQUIRED",
        },
        { status: 400 },
      );
    }

    const bbAuth = await getOrgBitbucketAuthOrThrow(orgId);

    const existing = await prisma.project.findMany({
      where: {
        organizationId: orgId,
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

    const repositories = await listBitbucketRepositoriesInWorkspace(
      bbAuth,
      workspace,
      connectedUuids,
    );

    return NextResponse.json({ repositories, workspace });
  } catch (e) {
    if (e instanceof BitbucketCredentialsInvalidError) {
      return NextResponse.json(
        {
          error:
            "Bitbucket connection expired or was revoked. Connect Bitbucket again under Settings → Integrations.",
          code: "BITBUCKET_CREDENTIALS_INVALID",
        },
        { status: 401 },
      );
    }
    const msg = e instanceof Error ? e.message : "Failed to list repositories";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
