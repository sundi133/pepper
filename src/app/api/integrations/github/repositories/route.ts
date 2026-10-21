import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import {
  getOrgGithubAccessTokenOrThrow,
  GithubTokenInvalidError,
} from "@/lib/github-connection";
import { listGithubRepositoriesForUser } from "@/lib/github-repos";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const token = await getOrgGithubAccessTokenOrThrow(orgId);

    const existing = await prisma.project.findMany({
      where: {
        organizationId: orgId,
        githubRepoId: { not: null },
      },
      select: { githubRepoId: true },
    });
    const connectedIds = new Set(
      existing
        .map((p) => p.githubRepoId)
        .filter((id): id is number => id != null),
    );

    const repositories = await listGithubRepositoriesForUser(
      token,
      connectedIds,
    );

    return NextResponse.json({ repositories });
  } catch (e) {
    if (e instanceof GithubTokenInvalidError) {
      return NextResponse.json(
        {
          error:
            "GitHub connection expired or was revoked. Connect GitHub again from this page.",
          code: "GITHUB_TOKEN_INVALID",
        },
        { status: 401 },
      );
    }
    const msg = e instanceof Error ? e.message : "Failed to list repositories";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
