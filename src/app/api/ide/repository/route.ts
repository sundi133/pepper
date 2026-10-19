import { NextRequest, NextResponse } from "next/server";
import { resolveApiKeyPrincipal } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { matchRepository, type RepositoryRow } from "@/lib/ide-repository";

/**
 * Which repository an IDE workspace belongs to, from its git remote
 * (docs/IDE_EXTENSION_SPEC.md §4.1). API key only; only the key's
 * organization's repositories are considered.
 *
 * GET /api/ide/repository?remote=git@github.com:org/repo.git&name=repo
 * GET /api/ide/repository?all=true   (every repository, for a picker)
 */
export async function GET(req: NextRequest) {
  const principal = await resolveApiKeyPrincipal(req.headers.get("authorization"));
  if (!principal) {
    return NextResponse.json({ error: "Invalid or missing API key" }, { status: 401 });
  }

  const url = new URL(req.url);
  const remote = url.searchParams.get("remote")?.slice(0, 2000) ?? null;
  const name = url.searchParams.get("name")?.slice(0, 200) ?? null;
  const all = url.searchParams.get("all") === "true";
  if (!remote && !name && !all) {
    return NextResponse.json({ error: "remote or name is required" }, { status: 400 });
  }

  const repos = await prisma.project.findMany({
    where: { organizationId: principal.organizationId },
    select: {
      id: true,
      name: true,
      repoUrl: true,
      defaultBranch: true,
      githubOwner: true,
      githubRepoName: true,
      bitbucketWorkspace: true,
      bitbucketRepoSlug: true,
      azureOrganization: true,
      azureProjectName: true,
      azureRepoName: true,
      gitlabNamespace: true,
    },
    orderBy: { updatedAt: "desc" },
    take: 5000,
  });

  const match = all ? { repository: null, matchedBy: null, candidates: repos.slice(0, 500) } : matchRepository(remote, name, repos);
  const view = (r: RepositoryRow) => ({ id: r.id, name: r.name, repoUrl: r.repoUrl, defaultBranch: r.defaultBranch });
  return NextResponse.json({
    repository: match.repository ? view(match.repository) : null,
    matchedBy: match.matchedBy,
    candidates: match.candidates.map(view),
  });
}
