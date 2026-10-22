import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  getOrgGithubAccessTokenOrThrow,
  GithubTokenInvalidError,
} from "@/lib/github-connection";
import { listGithubBranches } from "@/lib/github-repos";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const owner = searchParams.get("owner");
  const repo = searchParams.get("repo");

  if (!owner || !repo) {
    return NextResponse.json(
      { error: "owner and repo query params required" },
      { status: 400 },
    );
  }

  try {
    const token = await getOrgGithubAccessTokenOrThrow(orgId);
    const branches = await listGithubBranches(token, owner, repo);
    return NextResponse.json({ branches });
  } catch (e) {
    if (e instanceof GithubTokenInvalidError) {
      return NextResponse.json(
        { error: "GitHub token invalid", code: "GITHUB_TOKEN_INVALID" },
        { status: 401 },
      );
    }
    return NextResponse.json(
      { error: "Failed to fetch branches" },
      { status: 502 },
    );
  }
}
