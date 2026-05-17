import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { connectGithubRepositories } from "@/lib/connect-github-repositories";
import { GithubTokenInvalidError } from "@/lib/github-connection";

const bodySchema = z.object({
  repoIds: z.array(z.number().int().positive()).min(1).max(50),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const body = bodySchema.parse(await req.json());
    const result = await connectGithubRepositories({
      organizationId: orgId,
      userId: auth.session.user.id,
      repoIds: body.repoIds,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    if (e instanceof GithubTokenInvalidError) {
      return NextResponse.json(
        {
          error:
            "GitHub connection expired or was revoked. Connect GitHub again.",
          code: "GITHUB_TOKEN_INVALID",
        },
        { status: 401 },
      );
    }
    if (e instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: e.issues },
        { status: 400 },
      );
    }
    const msg = e instanceof Error ? e.message : "Failed to connect repositories";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
