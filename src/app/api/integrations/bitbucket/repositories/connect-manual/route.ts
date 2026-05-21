import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { connectManualBitbucketRepository } from "@/lib/connect-manual-bitbucket-repository";
import { BitbucketCredentialsInvalidError } from "@/lib/bitbucket-connection";

const bodySchema = z.object({
  repoUrl: z.string().min(1).max(500),
  branch: z.string().max(200).optional(),
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
    const result = await connectManualBitbucketRepository({
      organizationId: orgId,
      userId: auth.session.user.id,
      repoInput: body.repoUrl,
      branch: body.branch,
    });
    return NextResponse.json(
      {
        projectId: result.projectId,
        fullName: result.fullName,
        scanId: result.scanId,
        created: result.created,
      },
      { status: result.created ? 201 : 200 },
    );
  } catch (e) {
    if (e instanceof BitbucketCredentialsInvalidError) {
      return NextResponse.json(
        {
          error: e.message,
          code: "BITBUCKET_NOT_CONNECTED",
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
    const msg =
      e instanceof Error ? e.message : "Failed to connect repository";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}
