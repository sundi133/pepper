import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { connectBitbucketRepositories } from "@/lib/connect-bitbucket-repositories";
import {
  BitbucketCredentialsInvalidError,
  getBitbucketConnectionStatus,
} from "@/lib/bitbucket-connection";

const bodySchema = z.object({
  repoUuids: z.array(z.string().min(1)).min(1).max(50),
});

export async function POST(req: NextRequest) {
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
            "Bitbucket workspace is required. Reconnect under Settings → Integrations and set your workspace slug.",
          code: "BITBUCKET_WORKSPACE_REQUIRED",
        },
        { status: 400 },
      );
    }

    const body = bodySchema.parse(await req.json());
    const result = await connectBitbucketRepositories({
      organizationId: orgId,
      userId: auth.session.user.id,
      repoUuids: body.repoUuids,
      workspace,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    if (e instanceof BitbucketCredentialsInvalidError) {
      return NextResponse.json(
        {
          error:
            "Bitbucket connection expired or was revoked. Connect Bitbucket again.",
          code: "BITBUCKET_CREDENTIALS_INVALID",
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
