import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { connectAzureDevOpsRepositories } from "@/lib/connect-azure-devops-repositories";
import { AzureDevOpsCredentialsInvalidError } from "@/lib/azure-devops-connection";

const bodySchema = z.object({
  repoIds: z.array(z.string().min(1)).min(1).max(50),
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
    const result = await connectAzureDevOpsRepositories({
      organizationId: orgId,
      userId: auth.session.user.id,
      repoIds: body.repoIds,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    if (e instanceof AzureDevOpsCredentialsInvalidError) {
      return NextResponse.json(
        {
          error:
            "Azure DevOps connection expired or was revoked. Connect again under Settings → Integrations.",
          code: "AZURE_DEVOPS_CREDENTIALS_INVALID",
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
