import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { isGithubAppConfigured } from "@/lib/github-app";

/** GitHub App status for the Integrations page: configured, and the linked installations. */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const configured = isGithubAppConfigured();
  const rows = configured
    ? await prisma.orgGithubAppInstallation.findMany({ where: { organizationId: orgId }, orderBy: { createdAt: "asc" } })
    : [];
  return NextResponse.json({
    configured,
    installations: rows.map((r) => ({
      id: r.id,
      installationId: String(r.installationId),
      accountLogin: r.accountLogin,
      accountType: r.accountType,
      repositorySelection: r.repositorySelection,
      suspended: Boolean(r.suspendedAt),
      createdAt: r.createdAt.toISOString(),
      // Repository selection and uninstalling happen on GitHub.
      configureUrl:
        r.accountType === "Organization"
          ? `https://github.com/organizations/${encodeURIComponent(r.accountLogin)}/settings/installations/${r.installationId}`
          : `https://github.com/settings/installations/${r.installationId}`,
    })),
  });
}
