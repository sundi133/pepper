import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { GITHUB_APP_STATE_COOKIE, exchangeAppUserCode, getInstallation, githubAppConfig, userCanAccessInstallation } from "@/lib/github-app";
import { oauthStateCookieOptions, verifyGithubOAuthState } from "@/lib/github-oauth-state";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

/**
 * Where GitHub sends the user after installing the App (the App's Callback
 * URL, with "Request user authorization during installation" on). Links the
 * installation to the organization only after proving that the person who
 * installed it can access it (docs/GITHUB_APP_SPEC.md §5).
 */
function back(req: NextRequest, status: "installed" | "error", message?: string): NextResponse {
  const base = process.env.NEXTAUTH_URL?.replace(/\/$/, "") || req.nextUrl.origin;
  const url = new URL("/settings/integrations", base);
  url.searchParams.set("githubApp", status);
  if (message) url.searchParams.set("message", message.slice(0, 200));
  return NextResponse.redirect(url);
}

export async function GET(req: NextRequest) {
  const params = req.nextUrl.searchParams;
  const cookieStore = await cookies();
  const cookieState = cookieStore.get(GITHUB_APP_STATE_COOKIE)?.value;
  cookieStore.set(GITHUB_APP_STATE_COOKIE, "", { ...oauthStateCookieOptions(), maxAge: 0 });

  const cfg = githubAppConfig();
  if (!cfg) return back(req, "error", "The GitHub App is not configured on this Pepper server.");

  const setupAction = params.get("setup_action");
  if (setupAction === "request") {
    return back(req, "error", "The installation was requested; a GitHub organization owner must approve it, then install it from Pepper again.");
  }

  // 1. The state Pepper issued, for this signed-in user and organization.
  const payload = verifyGithubOAuthState(params.get("state") || "", cookieState);
  if (!payload) return back(req, "error", "Start the installation from Pepper (Settings → Integrations), then try again.");
  const auth = await requireAuth();
  if ("error" in auth) return back(req, "error", "Sign in to Pepper and try again.");
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId || orgId !== payload.orgId || auth.session.user.id !== payload.userId) {
    return back(req, "error", "This installation was started by a different user or organization.");
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return back(req, "error", "Only Admin and Security users can connect the GitHub App.");

  const installationId = Number(params.get("installation_id"));
  const code = params.get("code");
  if (!Number.isSafeInteger(installationId) || installationId <= 0 || !code) {
    return back(req, "error", "GitHub did not return an installation. Check that the App requests user authorization during installation.");
  }

  // 2. The person who installed can access this installation (no linking by editing the URL).
  const userToken = await exchangeAppUserCode(cfg, code);
  if (!userToken || !(await userCanAccessInstallation(userToken, installationId))) {
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "github_app.link_refused",
      resource: "integration",
      details: { installationId, reason: "user cannot access installation" },
      ipAddress: ipFromHeaders(req.headers),
    });
    return back(req, "error", "Your GitHub account can't access that installation.");
  }

  // 3. The installation itself, as the App sees it.
  const info = await getInstallation(cfg, installationId);
  if (!info?.account) return back(req, "error", "GitHub did not return the installation's details. Try again.");

  // 4. One organization per installation.
  const existing = await prisma.orgGithubAppInstallation.findUnique({ where: { installationId: BigInt(installationId) } });
  if (existing && existing.organizationId !== orgId) {
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "github_app.link_refused",
      resource: "integration",
      details: { installationId, account: info.account.login, reason: "linked to another organization" },
      ipAddress: ipFromHeaders(req.headers),
    });
    return back(req, "error", `The installation on ${info.account.login} is already linked to another Pepper organization.`);
  }

  const data = {
    accountLogin: info.account.login,
    accountType: info.account.type,
    repositorySelection: info.repository_selection,
    suspendedAt: info.suspended_at ? new Date(info.suspended_at) : null,
  };
  await prisma.orgGithubAppInstallation.upsert({
    where: { installationId: BigInt(installationId) },
    create: { organizationId: orgId, installationId: BigInt(installationId), createdBy: auth.session.user.id, ...data },
    update: data,
  });
  if (!existing) {
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "github_app.installed",
      resource: "integration",
      details: { installationId, account: info.account.login, repositorySelection: info.repository_selection },
      ipAddress: ipFromHeaders(req.headers),
    });
  }
  return back(req, "installed");
}
