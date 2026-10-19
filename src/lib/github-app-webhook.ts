/**
 * Webhook deliveries from the GitHub App (docs/GITHUB_APP_SPEC.md §8): signed
 * with the App's webhook secret and carrying `installation.id`. The linked
 * installation decides the organization; lifecycle events keep the link current.
 */
import { createHmac, timingSafeEqual } from "crypto";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { forgetInstallationToken } from "@/lib/github-app";

export function verifyAppWebhookSignature(body: string, signature: string | null, secret: string | null | undefined): boolean {
  if (!signature || !secret) return false;
  const expected = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export type AppWebhookAuth =
  | { kind: "not-app" }
  | { kind: "handled"; message: string }
  | { kind: "event"; organizationId: string; installationId: bigint };

/**
 * App-signed deliveries: lifecycle events are applied here; repository events
 * return the linked organization (or are ignored when the installation isn't
 * linked to one). Anything else is "not-app" and goes through the per-organization
 * webhook secrets as before.
 */
export async function authenticateAppWebhook(params: {
  body: string;
  signature: string | null;
  event: string | null;
  secret: string | null | undefined;
}): Promise<AppWebhookAuth> {
  if (!params.secret || !verifyAppWebhookSignature(params.body, params.signature, params.secret)) return { kind: "not-app" };
  let payload: { action?: string; installation?: { id?: number } };
  try {
    payload = JSON.parse(params.body);
  } catch {
    return { kind: "handled", message: "Invalid payload" };
  }
  const id = payload.installation?.id;
  if (typeof id !== "number") return { kind: "handled", message: "Event ignored" };
  const installationId = BigInt(id);

  if (params.event === "installation") {
    const action = payload.action;
    if (action === "deleted") {
      forgetInstallationToken(installationId);
      const { count } = await prisma.orgGithubAppInstallation.deleteMany({ where: { installationId } });
      logger.info({ installationId: String(installationId), unlinked: count }, "GitHub App uninstalled");
      return { kind: "handled", message: "Installation removed" };
    }
    if (action === "suspend" || action === "unsuspend") {
      forgetInstallationToken(installationId);
      await prisma.orgGithubAppInstallation.updateMany({
        where: { installationId },
        data: { suspendedAt: action === "suspend" ? new Date() : null },
      });
      return { kind: "handled", message: `Installation ${action}ed` };
    }
    return { kind: "handled", message: "Event ignored" };
  }
  if (params.event === "installation_repositories" || params.event === "ping") {
    // Repositories are listed live; nothing is stored per repository.
    return { kind: "handled", message: "Event ignored" };
  }

  const link = await prisma.orgGithubAppInstallation.findUnique({
    where: { installationId },
    select: { organizationId: true, suspendedAt: true },
  });
  if (!link || link.suspendedAt) return { kind: "handled", message: "Installation not linked to an organization" };
  return { kind: "event", organizationId: link.organizationId, installationId };
}
