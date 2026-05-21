import { NextResponse, type NextRequest } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { encryptSecret, decryptSecret } from "@/lib/token-encryption";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

type WebhookSecretBody = {
  github?: string | null;
  gitlab?: string | null;
  bitbucket?: string | null;
  azureDevOps?: string | null;
};

function encField(
  value: string | null | undefined,
): string | null | undefined {
  if (value === null) return null;
  if (typeof value === "string" && value.trim().length > 0) {
    return encryptSecret(value.trim());
  }
  return undefined;
}

function decryptField(enc: string | null | undefined): string | null {
  if (!enc) return null;
  try {
    return decryptSecret(enc);
  } catch {
    return null;
  }
}

function migrationHint(err: unknown): string | null {
  const msg = err instanceof Error ? err.message : String(err);
  if (
    msg.includes("githubWebhookSecretEnc") ||
    msg.includes("Unknown column") ||
    msg.includes("does not exist")
  ) {
    return "Database migration pending. Run: npx prisma migrate deploy";
  }
  return null;
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const reveal = req.nextUrl.searchParams.get("reveal") === "1";

  try {
    const settings = await prisma.orgSettings.findUnique({
      where: { organizationId: orgId },
      select: {
        githubWebhookSecretEnc: true,
        gitlabWebhookSecretEnc: true,
        bitbucketWebhookSecretEnc: true,
        azureDevOpsWebhookSecretEnc: true,
      },
    });

    return NextResponse.json({
      hasGithub: !!settings?.githubWebhookSecretEnc,
      hasGitlab: !!settings?.gitlabWebhookSecretEnc,
      hasBitbucket: !!settings?.bitbucketWebhookSecretEnc,
      hasAzureDevOps: !!settings?.azureDevOpsWebhookSecretEnc,
      envFallback: {
        github: !!process.env.GITHUB_WEBHOOK_SECRET?.trim(),
        gitlab: !!process.env.GITLAB_WEBHOOK_SECRET?.trim(),
        bitbucket: !!process.env.BITBUCKET_WEBHOOK_SECRET?.trim(),
        azureDevOps: !!process.env.AZURE_DEVOPS_WEBHOOK_SECRET?.trim(),
      },
      ...(reveal
        ? {
            github: decryptField(settings?.githubWebhookSecretEnc),
            gitlab: decryptField(settings?.gitlabWebhookSecretEnc),
            bitbucket: decryptField(settings?.bitbucketWebhookSecretEnc),
            azureDevOps: decryptField(settings?.azureDevOpsWebhookSecretEnc),
          }
        : {}),
    });
  } catch (err) {
    const hint = migrationHint(err);
    return NextResponse.json(
      {
        error: hint || "Failed to load webhook settings",
        detail: err instanceof Error ? err.message : String(err),
      },
      { status: hint ? 503 : 500 },
    );
  }
}

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  let body: WebhookSecretBody;
  try {
    body = (await req.json()) as WebhookSecretBody;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const githubWebhookSecretEnc = encField(body.github);
  const gitlabWebhookSecretEnc = encField(body.gitlab);
  const bitbucketWebhookSecretEnc = encField(body.bitbucket);
  const azureDevOpsWebhookSecretEnc = encField(body.azureDevOps);

  const hasUpdate =
    githubWebhookSecretEnc !== undefined ||
    gitlabWebhookSecretEnc !== undefined ||
    bitbucketWebhookSecretEnc !== undefined ||
    azureDevOpsWebhookSecretEnc !== undefined;

  if (!hasUpdate) {
    return NextResponse.json(
      {
        error:
          "Nothing to save. Enter a new secret, generate one, or click Clear on a saved secret.",
      },
      { status: 400 },
    );
  }

  try {
    await prisma.orgSettings.upsert({
      where: { organizationId: orgId },
      create: {
        organizationId: orgId,
        ...(githubWebhookSecretEnc !== undefined
          ? { githubWebhookSecretEnc }
          : {}),
        ...(gitlabWebhookSecretEnc !== undefined
          ? { gitlabWebhookSecretEnc }
          : {}),
        ...(bitbucketWebhookSecretEnc !== undefined
          ? { bitbucketWebhookSecretEnc }
          : {}),
        ...(azureDevOpsWebhookSecretEnc !== undefined
          ? { azureDevOpsWebhookSecretEnc }
          : {}),
      },
      update: {
        ...(githubWebhookSecretEnc !== undefined
          ? { githubWebhookSecretEnc }
          : {}),
        ...(gitlabWebhookSecretEnc !== undefined
          ? { gitlabWebhookSecretEnc }
          : {}),
        ...(bitbucketWebhookSecretEnc !== undefined
          ? { bitbucketWebhookSecretEnc }
          : {}),
        ...(azureDevOpsWebhookSecretEnc !== undefined
          ? { azureDevOpsWebhookSecretEnc }
          : {}),
      },
    });
  } catch (err) {
    const hint = migrationHint(err);
    if (err instanceof Error && err.message.includes("TOKEN_ENCRYPTION_KEY")) {
      return NextResponse.json(
        {
          error: "Server encryption is not configured",
          detail:
            "Set NEXTAUTH_SECRET or TOKEN_ENCRYPTION_KEY on the Pepper server.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      {
        error: hint || "Failed to save webhook secrets",
        detail: err instanceof Error ? err.message : String(err),
      },
      { status: hint ? 503 : 500 },
    );
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.webhooks.updated",
    resource: "settings",
    resourceId: orgId,
    details: {
      github: githubWebhookSecretEnc !== undefined,
      gitlab: gitlabWebhookSecretEnc !== undefined,
      bitbucket: bitbucketWebhookSecretEnc !== undefined,
      azureDevOps: azureDevOpsWebhookSecretEnc !== undefined,
    },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ ok: true });
}
