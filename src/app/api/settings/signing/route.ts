import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getActiveOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { decryptSecret, encryptSecret } from "@/lib/token-encryption";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { inspectSigningKey, keylessSigningStatus, type SigningKeyInfo } from "@/lib/code-signing";

const putSchema = z.object({
  enabled: z.boolean(),
  mode: z.enum(["keyless", "key"]),
  identity: z.string().trim().max(256).optional(),
  /** A new PEM key; null removes the stored key; omitted keeps it. */
  privateKeyPem: z.string().max(16_384).nullable().optional(),
});

function storedKeyInfo(enc: string | null | undefined): SigningKeyInfo | null {
  if (!enc) return null;
  try {
    return inspectSigningKey(decryptSecret(enc));
  } catch {
    return null;
  }
}

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const [settings, keyless, lastSigned, lastFailure] = await Promise.all([
    prisma.orgSettings.findUnique({
      where: { organizationId: orgId },
      select: {
        codeSigningEnabled: true,
        codeSigningMode: true,
        codeSigningKeyEnc: true,
        codeSigningIdentity: true,
      },
    }),
    keylessSigningStatus(),
    prisma.scanArtifact.findFirst({
      where: { type: "SIGNATURE", scan: { project: { organizationId: orgId } } },
      orderBy: { createdAt: "desc" },
      select: { scanId: true, createdAt: true },
    }),
    prisma.auditLog.findFirst({
      where: { organizationId: orgId, action: "scan.signing_failed" },
      orderBy: { createdAt: "desc" },
      select: { resourceId: true, createdAt: true, details: true },
    }),
  ]);
  const key = storedKeyInfo(settings?.codeSigningKeyEnc);
  const failures = (lastFailure?.details as { failures?: Record<string, string> } | null)
    ?.failures;
  return NextResponse.json({
    enabled: settings?.codeSigningEnabled ?? false,
    mode: settings?.codeSigningMode ?? "keyless",
    identity: settings?.codeSigningIdentity ?? "",
    hasKey: !!settings?.codeSigningKeyEnc,
    // A stored key that no longer decrypts or parses (e.g. rotated
    // encryption secret) is reported so the page can ask for a new one.
    keyValid: key !== null,
    key: key
      ? {
          type: key.keyType,
          bits: key.bits,
          fingerprint: key.fingerprint,
          publicKeyPem: key.publicKeyPem,
        }
      : null,
    keyless,
    lastSigned: lastSigned
      ? { scanId: lastSigned.scanId, at: lastSigned.createdAt }
      : null,
    lastFailure:
      lastFailure && (!lastSigned || lastFailure.createdAt > lastSigned.createdAt)
        ? {
            scanId: lastFailure.resourceId,
            at: lastFailure.createdAt,
            reason: failures ? Object.values(failures)[0] : undefined,
          }
        : null,
  });
}

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const parsed = putSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? "Invalid request" },
      { status: 400 },
    );
  }
  const body = parsed.data;

  const existing = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: { codeSigningKeyEnc: true },
  });
  const previousKey = storedKeyInfo(existing?.codeSigningKeyEnc);

  // Validate a new key before storing it, so a bad PEM fails here instead of
  // silently in the worker on every scan.
  let newKey: SigningKeyInfo | null = null;
  let codeSigningKeyEnc: string | null | undefined;
  if (body.privateKeyPem === null) {
    codeSigningKeyEnc = null;
  } else if (body.privateKeyPem && body.privateKeyPem.trim()) {
    try {
      newKey = inspectSigningKey(body.privateKeyPem);
    } catch (e) {
      return NextResponse.json({ error: (e as Error).message }, { status: 400 });
    }
    codeSigningKeyEnc = encryptSecret(body.privateKeyPem.trim());
  }

  const willHaveKey =
    codeSigningKeyEnc === undefined ? previousKey !== null : codeSigningKeyEnc !== null;
  if (body.enabled && body.mode === "key" && !willHaveKey) {
    return NextResponse.json(
      { error: "Upload a private key before enabling key-based signing" },
      { status: 400 },
    );
  }
  // Keyless readiness isn't enforced here: it's checked on this web server,
  // while signing runs on the worker, which may have cosign and a token.
  // The page shows the status and the worker reports real failures.

  const data = {
    codeSigningEnabled: body.enabled,
    codeSigningMode: body.mode,
    codeSigningIdentity: body.identity || null,
    ...(codeSigningKeyEnc !== undefined ? { codeSigningKeyEnc } : {}),
  };
  await prisma.orgSettings.upsert({
    where: { organizationId: orgId },
    create: { organizationId: orgId, ...data },
    update: data,
  });

  const ipAddress = ipFromHeaders(req.headers);
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.signing.updated",
    resource: "settings",
    resourceId: orgId,
    details: { enabled: body.enabled, mode: body.mode, identity: body.identity || null },
    ipAddress,
  });
  if (codeSigningKeyEnc !== undefined) {
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "settings.signing.key_changed",
      resource: "settings",
      resourceId: orgId,
      details: {
        change: newKey ? (previousKey ? "replaced" : "added") : "removed",
        previousFingerprint: previousKey?.fingerprint ?? null,
        fingerprint: newKey?.fingerprint ?? null,
      },
      ipAddress,
    });
  }

  return NextResponse.json({ ok: true });
}
