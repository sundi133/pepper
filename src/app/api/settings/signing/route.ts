import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { encryptSecret } from "@/lib/token-encryption";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: {
      codeSigningEnabled: true,
      codeSigningMode: true,
      codeSigningKeyEnc: true,
      codeSigningIdentity: true,
    },
  });
  return NextResponse.json({
    enabled: settings?.codeSigningEnabled ?? false,
    mode: settings?.codeSigningMode ?? "keyless",
    identity: settings?.codeSigningIdentity ?? "",
    hasKey: !!settings?.codeSigningKeyEnc,
  });
}

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const body = (await req.json()) as {
    enabled?: boolean;
    mode?: "keyless" | "key";
    identity?: string;
    privateKeyPem?: string | null;
  };

  let codeSigningKeyEnc: string | null | undefined;
  if (body.privateKeyPem === null) codeSigningKeyEnc = null;
  else if (typeof body.privateKeyPem === "string" && body.privateKeyPem.length > 0) {
    codeSigningKeyEnc = encryptSecret(body.privateKeyPem);
  }

  await prisma.orgSettings.upsert({
    where: { organizationId: orgId },
    create: {
      organizationId: orgId,
      codeSigningEnabled: body.enabled ?? false,
      codeSigningMode: body.mode ?? "keyless",
      codeSigningIdentity: body.identity || null,
      ...(codeSigningKeyEnc !== undefined ? { codeSigningKeyEnc } : {}),
    },
    update: {
      codeSigningEnabled: body.enabled ?? false,
      codeSigningMode: body.mode ?? "keyless",
      codeSigningIdentity: body.identity || null,
      ...(codeSigningKeyEnc !== undefined ? { codeSigningKeyEnc } : {}),
    },
  });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.signing.updated",
    resource: "settings",
    resourceId: orgId,
    details: { enabled: body.enabled, mode: body.mode },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ ok: true });
}
