import { NextResponse, type NextRequest } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { encryptSecret, decryptSecret } from "@/lib/token-encryption";
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
    select: { dastEnabled: true, dastEndpoint: true, dastApiKeyEnc: true },
  });
  return NextResponse.json({
    enabled: settings?.dastEnabled ?? false,
    endpoint: settings?.dastEndpoint ?? "",
    hasApiKey: !!settings?.dastApiKeyEnc,
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
    endpoint?: string;
    apiKey?: string | null;
  };

  let dastApiKeyEnc: string | null | undefined;
  if (body.apiKey === null) dastApiKeyEnc = null;
  else if (typeof body.apiKey === "string" && body.apiKey.length > 0) {
    dastApiKeyEnc = encryptSecret(body.apiKey);
  }

  await prisma.orgSettings.upsert({
    where: { organizationId: orgId },
    create: {
      organizationId: orgId,
      dastEnabled: body.enabled ?? false,
      dastEndpoint: body.endpoint || null,
      ...(dastApiKeyEnc !== undefined ? { dastApiKeyEnc } : {}),
    },
    update: {
      dastEnabled: body.enabled ?? false,
      dastEndpoint: body.endpoint || null,
      ...(dastApiKeyEnc !== undefined ? { dastApiKeyEnc } : {}),
    },
  });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.dast.updated",
    resource: "settings",
    resourceId: orgId,
    details: { enabled: body.enabled, endpointSet: !!body.endpoint },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ ok: true });
}

export async function POST() {
  // Test dapper reachability
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: { dastEndpoint: true, dastApiKeyEnc: true },
  });
  const endpoint = settings?.dastEndpoint;
  if (!endpoint) {
    return NextResponse.json({ error: "Dapper endpoint not configured" }, { status: 400 });
  }
  let apiKey: string | undefined;
  if (settings?.dastApiKeyEnc) {
    try {
      apiKey = decryptSecret(settings.dastApiKeyEnc);
    } catch {
      /* ignore */
    }
  }
  try {
    const res = await fetch(`${endpoint.replace(/\/+$/, "")}/health`, {
      headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
    });
    return NextResponse.json({ ok: res.ok, status: res.status });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : "fetch failed" },
      { status: 502 },
    );
  }
}
