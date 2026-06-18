import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { createApiKey, listApiKeys } from "@/lib/api-key";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const keys = await listApiKeys(orgId);
  return NextResponse.json({ keys });
}

export async function POST(req: NextRequest) {
  try {
    const auth = await requireAuth();
    if ("error" in auth) return auth.error;
    let orgId = getDefaultOrgId(auth.session);
    if (!orgId) {
      // Auto-create org if user has none
      const org = await prisma.organization.create({
        data: {
          name: `${auth.session.user.email || "User"}'s org`,
          slug: `org-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        },
      });
      await prisma.orgMember.create({
        data: {
          userId: auth.session.user.id,
          organizationId: org.id,
          role: "admin",
        },
      });
      orgId = org.id;
    }
    const body = (await req.json()) as {
      name?: string;
      expiresAt?: string | null;
    };
    if (!body.name?.trim()) {
      return NextResponse.json({ error: "name is required" }, { status: 400 });
    }
    const created = await createApiKey({
      organizationId: orgId,
      createdBy: auth.session.user.id,
      name: body.name.trim(),
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
    });
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "apikey.created",
      resource: "apikey",
      resourceId: created.id,
      details: { name: created.name, prefix: created.prefix },
      ipAddress: ipFromHeaders(req.headers),
    });
    return NextResponse.json(created, { status: 201 });
  } catch (err) {
    console.error("API key creation error:", err);
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
