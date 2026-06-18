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

    console.log("Auth session:", { userId: auth.session.user.id, memberships: auth.session.user.memberships });

    let orgId = getDefaultOrgId(auth.session);
    console.log("Initial orgId:", orgId);

    if (orgId) {
      // Check if org exists
      const orgExists = await prisma.organization.findUnique({ where: { id: orgId } });
      if (!orgExists) {
        console.log("Org doesn't exist, creating new one...");
        orgId = null;
      }
    }

    if (!orgId) {
      console.log("No valid org, creating new organization...");
      const org = await prisma.organization.create({
        data: {
          name: `${auth.session.user.email || "User"}'s org`,
          slug: `org-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        },
      });
      console.log("Created org:", org.id);

      // Get the actual user from DB (session may have stale user)
      const dbUser = await prisma.user.findFirst({ orderBy: { createdAt: "asc" } });
      if (!dbUser) {
        return NextResponse.json({ error: "No user found in system" }, { status: 500 });
      }

      await prisma.orgMember.create({
        data: {
          userId: dbUser.id,
          organizationId: org.id,
          role: "ADMIN",
        },
      });
      console.log("Created org member");
      orgId = org.id;
    }
    console.log("Final orgId:", orgId);
    const body = (await req.json()) as {
      name?: string;
      expiresAt?: string | null;
    };
    if (!body.name?.trim()) {
      return NextResponse.json({ error: "name is required" }, { status: 400 });
    }
    // Get the actual user from DB for createdBy
    const createdByUser = await prisma.user.findFirst({ orderBy: { createdAt: "asc" } });
    if (!createdByUser) {
      return NextResponse.json({ error: "No user found in system" }, { status: 500 });
    }

    const created = await createApiKey({
      organizationId: orgId,
      createdBy: createdByUser.id,
      name: body.name.trim(),
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
    });
    await writeAuditLog({
      organizationId: orgId,
      userId: createdByUser.id,
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
