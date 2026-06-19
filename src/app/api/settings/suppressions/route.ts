import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { z } from "zod";
import { hashSnippet } from "@/lib/suppression-rules";

const createSchema = z.object({
  projectId: z.string().optional(),
  ruleId: z.string().max(100).optional(),
  cweId: z.string().max(20).optional(),
  scanner: z.string().max(50).optional(),
  filePathPattern: z.string().max(500).optional(),
  titlePattern: z.string().max(300).optional(),
  snippet: z.string().max(5000).optional(),
  reason: z.string().min(1).max(2000),
});

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "50");

  const [rules, total] = await Promise.all([
    prisma.suppressionRule.findMany({
      where: { organizationId: orgId },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.suppressionRule.count({ where: { organizationId: orgId } }),
  ]);

  return NextResponse.json({
    rules,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  try {
    const body = await req.json();
    const data = createSchema.parse(body);

    const rule = await prisma.suppressionRule.create({
      data: {
        organizationId: orgId,
        projectId: data.projectId || null,
        ruleId: data.ruleId || null,
        cweId: data.cweId || null,
        scanner: data.scanner || null,
        filePathPattern: data.filePathPattern || null,
        titlePattern: data.titlePattern || null,
        snippetHash: data.snippet ? hashSnippet(data.snippet) : null,
        reason: data.reason,
        source: "user",
        createdBy: auth.session.user.id,
      },
    });

    return NextResponse.json(rule, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to create suppression rule" },
      { status: 500 },
    );
  }
}
