import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

const createPolicySchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  rule: z.string().min(10).max(2000),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).default("HIGH"),
  category: z.string().optional(),
  enabled: z.boolean().default(true),
});

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const policies = await prisma.securityPolicy.findMany({
    where: { organizationId: orgId },
    orderBy: [{ enabled: "desc" }, { severity: "asc" }, { name: "asc" }],
  });

  return NextResponse.json({ policies });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  try {
    const body = await req.json();
    const data = createPolicySchema.parse(body);

    const policy = await prisma.securityPolicy.create({
      data: {
        ...data,
        organizationId: orgId,
      },
    });

    return NextResponse.json(policy, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to create policy" },
      { status: 500 },
    );
  }
}
