import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

const updatePolicySchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().optional(),
  rule: z.string().min(10).max(2000).optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional(),
  category: z.string().optional(),
  enabled: z.boolean().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ policyId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { policyId } = await params;

  try {
    const body = await req.json();
    const data = updatePolicySchema.parse(body);

    const existingPolicy = await prisma.securityPolicy.findFirst({
      where: { id: policyId, organizationId: orgId },
      select: { id: true },
    });

    if (!existingPolicy) {
      return NextResponse.json({ error: "Policy not found" }, { status: 404 });
    }

    const policy = await prisma.securityPolicy.update({
      where: { id: policyId },
      data,
    });

    return NextResponse.json(policy);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update policy" },
      { status: 500 },
    );
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ policyId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { policyId } = await params;

  const result = await prisma.securityPolicy.deleteMany({
    where: { id: policyId, organizationId: orgId },
  });

  if (result.count === 0) {
    return NextResponse.json({ error: "Policy not found" }, { status: 404 });
  }

  return NextResponse.json({ success: true });
}
