import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { encryptSecret } from "@/lib/token-encryption";
import { z } from "zod";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  return NextResponse.json({
    containerRegistryType: settings?.containerRegistryType || null,
    containerRegistryRegion: settings?.containerRegistryRegion || null,
    hasCredentials: !!(settings?.containerRegistryUsernameEnc),
  });
}

const updateSchema = z.object({
  containerRegistryType: z
    .enum(["dockerhub", "ecr", "gcr", "ghcr", "custom"])
    .nullable()
    .optional(),
  containerRegistryUsername: z.string().optional(),
  containerRegistryPassword: z.string().optional(),
  containerRegistryRegion: z.string().optional(),
});

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  try {
    const body = await req.json();
    const data = updateSchema.parse(body);

    const updateData: Record<string, unknown> = {};

    if (data.containerRegistryType !== undefined) {
      updateData.containerRegistryType = data.containerRegistryType;
    }
    if (data.containerRegistryRegion !== undefined) {
      updateData.containerRegistryRegion = data.containerRegistryRegion || null;
    }

    // Encrypt credentials — empty string means "keep existing"
    if (data.containerRegistryUsername && data.containerRegistryUsername !== "") {
      updateData.containerRegistryUsernameEnc = encryptSecret(
        data.containerRegistryUsername,
      );
    }
    if (data.containerRegistryPassword && data.containerRegistryPassword !== "") {
      updateData.containerRegistryPasswordEnc = encryptSecret(
        data.containerRegistryPassword,
      );
    }

    // If type is explicitly set to null, clear all credentials
    if (data.containerRegistryType === null) {
      updateData.containerRegistryUsernameEnc = null;
      updateData.containerRegistryPasswordEnc = null;
      updateData.containerRegistryRegion = null;
    }

    await prisma.orgSettings.upsert({
      where: { organizationId: orgId },
      update: updateData,
      create: {
        organizationId: orgId,
        ...updateData,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update container registry settings" },
      { status: 500 },
    );
  }
}
