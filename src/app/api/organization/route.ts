import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";

export async function PATCH(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { name } = await request.json();

    if (!name || typeof name !== "string" || !name.trim()) {
      return NextResponse.json(
        { error: "Organization name is required" },
        { status: 400 }
      );
    }

    // Get user's organization
    const membership = await prisma.orgMember.findFirst({
      where: { userId: session.user.id },
      include: { organization: true },
    });

    if (!membership) {
      return NextResponse.json(
        { error: "User does not belong to any organization" },
        { status: 400 }
      );
    }

    // Check if user is admin
    if (membership.role !== "ADMIN") {
      return NextResponse.json(
        { error: "Only admins can update organization settings" },
        { status: 403 }
      );
    }

    // Update organization name
    const updated = await prisma.organization.update({
      where: { id: membership.organizationId },
      data: { name: name.trim() },
    });

    return NextResponse.json({
      success: true,
      organization: { id: updated.id, name: updated.name },
    }, {
      headers: {
        "x-nextauth-event": "Update"
      }
    });
  } catch (error) {
    console.error("Error updating organization:", error);
    return NextResponse.json(
      { error: "Failed to update organization" },
      { status: 500 }
    );
  }
}
