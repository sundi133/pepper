import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const superAdmin = await prisma.superAdmin.findUnique({
      where: { userId: session.user.id },
    });

    if (!superAdmin) {
      return NextResponse.json({ error: "Not a super admin" }, { status: 403 });
    }

    return NextResponse.json({ isSuperAdmin: true });
  } catch (error) {
    console.error("Error verifying super admin:", error);
    return NextResponse.json(
      { error: "Failed to verify" },
      { status: 500 }
    );
  }
}
