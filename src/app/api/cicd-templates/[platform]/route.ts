import { NextRequest, NextResponse } from "next/server";
import { buildCiTemplates } from "@/lib/cicd-templates";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ platform: string }> },
) {
  const { platform } = await params;
  const templates = buildCiTemplates();
  const t = templates[platform.toLowerCase()];
  if (!t) {
    return NextResponse.json(
      {
        error: "Unknown platform",
        availablePlatforms: Object.keys(templates),
      },
      { status: 404 },
    );
  }
  return new NextResponse(t.body, {
    headers: {
      "Content-Type": `${t.contentType}; charset=utf-8`,
      "Content-Disposition": `attachment; filename="${t.filename}"`,
    },
  });
}
