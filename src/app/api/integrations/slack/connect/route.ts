import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { upsertIntegration } from "@/lib/integrations";
import { notifySlackScanComplete } from "@/lib/integrations/slack";

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const body = await req.json();
  const { webhookUrl, channel, notifyOn, name } = body;

  if (!webhookUrl) {
    return NextResponse.json(
      { error: "webhookUrl is required" },
      { status: 400 },
    );
  }

  // Validate webhook URL format
  if (!webhookUrl.startsWith("https://hooks.slack.com/")) {
    return NextResponse.json(
      { error: "Invalid Slack webhook URL" },
      { status: 400 },
    );
  }

  try {
    // Test the webhook
    await notifySlackScanComplete(
      { webhookUrl, channel, notifyOn },
      {
        projectName: "Test Project",
        scanId: "test-scan-id",
        branch: "main",
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
        gateResult: "PASSED",
      },
    );

    // Save integration
    const integration = await upsertIntegration(orgId, {
      kind: "SLACK",
      name: name || "Slack",
      enabled: true,
      config: {
        webhookUrl,
        channel,
        notifyOn: notifyOn || ["scan_complete", "gate_failed"],
      },
    });

    return NextResponse.json({
      success: true,
      id: integration.id,
      name: integration.name,
      message: "Slack integration connected successfully",
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to connect Slack";
    return NextResponse.json(
      { error: message },
      { status: 400 },
    );
  }
}
