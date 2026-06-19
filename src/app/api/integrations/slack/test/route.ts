import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { getIntegrationConfig } from "@/lib/integrations";
import { notifySlackScanComplete } from "@/lib/integrations/slack";

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const body = await req.json();
  const { id } = body;

  try {
    // Get the integration config
    const integration = await getIntegrationConfig(orgId, "SLACK", id);
    if (!integration) {
      return NextResponse.json(
        { error: "Slack integration not found" },
        { status: 404 },
      );
    }

    // Send test message
    await notifySlackScanComplete(integration.config, {
      projectName: "Test Notification",
      scanId: "test-scan-123",
      branch: "main",
      severityCounts: {
        critical: 2,
        high: 5,
        medium: 8,
        low: 3,
        info: 1,
      },
      gateResult: "FAILED",
      scanUrl: "https://pepper.local/scans/test-scan-123",
    });

    return NextResponse.json({
      success: true,
      message: "Test message sent to Slack successfully",
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to send test message";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
