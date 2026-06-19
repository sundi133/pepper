import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { getIntegrationConfig } from "@/lib/integrations";
import { createJiraIssueForFinding } from "@/lib/integrations/jira";

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
    const integration = await getIntegrationConfig(orgId, "JIRA", id);
    if (!integration) {
      return NextResponse.json(
        { error: "Jira integration not found" },
        { status: 404 },
      );
    }

    // Create test issue
    const result = await createJiraIssueForFinding(
      integration.config,
      {
        pepperFindingId: "test-finding-123",
        title: "Test Security Finding",
        severity: "HIGH",
        description: "This is a test security finding created by Pepper integration test.",
        filePath: "src/app/test.ts",
        line: 42,
        ruleId: "TEST-001",
        cweId: "CWE-79",
        scanId: "test-scan-123",
        scanUrl: "https://pepper.local/scans/test-scan-123",
      },
    );

    return NextResponse.json({
      success: true,
      message: "Test issue created in Jira successfully",
      issueKey: result.key,
      issueUrl: result.url,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to create test issue";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
