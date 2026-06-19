import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { upsertIntegration } from "@/lib/integrations";

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const body = await req.json();
  const {
    baseUrl,
    email,
    apiToken,
    projectKey,
    issueType,
    priorityMap,
    openForSeverities,
    name,
  } = body;

  // Validation
  if (!baseUrl || !email || !apiToken || !projectKey) {
    return NextResponse.json(
      {
        error:
          "baseUrl, email, apiToken, and projectKey are required",
      },
      { status: 400 },
    );
  }

  try {
    // Test the connection by fetching project info
    const projectUrl = `${baseUrl.replace(/\/+$/, "")}/rest/api/3/project/${projectKey}`;
    const testRes = await fetch(projectUrl, {
      method: "GET",
      headers: {
        Authorization: `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`,
        Accept: "application/json",
      },
    });

    if (!testRes.ok) {
      const errorText = await testRes.text();
      return NextResponse.json(
        {
          error: `Failed to connect to Jira: ${testRes.status}. Check credentials and project key.`,
          details: errorText.slice(0, 200),
        },
        { status: 400 },
      );
    }

    // Save integration
    const integration = await upsertIntegration(orgId, {
      kind: "JIRA",
      name: name || `Jira (${projectKey})`,
      enabled: true,
      config: {
        baseUrl: baseUrl.replace(/\/+$/, ""),
        email,
        apiToken,
        projectKey,
        issueType: issueType || "Bug",
        priorityMap: priorityMap || {},
        openForSeverities: openForSeverities || ["CRITICAL", "HIGH"],
      },
    });

    return NextResponse.json({
      success: true,
      id: integration.id,
      name: integration.name,
      message: "Jira integration connected successfully",
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to connect Jira";
    return NextResponse.json(
      { error: message },
      { status: 400 },
    );
  }
}
