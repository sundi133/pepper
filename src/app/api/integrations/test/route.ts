import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  type IntegrationConfigData,
  type JiraConfig,
  type SlackConfig,
  type SiemConfig,
  type WebhookConfig,
} from "@/lib/integrations";
import {
  createJiraIssueForFinding,
} from "@/lib/integrations/jira";
import { notifySlackScanComplete } from "@/lib/integrations/slack";
import { forwardToSiem } from "@/lib/integrations/siem";
import { fireWebhook } from "@/lib/integrations/webhook";

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const body = (await req.json()) as IntegrationConfigData;

  try {
    if (body.kind === "SLACK") {
      await notifySlackScanComplete(body.config as SlackConfig, {
        projectName: "Pepper test",
        scanId: "test",
        gateResult: "PASSED",
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
      });
    } else if (body.kind === "JIRA") {
      const result = await createJiraIssueForFinding(body.config as JiraConfig, {
        pepperFindingId: "test-finding",
        title: "Pepper integration test",
        severity: "LOW",
        description:
          "This is a test ticket from Pepper to verify Jira integration. You can safely close it.",
        scanId: "test",
      });
      return NextResponse.json({ ok: true, jiraIssue: result });
    } else if (body.kind === "SIEM") {
      await forwardToSiem(body.config as SiemConfig, [
        {
          scanId: "test",
          organizationId: orgId,
          projectName: "Pepper test",
          severity: "INFO",
          title: "Pepper SIEM integration test",
          scanner: "PEPPER",
          detectedAt: new Date().toISOString(),
        },
      ]);
    } else if (body.kind === "WEBHOOK") {
      const result = await fireWebhook(body.config as WebhookConfig, "scan.completed", {
        event: "scan.completed",
        timestamp: new Date().toISOString(),
        scan: {
          id: "test-scan-id",
          projectName: "Pepper test project",
          branch: "main",
          url: undefined,
          criticalCount: 1,
          highCount: 2,
          mediumCount: 5,
          lowCount: 3,
          infoCount: 0,
          gateResult: "PASSED",
        },
      });
      if (!result.ok) {
        return NextResponse.json(
          { error: result.error ?? `HTTP ${result.status}` },
          { status: 500 },
        );
      }
      return NextResponse.json({ ok: true, status: result.status });
    } else {
      return NextResponse.json(
        { error: `Test not implemented for ${body.kind}` },
        { status: 400 },
      );
    }
    return NextResponse.json({ ok: true });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Test failed" },
      { status: 500 },
    );
  }
}
