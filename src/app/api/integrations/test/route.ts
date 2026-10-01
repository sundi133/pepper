import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
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
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { fireWebhook } from "@/lib/integrations/webhook";
import {
  boardsConfigError,
  validateBoardsConfig,
} from "@/lib/integrations/azure-boards";
import { boardsAuthResolver } from "@/lib/integrations/finding-tickets";
import { explainFetchError } from "@/lib/network-error";

/** The address a test talks to, for explaining network failures. */
function testTarget(body: IntegrationConfigData): string | undefined {
  const c = body?.config as { serverUrl?: string; baseUrl?: string; webhookUrl?: string; url?: string } | undefined;
  if (body?.kind === "AZURE_BOARDS") return c?.serverUrl?.trim() || "https://dev.azure.com";
  return c?.baseUrl || c?.webhookUrl || c?.url || undefined;
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const body: IntegrationConfigData = await req.json();
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.tested",
    resource: "integration",
    details: { kind: body.kind },
    ipAddress: ipFromHeaders(req.headers),
  });

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
    } else if (body.kind === "AZURE_BOARDS") {
      // Validate only — a test shouldn't leave junk work items on the board.
      const config = body.config;
      const error = boardsConfigError(config);
      if (error) return NextResponse.json({ error }, { status: 400 });
      const auth = await boardsAuthResolver(orgId)(config);
      if (!auth) {
        return NextResponse.json(
          { error: "No PAT: enter one, or connect Azure DevOps under Integrations first." },
          { status: 400 },
        );
      }
      const result = await validateBoardsConfig(auth, config, config.project?.trim() || null);
      return NextResponse.json({ ok: true, workItemType: result.workItemType });
    } else {
      const _exhaustiveCheck: never = body;
      return NextResponse.json(
        { error: `Test not implemented for this integration type` },
        { status: 400 },
      );
    }
    return NextResponse.json({ ok: true });
  } catch (e) {
    return NextResponse.json(
      { error: explainFetchError(e, testTarget(body)) || "Test failed" },
      { status: 500 },
    );
  }
}
