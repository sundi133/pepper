import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { decryptSecret } from "@/lib/token-encryption";
import { notifySlackFinding } from "@/lib/integrations/slack";
import { createJiraIssueForFinding } from "@/lib/integrations/jira";
import type { JiraConfig, SlackConfig } from "@/lib/integrations/types";
import { logger } from "@/lib/logger";
import {
  TICKET_FINDING_SELECT,
  boardsAuthResolver,
  listFindingTickets,
  loadBoardsIntegrations,
  raiseAzureBoardsWorkItem,
} from "@/lib/integrations/finding-tickets";

const FINDING_SEVERITIES = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);

function scanWebUrl(scanId: string): string | undefined {
  const base =
    process.env.NEXTAUTH_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL;
  return base ? `${base.replace(/\/+$/, "")}/scans/${scanId}` : undefined;
}

async function loadEnabled<T>(orgId: string, kind: string) {
  const rows = await prisma.integrationConfig.findMany({
    where: { organizationId: orgId, kind: kind as never, enabled: true },
  });
  const out: Array<{ id: string; name: string; config: T }> = [];
  for (const r of rows) {
    try {
      out.push({
        id: r.id,
        name: r.name,
        config: JSON.parse(decryptSecret(r.configEnc)) as T,
      });
    } catch {
      logger.warn({ orgId, kind, id: r.id }, "Skipping un-decryptable integration row");
    }
  }
  return out;
}

const FINDING_WITH_REPO_SELECT = {
  ...TICKET_FINDING_SELECT,
  scan: {
    select: {
      project: {
        select: { id: true, name: true, organizationId: true, azureProjectName: true },
      },
    },
  },
} as const;

/**
 * Which ticketing destinations are configured, and the work items already
 * linked to this finding's issue (for the finding panel).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const { findingId } = await params;
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, scan: { project: { organizationId: orgId } } },
    select: FINDING_WITH_REPO_SELECT,
  });
  if (!finding?.scan.project) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }
  const kinds = await prisma.integrationConfig.groupBy({
    by: ["kind"],
    where: { organizationId: orgId, enabled: true, kind: { in: ["SLACK", "JIRA", "AZURE_BOARDS"] } },
    _count: { _all: true },
  });
  const count = (k: string) => kinds.find((r) => r.kind === k)?._count._all ?? 0;
  return NextResponse.json({
    configured: { slack: count("SLACK"), jira: count("JIRA"), azureBoards: count("AZURE_BOARDS") },
    tickets: await listFindingTickets(finding.scan.project.id, finding),
  });
}

/**
 * Raise a scan finding to the organization's enabled Slack + Jira integrations
 * on demand (the "Send to Slack" / "Create Jira" buttons in the finding panel).
 * Best-effort per destination: each enabled integration is attempted and its
 * individual result reported so the UI can show what actually went out.
 * Azure Boards files one work item per issue: raising the same issue again
 * returns the existing work item.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { findingId } = await params;
  let channel = "all";
  try {
    const body = await req.json();
    if (typeof body?.channel === "string" && body.channel) {
      channel = body.channel;
    }
  } catch {
    // No body / invalid JSON — default to sending to all channels.
  }

  const finding = await prisma.finding.findFirst({
    where: { id: findingId, scan: { project: { organizationId: orgId } } },
    select: {
      id: true,
      scanId: true,
      severity: true,
      title: true,
      description: true,
      filePath: true,
      startLine: true,
      ruleId: true,
      cveId: true,
      cweId: true,
      scan: {
        select: {
          branch: true,
          project: { select: { id: true, name: true, azureProjectName: true } },
        },
      },
    },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }
  if (!FINDING_SEVERITIES.has(finding.severity)) {
    return NextResponse.json(
      { error: `Unsupported severity: ${finding.severity}` },
      { status: 400 },
    );
  }

  const scanUrl = scanWebUrl(finding.scanId);
  const results: Record<string, unknown> = {};

  // ----- Slack -----
  if (channel === "all" || channel === "slack") {
    const slacks = await loadEnabled<SlackConfig>(orgId, "SLACK");
    const slackResults: Array<{ id: string; ok: boolean; error?: string }> = [];
    for (const s of slacks) {
      try {
        await notifySlackFinding(s.config, {
          projectName: finding.scan.project?.name || "",
          findingTitle: finding.title,
          severity: finding.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
          description: finding.description,
          filePath: finding.filePath,
          line: finding.startLine,
          ruleId: finding.ruleId,
          cweId: finding.cweId,
          scanUrl,
        });
        slackResults.push({ id: s.id, ok: true });
      } catch (e) {
        slackResults.push({
          id: s.id,
          ok: false,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }
    results.slack = {
      destinationCount: slacks.length,
      results: slackResults,
    };
  }

  // ----- Jira -----
  if (channel === "all" || channel === "jira") {
    const jiras = await loadEnabled<JiraConfig>(orgId, "JIRA");
    const jiraResults: Array<{
      id: string;
      ok: boolean;
      key?: string;
      url?: string;
      error?: string;
    }> = [];
    for (const j of jiras) {
      try {
        const created = await createJiraIssueForFinding(j.config, {
          pepperFindingId: finding.id,
          title: finding.title,
          severity: finding.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
          description: finding.description,
          filePath: finding.filePath,
          line: finding.startLine,
          ruleId: finding.ruleId,
          cveId: finding.cveId,
          cweId: finding.cweId,
          scanId: finding.scanId,
          scanUrl,
        });
        jiraResults.push({ id: j.id, ok: true, key: created.key, url: created.url });
      } catch (e) {
        jiraResults.push({
          id: j.id,
          ok: false,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }
    results.jira = {
      destinationCount: jiras.length,
      results: jiraResults,
    };
  }

  // ----- Azure Boards -----
  if (channel === "all" || channel === "azure-boards") {
    const boards = await loadBoardsIntegrations(orgId);
    const boardResults: Array<{
      id: string;
      ok: boolean;
      workItemId?: string;
      url?: string;
      existing?: boolean;
      error?: string;
    }> = [];
    const repo = finding.scan.project;
    if (boards.length > 0 && repo) {
      const resolveAuth = boardsAuthResolver(orgId);
      const ticketFinding = await prisma.finding.findUniqueOrThrow({
        where: { id: finding.id },
        select: TICKET_FINDING_SELECT,
      });
      for (const b of boards) {
        try {
          const boardAuth = await resolveAuth(b.config);
          if (!boardAuth) {
            throw new Error("No PAT on the integration and no Azure DevOps connection to reuse");
          }
          const item = await raiseAzureBoardsWorkItem({
            integration: b,
            auth: boardAuth,
            repo: { ...repo, organizationId: orgId },
            finding: ticketFinding,
            branch: finding.scan.branch,
            scanUrl,
          });
          boardResults.push({ id: b.id, ok: true, workItemId: item.id, url: item.url, existing: item.existing });
        } catch (e) {
          boardResults.push({
            id: b.id,
            ok: false,
            error: e instanceof Error ? e.message : String(e),
          });
        }
      }
    }
    results.azureBoards = {
      destinationCount: boards.length,
      results: boardResults,
    };
  }

  const slackOk = (results.slack as { results: Array<{ ok: boolean }> } | undefined)
    ?.results.some((r) => r.ok);
  const jiraOk = (results.jira as { results: Array<{ ok: boolean }> } | undefined)
    ?.results.some((r) => r.ok);
  const boardsOk = (results.azureBoards as { results: Array<{ ok: boolean }> } | undefined)
    ?.results.some((r) => r.ok);
  const anyOk = slackOk || jiraOk || boardsOk;
  const anyConfigured =
    (results.slack as { destinationCount: number } | undefined)
      ?.destinationCount ||
    (results.jira as { destinationCount: number } | undefined)
      ?.destinationCount ||
    (results.azureBoards as { destinationCount: number } | undefined)
      ?.destinationCount;

  if (anyOk) {
    return NextResponse.json({ ok: true, results });
  }
  if (!anyConfigured) {
    return NextResponse.json(
      { ok: false, error: "No Slack, Jira or Azure Boards integration is configured for this organization.", results },
      { status: 404 },
    );
  }
  return NextResponse.json(
    { ok: false, error: "All configured integrations failed. See per-destination results.", results },
    { status: 502 },
  );
}