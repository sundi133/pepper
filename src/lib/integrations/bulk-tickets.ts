/**
 * File tickets for many findings at once (the "Raise tickets" action on a
 * scan's selected findings), in any of the organization's ticket systems.
 * Each issue is filed once per ticket project: findings that already have a
 * ticket there are reported as existing, not filed again.
 */
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/token-encryption";
import { logger } from "@/lib/logger";
import type { AzureBoardsConfig, JiraConfig } from "./types";
import {
  boardsAuthResolver,
  raiseAzureBoardsWorkItem,
  raiseJiraIssue,
  type TicketFinding,
  type TicketRepo,
} from "./finding-tickets";

export const TICKET_KINDS = ["AZURE_BOARDS", "JIRA"] as const;
export type TicketKind = (typeof TICKET_KINDS)[number];

export const TICKET_KIND_LABELS: Record<TicketKind, string> = {
  AZURE_BOARDS: "Azure Boards",
  JIRA: "Jira",
};

/** Most findings one request may file, to keep a click bounded. */
export const BULK_TICKET_LIMIT = 200;
/** Stop filing to a system after this many identical failures in a row (bad credentials, wrong project…). */
const SAME_ERROR_STOP = 3;

export type TicketIntegration =
  | { id: string; name: string; kind: "AZURE_BOARDS"; config: AzureBoardsConfig }
  | { id: string; name: string; kind: "JIRA"; config: JiraConfig };

/** What tells two integrations of the same kind apart (never secrets). */
export function ticketTargetDetail(i: TicketIntegration): string {
  if (i.kind === "AZURE_BOARDS") {
    const c = i.config;
    return [c.project?.trim() || "each repository's project", c.workItemType?.trim() || "Bug, or Issue"].join(" · ");
  }
  return [i.config.projectKey, i.config.issueType?.trim() || "Bug"].join(" · ");
}

/** The organization's enabled ticket systems (optionally only these ids). */
export async function loadTicketIntegrations(orgId: string, ids?: string[]): Promise<TicketIntegration[]> {
  const rows = await prisma.integrationConfig.findMany({
    where: {
      organizationId: orgId,
      enabled: true,
      kind: { in: [...TICKET_KINDS] },
      ...(ids ? { id: { in: ids } } : {}),
    },
    orderBy: [{ kind: "asc" }, { createdAt: "asc" }],
  });
  const out: TicketIntegration[] = [];
  for (const r of rows) {
    try {
      const config = JSON.parse(decryptSecret(r.configEnc));
      out.push({ id: r.id, name: r.name, kind: r.kind as TicketKind, config } as TicketIntegration);
    } catch {
      logger.warn({ orgId, id: r.id }, "Skipping un-decryptable ticket integration");
    }
  }
  return out;
}

export interface BulkTicketFinding extends TicketFinding {
  branch: string | null;
}

export interface BulkTicketResult {
  integrationId: string;
  name: string;
  kind: TicketKind;
  created: number;
  existing: number;
  tickets: Array<{ findingId: string; id: string; url: string; existing: boolean }>;
  failed: Array<{ findingId: string; title: string; error: string }>;
  /** Filing stopped early because every attempt failed the same way. */
  stoppedEarly?: string;
}

/** File each finding in each integration; never throws, reports per integration. */
export async function raiseTicketsForFindings(params: {
  orgId: string;
  repo: TicketRepo;
  findings: BulkTicketFinding[];
  integrations: TicketIntegration[];
  scanUrl?: string;
}): Promise<BulkTicketResult[]> {
  const { orgId, repo, findings, integrations, scanUrl } = params;
  const resolveBoardsAuth = boardsAuthResolver(orgId);
  const results: BulkTicketResult[] = [];

  for (const integration of integrations) {
    const result: BulkTicketResult = {
      integrationId: integration.id,
      name: integration.name,
      kind: integration.kind,
      created: 0,
      existing: 0,
      tickets: [],
      failed: [],
    };
    let lastError = "";
    let sameErrorRun = 0;

    for (const [i, finding] of findings.entries()) {
      try {
        let ticket: { id: string; url: string; existing: boolean };
        if (integration.kind === "AZURE_BOARDS") {
          const auth = await resolveBoardsAuth(integration.config);
          if (!auth) throw new Error("No PAT on the integration and no Azure DevOps connection to reuse");
          ticket = await raiseAzureBoardsWorkItem({ integration, auth, repo, finding, branch: finding.branch, scanUrl });
        } else {
          const issue = await raiseJiraIssue({ integration, repo, finding, branch: finding.branch, scanUrl });
          ticket = { id: issue.key, url: issue.url, existing: issue.existing };
        }
        result.tickets.push({ findingId: finding.id, ...ticket });
        if (ticket.existing) result.existing++;
        else result.created++;
        sameErrorRun = 0;
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        result.failed.push({ findingId: finding.id, title: finding.title, error });
        sameErrorRun = error === lastError ? sameErrorRun + 1 : 1;
        lastError = error;
        if (sameErrorRun >= SAME_ERROR_STOP && i < findings.length - 1) {
          result.stoppedEarly = `Stopped after ${SAME_ERROR_STOP} identical failures; ${findings.length - i - 1} finding(s) not attempted.`;
          break;
        }
      }
    }
    results.push(result);
  }
  return results;
}
