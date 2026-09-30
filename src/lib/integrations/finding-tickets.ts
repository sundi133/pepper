/**
 * Findings ↔ Azure Boards work items. Each issue (cross-scan fingerprint) is
 * filed once per board; later scans keep the link pointing at the newest
 * finding row, comment when Pepper no longer detects the issue, and comment
 * again if it comes back.
 *
 * A rescan replaces the project's scan and its findings, so "no longer
 * detected" is judged from the new scan alone: same branch, the reporting
 * scanner actually ran, and — for scanners whose results vary run to run —
 * missing from two scans in a row.
 */
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/token-encryption";
import { getOrgAzureDevOpsAuth } from "@/lib/azure-devops-connection";
import type { AzureDevOpsAuth } from "@/lib/azure-devops-api";
import { findingFingerprint } from "@/lib/fix-verification";
import { logger } from "@/lib/logger";
import {
  AZURE_BOARDS_SYSTEM,
  boardsAuth,
  boardsTarget,
  createWorkItem,
  markWorkItemFixed,
  noteWorkItemRegressed,
  type BoardsFindingInput,
  type WorkItemRef,
} from "./azure-boards";
import type { AzureBoardsConfig } from "./types";

/** Most work items one scan may file automatically. */
const AUTO_CREATE_CAP = 25;
/** LLM-backed scanners can miss an issue on one run; confirm absence twice. */
const VARIABLE_SCANNERS = new Set(["SAST_LLM", "SECRETS_LLM", "ZERO_DAY", "IAC", "K8S"]);
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export interface BoardsIntegration {
  id: string;
  name: string;
  config: AzureBoardsConfig;
}

export interface TicketFinding {
  id: string;
  scanId: string;
  scanner: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  filePath: string | null;
  startLine: number | null;
  snippet: string | null;
  ruleId: string | null;
  cveId: string | null;
  cweId: string | null;
}

export interface TicketRepo {
  id: string;
  name: string;
  organizationId: string;
  azureProjectName: string | null;
}

export const TICKET_FINDING_SELECT = {
  id: true,
  scanId: true,
  scanner: true,
  severity: true,
  status: true,
  title: true,
  description: true,
  filePath: true,
  startLine: true,
  snippet: true,
  ruleId: true,
  cveId: true,
  cweId: true,
} as const;

export async function loadBoardsIntegrations(orgId: string): Promise<BoardsIntegration[]> {
  const rows = await prisma.integrationConfig.findMany({
    where: { organizationId: orgId, kind: "AZURE_BOARDS", enabled: true },
    orderBy: { createdAt: "asc" },
  });
  const out: BoardsIntegration[] = [];
  for (const r of rows) {
    try {
      out.push({ id: r.id, name: r.name, config: JSON.parse(decryptSecret(r.configEnc)) as AzureBoardsConfig });
    } catch {
      logger.warn({ orgId, id: r.id }, "Skipping un-decryptable Azure Boards integration");
    }
  }
  return out;
}

/** The ADO project work items go to: the configured one, else the repo's own. */
export function boardsProjectFor(config: AzureBoardsConfig, repo: Pick<TicketRepo, "azureProjectName">): string | null {
  return config.project?.trim() || repo.azureProjectName?.trim() || null;
}

/** Resolves credentials, reading the org's repo connection only when needed. */
export function boardsAuthResolver(orgId: string) {
  let conn: Promise<AzureDevOpsAuth | null> | undefined;
  return async (config: AzureBoardsConfig) => {
    if (config.pat?.trim()) return boardsAuth(config, null);
    conn ??= getOrgAzureDevOpsAuth(orgId);
    return boardsAuth(config, await conn);
  };
}

function toBoardsInput(f: TicketFinding, repo: TicketRepo, scanUrl?: string): BoardsFindingInput {
  return {
    pepperFindingId: f.id,
    title: f.title,
    severity: f.severity as BoardsFindingInput["severity"],
    description: f.description,
    scanner: f.scanner,
    filePath: f.filePath,
    line: f.startLine,
    snippet: f.snippet,
    ruleId: f.ruleId,
    cveId: f.cveId,
    cweId: f.cweId,
    projectName: repo.name,
    scanUrl,
  };
}

/** Consecutive scans without the issue before Pepper reports it gone. */
export function missesToConfirmFix(scanner: string): number {
  return VARIABLE_SCANNERS.has(scanner) ? 2 : 1;
}

/**
 * Whether the scan ran (to completion) the scanner that reports this kind of
 * finding — an LLM-off or SCA-only scan says nothing about SAST_LLM issues.
 */
export function scanRanScanner(scannerProgress: unknown, scanner: string): boolean {
  const progress = (scannerProgress ?? {}) as Record<string, { status?: string } | undefined>;
  const done = (name: string) => progress[name]?.status === "DONE";
  // Rule-based IaC / Kubernetes checks report as IAC / K8S too.
  return done(scanner) || ((scanner === "IAC" || scanner === "K8S") && done("IAC_RULES"));
}

function isUniqueViolation(e: unknown): boolean {
  return (e as { code?: string })?.code === "P2002";
}

/**
 * File a work item for a finding, or return the one already filed for the
 * same issue on this board.
 */
export async function raiseAzureBoardsWorkItem(params: {
  integration: BoardsIntegration;
  auth: AzureDevOpsAuth;
  repo: TicketRepo;
  finding: TicketFinding;
  /** Branch of the finding's scan. */
  branch: string | null;
  scanUrl?: string;
}): Promise<WorkItemRef & { existing: boolean }> {
  const { integration, auth, repo, finding, branch, scanUrl } = params;
  const project = boardsProjectFor(integration.config, repo);
  if (!project) {
    throw new Error("No Azure DevOps project: set one on the Azure Boards integration (this repository wasn't imported from Azure DevOps).");
  }
  const target = boardsTarget(integration.config, project);
  const fingerprint = findingFingerprint(finding);
  const key = { projectId: repo.id, system: AZURE_BOARDS_SYSTEM, target, fingerprint };

  const existing = await prisma.findingTicket.findUnique({ where: { projectId_system_target_fingerprint: key } });
  if (existing) {
    if (existing.findingId !== finding.id) {
      await prisma.findingTicket.update({ where: { id: existing.id }, data: { findingId: finding.id } });
    }
    return { id: existing.externalId, url: existing.url, existing: true };
  }

  const created = await createWorkItem(auth, integration.config, project, toBoardsInput(finding, repo, scanUrl));
  try {
    await prisma.findingTicket.create({
      data: {
        ...key,
        organizationId: repo.organizationId,
        integrationId: integration.id,
        scanner: finding.scanner,
        branch,
        findingId: finding.id,
        externalId: created.id,
        url: created.url,
      },
    });
  } catch (e) {
    // Filed concurrently (auto-create racing a manual click): keep the first link.
    if (!isUniqueViolation(e)) throw e;
    logger.warn({ projectId: repo.id, workItem: created.id }, "Duplicate Azure Boards work item filed concurrently");
  }
  return { ...created, existing: false };
}

/**
 * After a scan completes: sync existing work items (gone / back again) and
 * file new ones for the severities each board auto-creates. PR scans are
 * skipped — they report on the pull request, and their findings may never
 * reach the default branch.
 */
export async function syncAzureBoardsForScan(scanId: string, scanUrl?: string): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      status: true,
      scanType: true,
      branch: true,
      scannerProgress: true,
      project: { select: { id: true, name: true, organizationId: true, azureProjectName: true } },
    },
  });
  if (!scan?.project || scan.status !== "COMPLETED" || scan.scanType === "INCREMENTAL") return;
  const repo: TicketRepo = scan.project;

  const integrations = await loadBoardsIntegrations(repo.organizationId);
  if (integrations.length === 0) return;
  const resolveAuth = boardsAuthResolver(repo.organizationId);

  const findings = (await prisma.finding.findMany({
    where: { scanId },
    select: { ...TICKET_FINDING_SELECT, riskScore: true },
  })) as Array<TicketFinding & { riskScore: number | null }>;
  const byFingerprint = new Map(findings.map((f) => [findingFingerprint(f), f]));

  for (const integration of integrations) {
    const log = logger.child({ scanId, integrationId: integration.id });
    const project = boardsProjectFor(integration.config, repo);
    const auth = await resolveAuth(integration.config);
    if (!project || !auth) {
      log.warn({ hasProject: Boolean(project), hasAuth: Boolean(auth) }, "Azure Boards sync skipped: no project or credentials");
      continue;
    }
    const target = boardsTarget(integration.config, project);
    const tickets = await prisma.findingTicket.findMany({
      where: { projectId: repo.id, system: AZURE_BOARDS_SYSTEM, target },
    });
    const ticketed = new Set(tickets.map((t) => t.fingerprint));

    // ── Existing work items ──
    for (const t of tickets) {
      const current = byFingerprint.get(t.fingerprint);
      try {
        if (current) {
          const back = Boolean(t.fixedNotifiedAt) && (current.status === "OPEN" || current.status === "IN_PROGRESS");
          if (back) await noteWorkItemRegressed(auth, integration.config, project, t.externalId, { scanUrl });
          if (back || t.findingId !== current.id || t.missedScans !== 0) {
            await prisma.findingTicket.update({
              where: { id: t.id },
              data: { findingId: current.id, missedScans: 0, ...(back ? { fixedNotifiedAt: null } : {}) },
            });
          }
          continue;
        }
        if (t.fixedNotifiedAt) continue;
        if ((t.branch ?? null) !== (scan.branch ?? null)) continue;
        if (!scanRanScanner(scan.scannerProgress, t.scanner)) continue;
        const missed = t.missedScans + 1;
        if (missed >= missesToConfirmFix(t.scanner)) {
          const exists = await markWorkItemFixed(auth, integration.config, project, t.externalId, { scanUrl, branch: scan.branch, scans: missed });
          if (!exists) log.info({ workItem: t.externalId }, "Linked work item was deleted");
          await prisma.findingTicket.update({ where: { id: t.id }, data: { missedScans: missed, fixedNotifiedAt: new Date() } });
        } else {
          await prisma.findingTicket.update({ where: { id: t.id }, data: { missedScans: missed } });
        }
      } catch (e) {
        log.warn({ err: e, workItem: t.externalId }, "Azure Boards work item sync failed");
      }
    }

    // ── New work items ──
    const severities = new Set(integration.config.autoCreateSeverities ?? []);
    if (severities.size === 0) continue;
    const candidates = findings
      .filter((f) => f.status === "OPEN" && severities.has(f.severity as never))
      .filter((f) => !ticketed.has(findingFingerprint(f)))
      .sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
          (b.riskScore ?? 0) - (a.riskScore ?? 0),
      );
    const seen = new Set<string>();
    let filed = 0;
    for (const f of candidates) {
      if (filed >= AUTO_CREATE_CAP) break;
      const fp = findingFingerprint(f);
      if (seen.has(fp)) continue;
      seen.add(fp);
      try {
        const res = await raiseAzureBoardsWorkItem({ integration, auth, repo, finding: f, branch: scan.branch, scanUrl });
        if (!res.existing) filed++;
      } catch (e) {
        log.warn({ err: e, findingId: f.id }, "Azure Boards auto-create failed");
        // Credentials / project problems fail every item the same way.
        break;
      }
    }
    if (candidates.length > AUTO_CREATE_CAP) {
      log.info({ filed, candidates: candidates.length }, "Azure Boards auto-create capped for this scan");
    }
  }
}

/** Work items already linked to this finding's issue, for the finding panel. */
export async function listFindingTickets(repoId: string, finding: TicketFinding) {
  const rows = await prisma.findingTicket.findMany({
    where: { projectId: repoId, fingerprint: findingFingerprint(finding) },
    select: { system: true, externalId: true, url: true, fixedNotifiedAt: true, createdAt: true },
    orderBy: { createdAt: "asc" },
  });
  return rows.map((r) => ({
    system: r.system,
    externalId: r.externalId,
    url: r.url,
    fixed: Boolean(r.fixedNotifiedAt),
  }));
}
