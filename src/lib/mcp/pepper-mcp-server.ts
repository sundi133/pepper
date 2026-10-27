import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import type { ApiKeyPrincipal } from "@/lib/auth-guard";
import type { Role } from "@/lib/api-key-role";
import {
  ROLE_HIERARCHY,
  SCANNER_LABELS,
  SCAN_STATUS_LABELS,
  SEVERITY_ORDER,
} from "@/lib/constants";
import { enrichFindingWithReport } from "@/lib/finding-report";
import {
  FINDING_STATUSES,
  applyFindingStatusChange,
} from "@/lib/finding-status-update";
import { isRiskDecisionStatus } from "@/lib/permissions";
import { queueNewScan } from "@/lib/scan-create";
import { computeScanProgress, type ScannerProgressMap } from "@/lib/scan-progress";
import { scanFindingsWhere, scanListWhere } from "@/lib/scan-queries";
import { rescanScan } from "@/lib/scan-rescan";
import { API_CREATE_SCAN_TYPES } from "@/lib/scan-types";
import { letterGradeFromCounts } from "@/lib/security-grade";
import { getOwasp2024Category } from "@/scanners/sast/owasp-mapper";

/**
 * Pepper's MCP server: the tools an IDE assistant (Copilot, JetBrains AI,
 * Cursor, Claude Code, …) can call to read findings, start scans and triage.
 *
 * Every tool runs as the API key's principal — the key's creator, in the key's
 * organization, with the key's capped role — and reuses the same queries and
 * actions as the web UI's API routes.
 */

export const PEPPER_MCP_SERVER_NAME = "pepper";
export const PEPPER_MCP_SERVER_VERSION = "1.0.0";

export interface PepperMcpContext {
  principal: ApiKeyPrincipal;
  /** Client IP, for audit entries. */
  ipAddress: string | null;
  /** Base URL of this Pepper instance, for links back to the UI. */
  appUrl: string;
}

const SEVERITIES = Object.keys(SEVERITY_ORDER) as [keyof typeof SEVERITY_ORDER, ...(keyof typeof SEVERITY_ORDER)[]];
const SCANNERS = Object.keys(SCANNER_LABELS) as [keyof typeof SCANNER_LABELS, ...(keyof typeof SCANNER_LABELS)[]];
const SCAN_STATUSES = Object.keys(SCAN_STATUS_LABELS) as [
  keyof typeof SCAN_STATUS_LABELS,
  ...(keyof typeof SCAN_STATUS_LABELS)[],
];
const SECRET_SCANNERS = new Set(["SECRETS_PATTERN", "SECRETS_LLM"]);

/** A failure the assistant should see and can act on (bad input, not found, forbidden). */
export class McpToolError extends Error {}

const SERVER_INSTRUCTIONS = `Pepper is a static application security testing (SAST) platform. These tools read and triage the security findings of the repositories in your Pepper organization.
- For the file open in the editor, call findings_for_file with the repository and the file's path relative to the repository root.
- To browse: list_repositories -> list_scans -> list_findings -> get_finding (full explanation, reproduction steps and remediation).
- start_scan / rescan queue a scan; it runs in the background, so poll get_scan for progress.
- update_finding_status records triage. Marking a finding FALSE_POSITIVE or ACCEPTED_RISK needs the Security role, which API keys do not carry; do that in the Pepper web UI.
Secrets are always returned masked.`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function requireMcpRole(ctx: PepperMcpContext, minRole: Role, action: string) {
  const have = ROLE_HIERARCHY[ctx.principal.role] ?? 0;
  if (have < ROLE_HIERARCHY[minRole]) {
    throw new McpToolError(
      `Forbidden: ${action} requires the ${minRole} role or higher; this API key acts as ${ctx.principal.role}.`,
    );
  }
}

/** Remove credentials embedded in a URL (e.g. https://token@host/repo). */
export function redactUrlCredentials(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const u = new URL(value);
    if (!u.password && (!u.username || u.username === "git")) return value;
    u.password = "";
    if (u.username !== "git") u.username = "";
    return u.toString();
  } catch {
    // Not a URL (e.g. scp-style git@host:org/repo): strip any "//user:pass@".
    return value.replace(/\/\/[^/@\s]+@/, "//");
  }
}

function hasEmbeddedCredentials(url: string): boolean {
  try {
    const u = new URL(url);
    return Boolean(u.password || (u.username && u.username !== "git"));
  } catch {
    return false;
  }
}

/** Comparable key for a repository URL: no scheme, credentials, ".git" or trailing slash. */
function repoUrlKey(url: string): string {
  let s = url.trim().toLowerCase();
  const scp = s.match(/^[^@/\s]+@([^:/\s]+):(.+)$/);
  if (scp) s = `${scp[1]}/${scp[2]}`;
  s = s.replace(/^[a-z+]+:\/\//, "").replace(/^[^@/]+@/, "");
  return s.replace(/\/+$/, "").replace(/\.git$/, "").replace(/\/+$/, "");
}

function describeSource(sourceType: string, sourceRef: string | null): string | null {
  if (sourceType === "UPLOAD") return "uploaded archive";
  return redactUrlCredentials(sourceRef);
}

function severityCounts(s: {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}) {
  return {
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
  };
}

function scanUrl(ctx: PepperMcpContext, scanId: string) {
  return `${ctx.appUrl}/scans/${scanId}`;
}

function pagination(page: number, limit: number, total: number) {
  return { page, limit, total, totalPages: Math.ceil(total / limit) };
}

/** Normalize an editor path: forward slashes, no leading "./" or "/". */
function normalizePath(path: string): string {
  return path.trim().replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/^\/+/, "");
}

/** Whether a finding's repo-relative path is the file the editor named (possibly absolute). */
function pathMatches(findingPath: string, requested: string): boolean {
  const stored = normalizePath(findingPath);
  if (!stored) return false;
  return requested === stored || requested.endsWith(`/${stored}`) || stored.endsWith(`/${requested}`);
}

type ProjectRow = { id: string; name: string; repoUrl: string | null; defaultBranch: string };
const PROJECT_SELECT = { id: true, name: true, repoUrl: true, defaultBranch: true } as const;

async function findProjectByRepoUrl(orgId: string, url: string): Promise<ProjectRow | null> {
  const key = repoUrlKey(url);
  const candidates = await prisma.project.findMany({
    where: { organizationId: orgId, repoUrl: { not: null } },
    select: PROJECT_SELECT,
    orderBy: { createdAt: "asc" },
  });
  return candidates.find((p) => p.repoUrl && repoUrlKey(p.repoUrl) === key) ?? null;
}

/** Resolve a repository by id, or by name / repository URL, within the caller's organization. */
async function resolveRepository(
  ctx: PepperMcpContext,
  args: { repositoryId?: string; repository?: string },
): Promise<ProjectRow> {
  const orgId = ctx.principal.organizationId;
  if (args.repositoryId) {
    const project = await prisma.project.findFirst({
      where: { id: args.repositoryId, organizationId: orgId },
      select: PROJECT_SELECT,
    });
    if (!project) throw new McpToolError("Repository not found. Call list_repositories to see the available ones.");
    return project;
  }
  const ref = args.repository?.trim();
  if (!ref) {
    throw new McpToolError("Specify repositoryId, or repository (its name or repository URL).");
  }
  const byName = await prisma.project.findMany({
    where: { organizationId: orgId, name: { equals: ref, mode: "insensitive" } },
    select: PROJECT_SELECT,
    take: 5,
  });
  if (byName.length === 1) return byName[0];
  if (byName.length > 1) {
    throw new McpToolError(
      `Several repositories are named "${ref}": ${byName.map((p) => p.id).join(", ")}. Pass repositoryId instead.`,
    );
  }
  const byUrl = await findProjectByRepoUrl(orgId, ref);
  if (byUrl) return byUrl;
  throw new McpToolError(`No repository named or located at "${ref}". Call list_repositories to see the available ones.`);
}

function findingSummary(f: {
  id: string;
  title: string;
  severity: string;
  scanner: string;
  status: string;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  confidence: number | null;
  isNew: boolean | null;
}) {
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    scanner: f.scanner,
    status: f.status,
    filePath: f.filePath,
    startLine: f.startLine,
    endLine: f.endLine,
    ruleId: f.ruleId,
    cweId: f.cweId,
    cveId: f.cveId,
    confidence: f.confidence,
    isNew: f.isNew,
  };
}

const FINDING_SUMMARY_SELECT = {
  id: true,
  title: true,
  severity: true,
  scanner: true,
  status: true,
  filePath: true,
  startLine: true,
  endLine: true,
  ruleId: true,
  cweId: true,
  cveId: true,
  confidence: true,
  isNew: true,
} as const;

function readString(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

function readStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim() !== "") : [];
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

async function listRepositories(ctx: PepperMcpContext, args: { search?: string; limit: number }) {
  const orgId = ctx.principal.organizationId;
  const q = args.search?.trim().slice(0, 200);
  const projects = await prisma.project.findMany({
    where: {
      organizationId: orgId,
      ...(q ? { name: { contains: q, mode: "insensitive" as const } } : {}),
    },
    orderBy: { updatedAt: "desc" },
    take: args.limit,
    select: {
      ...PROJECT_SELECT,
      scans: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: { id: true, status: true, scanType: true, gateResult: true, createdAt: true, completedAt: true },
      },
    },
  });

  const ids = projects.map((p) => p.id);
  const latestCompleted =
    ids.length === 0
      ? []
      : await prisma.scan.findMany({
          where: { projectId: { in: ids }, status: "COMPLETED" },
          orderBy: [{ projectId: "asc" }, { completedAt: "desc" }],
          distinct: ["projectId"],
          select: {
            id: true,
            projectId: true,
            completedAt: true,
            gateResult: true,
            criticalCount: true,
            highCount: true,
            mediumCount: true,
            lowCount: true,
          },
        });
  const completedByProject = new Map(latestCompleted.map((s) => [s.projectId, s]));

  return {
    repositories: projects.map((p) => {
      const last = p.scans[0];
      const lc = completedByProject.get(p.id);
      return {
        id: p.id,
        name: p.name,
        repoUrl: redactUrlCredentials(p.repoUrl),
        defaultBranch: p.defaultBranch,
        latestScan: last
          ? {
              id: last.id,
              status: last.status,
              scanType: last.scanType,
              gateResult: last.gateResult,
              createdAt: last.createdAt,
              completedAt: last.completedAt,
            }
          : null,
        latestCompletedScan: lc
          ? {
              id: lc.id,
              completedAt: lc.completedAt,
              gateResult: lc.gateResult,
              grade: letterGradeFromCounts(lc.criticalCount, lc.highCount, lc.mediumCount, lc.lowCount),
              severityCounts: severityCounts(lc),
              url: scanUrl(ctx, lc.id),
            }
          : null,
      };
    }),
  };
}

async function listScans(
  ctx: PepperMcpContext,
  args: { repositoryId?: string; status?: string; search?: string; page: number; limit: number },
) {
  const where = scanListWhere({
    orgId: ctx.principal.organizationId,
    projectId: args.repositoryId,
    status: args.status,
    q: args.search?.trim().slice(0, 200),
  });
  const [scans, total] = await Promise.all([
    prisma.scan.findMany({
      where,
      include: { project: { select: { id: true, name: true } } },
      orderBy: { createdAt: "desc" },
      skip: (args.page - 1) * args.limit,
      take: args.limit,
    }),
    prisma.scan.count({ where }),
  ]);
  return {
    scans: scans.map((s) => ({
      id: s.id,
      repository: { id: s.project.id, name: s.project.name },
      status: s.status,
      scanType: s.scanType,
      branch: s.branch,
      commitSha: s.commitSha,
      source: describeSource(s.sourceType, s.sourceRef),
      gateResult: s.gateResult,
      severityCounts: severityCounts(s),
      createdAt: s.createdAt,
      startedAt: s.startedAt,
      completedAt: s.completedAt,
      url: scanUrl(ctx, s.id),
    })),
    pagination: pagination(args.page, args.limit, total),
  };
}

async function getScan(ctx: PepperMcpContext, args: { scanId: string }) {
  const scan = await prisma.scan.findFirst({
    where: { id: args.scanId, project: { organizationId: ctx.principal.organizationId } },
    include: { project: { select: { id: true, name: true } } },
  });
  if (!scan) throw new McpToolError("Scan not found.");

  const progress = (scan.scannerProgress ?? null) as ScannerProgressMap | null;
  const active = scan.status === "QUEUED" || scan.status === "RUNNING" || scan.status === "PAUSED";
  const ended = scan.status === "FAILED" || scan.status === "CANCELLED" || scan.status === "STOPPED";
  const counts = severityCounts(scan);

  return {
    id: scan.id,
    url: scanUrl(ctx, scan.id),
    repository: { id: scan.project.id, name: scan.project.name },
    status: scan.status,
    scanType: scan.scanType,
    branch: scan.branch,
    commitSha: scan.commitSha,
    source: describeSource(scan.sourceType, scan.sourceRef),
    createdAt: scan.createdAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    progressPercent: scan.status === "COMPLETED" ? 100 : active ? computeScanProgress(progress, scan.status) : null,
    scanners: progress
      ? Object.fromEntries(
          Object.entries(progress).map(([name, p]) => [
            name,
            { status: p?.status, filesCompleted: p?.filesCompleted, filesTotal: p?.filesTotal },
          ]),
        )
      : {},
    // Excludes findings marked false positive, like the scan page.
    severityCounts: counts,
    totalFindings: counts.critical + counts.high + counts.medium + counts.low,
    newFindings: scan.newFindingCount,
    autoResolvedFindings: scan.autoResolvedCount,
    filesScanned: scan.filesScanned,
    dependenciesScanned: scan.depsScanned,
    gateResult: scan.gateResult,
    ...(ended && scan.errorMessage ? { failureReason: scan.errorMessage } : {}),
    // A completed scan whose AI analysis could not run: results are partial.
    ...(scan.status === "COMPLETED" && scan.errorMessage
      ? { incompleteScan: true, incompleteScanNote: `Incomplete scan: ${scan.errorMessage}` }
      : {}),
  };
}

async function listFindings(
  ctx: PepperMcpContext,
  args: {
    scanId: string;
    severity?: string[];
    scanner?: string[];
    status?: string[];
    filePath?: string;
    includeFalsePositives: boolean;
    newOnly: boolean;
    page: number;
    limit: number;
  },
) {
  const scan = await prisma.scan.findFirst({
    where: { id: args.scanId, project: { organizationId: ctx.principal.organizationId } },
    select: { id: true },
  });
  if (!scan) throw new McpToolError("Scan not found.");

  const where = scanFindingsWhere({
    scanId: scan.id,
    severity: args.severity?.length ? args.severity : null,
    scanner: args.scanner?.length ? args.scanner : null,
    status: args.status?.length ? args.status : null,
    filePath: args.filePath ? normalizePath(args.filePath) : null,
    includeFalsePositives: args.includeFalsePositives,
    isNew: args.newOnly ? true : null,
  });
  const [findings, total] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy: [{ severity: "asc" }, { filePath: "asc" }, { startLine: "asc" }],
      skip: (args.page - 1) * args.limit,
      take: args.limit,
      select: FINDING_SUMMARY_SELECT,
    }),
    prisma.finding.count({ where }),
  ]);
  return {
    scanId: scan.id,
    url: scanUrl(ctx, scan.id),
    findings: findings.map(findingSummary),
    pagination: pagination(args.page, args.limit, total),
  };
}

async function getFinding(ctx: PepperMcpContext, args: { findingId: string }) {
  const row = await prisma.finding.findFirst({
    where: { id: args.findingId, scan: { project: { organizationId: ctx.principal.organizationId } } },
    include: { scan: { select: { id: true, branch: true, project: { select: { id: true, name: true } } } } },
  });
  if (!row) throw new McpToolError("Finding not found.");

  const finding = enrichFindingWithReport(row);
  const metadata = (finding.metadata ?? {}) as Record<string, unknown>;
  const report = (metadata.reportSections ?? null) as Record<string, unknown> | null;
  const isSecret = SECRET_SCANNERS.has(finding.scanner);
  const packageName = readString(metadata.packageName);

  return {
    id: finding.id,
    url: scanUrl(ctx, finding.scanId),
    scanId: finding.scanId,
    branch: row.scan.branch,
    repository: { id: row.scan.project.id, name: row.scan.project.name },
    title: finding.title,
    severity: finding.severity,
    scanner: finding.scanner,
    status: finding.status,
    statusNote: finding.statusNote,
    isNew: finding.isNew,
    confidence: finding.confidence,
    riskScore: finding.riskScore,
    location: { filePath: finding.filePath, startLine: finding.startLine, endLine: finding.endLine },
    // Secret values are stored masked; a secret finding not marked masked is withheld.
    snippet: isSecret && !finding.masked ? null : finding.snippet,
    ...(isSecret ? { maskedValue: readString(metadata.maskedValue) } : {}),
    ruleId: finding.ruleId,
    cweId: finding.cweId,
    cveId: finding.cveId,
    owasp: readString(metadata.owaspCategory) ?? getOwasp2024Category(finding.cweId ?? undefined),
    description: finding.description,
    summary: readString(report?.summary),
    impact: readString(report?.impact),
    stepsToReproduce: readStringArray(report?.stepsToReproduce),
    remediation: readStringArray(report?.remediation),
    ...(packageName
      ? {
          package: {
            name: packageName,
            version: readString(metadata.packageVersion),
            ecosystem: readString(metadata.ecosystem),
            fixVersion: readString(metadata.fixVersion),
          },
        }
      : {}),
  };
}

async function findingsForFile(
  ctx: PepperMcpContext,
  args: {
    filePath: string;
    repositoryId?: string;
    repository?: string;
    branch?: string;
    minSeverity: keyof typeof SEVERITY_ORDER;
    includeFalsePositives: boolean;
  },
) {
  const requested = normalizePath(args.filePath);
  if (!requested) throw new McpToolError("filePath is empty.");
  const project = await resolveRepository(ctx, args);

  const scan = await prisma.scan.findFirst({
    where: {
      projectId: project.id,
      status: "COMPLETED",
      project: { organizationId: ctx.principal.organizationId },
      ...(args.branch ? { branch: args.branch } : {}),
    },
    orderBy: { completedAt: "desc" },
    select: { id: true, branch: true, commitSha: true, completedAt: true, errorMessage: true },
  });
  if (!scan) {
    return {
      repository: { id: project.id, name: project.name },
      scan: null,
      findings: [],
      note: `No completed scan${args.branch ? ` on branch ${args.branch}` : ""} yet. Use start_scan to scan this repository.`,
    };
  }

  // Stored paths are relative to the repository root; the editor may send an
  // absolute path, so narrow by file name in the database and match in code.
  const baseName = requested.split("/").pop() || requested;
  const minRank = SEVERITY_ORDER[args.minSeverity];
  const rows = await prisma.finding.findMany({
    where: {
      scanId: scan.id,
      filePath: { endsWith: baseName },
      severity: { in: SEVERITIES.filter((s) => SEVERITY_ORDER[s] >= minRank) },
      ...(args.includeFalsePositives ? {} : { status: { not: "FALSE_POSITIVE" as const } }),
    },
    orderBy: [{ startLine: "asc" }, { severity: "asc" }],
    take: 500,
    select: FINDING_SUMMARY_SELECT,
  });
  const findings = rows.filter((f) => f.filePath && pathMatches(f.filePath, requested));

  return {
    repository: { id: project.id, name: project.name },
    scan: {
      id: scan.id,
      branch: scan.branch,
      commitSha: scan.commitSha,
      completedAt: scan.completedAt,
      url: scanUrl(ctx, scan.id),
      ...(scan.errorMessage ? { incompleteScanNote: `Incomplete scan: ${scan.errorMessage}` } : {}),
    },
    filePath: args.filePath,
    findings: findings.map(findingSummary),
  };
}

async function startScan(
  ctx: PepperMcpContext,
  args: {
    repositoryId?: string;
    repository?: string;
    repoUrl?: string;
    branch?: string;
    scanType: (typeof API_CREATE_SCAN_TYPES)[number];
  },
) {
  requireMcpRole(ctx, "DEVELOPER", "Starting a scan");
  const { organizationId: orgId, userId } = ctx.principal;
  const branch = args.branch?.trim() || undefined;
  const common = { orgId, userId, ipAddress: ctx.ipAddress, via: "mcp" };

  let result;
  let note: string | undefined;
  if (!args.repositoryId && !args.repository?.trim()) {
    const repoUrl = args.repoUrl?.trim();
    if (!repoUrl) {
      throw new McpToolError("Specify repositoryId, repository (name or URL), or repoUrl.");
    }
    if (!/^(https?|ssh):\/\/\S+$/i.test(repoUrl) && !/^[\w.-]+@[\w.-]+:\S+$/.test(repoUrl)) {
      throw new McpToolError("repoUrl must be an https://, http://, ssh:// or git@host:path repository URL.");
    }
    if (hasEmbeddedCredentials(repoUrl)) {
      throw new McpToolError(
        "Do not put credentials in repoUrl. Connect the Git provider in Pepper (Settings → Integrations) so Pepper can clone private repositories.",
      );
    }
    const existing = await findProjectByRepoUrl(orgId, repoUrl);
    result = await queueNewScan({
      ...common,
      scanParams: {
        projectId: existing?.id,
        repoUrl: existing?.repoUrl ?? repoUrl,
        branch: branch ?? existing?.defaultBranch,
        scanType: args.scanType,
      },
    });
  } else {
    const project = await resolveRepository(ctx, args);
    if (project.repoUrl) {
      // As the repository list's Scan button: clone the repository's URL.
      result = await queueNewScan({
        ...common,
        scanParams: {
          projectId: project.id,
          repoUrl: project.repoUrl,
          branch: branch ?? project.defaultBranch,
          scanType: args.scanType,
        },
      });
    } else {
      // No repository URL (uploaded or SVN source): rescan the latest source.
      const latest = await prisma.scan.findFirst({
        where: { projectId: project.id, sourceRef: { not: null } },
        orderBy: { createdAt: "desc" },
        select: { id: true },
      });
      if (!latest) {
        throw new McpToolError(
          "This repository has no repository URL and no earlier scan to repeat. Upload its source in the Pepper web UI.",
        );
      }
      if (branch) note = "Branch ignored: this repository's source is an upload or SVN checkout, rescanned as before.";
      result = await rescanScan({ ...common, scanId: latest.id, scanType: args.scanType });
    }
  }

  if (!result.ok) throw new McpToolError(result.error);
  return {
    scanId: result.scanId,
    repositoryId: result.projectId,
    status: "QUEUED",
    url: scanUrl(ctx, result.scanId),
    ...(note ? { note } : {}),
    next: "The scan runs in the background. Call get_scan to follow its progress.",
  };
}

async function rescan(
  ctx: PepperMcpContext,
  args: { scanId: string; scanType?: (typeof API_CREATE_SCAN_TYPES)[number] },
) {
  requireMcpRole(ctx, "DEVELOPER", "Rescanning");
  const result = await rescanScan({
    orgId: ctx.principal.organizationId,
    userId: ctx.principal.userId,
    scanId: args.scanId,
    scanType: args.scanType,
    ipAddress: ctx.ipAddress,
    via: "mcp",
  });
  if (!result.ok) throw new McpToolError(result.error);
  return {
    scanId: result.scanId,
    previousScanId: args.scanId,
    repositoryId: result.projectId,
    status: "QUEUED",
    url: scanUrl(ctx, result.scanId),
    next: "The scan runs in the background. Call get_scan to follow its progress.",
  };
}

async function updateFindingStatus(
  ctx: PepperMcpContext,
  args: { findingId: string; status: (typeof FINDING_STATUSES)[number]; note?: string },
) {
  requireMcpRole(ctx, "DEVELOPER", "Changing a finding's status");
  if (isRiskDecisionStatus(args.status)) {
    // Same rule as the findings API: risk decisions are for Security or Admin.
    if ((ROLE_HIERARCHY[ctx.principal.role] ?? 0) < ROLE_HIERARCHY.SECURITY) {
      throw new McpToolError(
        "Marking findings as false positive or accepted risk requires the Security or Admin role. API keys act with at most the Developer role, so make this change in the Pepper web UI.",
      );
    }
  }

  const updated = await applyFindingStatusChange({
    orgId: ctx.principal.organizationId,
    userId: ctx.principal.userId,
    findingId: args.findingId,
    status: args.status,
    statusNote: args.note,
    ipAddress: ctx.ipAddress,
    via: "mcp",
  });
  if (!updated) throw new McpToolError("Finding not found.");

  const scan = await prisma.scan.findUnique({
    where: { id: updated.finding.scanId },
    select: { criticalCount: true, highCount: true, mediumCount: true, lowCount: true },
  });
  return {
    id: updated.finding.id,
    title: updated.finding.title,
    previousStatus: updated.previousStatus,
    status: updated.finding.status,
    statusNote: updated.finding.statusNote,
    scanId: updated.finding.scanId,
    ...(scan ? { scanSeverityCounts: severityCounts(scan) } : {}),
  };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function run(fn: () => Promise<unknown>): Promise<CallToolResult> {
  try {
    const data = await fn();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  } catch (err) {
    if (err instanceof McpToolError) {
      return { isError: true, content: [{ type: "text", text: err.message }] };
    }
    console.error("[mcp] tool failed:", err);
    return { isError: true, content: [{ type: "text", text: "Internal error while running the tool." }] };
  }
}

const page = z.number().int().min(1).default(1).describe("1-based page number.");
const repositoryRef = {
  repositoryId: z.string().optional().describe("Repository id (from list_repositories)."),
  repository: z
    .string()
    .max(500)
    .optional()
    .describe("Repository name or repository URL, when the id is not known."),
};
const READ_ONLY = { readOnlyHint: true, openWorldHint: false } as const;

/** Build a Pepper MCP server whose tools act as the given API-key principal. */
export function createPepperMcpServer(ctx: PepperMcpContext): McpServer {
  const server = new McpServer(
    { name: PEPPER_MCP_SERVER_NAME, version: PEPPER_MCP_SERVER_VERSION },
    { instructions: SERVER_INSTRUCTIONS },
  );

  server.registerTool(
    "list_repositories",
    {
      title: "List repositories",
      description:
        "List the repositories in your Pepper organization, newest activity first, with each one's latest scan status and the severity counts of its latest completed scan.",
      inputSchema: {
        search: z.string().max(200).optional().describe("Case-insensitive substring of the repository name."),
        limit: z.number().int().min(1).max(200).default(50).describe("Maximum repositories to return (default 50)."),
      },
      annotations: READ_ONLY,
    },
    (args) => run(() => listRepositories(ctx, args)),
  );

  server.registerTool(
    "list_scans",
    {
      title: "List scans",
      description:
        "List scans, newest first. Filter by repository, status, or a search over repository name, source URL, branch and scan id.",
      inputSchema: {
        repositoryId: z.string().optional().describe("Only scans of this repository (id from list_repositories)."),
        status: z.enum(SCAN_STATUSES).optional().describe("Only scans in this status."),
        search: z.string().max(200).optional().describe("Repository name, source URL, branch or scan id."),
        page,
        limit: z.number().int().min(1).max(100).default(20).describe("Scans per page (default 20)."),
      },
      annotations: READ_ONLY,
    },
    (args) => run(() => listScans(ctx, args)),
  );

  server.registerTool(
    "get_scan",
    {
      title: "Get scan",
      description:
        "Get one scan: status, progress percentage while running, per-scanner status, severity counts (excluding false positives), build-gate result, and why it failed or whether it is incomplete (AI analysis did not run).",
      inputSchema: { scanId: z.string().describe("Scan id.") },
      annotations: READ_ONLY,
    },
    (args) => run(() => getScan(ctx, args)),
  );

  server.registerTool(
    "list_findings",
    {
      title: "List findings",
      description:
        "List a scan's findings, most severe first. False positives and INFO-severity findings are hidden unless requested (as in the web UI). Use get_finding for the full explanation of one.",
      inputSchema: {
        scanId: z.string().describe("Scan id."),
        severity: z.array(z.enum(SEVERITIES)).optional().describe("Only these severities (pass INFO explicitly to see INFO findings)."),
        scanner: z.array(z.enum(SCANNERS)).optional().describe("Only findings from these scanners."),
        status: z.array(z.enum(FINDING_STATUSES)).optional().describe("Only findings in these triage statuses."),
        filePath: z.string().max(1000).optional().describe("Only findings whose file path contains this text."),
        includeFalsePositives: z.boolean().default(false).describe("Include findings marked false positive."),
        newOnly: z.boolean().default(false).describe("Only findings new since the previous scan."),
        page,
        limit: z.number().int().min(1).max(200).default(50).describe("Findings per page (default 50)."),
      },
      annotations: READ_ONLY,
    },
    (args) => run(() => listFindings(ctx, args)),
  );

  server.registerTool(
    "get_finding",
    {
      title: "Get finding",
      description:
        "Get one finding in full: description, file and lines, code snippet (secrets masked), CWE / CVE / OWASP category, impact, steps to reproduce and remediation, plus package and fix version for dependency findings.",
      inputSchema: { findingId: z.string().describe("Finding id.") },
      annotations: READ_ONLY,
    },
    (args) => run(() => getFinding(ctx, args)),
  );

  server.registerTool(
    "findings_for_file",
    {
      title: "Findings for file",
      description:
        "Findings in one source file from the repository's latest completed scan — use this for the file open in the editor. Pass the path relative to the repository root (an absolute path also works) and identify the repository by id, name or URL.",
      inputSchema: {
        filePath: z.string().min(1).max(1000).describe("File path, ideally relative to the repository root, e.g. src/app/api/login.ts."),
        ...repositoryRef,
        branch: z.string().max(255).optional().describe("Use the latest completed scan of this branch."),
        minSeverity: z.enum(SEVERITIES).default("LOW").describe("Lowest severity to include (default LOW)."),
        includeFalsePositives: z.boolean().default(false).describe("Include findings marked false positive."),
      },
      annotations: READ_ONLY,
    },
    (args) => run(() => findingsForFile(ctx, args)),
  );

  server.registerTool(
    "start_scan",
    {
      title: "Start scan",
      description:
        "Queue a new scan of a repository known to Pepper (by id, name or URL), or of a Git repository URL (a repository is created for a URL Pepper does not know yet). Requires the Developer role. The scan runs in the background; follow it with get_scan.",
      inputSchema: {
        ...repositoryRef,
        repoUrl: z
          .string()
          .max(2000)
          .optional()
          .describe("Git repository URL to scan when the repository is not given. Never include credentials."),
        branch: z.string().max(255).optional().describe("Branch to scan (default: the repository's default branch)."),
        scanType: z.enum(API_CREATE_SCAN_TYPES).default("FULL").describe("Scan depth: FULL runs every enabled scanner (default)."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => run(() => startScan(ctx, args)),
  );

  server.registerTool(
    "rescan",
    {
      title: "Rescan",
      description:
        "Queue a new scan of the same source as an earlier scan (the Rescan button). Requires the Developer role. The earlier scan is kept as history.",
      inputSchema: {
        scanId: z.string().describe("Id of the scan to repeat."),
        scanType: z.enum(API_CREATE_SCAN_TYPES).optional().describe("Scan depth; omitted reuses the earlier scan's."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => run(() => rescan(ctx, args)),
  );

  server.registerTool(
    "update_finding_status",
    {
      title: "Update finding status",
      description:
        "Set a finding's triage status with an optional note; the scan's severity totals are recounted and the change is audit-logged. OPEN, IN_PROGRESS and RESOLVED need the Developer role. FALSE_POSITIVE and ACCEPTED_RISK need the Security or Admin role, which API keys do not carry.",
      inputSchema: {
        findingId: z.string().describe("Finding id."),
        status: z.enum(FINDING_STATUSES).describe("New triage status."),
        note: z.string().max(2000).optional().describe("Why the status changed."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    (args) => run(() => updateFindingStatus(ctx, args)),
  );

  return server;
}
