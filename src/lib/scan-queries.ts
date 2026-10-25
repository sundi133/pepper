/**
 * Filters shared by the scan and finding list endpoints (the UI's API routes
 * and the MCP server), so every client sees the same rows for the same query.
 */

/** Where-clause for an organization's scans, as the Scans page lists them. */
export function scanListWhere(params: {
  orgId: string;
  projectId?: string | null;
  status?: string | null;
  /** Repository name, source (repo URL or upload name), branch, or scan id. */
  q?: string | null;
}): Record<string, unknown> {
  const where: Record<string, unknown> = {
    project: { organizationId: params.orgId },
  };
  if (params.projectId) where.projectId = params.projectId;
  if (params.status) where.status = params.status;
  const q = params.q;
  if (q) {
    const contains = { contains: q, mode: "insensitive" as const };
    where.OR = [
      { project: { name: contains } },
      { sourceRef: contains },
      { branch: contains },
      { id: q },
    ];
  }
  return where;
}

/** Where-clause for one scan's findings, as the scan page lists them. */
export function scanFindingsWhere(params: {
  scanId: string;
  severity?: string[] | null;
  scanner?: string[] | null;
  /** Substring of the file path. */
  filePath?: string | null;
  status?: string[] | null;
  /** Findings triaged as false positives are hidden unless asked for. */
  includeFalsePositives?: boolean;
  isNew?: boolean | null;
}): Record<string, unknown> {
  const { severity, scanner, filePath, status } = params;
  const where: Record<string, unknown> = { scanId: params.scanId };
  if (severity) where.severity = { in: severity };
  if (scanner) where.scanner = { in: scanner };
  if (filePath) where.filePath = { contains: filePath };
  // Findings triaged as false positives are not issues to fix. An explicit
  // status filter still returns exactly that.
  if (status) where.status = { in: status };
  else if (!params.includeFalsePositives) where.status = { not: "FALSE_POSITIVE" };
  if (params.isNew === true) where.isNew = true;
  else if (params.isNew === false) where.isNew = false;

  // Exclude INFO severity findings from UI (INFO is internal categorization only)
  // Valid UI severities: CRITICAL, HIGH, MEDIUM, LOW
  if (!severity) {
    where.severity = { notIn: ["INFO"] };
  }
  return where;
}

/**
 * Where-clause for the Vulnerabilities workspace: findings across a set of
 * scans (typically the latest completed scan per project in an org), with the
 * same severity/scanner/status/false-positive rules as the per-scan view plus a
 * cross-field search.
 */
export function orgFindingsWhere(params: {
  scanIds: string[];
  severity?: string[] | null;
  scanner?: string[] | null;
  status?: string[] | null;
  includeFalsePositives?: boolean;
  q?: string | null;
}): Record<string, unknown> {
  const { scanIds, severity, scanner, status, q } = params;
  const where: Record<string, unknown> = { scanId: { in: scanIds } };
  if (severity && severity.length) where.severity = { in: severity };
  else where.severity = { notIn: ["INFO"] };
  if (scanner && scanner.length) where.scanner = { in: scanner };
  if (status && status.length) where.status = { in: status };
  else if (!params.includeFalsePositives) where.status = { not: "FALSE_POSITIVE" };
  if (q) {
    const contains = { contains: q, mode: "insensitive" as const };
    where.OR = [
      { title: contains },
      { filePath: contains },
      { cweId: contains },
      { cveId: contains },
      { description: contains },
    ];
  }
  return where;
}
