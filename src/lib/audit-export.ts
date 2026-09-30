/**
 * Audit log query filters (shared by the list and export APIs) and the
 * CSV / JSON export stream.
 */
import { prisma } from "@/lib/prisma";
import { AUDIT_ORDER, auditWhere, type AuditQueryParams } from "@/lib/audit-log";

export type AuditFilters = Omit<AuditQueryParams, "organizationId" | "cursor" | "limit">;

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Parse `from` / `to` (ISO timestamps or YYYY-MM-DD; a date-only `to`
 * includes that whole day, UTC) plus the action / resource / user filters.
 */
export function parseAuditFilters(params: URLSearchParams): { filters: AuditFilters } | { error: string } {
  const filters: AuditFilters = {};
  for (const key of ["action", "resource", "userId"] as const) {
    const v = params.get(key)?.trim();
    if (v) filters[key] = v;
  }
  for (const key of ["from", "to"] as const) {
    const raw = params.get(key)?.trim();
    if (!raw) continue;
    const d = new Date(DATE_ONLY.test(raw) ? `${raw}T00:00:00.000Z` : raw);
    if (Number.isNaN(d.getTime())) return { error: `Invalid "${key}" date: ${raw}` };
    if (key === "to" && DATE_ONLY.test(raw)) d.setUTCHours(23, 59, 59, 999);
    filters[key] = d;
  }
  if (filters.from && filters.to && filters.from > filters.to) {
    return { error: `"from" is after "to"` };
  }
  return { filters };
}

export const CSV_COLUMNS = [
  "timestamp",
  "action",
  "resource",
  "resourceId",
  "userId",
  "userEmail",
  "userName",
  "ipAddress",
  "details",
] as const;

/**
 * RFC 4180 quoting, plus a leading `'` on values a spreadsheet would treat
 * as a formula (CSV injection): details and names can carry user input.
 */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let s = typeof value === "string" ? value : JSON.stringify(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export interface ExportRow {
  id: string;
  createdAt: Date;
  action: string;
  resource: string;
  resourceId: string | null;
  userId: string | null;
  ipAddress: string | null;
  details: unknown;
  user: { email: string | null; name: string | null } | null;
}

export function csvLine(r: ExportRow): string {
  return [
    r.createdAt.toISOString(),
    r.action,
    r.resource,
    r.resourceId,
    r.userId,
    r.user?.email,
    r.user?.name,
    r.ipAddress,
    r.details,
  ]
    .map(csvCell)
    .join(",");
}

export function jsonRecord(r: ExportRow) {
  return {
    id: r.id,
    timestamp: r.createdAt.toISOString(),
    action: r.action,
    resource: r.resource,
    resourceId: r.resourceId,
    user: r.userId ? { id: r.userId, email: r.user?.email ?? null, name: r.user?.name ?? null } : null,
    ipAddress: r.ipAddress,
    details: r.details ?? null,
  };
}

const PAGE = 1000;

/** Every matching entry, newest first, a page at a time. */
export async function* auditRows(organizationId: string, filters: AuditFilters): AsyncGenerator<ExportRow> {
  let cursor: string | undefined;
  for (;;) {
    const rows = await prisma.auditLog.findMany({
      where: auditWhere({ organizationId, ...filters }),
      orderBy: AUDIT_ORDER,
      take: PAGE,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    if (rows.length === 0) return;
    const ids = [...new Set(rows.map((r) => r.userId).filter((x): x is string => Boolean(x)))];
    const users = ids.length
      ? await prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, email: true, name: true } })
      : [];
    const byId = new Map(users.map((u) => [u.id, u]));
    for (const r of rows) {
      yield { ...r, user: r.userId ? (byId.get(r.userId) ?? null) : null };
    }
    if (rows.length < PAGE) return;
    cursor = rows[rows.length - 1].id;
  }
}

/** A streaming CSV or JSON (array) body for the export download. */
export function exportStream(format: "csv" | "json", rows: AsyncIterable<ExportRow>): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const iterator = rows[Symbol.asyncIterator]();
  let first = true;
  let done = false;
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      controller.enqueue(enc.encode(format === "csv" ? `${CSV_COLUMNS.join(",")}\r\n` : "["));
    },
    async pull(controller) {
      if (done) return;
      const chunk: string[] = [];
      for (let i = 0; i < 500; i++) {
        const next = await iterator.next();
        if (next.done) {
          done = true;
          break;
        }
        if (format === "csv") chunk.push(`${csvLine(next.value)}\r\n`);
        else {
          chunk.push(`${first ? "\n" : ",\n"}${JSON.stringify(jsonRecord(next.value))}`);
          first = false;
        }
      }
      if (chunk.length) controller.enqueue(enc.encode(chunk.join("")));
      if (done) {
        if (format === "json") controller.enqueue(enc.encode(first ? "]\n" : "\n]\n"));
        controller.close();
      }
    },
    async cancel() {
      await iterator.return?.(undefined);
    },
  });
}
