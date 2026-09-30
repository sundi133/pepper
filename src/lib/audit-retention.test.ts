import { gunzipSync } from "node:zlib";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Row = {
  id: string;
  organizationId: string | null;
  userId: string | null;
  action: string;
  resource: string;
  resourceId: string | null;
  details: unknown;
  ipAddress: string | null;
  createdAt: Date;
};
const db = { logs: [] as Row[], orgs: [] as Array<{ id: string; settings: { auditLogRetentionDays: number | null; auditLogArchive: boolean } | null }> };
const uploads: Array<{ key: string; body: Buffer }> = [];
let failUpload = false;

vi.mock("@/lib/prisma", () => ({
  prisma: {
    auditLog: {
      findMany: vi.fn(async ({ where, take }: { where: { organizationId: string | null; createdAt: { lt: Date } }; take: number }) =>
        db.logs
          .filter((r) => r.organizationId === where.organizationId && r.createdAt < where.createdAt.lt)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id))
          .slice(0, take),
      ),
      deleteMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
        const before = db.logs.length;
        db.logs = db.logs.filter((r) => !where.id.in.includes(r.id));
        return { count: before - db.logs.length };
      }),
      create: vi.fn(async ({ data }: { data: Omit<Row, "id" | "createdAt"> }) => {
        const row = { ...data, id: `new${db.logs.length}`, createdAt: new Date() } as Row;
        db.logs.push(row);
        return row;
      }),
    },
    organization: { findMany: vi.fn(async () => db.orgs) },
  },
}));
vi.mock("@/lib/minio", () => ({
  minioClient: {},
  BUCKET: "b",
  uploadObject: vi.fn(async (key: string, body: Buffer) => {
    if (failUpload) throw new Error("storage down");
    uploads.push({ key, body });
  }),
}));
vi.mock("@/lib/redis", () => ({ redis: { set: vi.fn(async () => "OK") } }));

import {
  archiveKey,
  effectiveRetentionDays,
  instanceRetentionDays,
  isOrgArchiveKey,
  purgeExpiredAuditLogs,
  purgeOrganization,
} from "./audit-retention";

const NOW = new Date("2026-10-01T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000);
function seed(org: string | null, ages: number[]) {
  for (const age of ages) {
    db.logs.push({
      id: `${org}-${age}-${db.logs.length}`,
      organizationId: org,
      userId: "u1",
      action: "user.login",
      resource: "user",
      resourceId: "u1",
      details: null,
      ipAddress: "10.0.0.1",
      createdAt: daysAgo(age),
    });
  }
}

beforeEach(() => {
  db.logs = [];
  db.orgs = [];
  uploads.length = 0;
  failUpload = false;
  delete process.env.AUDIT_LOG_RETENTION_DAYS;
});

describe("retention settings", () => {
  it("keeps forever unless configured, and never goes below 30 days", () => {
    expect(instanceRetentionDays({})).toBeNull();
    expect(instanceRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "90" })).toBe(90);
    expect(instanceRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "7" })).toBe(30);
    expect(instanceRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "abc" })).toBeNull();
    expect(effectiveRetentionDays(null, 90)).toBe(90);
    expect(effectiveRetentionDays(365, 90)).toBe(365);
    expect(effectiveRetentionDays(0, 90)).toBeNull();
    expect(effectiveRetentionDays(undefined, null)).toBeNull();
  });

  it("scopes archive keys to the organization", () => {
    const key = archiveKey("org1", daysAgo(200), daysAgo(100), 12);
    expect(key).toBe("audit-archive/org1/2026/20260315T000000Z_20260623T000000Z_12.ndjson.gz");
    expect(isOrgArchiveKey("org1", key)).toBe(true);
    expect(isOrgArchiveKey("org2", key)).toBe(false);
    expect(isOrgArchiveKey("org1", "audit-archive/org1/../org2/x.ndjson.gz")).toBe(false);
  });
});

describe("purgeOrganization", () => {
  it("archives expired entries, then deletes only those", async () => {
    seed("org1", [200, 120, 91, 89, 1]);
    seed("org2", [400]);
    const res = await purgeOrganization("org1", 90, true, NOW);
    expect(res).toMatchObject({ deleted: 3, archiveObjects: 1 });
    expect(db.logs.filter((r) => r.organizationId === "org1").map((r) => r.createdAt)).toEqual([daysAgo(89), daysAgo(1)]);
    expect(db.logs.some((r) => r.organizationId === "org2")).toBe(true);
    const lines = gunzipSync(uploads[0].body).toString().trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.map((l) => l.createdAt)).toEqual([daysAgo(200), daysAgo(120), daysAgo(91)].map((d) => d.toISOString()));
    expect(lines[0]).toMatchObject({ action: "user.login", ipAddress: "10.0.0.1" });
  });

  it("deletes nothing when the archive upload fails", async () => {
    seed("org1", [200, 150]);
    failUpload = true;
    const res = await purgeOrganization("org1", 90, true, NOW);
    expect(res.deleted).toBe(0);
    expect(res.error).toMatch(/storage down/);
    expect(db.logs).toHaveLength(2);
  });

  it("deletes without archiving when archiving is off", async () => {
    seed("org1", [200]);
    const res = await purgeOrganization("org1", 90, false, NOW);
    expect(res).toMatchObject({ deleted: 1, archiveObjects: 0 });
    expect(uploads).toHaveLength(0);
  });
});

describe("purgeExpiredAuditLogs", () => {
  it("by default deletes nothing", async () => {
    db.orgs = [{ id: "org1", settings: null }];
    seed("org1", [5000]);
    await purgeExpiredAuditLogs(NOW);
    expect(db.logs).toHaveLength(1);
  });

  it("applies each org's setting, the instance default, and records the purge", async () => {
    process.env.AUDIT_LOG_RETENTION_DAYS = "90";
    db.orgs = [
      { id: "keep", settings: { auditLogRetentionDays: 0, auditLogArchive: true } },
      { id: "year", settings: { auditLogRetentionDays: 365, auditLogArchive: true } },
      { id: "dflt", settings: null },
    ];
    seed("keep", [1000]);
    seed("year", [400, 200]);
    seed("dflt", [100, 10]);
    seed(null, [100]);
    const results = await purgeExpiredAuditLogs(NOW);
    const left = (org: string | null) => db.logs.filter((r) => r.organizationId === org && r.action === "user.login").length;
    expect([left("keep"), left("year"), left("dflt"), left(null)]).toEqual([1, 1, 1, 0]);
    expect(results.map((r) => [r.organizationId, r.deleted])).toEqual([["year", 1], ["dflt", 1], [null, 1]]);
    const purged = db.logs.filter((r) => r.action === "audit.purged");
    expect(purged.map((r) => r.organizationId)).toEqual(["year", "dflt", null]);
    expect(purged[0].details).toMatchObject({ retentionDays: 365, deleted: 1, archived: true, archiveObjects: 1 });
  });
});
