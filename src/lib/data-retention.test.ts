import { beforeEach, describe, expect, it, vi } from "vitest";

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date("2026-09-30T00:00:00Z");
const ago = (days: number) => new Date(NOW.getTime() - days * DAY);

type Obj = { name: string; lastModified: Date };
type ScanRow = { sourceRef: string; sourceType: string; status: string; project: { organizationId: string } };
type Snap = { id: string; projectId: string; organizationId: string; scanType: string; completedAt: Date };
type Run = { id: string; organizationId: string; status: string; createdAt: Date };

const db = {
  objects: [] as Obj[],
  scans: [] as ScanRow[],
  snapshots: [] as Snap[],
  runs: [] as Run[],
  audit: [] as Array<{ organizationId: string | null; action: string; details: Record<string, unknown> }>,
};
const deleted: string[] = [];
let failList = false;

vi.mock("@/lib/minio", () => ({
  BUCKET: "b",
  minioClient: {
    listObjectsV2: vi.fn((_b: string, prefix: string) => {
      if (failList) throw new Error("storage down");
      return (async function* () {
        for (const o of db.objects.filter((x) => x.name.startsWith(prefix))) yield o;
      })();
    }),
  },
  deleteObject: vi.fn(async (key: string) => {
    deleted.push(key);
    db.objects = db.objects.filter((o) => o.name !== key);
  }),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: {
      findMany: vi.fn(async ({ where }: { where: { sourceType: string; sourceRef: { in: string[] } } }) =>
        db.scans.filter((s) => s.sourceType === where.sourceType && where.sourceRef.in.includes(s.sourceRef)),
      ),
    },
    scanSnapshot: {
      findMany: vi.fn(
        async (args: {
          where: { completedAt?: { lt: Date }; projectId?: { in: string[] } };
          distinct?: string[];
        }) => {
          if (args.where.completedAt) return db.snapshots.filter((s) => s.completedAt < args.where.completedAt!.lt);
          // newest per (projectId, scanType)
          const inProjects = db.snapshots.filter((s) => args.where.projectId!.in.includes(s.projectId));
          const best = new Map<string, Snap>();
          for (const s of inProjects) {
            const k = `${s.projectId}|${s.scanType}`;
            const cur = best.get(k);
            if (!cur || s.completedAt > cur.completedAt) best.set(k, s);
          }
          return [...best.values()];
        },
      ),
      deleteMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
        const before = db.snapshots.length;
        db.snapshots = db.snapshots.filter((s) => !where.id.in.includes(s.id));
        return { count: before - db.snapshots.length };
      }),
    },
    remediationRun: {
      findMany: vi.fn(async ({ where }: { where: { createdAt: { lt: Date }; status: { in: string[] } } }) =>
        db.runs.filter((r) => r.createdAt < where.createdAt.lt && where.status.in.includes(r.status)),
      ),
      deleteMany: vi.fn(async ({ where }: { where: { id: { in: string[] }; status: { in: string[] } } }) => {
        const before = db.runs.length;
        db.runs = db.runs.filter((r) => !(where.id.in.includes(r.id) && where.status.in.includes(r.status)));
        return { count: before - db.runs.length };
      }),
    },
  },
}));
vi.mock("@/lib/audit-log", () => ({
  writeAuditLog: vi.fn(async (e: { organizationId: string | null; action: string; details: Record<string, unknown> }) => {
    db.audit.push(e);
  }),
}));
vi.mock("@/lib/redis", () => ({ redis: { set: vi.fn(async () => "OK") } }));

import {
  isUploadSourceKey,
  purgeExpiredUploads,
  purgeScanHistory,
  runDataRetention,
  scanHistoryRetentionDays,
  uploadRetentionDays,
} from "./data-retention";

beforeEach(() => {
  db.objects = [];
  db.scans = [];
  db.snapshots = [];
  db.runs = [];
  db.audit = [];
  deleted.length = 0;
  failList = false;
  delete process.env.UPLOAD_RETENTION_DAYS;
  delete process.env.SCAN_HISTORY_RETENTION_DAYS;
});

describe("retention settings", () => {
  it("is off unless set, and enforces minimum windows", () => {
    expect(uploadRetentionDays({})).toBeNull();
    expect(scanHistoryRetentionDays({})).toBeNull();
    expect(uploadRetentionDays({ UPLOAD_RETENTION_DAYS: "0" })).toBeNull();
    expect(uploadRetentionDays({ UPLOAD_RETENTION_DAYS: "abc" })).toBeNull();
    expect(uploadRetentionDays({ UPLOAD_RETENTION_DAYS: "7" })).toBe(7);
    expect(scanHistoryRetentionDays({ SCAN_HISTORY_RETENTION_DAYS: "5" })).toBe(30);
    expect(scanHistoryRetentionDays({ SCAN_HISTORY_RETENTION_DAYS: "365" })).toBe(365);
  });

  it("recognises only uploaded source archives", () => {
    expect(isUploadSourceKey("scans/abc/source.zip")).toBe(true);
    expect(isUploadSourceKey("scans/abc/source.tar.gz")).toBe(true);
    expect(isUploadSourceKey("sboms/abc/cyclonedx.json")).toBe(false);
    expect(isUploadSourceKey("scans/abc/other.zip")).toBe(false);
    expect(isUploadSourceKey("scans/abc/def/source.zip")).toBe(false);
  });
});

describe("upload retention", () => {
  it("deletes expired archives, keeps recent ones and ones an active scan still needs", async () => {
    db.objects = [
      { name: "scans/old/source.zip", lastModified: ago(10) },
      { name: "scans/orphan/source.tgz", lastModified: ago(10) },
      { name: "scans/busy/source.zip", lastModified: ago(10) },
      { name: "scans/new/source.zip", lastModified: ago(2) },
      { name: "sboms/old/cyclonedx.json", lastModified: ago(100) },
    ];
    db.scans = [
      { sourceRef: "scans/old/source.zip", sourceType: "UPLOAD", status: "COMPLETED", project: { organizationId: "org1" } },
      { sourceRef: "scans/busy/source.zip", sourceType: "UPLOAD", status: "RUNNING", project: { organizationId: "org1" } },
      { sourceRef: "scans/new/source.zip", sourceType: "UPLOAD", status: "COMPLETED", project: { organizationId: "org2" } },
    ];
    const r = await purgeExpiredUploads(7, NOW);
    expect(deleted.sort()).toEqual(["scans/old/source.zip", "scans/orphan/source.tgz"]);
    expect(r.deleted).toBe(2);
    expect(r.inUse).toBe(1);
    expect(r.byOrganization.get("org1")).toBe(1);
    expect(r.byOrganization.get(null)).toBe(1);
  });

  it("reports a storage failure without deleting anything", async () => {
    failList = true;
    const r = await purgeExpiredUploads(7, NOW);
    expect(r.error).toMatch(/storage down/);
    expect(deleted).toEqual([]);
  });
});

describe("scan history retention", () => {
  it("deletes old snapshots but keeps each project's latest per scan type", async () => {
    db.snapshots = [
      { id: "p1-full-old", projectId: "p1", organizationId: "org1", scanType: "FULL", completedAt: ago(400) },
      { id: "p1-full-latest", projectId: "p1", organizationId: "org1", scanType: "FULL", completedAt: ago(200) },
      { id: "p1-pr-latest", projectId: "p1", organizationId: "org1", scanType: "SAST_ONLY", completedAt: ago(300) },
      { id: "p1-recent", projectId: "p1", organizationId: "org1", scanType: "INCREMENTAL", completedAt: ago(10) },
      { id: "p2-only", projectId: "p2", organizationId: "org2", scanType: "FULL", completedAt: ago(500) },
    ];
    // p1's newest FULL is recent here, so both older FULL snapshots may go.
    db.snapshots.push({ id: "p1-full-new", projectId: "p1", organizationId: "org1", scanType: "FULL", completedAt: ago(5) });
    db.runs = [
      { id: "run-old", organizationId: "org1", status: "COMPLETED", createdAt: ago(200) },
      { id: "run-old-running", organizationId: "org1", status: "RUNNING", createdAt: ago(200) },
      { id: "run-new", organizationId: "org1", status: "FAILED", createdAt: ago(5) },
    ];
    const r = await purgeScanHistory(90, NOW);
    expect(db.snapshots.map((s) => s.id).sort()).toEqual(["p1-full-new", "p1-pr-latest", "p1-recent", "p2-only"]);
    expect(r.snapshots).toBe(2);
    expect(db.runs.map((x) => x.id).sort()).toEqual(["run-new", "run-old-running"]);
    expect(r.remediationRuns).toBe(1);
    expect(r.byOrganization.get("org1")).toEqual({ snapshots: 2, remediationRuns: 1 });
  });
});

describe("runDataRetention", () => {
  it("does nothing when neither policy is set", async () => {
    db.objects = [{ name: "scans/old/source.zip", lastModified: ago(1000) }];
    db.snapshots = [{ id: "s", projectId: "p", organizationId: "o", scanType: "FULL", completedAt: ago(1000) }];
    const r = await runDataRetention(NOW);
    expect(r).toEqual({ uploads: null, history: null });
    expect(deleted).toEqual([]);
    expect(db.audit).toEqual([]);
  });

  it("records purges in each organization's audit log", async () => {
    process.env.UPLOAD_RETENTION_DAYS = "30";
    db.objects = [{ name: "scans/old/source.zip", lastModified: ago(40) }];
    db.scans = [{ sourceRef: "scans/old/source.zip", sourceType: "UPLOAD", status: "COMPLETED", project: { organizationId: "org1" } }];
    await runDataRetention(NOW);
    expect(db.audit).toEqual([
      expect.objectContaining({ organizationId: "org1", action: "scan.uploads_purged", details: expect.objectContaining({ deleted: 1, retentionDays: 30 }) }),
    ]);
  });
});

describe("purgeOldScans", () => {
  it("deletes earlier scans past the window but keeps the latest, latest completed and active ones", async () => {
    const { prisma } = await import("@/lib/prisma");
    type S = { id: string; projectId: string; status: string; createdAt: Date; completedAt: Date | null };
    const scans: S[] = [
      { id: "p1-old", projectId: "p1", status: "COMPLETED", createdAt: ago(200), completedAt: ago(200) },
      { id: "p1-completed", projectId: "p1", status: "COMPLETED", createdAt: ago(150), completedAt: ago(150) },
      { id: "p1-latest-failed", projectId: "p1", status: "FAILED", createdAt: ago(120), completedAt: null },
      { id: "p2-stuck", projectId: "p2", status: "PAUSED", createdAt: ago(300), completedAt: null },
      { id: "p2-new", projectId: "p2", status: "COMPLETED", createdAt: ago(5), completedAt: ago(5) },
      { id: "p3-only", projectId: "p3", status: "COMPLETED", createdAt: ago(400), completedAt: ago(400) },
    ];
    const removed: string[] = [];
    const org = { project: { organizationId: "org1" } };
    vi.mocked(prisma.scan.findMany).mockImplementation((async (args: {
      where: { status?: { notIn?: string[] } | string; createdAt?: { lt: Date }; projectId?: { in: string[] } };
      distinct?: string[];
    }) => {
      const w = args.where;
      if (w.createdAt) {
        const notIn = (w.status as { notIn: string[] }).notIn;
        return scans.filter((s) => s.createdAt < w.createdAt!.lt && !notIn.includes(s.status)).map((s) => ({ ...s, ...org }));
      }
      const pool = scans.filter((s) => w.projectId!.in.includes(s.projectId) && (w.status ? s.status === w.status : true));
      const best = new Map<string, S>();
      for (const s of pool) {
        const cur = best.get(s.projectId);
        const t = (x: S) => (w.status ? x.completedAt!.getTime() : x.createdAt.getTime());
        if (!cur || t(s) > t(cur)) best.set(s.projectId, s);
      }
      return [...best.values()];
    }) as never);
    const p = prisma as unknown as Record<string, unknown>;
    p.scanArtifact = {
      findMany: vi.fn(async () => [{ objectKey: "artifacts/x.json" }]),
      deleteMany: vi.fn(async () => ({ count: 1 })),
    };
    p.finding = { deleteMany: vi.fn(async () => ({ count: 3 })) };
    (p.scan as Record<string, unknown>).deleteMany = vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
      removed.push(...where.id.in);
      return { count: where.id.in.length };
    });
    p.$transaction = vi.fn(async (ops: Promise<unknown>[]) => Promise.all(ops));

    const { purgeOldScans } = await import("./data-retention");
    const r = await purgeOldScans(90, NOW);
    expect(removed).toEqual(["p1-old"]);
    expect(r.scans).toBe(1);
    expect(r.byOrganization.get("org1")).toBe(1);
    expect(deleted).toContain("artifacts/x.json");
  });
});
