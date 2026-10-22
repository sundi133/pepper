import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: {
      findFirst: vi.fn(),
    },
  },
}));

vi.mock("@/lib/active-project-scans", () => ({
  cancelActiveScansForProject: vi.fn(),
}));

import { prisma } from "@/lib/prisma";
import { cancelActiveScansForProject } from "@/lib/active-project-scans";
import { ensureWebhookScanSlot } from "./webhook-scan-slot";

describe("ensureWebhookScanSlot", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns READY when project has no scan", async () => {
    vi.mocked(prisma.scan.findFirst).mockResolvedValue(null);
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "abc",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ status: "READY" });
    expect(cancelActiveScansForProject).not.toHaveBeenCalled();
  });

  it("returns ALREADY_QUEUED for same commit in flight", async () => {
    vi.mocked(prisma.scan.findFirst).mockResolvedValue({
      id: "scan-1",
      commitSha: "abc",
      scanType: "INCREMENTAL",
      status: "QUEUED",
    } as never);
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "abc",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ scanId: "scan-1", status: "ALREADY_QUEUED" });
    expect(cancelActiveScansForProject).not.toHaveBeenCalled();
  });

  it("keeps the earlier scan and stops any in progress before a new webhook scan", async () => {
    vi.mocked(prisma.scan.findFirst).mockResolvedValue({
      id: "scan-old",
      commitSha: "old",
      scanType: "FULL",
      status: "COMPLETED",
    } as never);
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "new",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ status: "READY" });
    expect(cancelActiveScansForProject).toHaveBeenCalledWith("p1");
  });
});
