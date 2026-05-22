import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: {
      findUnique: vi.fn(),
    },
  },
}));

vi.mock("@/lib/remove-project-scans", () => ({
  removeAllScansForProject: vi.fn(),
}));

import { prisma } from "@/lib/prisma";
import { removeAllScansForProject } from "@/lib/remove-project-scans";
import { ensureWebhookScanSlot } from "./webhook-scan-slot";

describe("ensureWebhookScanSlot", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns READY when project has no scan", async () => {
    vi.mocked(prisma.scan.findUnique).mockResolvedValue(null);
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "abc",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ status: "READY" });
    expect(removeAllScansForProject).not.toHaveBeenCalled();
  });

  it("returns ALREADY_QUEUED for same commit in flight", async () => {
    vi.mocked(prisma.scan.findUnique).mockResolvedValue({
      id: "scan-1",
      commitSha: "abc",
      scanType: "INCREMENTAL",
      status: "QUEUED",
    });
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "abc",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ scanId: "scan-1", status: "ALREADY_QUEUED" });
    expect(removeAllScansForProject).not.toHaveBeenCalled();
  });

  it("replaces existing completed scan before new webhook scan", async () => {
    vi.mocked(prisma.scan.findUnique).mockResolvedValue({
      id: "scan-old",
      commitSha: "old",
      scanType: "FULL",
      status: "COMPLETED",
    });
    await expect(
      ensureWebhookScanSlot({
        projectId: "p1",
        commitSha: "new",
        scanType: "INCREMENTAL",
      }),
    ).resolves.toEqual({ status: "READY" });
    expect(removeAllScansForProject).toHaveBeenCalledWith("p1");
  });
});
