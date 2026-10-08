import { beforeEach, describe, expect, it, vi } from "vitest";

const findMany = vi.fn();
const updateMany = vi.fn();
const getJob = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { scan: { findMany: (...a: unknown[]) => findMany(...a), updateMany: (...a: unknown[]) => updateMany(...a) } },
}));
vi.mock("@/lib/queue", () => ({ scanQueue: { getJob: (...a: unknown[]) => getJob(...a) } }));

import { cancelActiveScansForProject } from "./active-project-scans";

beforeEach(() => vi.clearAllMocks());

describe("cancelActiveScansForProject", () => {
  it("cancels only the repository's in-progress scans and removes their queued jobs", async () => {
    const remove = vi.fn();
    findMany.mockResolvedValue([{ id: "s2", jobId: "j2" }, { id: "s3", jobId: null }]);
    getJob.mockResolvedValue({ remove });
    expect(await cancelActiveScansForProject("p1")).toEqual(["s2", "s3"]);
    expect(findMany.mock.calls[0][0].where).toEqual({ projectId: "p1", status: { in: ["QUEUED", "RUNNING", "PAUSED"] } });
    expect(remove).toHaveBeenCalledTimes(1);
    expect(updateMany.mock.calls[0][0]).toMatchObject({
      where: { id: { in: ["s2", "s3"] }, status: { in: ["QUEUED", "RUNNING", "PAUSED"] } },
      data: { status: "CANCELLED" },
    });
  });

  it("leaves completed scans alone (nothing is deleted)", async () => {
    findMany.mockResolvedValue([]);
    expect(await cancelActiveScansForProject("p1")).toEqual([]);
    expect(updateMany).not.toHaveBeenCalled();
  });

  it("still cancels when the queued job can't be removed", async () => {
    findMany.mockResolvedValue([{ id: "s2", jobId: "j2" }]);
    getJob.mockRejectedValue(new Error("locked"));
    expect(await cancelActiveScansForProject("p1")).toEqual(["s2"]);
    expect(updateMany).toHaveBeenCalled();
  });
});
