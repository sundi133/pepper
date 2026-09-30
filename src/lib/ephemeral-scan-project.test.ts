import { describe, it, expect, vi, beforeEach } from "vitest";

const findFirst = vi.fn();
const createProjectWithBuildGate = vi.fn();

vi.mock("@/lib/prisma", () => ({
  prisma: { project: { findFirst: (...a: unknown[]) => findFirst(...a) } },
}));
vi.mock("@/lib/create-project-with-build-gate", () => ({
  createProjectWithBuildGate: (...a: unknown[]) =>
    createProjectWithBuildGate(...a),
}));

import { resolveEphemeralProject } from "./ephemeral-scan-project";

beforeEach(() => {
  findFirst.mockReset();
  createProjectWithBuildGate.mockReset();
});

describe("resolveEphemeralProject", () => {
  it("only ever matches ephemeral projects — never a canonical one", async () => {
    // This is the safety property: a dev scan must not select a real project,
    // because creating a scan wipes that project's prior scans.
    findFirst.mockResolvedValue({ id: "eph1" });
    await resolveEphemeralProject({ organizationId: "org1", name: "repo (dev scan)" });

    const where = findFirst.mock.calls[0][0].where;
    expect(where.ephemeral).toBe(true);
    expect(where.organizationId).toBe("org1");
    expect(where.name).toBe("repo (dev scan)");
  });

  it("reuses the existing ephemeral project without creating a new one", async () => {
    findFirst.mockResolvedValue({ id: "eph1" });

    const result = await resolveEphemeralProject({
      organizationId: "org1",
      name: "repo (dev scan)",
    });

    expect(result).toEqual({ id: "eph1", created: false });
    expect(createProjectWithBuildGate).not.toHaveBeenCalled();
  });

  it("creates a new ephemeral project when none exists", async () => {
    findFirst.mockResolvedValue(null);
    createProjectWithBuildGate.mockResolvedValue({ id: "eph2" });

    const result = await resolveEphemeralProject({
      organizationId: "org1",
      name: "repo (dev scan)",
      repoUrl: "https://github.com/a/b",
      defaultBranch: "dev",
    });

    expect(result).toEqual({ id: "eph2", created: true });
    // Must be flagged ephemeral so it stays segregated from canonical projects.
    expect(createProjectWithBuildGate).toHaveBeenCalledWith(
      expect.objectContaining({ ephemeral: true, organizationId: "org1" }),
    );
  });

  it("does not proliferate: a second call with the same name reuses", async () => {
    // First call creates, subsequent calls find it.
    findFirst.mockResolvedValueOnce(null).mockResolvedValue({ id: "eph3" });
    createProjectWithBuildGate.mockResolvedValue({ id: "eph3" });

    const first = await resolveEphemeralProject({ organizationId: "o", name: "n" });
    const second = await resolveEphemeralProject({ organizationId: "o", name: "n" });

    expect(first.created).toBe(true);
    expect(second).toEqual({ id: "eph3", created: false });
    expect(createProjectWithBuildGate).toHaveBeenCalledTimes(1);
  });
});
