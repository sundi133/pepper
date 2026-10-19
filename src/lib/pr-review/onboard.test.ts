import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({ project: { findFirst: vi.fn(), update: vi.fn(async (_a: unknown) => ({})) } }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const create = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: (a: Record<string, unknown>) => create(a) }));

import { ensureProjectForGithubRepo } from "./onboard";

beforeEach(() => vi.clearAllMocks());

describe("zero-setup onboarding", () => {
  const repo = { id: 123, name: "api", full_name: "acme/api", default_branch: "trunk", owner: { login: "acme" }, language: "TypeScript", clone_url: "https://evil.example/acme/api.git" };

  it("creates the repository with a clone URL built from owner and name, never the payload's", async () => {
    db.project.findFirst.mockResolvedValue(null);
    expect(await ensureProjectForGithubRepo("o1", repo)).toEqual({ id: "p-new", created: true });
    expect(create.mock.calls[0][0]).toEqual({ organizationId: "o1", name: "acme/api", repoUrl: "https://github.com/acme/api.git", defaultBranch: "trunk" });
    expect(db.project.update.mock.calls[0][0]).toMatchObject({ data: { githubRepoId: 123, githubOwner: "acme", githubRepoName: "api", connectedViaGithub: true } });
  });

  it("reuses an existing repository in the organization", async () => {
    db.project.findFirst.mockResolvedValue({ id: "p1" });
    expect(await ensureProjectForGithubRepo("o1", repo)).toEqual({ id: "p1", created: false });
    expect(db.project.findFirst.mock.calls[0][0].where).toEqual({ organizationId: "o1", OR: [{ githubRepoId: 123 }, { repoUrl: "https://github.com/acme/api.git" }] });
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects payloads without a usable identity", async () => {
    expect(await ensureProjectForGithubRepo("o1", { ...repo, id: undefined })).toBeNull();
    expect(await ensureProjectForGithubRepo("o1", { ...repo, name: "../x", full_name: "acme/../x" })).toBeNull();
    expect(create).not.toHaveBeenCalled();
  });
});
