import { describe, expect, it } from "vitest";
import { matchRepository, type RepositoryRow } from "./ide-repository";

const repo = (id: string, name: string, extra: Partial<RepositoryRow> = {}): RepositoryRow => ({ id, name, repoUrl: null, defaultBranch: "main", ...extra });

const REPOS: RepositoryRow[] = [
  repo("p1", "payments-api", { repoUrl: "https://github.com/Acme/payments-api.git" }),
  repo("p2", "web", { githubOwner: "acme", githubRepoName: "web" }),
  repo("p3", "billing", { azureOrganization: "contoso", azureProjectName: "Finance", azureRepoName: "billing" }),
  repo("p4", "infra", { gitlabNamespace: "platform/infra" }),
  repo("p5", "worker"),
  repo("p6", "docs"),
  repo("p7", "docs"),
];

describe("matchRepository", () => {
  it("matches the stored repository URL in any remote form", () => {
    for (const remote of ["git@github.com:acme/payments-api.git", "https://user:tok@github.com/ACME/payments-api"]) {
      expect(matchRepository(remote, null, REPOS)).toMatchObject({ repository: { id: "p1" }, matchedBy: "url" });
    }
  });

  it("matches provider identities when there is no URL", () => {
    expect(matchRepository("git@github.com:acme/web.git", null, REPOS)).toMatchObject({ repository: { id: "p2" }, matchedBy: "provider" });
    expect(matchRepository("git@ssh.dev.azure.com:v3/contoso/Finance/billing", null, REPOS)).toMatchObject({ repository: { id: "p3" }, matchedBy: "provider" });
    expect(matchRepository("git@gitlab.corp.io:platform/infra.git", null, REPOS)).toMatchObject({ repository: { id: "p4" }, matchedBy: "provider" });
  });

  it("falls back to the repository or folder name, and offers candidates when it is ambiguous", () => {
    expect(matchRepository("git@github.com:someone-else/worker.git", null, REPOS)).toMatchObject({ repository: { id: "p5" }, matchedBy: "name" });
    expect(matchRepository(null, "worker", REPOS)).toMatchObject({ repository: { id: "p5" }, matchedBy: "name" });
    const amb = matchRepository(null, "docs", REPOS);
    expect(amb.repository).toBeNull();
    expect(amb.candidates.map((c) => c.id).sort()).toEqual(["p6", "p7"]);
  });

  it("returns candidates, closest names first, when nothing matches", () => {
    const none = matchRepository("git@github.com:acme/payments-ui.git", null, [...REPOS, repo("p8", "payments-ui-legacy")]);
    expect(none.repository).toBeNull();
    expect(none.candidates[0].id).toBe("p8");
    expect(matchRepository("git@github.com:acme/x.git", null, REPOS, 3).candidates).toHaveLength(3);
  });
});
