import { describe, expect, it } from "vitest";
import { authenticatedRepoUrl, resolveRemediationRepo } from "./repo-target";

const project = {
  repoUrl: null,
  defaultBranch: "main",
  connectedViaGithub: false,
  connectedViaBitbucket: false,
  connectedViaAzure: false,
};

describe("resolveRemediationRepo", () => {
  it("uses the scan clone URL for git scans and detects GitHub", () => {
    const r = resolveRemediationRepo({
      scan: { sourceType: "GIT_CLONE", sourceRef: "https://github.com/acme/api.git", branch: "dev" },
      project,
    });
    expect(r).toEqual({ ok: true, provider: "github", repoUrl: "https://github.com/acme/api.git", baseBranch: "dev" });
  });

  it("falls back to the project repo URL for uploads", () => {
    const r = resolveRemediationRepo({
      scan: { sourceType: "UPLOAD", sourceRef: "scans/x.zip", branch: null },
      project: { ...project, repoUrl: "https://bitbucket.org/acme/api" },
    });
    expect(r).toMatchObject({ ok: true, provider: "bitbucket", baseBranch: "main" });
  });

  it("recognises Azure DevOps cloud and on-prem Server repos", () => {
    expect(
      resolveRemediationRepo({
        scan: { sourceType: "WEBHOOK", sourceRef: "https://dev.azure.com/acme/Web/_git/api", branch: null },
        project,
      }),
    ).toMatchObject({ ok: true, provider: "azure_devops" });
    expect(
      resolveRemediationRepo({
        scan: { sourceType: "GIT_CLONE", sourceRef: "http://tfs.corp.local/DefaultCollection/Web/_git/api", branch: null },
        project: { ...project, connectedViaAzure: true },
      }),
    ).toMatchObject({ ok: true, provider: "azure_devops" });
  });

  it("rejects scans without a repository and unknown hosts", () => {
    expect(
      resolveRemediationRepo({ scan: { sourceType: "UPLOAD", sourceRef: "scans/x.zip", branch: null }, project }),
    ).toMatchObject({ ok: false, code: "REPO_REQUIRED" });
    expect(
      resolveRemediationRepo({
        scan: { sourceType: "GIT_CLONE", sourceRef: "https://git.example.com/a/b.git", branch: null },
        project,
      }),
    ).toMatchObject({ ok: false, code: "PROVIDER_UNSUPPORTED" });
  });
});

describe("authenticatedRepoUrl", () => {
  it("embeds provider credentials", () => {
    expect(authenticatedRepoUrl("https://github.com/a/b.git", { provider: "github", token: "tok" })).toBe(
      "https://x-access-token:tok@github.com/a/b.git",
    );
    expect(
      authenticatedRepoUrl("https://dev.azure.com/o/p/_git/r", {
        provider: "azure_devops",
        auth: { organization: "o", pat: "pat" },
      }),
    ).toBe("https://pat@dev.azure.com/o/p/_git/r");
  });
});
