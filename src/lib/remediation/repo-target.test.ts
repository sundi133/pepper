import { describe, expect, it } from "vitest";
import { authenticatedRepoUrl, credentialsMismatch, resolveRemediationRepo } from "./repo-target";

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

  it("recognises an Azure DevOps Server repo added by URL (not via the integration)", () => {
    for (const url of [
      "https://tfs.corp.local/DefaultCollection/Web/_git/api",
      "https://tfs.corp.local/tfs/DefaultCollection/Web/_git/api",
      "http://10.0.0.5:8080/DefaultCollection/Web/_git/api.git",
    ]) {
      expect(
        resolveRemediationRepo({ scan: { sourceType: "UPLOAD", sourceRef: "scans/x.zip", branch: null }, project: { ...project, repoUrl: url } }),
        url,
      ).toMatchObject({ ok: true, provider: "azure_devops", repoUrl: url });
    }
    // `_git` needs a collection and project before it, and a repo after it.
    expect(
      resolveRemediationRepo({ scan: { sourceType: "GIT_CLONE", sourceRef: "https://git.example.com/_git/api", branch: null }, project }),
    ).toMatchObject({ ok: false, code: "PROVIDER_UNSUPPORTED" });
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

describe("credentialsMismatch", () => {
  const server = { provider: "azure_devops" as const, auth: { organization: "DefaultCollection", pat: "p", serverUrl: "https://tfs.corp.local/tfs" } };
  const cloud = { provider: "azure_devops" as const, auth: { organization: "acme", pat: "p" } };

  it("allows the connected server or cloud", () => {
    expect(credentialsMismatch("https://tfs.corp.local/tfs/DefaultCollection/Web/_git/api", server)).toBeNull();
    expect(credentialsMismatch("https://TFS.corp.local/tfs/DefaultCollection/Web/_git/api", server)).toBeNull();
    expect(credentialsMismatch("https://dev.azure.com/acme/Web/_git/api", cloud)).toBeNull();
    expect(credentialsMismatch("https://acme.visualstudio.com/Web/_git/api", cloud)).toBeNull();
  });

  it("never sends the PAT to another host", () => {
    expect(credentialsMismatch("https://evil.example/c/p/_git/api", server)).toMatch(/is not the connected Azure DevOps Server \(tfs\.corp\.local\)/);
    expect(credentialsMismatch("http://tfs.corp.local/tfs/DefaultCollection/Web/_git/api", server)).toMatch(/not the connected/);
    expect(credentialsMismatch("https://tfs.corp.local/c/p/_git/api", cloud)).toMatch(/connected to Azure DevOps Services/);
  });

  it("leaves other providers alone", () => {
    expect(credentialsMismatch("https://github.com/a/b", { provider: "github", token: "t" })).toBeNull();
  });
});
