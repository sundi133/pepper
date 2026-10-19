import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticatedRepoUrl, credentialsMismatch, openProviderPullRequest, repoGitEnv, resolveRemediationRepo, type ProviderCredentials } from "./repo-target";

const project = {
  repoUrl: null,
  defaultBranch: "main",
  connectedViaGithub: false,
  connectedViaBitbucket: false,
  connectedViaAzure: false,
};
const creds: ProviderCredentials = { provider: "gitlab", auth: { hostUrl: "https://gitlab.example.com", accessToken: "glpat-s3cr3t" } };

afterEach(() => vi.restoreAllMocks());

describe("GitLab as a remediation provider", () => {
  it("recognises gitlab.com, and self-managed GitLab from a GitLab-connected project", () => {
    expect(resolveRemediationRepo({ scan: { sourceType: "WEBHOOK", sourceRef: "https://gitlab.com/acme/api.git", branch: "feature" }, project })).toEqual({
      ok: true, provider: "gitlab", repoUrl: "https://gitlab.com/acme/api.git", baseBranch: "feature",
    });
    const selfManaged = { scan: { sourceType: "WEBHOOK", sourceRef: "https://gitlab.example.com/acme/api.git", branch: null } };
    expect(resolveRemediationRepo({ ...selfManaged, project: { ...project, connectedViaGitlab: true } })).toMatchObject({ ok: true, provider: "gitlab" });
    expect(resolveRemediationRepo({ ...selfManaged, project: { ...project, gitlabProjectId: 42 } })).toMatchObject({ ok: true, provider: "gitlab" });
    // An unknown host is still unsupported, as before.
    expect(resolveRemediationRepo({ ...selfManaged, project })).toMatchObject({ ok: false, code: "PROVIDER_UNSUPPORTED" });
  });

  it("keeps the other providers' detection unchanged", () => {
    const scan = (u: string) => ({ sourceType: "WEBHOOK", sourceRef: u, branch: null });
    expect(resolveRemediationRepo({ scan: scan("https://github.com/a/b"), project: { ...project, gitlabProjectId: 1 } })).toMatchObject({ provider: "github" });
    expect(resolveRemediationRepo({ scan: scan("https://dev.azure.com/a/P/_git/r"), project: { ...project, connectedViaGitlab: true } })).toMatchObject({ provider: "azure_devops" });
  });

  it("uses the token only on the connection's host", () => {
    expect(credentialsMismatch("https://gitlab.example.com/acme/api.git", creds)).toBeNull();
    expect(credentialsMismatch("https://gitlab.com/acme/api.git", creds)).toMatch(/is not the connected GitLab/);
    expect(authenticatedRepoUrl("https://gitlab.example.com/acme/api.git", creds)).toBe("https://oauth2:glpat-s3cr3t@gitlab.example.com/acme/api.git");
    expect(authenticatedRepoUrl("https://gitlab.com/acme/api.git", creds)).toBe("https://gitlab.com/acme/api.git");
    expect(repoGitEnv(creds)).toBeUndefined();
  });

  it("opens a merge request on the project path", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ iid: 12, web_url: "https://gitlab.example.com/acme/api/-/merge_requests/12" }), { status: 201 }));
    const r = await openProviderPullRequest(creds, { repoUrl: "https://gitlab.example.com/acme/sub/api.git", head: "pepper/fix-1", base: "feature", title: "Fix SQL injection", body: "…" });
    expect(r).toEqual({ ok: true, url: "https://gitlab.example.com/acme/api/-/merge_requests/12", number: 12 });
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gitlab.example.com/api/v4/projects/acme%2Fsub%2Fapi/merge_requests");
    expect(JSON.parse(String(init.body))).toMatchObject({ source_branch: "pepper/fix-1", target_branch: "feature", remove_source_branch: true });
  });

  it("reports GitLab's reason when it refuses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: ["Another open merge request already exists for this source branch"] }), { status: 409 }));
    const r = await openProviderPullRequest(creds, { repoUrl: "https://gitlab.example.com/acme/api", head: "h", base: "b", title: "t", body: "b" });
    expect(r).toMatchObject({ ok: false, error: expect.stringMatching(/409.*Another open merge request/) });
  });
});
