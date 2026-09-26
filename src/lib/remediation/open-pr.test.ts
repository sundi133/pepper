import { afterEach, describe, expect, it, vi } from "vitest";
import { openProviderPullRequest } from "./repo-target";

type Call = { url: string; method: string; body: Record<string, unknown>; auth: string };

function mockFetch(response: unknown, status = 201): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const headers = init.headers as Record<string, string>;
      calls.push({
        url: String(url),
        method: init.method ?? "GET",
        body: JSON.parse(String(init.body ?? "{}")),
        auth: headers.Authorization ?? "",
      });
      return new Response(JSON.stringify(response), { status });
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

const pr = { head: "pepper/ai-remediation-x", base: "main", title: "fix(security): t", body: "body" };

describe("openProviderPullRequest", () => {
  it("GitHub: POST /repos/{owner}/{repo}/pulls", async () => {
    const calls = mockFetch({ html_url: "https://github.com/acme/api/pull/5", number: 5 });
    const r = await openProviderPullRequest(
      { provider: "github", token: "tok" },
      { ...pr, repoUrl: "https://github.com/acme/api.git" },
    );
    expect(r).toEqual({ ok: true, url: "https://github.com/acme/api/pull/5", number: 5 });
    expect(calls[0].url).toBe("https://api.github.com/repos/acme/api/pulls");
    expect(calls[0].body).toMatchObject({ head: pr.head, base: "main", title: pr.title });
    expect(calls[0].auth).toBe("Bearer tok");
  });

  it("Bitbucket Cloud: POST /repositories/{ws}/{slug}/pullrequests", async () => {
    const calls = mockFetch({ id: 9, links: { html: { href: "https://bitbucket.org/acme/api/pull-requests/9" } } });
    const r = await openProviderPullRequest(
      { provider: "bitbucket", auth: { username: "u", appPassword: "p" } },
      { ...pr, repoUrl: "https://bitbucket.org/acme/api.git" },
    );
    expect(r).toEqual({ ok: true, url: "https://bitbucket.org/acme/api/pull-requests/9", number: 9 });
    expect(calls[0].url).toBe("https://api.bitbucket.org/2.0/repositories/acme/api/pullrequests");
    expect(calls[0].body).toMatchObject({
      source: { branch: { name: pr.head } },
      destination: { branch: { name: "main" } },
      close_source_branch: true,
    });
  });

  it("Azure DevOps Services: POST pullrequests and build the web URL", async () => {
    const calls = mockFetch({ pullRequestId: 42 });
    const r = await openProviderPullRequest(
      { provider: "azure_devops", auth: { organization: "acme", pat: "pat" } },
      { ...pr, repoUrl: "https://dev.azure.com/acme/Web%20Team/_git/api" },
    );
    expect(r).toEqual({ ok: true, url: "https://dev.azure.com/acme/Web%20Team/_git/api/pullrequest/42", number: 42 });
    expect(calls[0].url).toMatch(/^https:\/\/dev\.azure\.com\/acme\/Web%20Team\/_apis\/git\/repositories\/api\/pullrequests\?api-version=/);
    expect(calls[0].body).toMatchObject({ sourceRefName: `refs/heads/${pr.head}`, targetRefName: "refs/heads/main" });
  });

  it("Azure DevOps Server: uses the on-prem base and truncates long descriptions", async () => {
    const calls = mockFetch({ pullRequestId: 7 });
    const r = await openProviderPullRequest(
      { provider: "azure_devops", auth: { organization: "DefaultCollection", pat: "pat", serverUrl: "https://tfs.corp/tfs" } },
      { ...pr, body: "x".repeat(5000), repoUrl: "https://tfs.corp/tfs/DefaultCollection/Payments/_git/api" },
    );
    expect(r).toMatchObject({ ok: true, url: "https://tfs.corp/tfs/DefaultCollection/Payments/_git/api/pullrequest/7" });
    expect(String(calls[0].body.description).length).toBeLessThanOrEqual(4000);
  });

  it("surfaces provider errors", async () => {
    mockFetch({ message: "Validation Failed", errors: [{ message: "A pull request already exists" }] }, 422);
    const r = await openProviderPullRequest(
      { provider: "github", token: "tok" },
      { ...pr, repoUrl: "https://github.com/acme/api" },
    );
    expect(r.ok).toBe(false);
  });
});
