import { describe, it, expect, vi, beforeEach } from "vitest";

const { resolveGithubToken } = vi.hoisted(() => ({
  resolveGithubToken: vi.fn(),
}));

vi.mock("@/lib/github-token-resolve", () => ({
  resolveGithubToken,
}));

import { resolveGithubPrTokenForOrg } from "./github-pr-token-resolve";

describe("resolveGithubPrTokenForOrg", () => {
  beforeEach(() => {
    resolveGithubToken.mockReset();
  });

  it("returns oauth token when connected", async () => {
    resolveGithubToken.mockResolvedValue({ token: "oauth-token-abc", source: "oauth" });
    const r = await resolveGithubPrTokenForOrg("org1");
    expect(r.source).toBe("github_oauth");
    expect(r.token).toBe("oauth-token-abc");
  });

  it("returns none when not connected", async () => {
    resolveGithubToken.mockResolvedValue(null);
    const r = await resolveGithubPrTokenForOrg("org1");
    expect(r.source).toBe("none");
    expect(r.token).toBeUndefined();
  });

  it("uses the GitHub App installation for the repository when one is linked", async () => {
    resolveGithubToken.mockResolvedValue({ token: "ghs_app", source: "app", installationId: BigInt(7) });
    const r = await resolveGithubPrTokenForOrg("org1", { owner: "acme", name: "api" });
    expect(resolveGithubToken).toHaveBeenCalledWith("org1", { owner: "acme", name: "api" });
    expect(r).toEqual({ token: "ghs_app", source: "github_app" });
  });
});
