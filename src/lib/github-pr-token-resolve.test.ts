import { describe, it, expect, vi, beforeEach } from "vitest";

const { getOrgGithubAccessToken } = vi.hoisted(() => ({
  getOrgGithubAccessToken: vi.fn(),
}));

vi.mock("@/lib/github-connection", () => ({
  getOrgGithubAccessToken,
}));

import { resolveGithubPrTokenForOrg } from "./github-pr-token-resolve";

describe("resolveGithubPrTokenForOrg", () => {
  beforeEach(() => {
    getOrgGithubAccessToken.mockReset();
  });

  it("returns oauth token when connected", async () => {
    getOrgGithubAccessToken.mockResolvedValue("oauth-token-abc");
    const r = await resolveGithubPrTokenForOrg("org1");
    expect(r.source).toBe("github_oauth");
    expect(r.token).toBe("oauth-token-abc");
  });

  it("returns none when not connected", async () => {
    getOrgGithubAccessToken.mockResolvedValue(null);
    const r = await resolveGithubPrTokenForOrg("org1");
    expect(r.source).toBe("none");
    expect(r.token).toBeUndefined();
  });
});
