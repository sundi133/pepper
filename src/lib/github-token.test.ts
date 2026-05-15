import { describe, it, expect } from "vitest";
import { isPlausibleGithubPersonalAccessToken } from "./github-token";

describe("isPlausibleGithubPersonalAccessToken", () => {
  it("accepts classic-style ghp token shape", () => {
    expect(
      isPlausibleGithubPersonalAccessToken(
        "ghp_" + "a".repeat(36),
      ),
    ).toBe(true);
  });

  it("accepts fine-grained github_pat prefix", () => {
    expect(
      isPlausibleGithubPersonalAccessToken(
        "github_pat_" + "A1b_".repeat(10),
      ),
    ).toBe(true);
  });

  it("rejects pasted prose / UI", () => {
    expect(
      isPlausibleGithubPersonalAccessToken(
        "Pepper Security Dashboard New Scan Projects",
      ),
    ).toBe(false);
  });

  it("rejects whitespace inside", () => {
    expect(isPlausibleGithubPersonalAccessToken("ghp_abc def")).toBe(false);
  });
});
