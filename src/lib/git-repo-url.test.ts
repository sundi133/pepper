import { describe, it, expect } from "vitest";
import { withGitCredentials } from "./git-repo-url";

describe("withGitCredentials", () => {
  it("returns original URL when token empty", () => {
    expect(withGitCredentials("https://github.com/a/b.git", "")).toBe(
      "https://github.com/a/b.git",
    );
  });

  it("embeds token as HTTP basic user", () => {
    const u = withGitCredentials("https://github.com/a/b.git", "ghp_secret");
    const parsed = new URL(u);
    expect(parsed.hostname).toBe("github.com");
    expect(parsed.username).toBe("ghp_secret");
    expect(parsed.pathname).toContain("b.git");
  });
});
