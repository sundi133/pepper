import { describe, it, expect } from "vitest";
import { withGitCredentials, withAzureDevOpsCredentials } from "./git-repo-url";

describe("withAzureDevOpsCredentials", () => {
  it("puts the PAT in the username (never an empty username)", () => {
    const url = withAzureDevOpsCredentials(
      "http://ado.corp/DefaultCollection/proj/_git/repo",
      "mypat",
    );
    // PAT in username, empty password → git sends Basic base64("mypat:")
    expect(url).toBe("http://mypat@ado.corp/DefaultCollection/proj/_git/repo");
    // Must NOT be the `:PAT@` (empty-username) form git refuses to send.
    expect(url).not.toContain("://:");
  });

  it("returns the URL unchanged for an empty PAT or non-http URL", () => {
    expect(withAzureDevOpsCredentials("http://ado/x", "")).toBe("http://ado/x");
    expect(withAzureDevOpsCredentials("git@ado:x", "pat")).toBe("git@ado:x");
  });
});

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
