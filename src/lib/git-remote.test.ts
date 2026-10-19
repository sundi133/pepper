import { describe, expect, it } from "vitest";
import { normalizeGitRemote, remoteRepoName } from "./git-remote";

describe("normalizeGitRemote", () => {
  it("gives HTTPS, SSH and scp-style remotes of one repository the same form", () => {
    const forms = [
      "https://github.com/Org/Repo.git",
      "https://github.com/org/repo",
      "https://user:ghp_secret@github.com/Org/Repo.git/",
      "http://www.github.com/Org/Repo",
      "git@github.com:Org/Repo.git",
      "ssh://git@github.com/Org/Repo.git",
      "ssh://git@github.com:22/Org/Repo.git",
      "github.com/Org/Repo",
    ];
    for (const f of forms) expect(normalizeGitRemote(f), f).toBe("github.com/org/repo");
  });

  it("keeps nested groups and self-hosted ports out of the path", () => {
    expect(normalizeGitRemote("https://gitlab.example.com/group/sub/repo.git")).toBe("gitlab.example.com/group/sub/repo");
    expect(normalizeGitRemote("ssh://git@bitbucket.corp:7999/team/repo.git")).toBe("bitbucket.corp/team/repo");
  });

  it("maps every Azure DevOps form to dev.azure.com/org/project/repo", () => {
    for (const f of [
      "https://contoso@dev.azure.com/contoso/Payments/_git/api",
      "https://dev.azure.com/contoso/Payments/_git/api",
      "git@ssh.dev.azure.com:v3/contoso/Payments/api",
      "contoso@vs-ssh.visualstudio.com:v3/contoso/Payments/api",
      "https://contoso.visualstudio.com/Payments/_git/api",
    ]) {
      expect(normalizeGitRemote(f), f).toBe("dev.azure.com/contoso/payments/api");
    }
  });

  it("decodes escaped paths and rejects what isn't a remote", () => {
    expect(normalizeGitRemote("https://dev.azure.com/contoso/My%20Project/_git/api")).toBe("dev.azure.com/contoso/my project/api");
    expect(normalizeGitRemote("")).toBeNull();
    expect(normalizeGitRemote(null)).toBeNull();
    expect(normalizeGitRemote("https://github.com")).toBeNull();
  });

  it("returns the repository name", () => {
    expect(remoteRepoName("git@github.com:Org/My-Repo.git")).toBe("my-repo");
  });
});
