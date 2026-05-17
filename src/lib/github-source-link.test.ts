import { describe, it, expect } from "vitest";
import {
  githubBlobLineUrl,
  parseGithubRepo,
  resolveGithubRepoUrlForOpenPr,
} from "./github-source-link";

describe("parseGithubRepo", () => {
  it("parses https github clone URL", () => {
    expect(parseGithubRepo("https://github.com/acme/widget.git")).toEqual({
      owner: "acme",
      repo: "widget",
    });
  });

  it("parses https URL with userinfo (no leaked host confusion)", () => {
    expect(
      parseGithubRepo("https://oauth2:tok@github.com/acme/widget.git"),
    ).toEqual({ owner: "acme", repo: "widget" });
  });

  it("parses ssh:// and git:// github URLs", () => {
    expect(parseGithubRepo("ssh://git@github.com/acme/widget.git")).toEqual({
      owner: "acme",
      repo: "widget",
    });
    expect(parseGithubRepo("git://github.com/acme/widget.git")).toEqual({
      owner: "acme",
      repo: "widget",
    });
  });

  it("parses ssh URL", () => {
    expect(parseGithubRepo("git@github.com:acme/widget.git")).toEqual({
      owner: "acme",
      repo: "widget",
    });
  });

  it("returns null for non-GitHub", () => {
    expect(parseGithubRepo("https://gitlab.com/a/b.git")).toBeNull();
  });
});

describe("resolveGithubRepoUrlForOpenPr", () => {
  it("falls back to scan sourceRef when project has no GitHub URL", () => {
    expect(
      resolveGithubRepoUrlForOpenPr({
        projectRepoUrl: null,
        scanSourceType: "GIT_CLONE",
        scanSourceRef: "https://github.com/acme/widget.git",
      }),
    ).toBe("https://github.com/acme/widget.git");
  });

  it("prefers project URL when it parses as GitHub", () => {
    expect(
      resolveGithubRepoUrlForOpenPr({
        projectRepoUrl: "https://github.com/org/a.git",
        scanSourceType: "GIT_CLONE",
        scanSourceRef: "https://github.com/other/b.git",
      }),
    ).toBe("https://github.com/org/a.git");
  });

  it("uses scan ref when project URL is not GitHub", () => {
    expect(
      resolveGithubRepoUrlForOpenPr({
        projectRepoUrl: "https://gitlab.com/a/b.git",
        scanSourceType: "GIT_CLONE",
        scanSourceRef: "https://github.com/acme/widget.git",
      }),
    ).toBe("https://github.com/acme/widget.git");
  });
});

describe("githubBlobLineUrl", () => {
  it("uses commit SHA and line anchor when present", () => {
    expect(
      githubBlobLineUrl({
        repoUrl: "https://github.com/acme/widget",
        commitSha: "abcdef1234567890",
        branch: "main",
        defaultBranch: "main",
        filePath: "app/server.py",
        startLine: 42,
      }),
    ).toBe(
      "https://github.com/acme/widget/blob/abcdef1234567890/app/server.py#L42",
    );
  });

  it("falls back to branch then defaultBranch", () => {
    expect(
      githubBlobLineUrl({
        repoUrl: "https://github.com/acme/widget.git",
        commitSha: null,
        branch: "develop",
        defaultBranch: "main",
        filePath: "src/x.ts",
        startLine: null,
      }),
    ).toBe("https://github.com/acme/widget/blob/develop/src/x.ts");
  });
});
