import { describe, it, expect } from "vitest";
import {
  githubBlobLineUrl,
  gitlabBlobLineUrl,
  parseGithubRepo,
  parseGitlabRepo,
  repoFileLineLink,
  resolveGithubRepoUrlForOpenPr,
  resolveScanCloneRepoUrl,
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

  it("prefers scan clone URL when it parses as GitHub", () => {
    expect(
      resolveGithubRepoUrlForOpenPr({
        projectRepoUrl: "https://github.com/org/a.git",
        scanSourceType: "GIT_CLONE",
        scanSourceRef: "https://github.com/other/b.git",
      }),
    ).toBe("https://github.com/other/b.git");
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

describe("resolveScanCloneRepoUrl", () => {
  it("uses GitLab scan ref over GitHub project URL", () => {
    expect(
      resolveScanCloneRepoUrl({
        projectRepoUrl: "https://github.com/shemkumar/penetration-pal.git",
        scanSourceType: "WEBHOOK",
        scanSourceRef: "https://gitlab.com/shemkumar/penetration-pal.git",
      }),
    ).toBe("https://gitlab.com/shemkumar/penetration-pal.git");
  });
});

describe("parseGitlabRepo", () => {
  it("parses gitlab.com clone URL", () => {
    expect(
      parseGitlabRepo("https://gitlab.com/shemkumar/penetration-pal.git"),
    ).toEqual({ projectPath: "shemkumar/penetration-pal" });
  });
});

describe("gitlabBlobLineUrl", () => {
  it("builds blob URL with branch and line", () => {
    expect(
      gitlabBlobLineUrl({
        repoUrl: "https://gitlab.com/shemkumar/penetration-pal.git",
        branch: "feature/test",
        defaultBranch: "main",
        filePath: ".github/workflows/pr-compliance.yml",
        startLine: 409,
      }),
    ).toBe(
      "https://gitlab.com/shemkumar/penetration-pal/-/blob/feature%2Ftest/.github/workflows/pr-compliance.yml#L409",
    );
  });
});

describe("repoFileLineLink", () => {
  it("returns GitLab label for gitlab scan", () => {
    expect(
      repoFileLineLink({
        repoUrl: "https://gitlab.com/shemkumar/penetration-pal.git",
        branch: "feature/test",
        filePath: ".github/workflows/pr-compliance.yml",
        startLine: 409,
      }),
    ).toEqual({
      url: "https://gitlab.com/shemkumar/penetration-pal/-/blob/feature%2Ftest/.github/workflows/pr-compliance.yml#L409",
      label: "View on GitLab",
    });
  });

  it("opens absolute URLs for DAST-style findings", () => {
    expect(
      repoFileLineLink({
        repoUrl: "https://github.com/acme/app.git",
        filePath: "https://app.example.com/admin",
        startLine: null,
      }),
    ).toEqual({
      url: "https://app.example.com/admin",
      label: "Open URL",
    });
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

  it("strips leading ./ from file paths", () => {
    expect(
      githubBlobLineUrl({
        repoUrl: "https://github.com/acme/widget.git",
        branch: "main",
        filePath: "./src/index.ts",
        startLine: 1,
      }),
    ).toBe("https://github.com/acme/widget/blob/main/src/index.ts#L1");
  });
});
