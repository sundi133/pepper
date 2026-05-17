import { describe, it, expect } from "vitest";
import {
  explainGithubPatAccessError,
  githubRepoAllowsPush,
  humanizeGithubApiError,
  normalizeRepoFilePath,
  parseGithubErrorBody,
} from "./github-api";

describe("explainGithubPatAccessError", () => {
  it("passes through unrelated GitHub messages", () => {
    expect(
      explainGithubPatAccessError("Validation Failed", "o", "r"),
    ).toBe("Validation Failed");
  });

  it("parses GitHub errors array", () => {
    const msg = parseGithubErrorBody(
      {
        message: "Validation Failed",
        errors: [{ code: "invalid", message: "Reference already exists" }],
      },
      "",
    );
    expect(msg).toContain("Validation Failed");
    expect(msg).toContain("Reference already exists");
  });

  it("detects push permission from repo metadata", () => {
    expect(githubRepoAllowsPush({ default_branch: "main" })).toBe(true);
    expect(
      githubRepoAllowsPush({
        default_branch: "main",
        permissions: { pull: true, push: false },
      }),
    ).toBe(false);
    expect(
      githubRepoAllowsPush({
        default_branch: "main",
        permissions: { push: true },
      }),
    ).toBe(true);
  });

  it("replaces bare Not Found with fallback context", () => {
    const out = humanizeGithubApiError(
      "Not Found",
      "acme",
      "widget",
      "File missing on branch main.",
    );
    expect(out).toBe("File missing on branch main.");
  });

  it("normalizes repo-relative paths", () => {
    expect(normalizeRepoFilePath("./src/app.ts")).toBe("src/app.ts");
    expect(normalizeRepoFilePath("\\comp\\app.py")).toBe("comp/app.py");
  });

  it("expands GitHub PAT permission denial with actionable hints", () => {
    const out = explainGithubPatAccessError(
      "Resource not accessible by personal access token",
      "acme",
      "widget",
    );
    expect(out).toContain("acme/widget");
    expect(out).toContain("Contents + Pull requests");
    expect(out).toContain("Repositories");
  });
});
