import { describe, it, expect } from "vitest";
import {
  githubHttpsCloneUrl,
  parseGithubRepoInput,
} from "./parse-github-repo-input";

describe("parseGithubRepoInput", () => {
  it("parses owner/repo", () => {
    expect(parseGithubRepoInput("acme/widget")).toEqual({
      owner: "acme",
      repo: "widget",
    });
  });

  it("parses https URL", () => {
    expect(parseGithubRepoInput("https://github.com/acme/widget.git")).toEqual({
      owner: "acme",
      repo: "widget",
    });
  });

  it("builds clone URL", () => {
    expect(githubHttpsCloneUrl("acme", "widget")).toBe(
      "https://github.com/acme/widget.git",
    );
  });
});
