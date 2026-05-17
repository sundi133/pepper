import { describe, it, expect } from "vitest";
import {
  projectNameFromGitUrl,
  projectNameFromUploadFilename,
  projectNameFromSvnUrl,
} from "./project-name-from-source";

describe("projectNameFromGitUrl", () => {
  it("uses owner/repo from https URL", () => {
    expect(projectNameFromGitUrl("https://github.com/acme/widget.git")).toBe(
      "acme/widget",
    );
  });

  it("handles scp-style remotes", () => {
    expect(projectNameFromGitUrl("git@github.com:acme/widget.git")).toBe(
      "acme/widget",
    );
  });
});

describe("projectNameFromUploadFilename", () => {
  it("strips archive extension", () => {
    expect(projectNameFromUploadFilename("my-app.zip")).toBe("my-app");
  });
});

describe("projectNameFromSvnUrl", () => {
  it("uses last path segment", () => {
    expect(
      projectNameFromSvnUrl("https://svn.example.org/repos/myproduct/trunk"),
    ).toBe("trunk");
  });
});
