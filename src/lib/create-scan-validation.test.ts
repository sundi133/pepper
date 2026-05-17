import { describe, it, expect } from "vitest";
import {
  validateCreateScanFields,
  nextFindingSelection,
} from "./create-scan-validation";

describe("validateCreateScanFields", () => {
  it("does not require an existing project when git URL is set", () => {
    expect(
      validateCreateScanFields({
        projectId: "",
        sourceMode: "git",
        file: null,
        repoUrl: "https://github.com/a/b.git",
        svnUrl: "",
      }),
    ).toEqual({});
    expect(
      validateCreateScanFields({
        projectId: "__new__",
        sourceMode: "git",
        file: null,
        repoUrl: "https://github.com/a/b.git",
        svnUrl: "",
      }),
    ).toEqual({});
  });

  it("requires git repo URL for new project without upload/svn", () => {
    expect(
      validateCreateScanFields({
        projectId: "__new__",
        sourceMode: "git",
        file: null,
        repoUrl: "  ",
        svnUrl: "",
      }).source,
    ).toBe("Source Code is required.");
  });
  it("requires git repo URL", () => {
    expect(
      validateCreateScanFields({
        projectId: "p1",
        sourceMode: "git",
        file: null,
        repoUrl: "  ",
        svnUrl: "",
      }).source,
    ).toBe("Source Code is required.");
  });

  it("requires upload file", () => {
    expect(
      validateCreateScanFields({
        projectId: "p1",
        sourceMode: "upload",
        file: null,
        repoUrl: "",
        svnUrl: "",
      }).source,
    ).toBe("Source Code is required.");
  });

  it("requires svn URL", () => {
    expect(
      validateCreateScanFields({
        projectId: "p1",
        sourceMode: "svn",
        file: null,
        repoUrl: "",
        svnUrl: "",
      }).source,
    ).toBe("Source Code is required.");
  });

  it("passes when git URL set", () => {
    expect(
      validateCreateScanFields({
        projectId: "p1",
        sourceMode: "git",
        file: null,
        repoUrl: "https://github.com/a/b.git",
        svnUrl: "",
      }),
    ).toEqual({});
  });
});

describe("nextFindingSelection", () => {
  it("opens when none selected", () => {
    const f = { id: "a", title: "t" };
    expect(nextFindingSelection(null, f)).toBe(f);
  });

  it("switches to different finding", () => {
    const a = { id: "a", title: "a" };
    const b = { id: "b", title: "b" };
    expect(nextFindingSelection(a, b)).toBe(b);
  });

  it("collapses when same finding clicked", () => {
    const a = { id: "a", title: "a" };
    expect(nextFindingSelection(a, a)).toBeNull();
  });
});
