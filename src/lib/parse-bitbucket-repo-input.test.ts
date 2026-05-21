import { describe, expect, it } from "vitest";
import {
  bitbucketHttpsCloneUrl,
  normalizeBitbucketUuid,
  parseBitbucketRepoInput,
} from "./parse-bitbucket-repo-input";

describe("normalizeBitbucketUuid", () => {
  it("strips braces", () => {
    expect(normalizeBitbucketUuid("{abc-def}")).toBe("abc-def");
  });
});

describe("parseBitbucketRepoInput", () => {
  it("parses workspace/slug", () => {
    expect(parseBitbucketRepoInput("acme/widget")).toEqual({
      workspace: "acme",
      slug: "widget",
    });
  });

  it("parses bitbucket.org URL", () => {
    expect(
      parseBitbucketRepoInput("https://bitbucket.org/acme/widget.git"),
    ).toEqual({
      workspace: "acme",
      slug: "widget",
    });
  });
});

describe("bitbucketHttpsCloneUrl", () => {
  it("builds clone URL", () => {
    expect(bitbucketHttpsCloneUrl("acme", "widget")).toBe(
      "https://bitbucket.org/acme/widget.git",
    );
  });
});
