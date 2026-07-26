import { describe, it, expect } from "vitest";
import { repositoryOwner, sameRepositoryOwner } from "./repo-owner";

describe("repositoryOwner", () => {
  // These are the exact shapes npm and PyPI return.
  it("parses the git+https form npm stores", () => {
    expect(repositoryOwner("git+https://github.com/preactjs/preact.git")).toBe(
      "github.com/preactjs",
    );
    expect(repositoryOwner("git+https://github.com/vuejs/core.git")).toBe(
      "github.com/vuejs",
    );
  });

  it("parses the plain https form PyPI stores", () => {
    expect(
      repositoryOwner("https://github.com/modelcontextprotocol/python-sdk"),
    ).toBe("github.com/modelcontextprotocol");
    expect(repositoryOwner("https://github.com/psf/requests")).toBe(
      "github.com/psf",
    );
  });

  it("parses git:// and scp-style remotes", () => {
    expect(repositoryOwner("git://github.com/lodash/lodash.git")).toBe(
      "github.com/lodash",
    );
    expect(repositoryOwner("git@github.com:vuejs/vuex.git")).toBe(
      "github.com/vuejs",
    );
  });

  it("handles other forges", () => {
    expect(repositoryOwner("https://gitlab.com/inkscape/inkscape")).toBe(
      "gitlab.com/inkscape",
    );
    expect(repositoryOwner("https://bitbucket.org/team/repo")).toBe(
      "bitbucket.org/team",
    );
  });

  it("is case and www insensitive", () => {
    expect(repositoryOwner("https://WWW.GitHub.com/PreactJS/preact")).toBe(
      "github.com/preactjs",
    );
  });

  it("returns undefined for anything that is not a forge URL", () => {
    // A personal site or a docs page says nothing about ownership.
    expect(repositoryOwner("https://lodash.com/")).toBeUndefined();
    expect(repositoryOwner("not a url")).toBeUndefined();
    expect(repositoryOwner("")).toBeUndefined();
    expect(repositoryOwner(undefined)).toBeUndefined();
  });

  it("returns undefined when there is no owner segment", () => {
    expect(repositoryOwner("https://github.com/")).toBeUndefined();
  });
});

describe("sameRepositoryOwner", () => {
  it("recognises a project's own siblings across languages", () => {
    // The mcp false positive: both publish from modelcontextprotocol.
    expect(
      sameRepositoryOwner(
        "https://github.com/modelcontextprotocol/python-sdk",
        "git+https://github.com/modelcontextprotocol/typescript-sdk.git",
      ),
    ).toBe(true);
  });

  it("recognises sibling packages in one organisation", () => {
    // vuex (vuejs/vuex) against vue (vuejs/core).
    expect(
      sameRepositoryOwner(
        "git+https://github.com/vuejs/vuex.git",
        "git+https://github.com/vuejs/core.git",
      ),
    ).toBe(true);
  });

  it("does not treat independent projects as the same owner", () => {
    // preact is legitimate but genuinely separate from react — cleared by the
    // maturity check instead, not by ownership.
    expect(
      sameRepositoryOwner(
        "git+https://github.com/preactjs/preact.git",
        "git+https://github.com/facebook/react.git",
      ),
    ).toBe(false);
  });

  it("returns false when either repository is unknown", () => {
    // Absent data must never clear a finding.
    expect(
      sameRepositoryOwner("https://github.com/vuejs/vuex", undefined),
    ).toBe(false);
    expect(sameRepositoryOwner(undefined, undefined)).toBe(false);
    expect(
      sameRepositoryOwner("https://github.com/vuejs/vuex", "https://evil.test/x"),
    ).toBe(false);
  });

  it("does not match on repository name alone", () => {
    // Same repo name under different owners is exactly the squat case.
    expect(
      sameRepositoryOwner(
        "https://github.com/attacker/lodash",
        "https://github.com/lodash/lodash",
      ),
    ).toBe(false);
  });
});
