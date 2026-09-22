import { describe, expect, it } from "vitest";
import {
  azureDevOpsHttpsCloneUrl,
  parseAzureDevOpsRef,
  parseAzureDevOpsRepoInput,
} from "./parse-azure-devops-repo-input";

describe("parseAzureDevOpsRef", () => {
  it("strips refs/heads/", () => {
    expect(parseAzureDevOpsRef("refs/heads/main")).toBe("main");
    expect(parseAzureDevOpsRef("refs/heads/feature/x")).toBe("feature/x");
  });

  it("passes through a bare branch name", () => {
    expect(parseAzureDevOpsRef("develop")).toBe("develop");
  });

  it("defaults to main when empty/nullish", () => {
    expect(parseAzureDevOpsRef(null)).toBe("main");
    expect(parseAzureDevOpsRef(undefined)).toBe("main");
    expect(parseAzureDevOpsRef("  ")).toBe("main");
    expect(parseAzureDevOpsRef("refs/heads/")).toBe("main");
  });
});

describe("azureDevOpsHttpsCloneUrl", () => {
  it("builds the dev.azure.com _git URL and encodes segments", () => {
    expect(azureDevOpsHttpsCloneUrl("acme", "Web Team", "api")).toBe(
      "https://dev.azure.com/acme/Web%20Team/_git/api",
    );
  });
});

describe("parseAzureDevOpsRepoInput", () => {
  it("parses org/project/repo shorthand", () => {
    expect(parseAzureDevOpsRepoInput("acme/team/widget")).toEqual({
      organization: "acme",
      project: "team",
      repo: "widget",
    });
  });

  it("parses project/repo using the default organization", () => {
    expect(parseAzureDevOpsRepoInput("team/widget", "acme")).toEqual({
      organization: "acme",
      project: "team",
      repo: "widget",
    });
  });

  it("returns null for project/repo without a default organization", () => {
    expect(parseAzureDevOpsRepoInput("team/widget")).toBeNull();
  });

  it("parses a modern dev.azure.com _git URL", () => {
    expect(
      parseAzureDevOpsRepoInput(
        "https://dev.azure.com/acme/team/_git/widget",
      ),
    ).toEqual({ organization: "acme", project: "team", repo: "widget" });
  });

  it("strips a trailing .git and decodes spaces in URL segments", () => {
    expect(
      parseAzureDevOpsRepoInput(
        "https://dev.azure.com/acme/Web%20Team/_git/api.git",
      ),
    ).toEqual({ organization: "acme", project: "Web Team", repo: "api" });
  });

  it("parses a legacy {org}.visualstudio.com URL (org from subdomain)", () => {
    expect(
      parseAzureDevOpsRepoInput(
        "https://acme.visualstudio.com/team/_git/widget",
      ),
    ).toEqual({ organization: "acme", project: "team", repo: "widget" });
  });

  it("parses a legacy visualstudio.com URL that includes a collection", () => {
    expect(
      parseAzureDevOpsRepoInput(
        "https://acme.visualstudio.com/DefaultCollection/team/_git/widget",
      ),
    ).toEqual({ organization: "acme", project: "team", repo: "widget" });
  });

  it("rejects a look-alike host (no substring matching)", () => {
    expect(
      parseAzureDevOpsRepoInput(
        "https://dev.azure.com.attacker.example/acme/team/_git/widget",
      ),
    ).toBeNull();
  });

  it("rejects a dev.azure.com URL missing the _git segment", () => {
    expect(
      parseAzureDevOpsRepoInput("https://dev.azure.com/acme/team/widget"),
    ).toBeNull();
  });

  it("returns null for empty or unparseable input", () => {
    expect(parseAzureDevOpsRepoInput("")).toBeNull();
    expect(parseAzureDevOpsRepoInput("   ")).toBeNull();
    expect(parseAzureDevOpsRepoInput("just-one-segment")).toBeNull();
    expect(parseAzureDevOpsRepoInput("a/b/c/d/e")).toBeNull();
  });
});
