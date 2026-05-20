import { describe, expect, it } from "vitest";
import {
  githubRefToBranch,
  isMergedPullRequestToDefaultBranch,
  isPushToDefaultBranch,
  mainBranchWebhookScanType,
} from "./github-webhook-scan";

describe("github-webhook-scan helpers", () => {
  it("parses branch from refs/heads", () => {
    expect(githubRefToBranch("refs/heads/main")).toBe("main");
    expect(githubRefToBranch("refs/heads/feature/x")).toBe("feature/x");
    expect(githubRefToBranch("refs/tags/v1")).toBeNull();
  });

  it("detects push to default branch", () => {
    expect(
      isPushToDefaultBranch({ ref: "refs/heads/main", defaultBranch: "main" }),
    ).toBe(true);
    expect(
      isPushToDefaultBranch({
        ref: "refs/heads/develop",
        defaultBranch: "main",
      }),
    ).toBe(false);
  });

  it("detects merged PR into default branch", () => {
    expect(
      isMergedPullRequestToDefaultBranch({
        merged: true,
        baseRef: "main",
        defaultBranch: "main",
      }),
    ).toBe(true);
    expect(
      isMergedPullRequestToDefaultBranch({
        merged: true,
        baseRef: "develop",
        defaultBranch: "main",
      }),
    ).toBe(false);
    expect(
      isMergedPullRequestToDefaultBranch({
        merged: false,
        baseRef: "main",
        defaultBranch: "main",
      }),
    ).toBe(false);
  });

  it("defaults main-branch webhook scan to SAST_ONLY", () => {
    const prev = process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    delete process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    expect(mainBranchWebhookScanType()).toBe("SAST_ONLY");
    process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE = "FULL";
    expect(mainBranchWebhookScanType()).toBe("FULL");
    if (prev === undefined) delete process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    else process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE = prev;
  });
});
