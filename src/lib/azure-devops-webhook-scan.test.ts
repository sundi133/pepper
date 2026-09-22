import { describe, expect, it } from "vitest";
import {
  isAzureDevOpsPushToDefaultBranch,
  mainBranchWebhookScanType,
} from "./azure-devops-webhook-scan";

describe("isAzureDevOpsPushToDefaultBranch", () => {
  it("matches a push to the default branch (refs/heads form)", () => {
    expect(
      isAzureDevOpsPushToDefaultBranch({
        refName: "refs/heads/main",
        defaultBranch: "main",
      }),
    ).toBe(true);
  });

  it("matches when the default branch itself is stored as refs/heads", () => {
    expect(
      isAzureDevOpsPushToDefaultBranch({
        refName: "refs/heads/release",
        defaultBranch: "release",
      }),
    ).toBe(true);
  });

  it("ignores a push to a non-default branch", () => {
    expect(
      isAzureDevOpsPushToDefaultBranch({
        refName: "refs/heads/feature/x",
        defaultBranch: "main",
      }),
    ).toBe(false);
  });

  it("falls back to main when the default branch is empty", () => {
    expect(
      isAzureDevOpsPushToDefaultBranch({
        refName: "refs/heads/main",
        defaultBranch: "",
      }),
    ).toBe(true);
    expect(
      isAzureDevOpsPushToDefaultBranch({
        refName: "refs/heads/dev",
        defaultBranch: "",
      }),
    ).toBe(false);
  });
});

describe("mainBranchWebhookScanType (re-exported for ADO webhooks)", () => {
  it("is available and defaults to SAST_ONLY", () => {
    const prev = process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    delete process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    expect(mainBranchWebhookScanType()).toBe("SAST_ONLY");
    if (prev === undefined) delete process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE;
    else process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE = prev;
  });
});
