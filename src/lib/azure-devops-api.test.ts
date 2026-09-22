import { describe, expect, it } from "vitest";
import {
  azureApiBase,
  isAzureDevOpsServer,
  parseAzureErrorBody,
} from "./azure-devops-api";

describe("azureApiBase / isAzureDevOpsServer", () => {
  it("builds the hosted-service base for a cloud connection", () => {
    const auth = { organization: "acme", pat: "p" };
    expect(isAzureDevOpsServer(auth)).toBe(false);
    expect(azureApiBase(auth)).toBe("https://dev.azure.com/acme");
  });

  it("builds the on-prem Server base from serverUrl + collection", () => {
    const auth = {
      organization: "DefaultCollection",
      pat: "p",
      serverUrl: "https://tfs.company.com",
    };
    expect(isAzureDevOpsServer(auth)).toBe(true);
    expect(azureApiBase(auth)).toBe(
      "https://tfs.company.com/DefaultCollection",
    );
  });

  it("preserves a Server virtual directory and trims trailing slashes", () => {
    expect(
      azureApiBase({
        organization: "DefaultCollection",
        pat: "p",
        serverUrl: "https://tfs.company.com/tfs/",
      }),
    ).toBe("https://tfs.company.com/tfs/DefaultCollection");
  });

  it("treats a blank serverUrl as cloud", () => {
    const auth = { organization: "acme", pat: "p", serverUrl: "   " };
    expect(isAzureDevOpsServer(auth)).toBe(false);
    expect(azureApiBase(auth)).toBe("https://dev.azure.com/acme");
  });
});

describe("parseAzureErrorBody", () => {
  it("prefers the top-level message field", () => {
    expect(
      parseAzureErrorBody({ message: "TF401019: repo not found" }, "{...}"),
    ).toBe("TF401019: repo not found");
  });

  it("falls back to the nested value.Message shape", () => {
    expect(
      parseAzureErrorBody({ value: { Message: "Access denied" } }, "{...}"),
    ).toBe("Access denied");
  });

  it("uses the raw body (truncated) when no known field is present", () => {
    const raw = "x".repeat(600);
    const out = parseAzureErrorBody({}, raw);
    expect(out).toHaveLength(500);
  });

  it("returns an empty string when there is nothing to report", () => {
    expect(parseAzureErrorBody(null, "")).toBe("");
    expect(parseAzureErrorBody(undefined, "   ")).toBe("");
  });
});
