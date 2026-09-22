import { describe, expect, it } from "vitest";
import { parseAzureErrorBody } from "./azure-devops-api";

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
