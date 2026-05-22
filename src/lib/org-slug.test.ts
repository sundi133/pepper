import { describe, expect, it } from "vitest";
import { slugifyOrganizationName } from "./org-slug";

describe("slugifyOrganizationName", () => {
  it("lowercases and hyphenates", () => {
    expect(slugifyOrganizationName("Acme Security")).toBe("acme-security");
  });

  it("falls back for empty input", () => {
    expect(slugifyOrganizationName("   ")).toBe("org");
  });
});
