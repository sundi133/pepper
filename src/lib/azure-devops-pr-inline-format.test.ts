import { describe, it, expect } from "vitest";
import { parseAzureChangedFiles } from "./azure-devops-pr-inline-format";

describe("parseAzureChangedFiles", () => {
  it("returns empty set for null/empty input", () => {
    expect(parseAzureChangedFiles(null).size).toBe(0);
    expect(parseAzureChangedFiles(undefined).size).toBe(0);
    expect(parseAzureChangedFiles({}).size).toBe(0);
    expect(parseAzureChangedFiles({ changeEntries: [] }).size).toBe(0);
  });

  it("strips leading slashes from ADO server paths", () => {
    const result = parseAzureChangedFiles({
      changeEntries: [
        { item: { path: "/src/foo.ts" }, changeType: "edit" },
        { item: { path: "/README.md" }, changeType: "add" },
      ],
    });
    expect([...result].sort()).toEqual(["README.md", "src/foo.ts"]);
  });

  it("skips folder entries", () => {
    const result = parseAzureChangedFiles({
      changeEntries: [
        { item: { path: "/src", isFolder: true }, changeType: "edit" },
        { item: { path: "/src/foo.ts" }, changeType: "edit" },
      ],
    });
    expect([...result]).toEqual(["src/foo.ts"]);
  });

  it("excludes pure deletes (no right-side line to anchor on)", () => {
    const result = parseAzureChangedFiles({
      changeEntries: [
        { item: { path: "/old.ts" }, changeType: "delete" },
        { item: { path: "/new.ts" }, changeType: "add" },
        { item: { path: "/touched.ts" }, changeType: "edit" },
      ],
    });
    expect([...result].sort()).toEqual(["new.ts", "touched.ts"]);
  });

  it("keeps rename/edit composites — content side still exists", () => {
    // ADO sometimes returns composite changeTypes like "rename, edit"
    const result = parseAzureChangedFiles({
      changeEntries: [
        { item: { path: "/renamed.ts" }, changeType: "rename, edit" },
        { item: { path: "/edit-only.ts" }, changeType: "edit" },
      ],
    });
    expect([...result].sort()).toEqual(["edit-only.ts", "renamed.ts"]);
  });

  it("handles missing changeType (defaults to keep)", () => {
    const result = parseAzureChangedFiles({
      changeEntries: [{ item: { path: "/x.ts" } }],
    });
    expect([...result]).toEqual(["x.ts"]);
  });
});
