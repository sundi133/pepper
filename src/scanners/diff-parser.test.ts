import { describe, expect, it } from "vitest";
import { parseDiffNameStatus, filterToChangedFiles } from "./diff-parser";

describe("diff-parser", () => {
  it("parses added, modified, and renamed files", () => {
    const out = parseDiffNameStatus(
      "A\tnew.ts\nM\tchanged.ts\nR100\told.ts\trenamed.ts\nD\tdeleted.ts",
    );
    expect(out.map((f) => f.path)).toEqual(["new.ts", "changed.ts", "renamed.ts"]);
    expect(out.find((f) => f.path === "deleted.ts")).toBeUndefined();
  });

  it("filters enumerated files to diff paths", () => {
    const filtered = filterToChangedFiles(
      ["src/a.ts", "src/b.ts"],
      [{ status: "M", path: "src/a.ts" }],
    );
    expect(filtered).toEqual(["src/a.ts"]);
  });
});
