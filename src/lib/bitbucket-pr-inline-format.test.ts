import { describe, it, expect } from "vitest";
import { parseBitbucketDiff } from "./bitbucket-pr-inline-format";

describe("parseBitbucketDiff", () => {
  it("returns empty for null or empty diffs", () => {
    expect(parseBitbucketDiff(null).size).toBe(0);
    expect(parseBitbucketDiff("").size).toBe(0);
  });

  it("splits a multi-file diff and returns per-file added/context lines", () => {
    const diff = [
      "diff --git a/src/a.ts b/src/a.ts",
      "index 1111111..2222222 100644",
      "--- a/src/a.ts",
      "+++ b/src/a.ts",
      "@@ -1,3 +1,4 @@",
      " const x = 1;",
      "-const y = 2;",
      "+const y = 3;",
      "+const z = 4;",
      " const w = 5;",
      "diff --git a/src/b.ts b/src/b.ts",
      "index 3333333..4444444 100644",
      "--- a/src/b.ts",
      "+++ b/src/b.ts",
      "@@ -10,2 +10,3 @@",
      " keep",
      "+added",
      " keep2",
    ].join("\n");

    const result = parseBitbucketDiff(diff);
    expect([...result.keys()].sort()).toEqual(["src/a.ts", "src/b.ts"]);
    expect([...result.get("src/a.ts")!].sort((a, b) => a - b)).toEqual([
      1, 2, 3, 4,
    ]);
    expect([...result.get("src/b.ts")!].sort((a, b) => a - b)).toEqual([
      10, 11, 12,
    ]);
  });

  it("handles a renamed file by using the new path", () => {
    const diff = [
      "diff --git a/old.ts b/renamed.ts",
      "similarity index 95%",
      "rename from old.ts",
      "rename to renamed.ts",
      "index aaaaaaa..bbbbbbb 100644",
      "--- a/old.ts",
      "+++ b/renamed.ts",
      "@@ -1,1 +1,2 @@",
      " keep",
      "+added",
    ].join("\n");

    const result = parseBitbucketDiff(diff);
    expect([...result.keys()]).toEqual(["renamed.ts"]);
    expect([...result.get("renamed.ts")!].sort((a, b) => a - b)).toEqual([1, 2]);
  });

  it("skips binary files (no patch content)", () => {
    const diff = [
      "diff --git a/logo.png b/logo.png",
      "index 1111111..2222222 100644",
      "Binary files a/logo.png and b/logo.png differ",
      "diff --git a/src/c.ts b/src/c.ts",
      "index 3333333..4444444 100644",
      "--- a/src/c.ts",
      "+++ b/src/c.ts",
      "@@ -1,1 +1,2 @@",
      " keep",
      "+added",
    ].join("\n");

    const result = parseBitbucketDiff(diff);
    expect([...result.keys()]).toEqual(["src/c.ts"]);
    expect(result.has("logo.png")).toBe(false);
  });

  it("ignores deleted files (no new-side lines)", () => {
    const diff = [
      "diff --git a/gone.ts b/gone.ts",
      "deleted file mode 100644",
      "index 1111111..0000000",
      "--- a/gone.ts",
      "+++ /dev/null",
      "@@ -1,2 +0,0 @@",
      "-line a",
      "-line b",
    ].join("\n");

    const result = parseBitbucketDiff(diff);
    expect(result.size).toBe(0);
  });
});
