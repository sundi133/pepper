import * as os from "os";
import * as path from "path";
import { describe, expect, it } from "vitest";
import { extractArchive } from "./extract-archive";

describe("extractArchive", () => {
  it("throws when destination directory does not exist", () => {
    expect(() =>
      extractArchive("/nonexistent/source.zip", "/nonexistent/dest"),
    ).toThrow(/destination does not exist/);
  });

  it("throws for unsupported archive extension", () => {
    const tmp = os.tmpdir();
    expect(() =>
      extractArchive(path.join(tmp, "pepper-test-fake.unknown"), tmp),
    ).toThrow(/Unsupported archive format/);
  });
});
