import { describe, it, expect } from "vitest";
import { parsePoetryLock } from "./poetry-lock";

describe("parsePoetryLock", () => {
  it("should parse poetry.lock with multiple packages", () => {
    const content = `
[[package]]
name = "requests"
version = "2.28.1"

[[package]]
name = "urllib3"
version = "1.26.12"
`;
    const deps = parsePoetryLock(content);
    expect(deps).toHaveLength(2);
    expect(deps[0]).toEqual({
      name: "requests",
      version: "2.28.1",
      ecosystem: "pip",
      isDev: false,
    });
    expect(deps[1]).toEqual({
      name: "urllib3",
      version: "1.26.12",
      ecosystem: "pip",
      isDev: false,
    });
  });

  it("should handle scoped package names", () => {
    const content = `
[[package]]
name = "@scope/package"
version = "1.0.0"
`;
    const deps = parsePoetryLock(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe("@scope/package");
  });

  it("should skip packages without version", () => {
    const content = `
[[package]]
name = "incomplete-pkg"

[[package]]
name = "complete"
version = "1.0.0"
`;
    const deps = parsePoetryLock(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe("complete");
  });

  it("should handle empty input", () => {
    const deps = parsePoetryLock("");
    expect(deps).toHaveLength(0);
  });
});
