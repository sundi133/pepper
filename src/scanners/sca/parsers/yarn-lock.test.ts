import { describe, it, expect } from "vitest";
import { parseYarnLock } from "./yarn-lock";

describe("parseYarnLock", () => {
  it("should parse yarn.lock v1 format", () => {
    const content = `
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae3f6a9aadc42ead7bc6e4d7"

react@^18.0.0:
  version "18.2.0"
  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz#ac803a40979201e4296cea4229075050f2e7434f"
`;
    const deps = parseYarnLock(content);
    expect(deps.length).toBeGreaterThanOrEqual(2);
    expect(deps.map((d) => d.name)).toContain("lodash");
    expect(deps.map((d) => d.name)).toContain("react");
  });

  it("should extract version from URL if version field missing", () => {
    const content = `
package-name@^1.0.0:
  resolved "https://registry.yarnpkg.com/package-name/-/package-name-1.5.3.tgz#hash"
`;
    const deps = parseYarnLock(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].version).toBe("1.5.3");
  });

  it("should handle scoped packages", () => {
    const content = `
"@babel/core@^7.0.0":
  version "7.12.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.0.tgz#hash"
`;
    const deps = parseYarnLock(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe("@babel/core");
  });

  it("should deduplicate same package@version", () => {
    const content = `
lodash@4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#hash"

lodash@4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#hash"
`;
    const deps = parseYarnLock(content);
    expect(deps).toHaveLength(1);
  });

  it("should handle empty input", () => {
    const deps = parseYarnLock("");
    expect(deps).toHaveLength(0);
  });
});
