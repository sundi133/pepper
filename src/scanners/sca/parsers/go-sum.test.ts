import { describe, it, expect } from "vitest";
import { parseGoSum } from "./go-sum";

describe("parseGoSum", () => {
  it("should parse go.sum entries", () => {
    const content = `github.com/stretchr/testify v1.8.0 h1:pSthTJgkF150pPf5iBvCEh2D+EWQOZzY1T7Y0K3KUY=
github.com/stretchr/testify v1.8.0/go.mod h1:jp+lzKIjW0J+/q1qrQ8+C0DqpVUYlFWCHo3/JmX8/A=
golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 h1:SrN+KX8Art/Sf7SMFWLvkdslqW5NDs7jWhMsDjeQmE8=
golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1/go.mod h1:oPkhp1MjuhygsvLauVZzXXc9MLWrHv6KNUiUx7dHsK=
`;
    const deps = parseGoSum(content);
    // Should have 2 unique versions (deduplicated from /go.mod variants)
    expect(deps.length).toBe(2);
    expect(deps[0]).toEqual({
      name: "github.com/stretchr/testify",
      version: "v1.8.0",
      ecosystem: "go",
      isDev: false,
    });
  });

  it("should skip /go.mod variants", () => {
    const content = `module.io v1.0.0 h1:hash=
module.io v1.0.0/go.mod h1:hash=
`;
    const deps = parseGoSum(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].version).toBe("v1.0.0");
  });

  it("should handle pre-release versions", () => {
    const content = `github.com/lib/pq v1.0.0-rc.1+meta h1:hash=
`;
    const deps = parseGoSum(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].version).toBe("v1.0.0-rc.1");
  });

  it("should ignore malformed lines", () => {
    const content = `github.com/valid v1.0.0 h1:hash=
invalid line without version
another.valid v2.0.0 h1:hash=
`;
    const deps = parseGoSum(content);
    expect(deps).toHaveLength(2);
  });

  it("should handle empty input", () => {
    const deps = parseGoSum("");
    expect(deps).toHaveLength(0);
  });
});
