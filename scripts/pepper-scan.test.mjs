import { describe, it, expect } from "vitest";
import { parseArgs, projectName } from "./pepper-scan.mjs";

describe("parseArgs", () => {
  it("defaults to a waiting, advisory full scan", () => {
    const o = parseArgs([]);
    expect(o.wait).toBe(true);
    expect(o.gate).toBe(false);
    expect(o.type).toBeNull();
    expect(o.download).toBeNull();
  });

  it("reads --type in both forms and upper-cases it", () => {
    expect(parseArgs(["--type", "sca"]).type).toBe("SCA");
    expect(parseArgs(["--type=secrets"]).type).toBe("SECRETS");
  });

  it("reads --download with a directory or a default", () => {
    expect(parseArgs(["--download", "./out"]).download).toBe("./out");
    expect(parseArgs(["--download=./x"]).download).toBe("./x");
    expect(parseArgs(["--download"]).download).toBe("./pepper-report");
  });

  it("turns gating on only when asked", () => {
    expect(parseArgs(["--gate"]).gate).toBe(true);
  });

  it("supports fire-and-forget", () => {
    expect(parseArgs(["--wait=false"]).wait).toBe(false);
    expect(parseArgs(["--no-wait"]).wait).toBe(false);
  });
});

describe("projectName", () => {
  it("derives a stable name from an https remote", () => {
    expect(projectName("https://github.com/sundi133/pepper.git", "/x/pepper")).toBe(
      "sundi133/pepper (dev scan)",
    );
  });

  it("derives from an ssh remote", () => {
    expect(projectName("git@github.com:acme/api.git", "/x/api")).toBe(
      "acme/api (dev scan)",
    );
  });

  it("falls back to the directory name with no remote", () => {
    expect(projectName("", "/home/dev/myrepo")).toBe("myrepo (dev scan)");
  });

  it("always carries the dev-scan marker so it segregates from real projects", () => {
    // The name is what the server matches ephemeral projects on; it must never
    // collide with a canonical project's plain name.
    for (const remote of ["https://x/y.git", "git@h:o/r.git", ""]) {
      expect(projectName(remote, "/tmp/fallback")).toMatch(/\(dev scan\)$/);
    }
  });
});
