import { describe, it, expect } from "vitest";
import {
  parseArgs,
  projectName,
  diffFileSet,
  isManifest,
  hookScript,
} from "./pepper-scan.mjs";

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

describe("subcommand parsing", () => {
  it("defaults to scan and reads --diff", () => {
    expect(parseArgs([]).command).toBe("scan");
    expect(parseArgs(["--diff", "origin/main"]).diff).toBe("origin/main");
    expect(parseArgs(["--diff=origin/main"]).diff).toBe("origin/main");
    expect(parseArgs(["--diff"]).diff).toBe("@{upstream}");
  });

  it("treats a leading bare word as a subcommand", () => {
    const o = parseArgs(["install-hook", "--gate"]);
    expect(o.command).toBe("install-hook");
    expect(o.gate).toBe(true);
  });
});

describe("isManifest", () => {
  it("recognises manifests and lockfiles across ecosystems", () => {
    for (const f of [
      "package.json", "a/b/package-lock.json", "requirements.txt",
      "go.mod", "Cargo.lock", "pom.xml", "Gemfile.lock", "composer.json",
      "src/App.csproj", "pubspec.yaml",
    ]) {
      expect(isManifest(f)).toBe(true);
    }
  });

  it("does not treat source files as manifests", () => {
    for (const f of ["index.ts", "main.py", "README.md", "a/b.json"]) {
      expect(isManifest(f)).toBe(false);
    }
  });
});

describe("diffFileSet", () => {
  it("includes changed files plus every manifest, unchanged or not", () => {
    // SCA needs the manifests even when a change doesn't touch them.
    const changed = ["src/a.ts", "src/b.ts"];
    const tracked = ["src/a.ts", "package.json", "go.mod", "src/z.ts"];
    const set = diffFileSet(changed, tracked);
    expect(set).toContain("src/a.ts");
    expect(set).toContain("src/b.ts");
    expect(set).toContain("package.json");
    expect(set).toContain("go.mod");
    expect(set).not.toContain("src/z.ts");
  });

  it("does not duplicate a changed manifest", () => {
    const set = diffFileSet(["package.json"], ["package.json"]);
    expect(set.filter((f) => f === "package.json")).toHaveLength(1);
  });

  it("is empty when nothing changed and there are no manifests", () => {
    expect(diffFileSet([], ["src/a.ts"])).toEqual([]);
  });
});

describe("hookScript", () => {
  it("advisory install can never block a push", () => {
    const s = hookScript("/x/cli.mjs", false);
    expect(s).toContain("--wait=false");
    expect(s).toContain("|| true");
    expect(s).not.toContain("--gate");
  });

  it("gate install blocks on gate failure", () => {
    const s = hookScript("/x/cli.mjs", true);
    expect(s).toContain("--gate");
    expect(s).not.toContain("|| true");
  });

  it("honours a skip escape hatch", () => {
    expect(hookScript("/x/cli.mjs", false)).toContain("PEPPER_SKIP");
  });
});
