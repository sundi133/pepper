import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const llm = vi.hoisted(() => ({ answers: [] as string[], calls: [] as Array<{ system: string; user: string }> }));

vi.mock("@/lib/llm-gateway", async (orig) => ({
  ...(await orig<typeof import("@/lib/llm-gateway")>()),
  createLlmClient: () => ({ type: "openai" }),
  analyzeWithLlm: async (_c: unknown, _m: string, system: string, user: string) => {
    llm.calls.push({ system, user });
    const next = llm.answers.shift();
    if (next === undefined) throw new Error("no answer");
    return next;
  },
}));

import { getRepoMap, forgetRepoMap, expandRiskPaths, renderTree } from "./ai-repo-map";
import type { ScanContext } from "../types";

function repo(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-repomap-"));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}

function ctx(workDir: string, fileList: string[], extra: Partial<ScanContext> = {}): ScanContext {
  return {
    workDir,
    fileList,
    scanType: "FULL",
    orgSettings: {
      llmProvider: "openai",
      llmBaseUrl: "",
      llmModel: "m",
      llmApiKey: "k",
      enableLlmSast: true,
      enableLlmSecrets: false,
      osvApiUrl: "",
      vulnDbMode: "offline",
    },
    ...extra,
  };
}

describe("AI repo map", () => {
  beforeEach(() => {
    llm.answers = [];
    llm.calls = [];
    forgetRepoMap();
  });

  it("explores, reads the chosen files and renders the map", async () => {
    const files = {
      "Cargo.toml": "[package]\nname='router'",
      "crates/router/src/routes/payments.rs": "pub async fn payments_create() {}",
      "crates/router/src/services/authentication.rs": "pub struct ApiKeyAuth;",
      "crates/router/src/core/refunds.rs": "fn refund() {}",
    };
    const dir = repo(files);
    llm.answers = [
      JSON.stringify({ files: ["crates/router/src/services/authentication.rs", "does/not/exist.rs"] }),
      JSON.stringify({
        architecture: "Payments router in Rust.",
        frameworks: ["actix-web"],
        routes: [{ method: "POST", path: "/payments", handler: "payments_create", file: "crates/router/src/routes/payments.rs", auth: "ApiKeyAuth" }],
        authModel: { mechanisms: ["API key"], gaps: ["refunds route lacks merchant scoping"] },
        highRiskFiles: [{ path: "crates/router/src/core/", reason: "money" }, "crates/router/src/routes/payments.rs"],
      }),
    ];
    const map = await getRepoMap(ctx(dir, Object.keys(files)));
    expect(map.source).toBe("ai");
    expect(map.summary).toContain("REPOSITORY SECURITY MAP");
    expect(map.summary).toContain("actix-web");
    expect(map.summary).toContain("POST /payments");
    expect(map.summary).toContain("refunds route lacks merchant scoping");
    expect(map.highRiskFiles).toEqual(["crates/router/src/core/refunds.rs", "crates/router/src/routes/payments.rs"]);
    // The MAP call reads only real files the model chose.
    expect(llm.calls[1].user).toContain("### crates/router/src/services/authentication.rs");
    expect(llm.calls[1].user).not.toContain("does/not/exist.rs\n```");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("is built once per scan and shared by concurrent scanners", async () => {
    const dir = repo({ "a.ts": "x" });
    llm.answers = [JSON.stringify({ files: ["a.ts"] }), JSON.stringify({ architecture: "tiny" })];
    const c = ctx(dir, ["a.ts"], { scanId: "s1" });
    const [m1, m2] = await Promise.all([getRepoMap(c), getRepoMap(c)]);
    expect(m1).toBe(m2);
    expect(llm.calls).toHaveLength(2);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("maps the whole repository on PR scans, not just changed files", async () => {
    const dir = repo({ "src/changed.ts": "x", "src/auth/guard.ts": "y" });
    llm.answers = [JSON.stringify({ files: [] }), JSON.stringify({ architecture: "app" })];
    await getRepoMap(ctx(dir, ["src/changed.ts"], { repoFileList: ["src/changed.ts", "src/auth/guard.ts"] }));
    expect(llm.calls[0].user).toContain("src/auth/guard.ts");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("falls back to a path summary when the model fails", async () => {
    const dir = repo({ "a.ts": "x" });
    const map = await getRepoMap(ctx(dir, ["a.ts"]));
    expect(map.source).toBe("fallback");
    expect(map.highRiskFiles).toEqual([]);
    expect(map.summary).toContain("REPOSITORY CONTEXT");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("falls back without calling the model when no API key is set", async () => {
    const dir = repo({ "a.ts": "x" });
    const c = ctx(dir, ["a.ts"]);
    c.orgSettings.llmApiKey = "";
    expect((await getRepoMap(c)).source).toBe("fallback");
    expect(llm.calls).toHaveLength(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("expands directory risk entries and ignores unknown paths", () => {
    expect(expandRiskPaths(["src/", { path: "nope.ts" }, "src/a.ts"], ["src/a.ts", "src/b.ts", "lib/c.ts"])).toEqual([
      "src/a.ts",
      "src/b.ts",
    ]);
  });

  it("collapses large trees to directories with counts", () => {
    const many = Array.from({ length: 5000 }, (_, i) => `crates/c${i % 50}/src/file_${i}.rs`);
    const tree = renderTree(many, 4000);
    expect(tree.length).toBeLessThanOrEqual(4000);
    expect(tree).toMatch(/crates\/ \(5000 files\)/);
  });
});
