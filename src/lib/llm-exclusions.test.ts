import { describe, expect, it } from "vitest";
import { configuredLlmExcludes, llmExcludedPath } from "./llm-exclusions";

describe("llm path exclusions", () => {
  it("always excludes private key and keystore files", () => {
    for (const p of ["certs/server.key", "deploy/tls.pem", "id_rsa", "home/.ssh/id_ed25519", "android/app.jks", "a/b/store.P12"]) {
      expect(llmExcludedPath(p, {}), p).toBe(true);
    }
    for (const p of ["src/keys.ts", "src/key.go", "README.md", "id_rsa.pub", "src/pem.ts"]) {
      expect(llmExcludedPath(p, {}), p).toBe(false);
    }
  });

  it("applies LLM_EXCLUDE_PATHS globs", () => {
    const env = { LLM_EXCLUDE_PATHS: " config/prod/** , *.tfvars,/deploy/secrets.yaml,src/**/generated/*.ts" };
    expect(configuredLlmExcludes(env)).toEqual(["config/prod/**", "*.tfvars", "/deploy/secrets.yaml", "src/**/generated/*.ts"]);
    expect(llmExcludedPath("config/prod/db.yaml", env)).toBe(true);
    expect(llmExcludedPath("config/prod/eu/db.yaml", env)).toBe(true);
    expect(llmExcludedPath("config/dev/db.yaml", env)).toBe(false);
    expect(llmExcludedPath("infra/envs/prod.tfvars", env)).toBe(true);
    expect(llmExcludedPath("deploy/secrets.yaml", env)).toBe(true);
    expect(llmExcludedPath("other/deploy/secrets.yaml", env)).toBe(false);
    expect(llmExcludedPath("src/generated/api.ts", env)).toBe(true);
    expect(llmExcludedPath("src/a/b/generated/api.ts", env)).toBe(true);
    expect(llmExcludedPath("src/app.ts", env)).toBe(false);
  });

  it("accepts OS paths and leading ./", () => {
    const env = { LLM_EXCLUDE_PATHS: "config/prod/**" };
    expect(llmExcludedPath("./config/prod/x.yml", env)).toBe(true);
  });
});
