import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { containerScanner, discoverImages } from "./index";

function makeWorkdir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-container-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

const baseOrgSettings = {
  llmProvider: "openai",
  llmBaseUrl: "",
  llmModel: "",
  enableLlmSast: false,
  enableLlmSecrets: false,
  osvApiUrl: "",
  vulnDbMode: "offline" as const,
};

describe("container scanner", () => {
  it("returns no findings when no image references are present", async () => {
    const workDir = makeWorkdir({ "src/index.ts": "console.log()" });
    try {
      const findings = await containerScanner.scan({
        workDir,
        fileList: ["src/index.ts"],
        scanType: "FULL",
        orgSettings: baseOrgSettings,
      });
      expect(findings).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("discovers Dockerfile and docker-compose image references", () => {
    const workDir = makeWorkdir({
      Dockerfile: `FROM node:20-alpine AS builder\nFROM nginx:1.25\n`,
      "docker-compose.yml": `services:\n  api:\n    image: ghcr.io/acme/api:1.0.0\n`,
    });
    try {
      const refs = discoverImages(workDir, ["Dockerfile", "docker-compose.yml"]);
      const images = refs.map((r) => r.image);
      expect(images).toContain("node:20-alpine");
      expect(images).toContain("nginx:1.25");
      expect(images).toContain("ghcr.io/acme/api:1.0.0");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});

describe("container scanner with trivy", () => {
  it.skipIf(!process.env.PEPPER_TRIVY_INTEGRATION)(
    "runs trivy against discovered images",
    async () => {
      const workDir = makeWorkdir({
        Dockerfile: "FROM alpine:3.19\n",
      });
      try {
        const findings = await containerScanner.scan({
          workDir,
          fileList: ["Dockerfile"],
          scanType: "CONTAINER_ONLY",
          orgSettings: baseOrgSettings,
        });
        expect(findings.length).toBeGreaterThan(0);
        expect(findings.every((f) => f.scanner === "CONTAINER")).toBe(true);
      } finally {
        fs.rmSync(workDir, { recursive: true, force: true });
      }
    },
    600_000,
  );
});
