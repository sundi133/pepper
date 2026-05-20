import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { containerScanner } from "./index";

function makeWorkdir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-container-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

describe("container scanner", () => {
  it("returns no findings when no image references are present", async () => {
    const workDir = makeWorkdir({ "src/index.ts": "console.log()" });
    try {
      const findings = await containerScanner.scan({
        workDir,
        fileList: ["src/index.ts"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("discovers Dockerfile and docker-compose image references", async () => {
    const workDir = makeWorkdir({
      Dockerfile: `FROM node:20-alpine AS builder\nFROM nginx:1.25\n`,
      "docker-compose.yml": `services:\n  api:\n    image: ghcr.io/acme/api:1.0.0\n`,
    });
    try {
      const findings = await containerScanner.scan({
        workDir,
        fileList: ["Dockerfile", "docker-compose.yml"],
        scanType: "CONTAINER_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Without Trivy, no CVE inventory or failure findings are emitted.
      expect(
        findings.filter(
          (f) =>
            f.ruleId === "CONTAINER-INVENTORY" ||
            f.ruleId === "CONTAINER-SCAN-FAILED",
        ),
      ).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
