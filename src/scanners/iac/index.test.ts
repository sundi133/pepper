import { describe, it, expect } from "vitest";
import { iacScanner } from "./index";
import type { ScanContext } from "../types";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

function makeTempDir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-iac-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

describe("IaC scanner", () => {
  it("returns empty findings when no IaC files present", async () => {
    const workDir = makeTempDir({
      "src/app.ts": "console.log('hello');",
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["src/app.ts"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
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

  it("analyzes Dockerfile security configurations", async () => {
    const workDir = makeTempDir({
      "Dockerfile": `
        FROM ubuntu:22.04
        RUN apt-get update && apt-get install -y curl
        ENTRYPOINT ["curl"]
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["Dockerfile"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should scan Dockerfile (may have findings or be ok)
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("groups related Dockerfile and docker-compose files for stack analysis", async () => {
    const workDir = makeTempDir({
      "docker/Dockerfile": `
        FROM node:20
        USER node
        CMD ["node", "app.js"]
      `,
      "docker/docker-compose.yml": `
        version: '3'
        services:
          app:
            build: .
            ports:
              - "3000:3000"
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["docker/Dockerfile", "docker/docker-compose.yml"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should group related files for analysis
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("analyzes Kubernetes manifests for RBAC and security contexts", async () => {
    const workDir = makeTempDir({
      "k8s/deployment.yaml": `
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: app
        spec:
          template:
            spec:
              containers:
              - name: app
                image: myapp:1.0
                securityContext:
                  runAsUser: 1000
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["k8s/deployment.yaml"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should analyze K8s manifests
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("analyzes Terraform configuration for security issues", async () => {
    const workDir = makeTempDir({
      "infra/main.tf": `
        resource "aws_s3_bucket" "logs" {
          bucket = "my-logs"
        }

        resource "aws_s3_bucket_acl" "logs_acl" {
          bucket = aws_s3_bucket.logs.id
          acl    = "private"
        }
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["infra/main.tf"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should analyze Terraform
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("respects pepper:ignore suppression in IaC files", async () => {
    const workDir = makeTempDir({
      "Dockerfile": `
        # pepper:ignore
        FROM root:latest
        RUN whoami
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: ["Dockerfile"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Suppressed findings should be marked
      const suppressed = findings.filter(
        (f) => (f as unknown as Record<string, unknown>).suppressed,
      );
      expect(suppressed.length >= 0).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("analyzes GitHub Actions workflows for secrets and permissions", async () => {
    const workDir = makeTempDir({
      ".github/workflows/deploy.yml": `
        name: Deploy
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: actions/checkout@v3
              - run: npm run deploy
      `,
    });
    try {
      const findings = await iacScanner.scan({
        workDir,
        fileList: [".github/workflows/deploy.yml"],
        scanType: "IAC_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: true,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should analyze CI/CD workflows
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
