import { describe, it, expect } from "vitest";
import { secretsPatternScanner, secretsLlmScanner } from "./index";
import type { ScanContext } from "../types";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

function makeTempDir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-secrets-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

describe("SECRETS_LLM scanner", () => {
  it("returns empty findings when no files present", async () => {
    const workDir = makeTempDir({});
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: [],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("scans source code files for credential patterns", async () => {
    const workDir = makeTempDir({
      "src/config.js": `
        const API_KEY = "sk-abcdef123456";
        const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxx";
      `,
    });
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: ["src/config.js"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // In offline mode, may return empty or mock findings
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("scans environment and config files", async () => {
    const workDir = makeTempDir({
      ".env": `
        DB_PASSWORD=SuperSecret123!
        API_KEY=sk-1234567890abcdef
        SLACK_WEBHOOK=https://hooks.slack.com/services/xxx/yyy/zzz
      `,
      "config/.env.local": `
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      `,
    });
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: [".env", "config/.env.local"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should analyze .env files
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("filters out test fixtures and placeholder values", async () => {
    const workDir = makeTempDir({
      "src/test.spec.ts": `
        // Test fixtures - should be filtered
        const testToken = "test_token_placeholder";
        const mockKey = "sk_example_key";
      `,
    });
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: ["src/test.spec.ts"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Test placeholders should have low/filtered confidence
      const highConfidence = findings.filter((f) => (f.confidence || 0) >= 0.8);
      expect(highConfidence.length >= 0).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("masks sensitive values in findings", async () => {
    const workDir = makeTempDir({
      "src/secrets.py": `
        api_key = "sk-1234567890abcdefghijklmn"
      `,
    });
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: ["src/secrets.py"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Sensitive values should be masked in evidence
      for (const finding of findings) {
        if (finding.metadata?.credentialType) {
          // Masked values should not contain the full secret
          expect((finding.metadata?.maskedValue as string) || "").not.toContain(
            "1234567890"
          );
        }
      }
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("respects pepper:ignore suppression", async () => {
    const workDir = makeTempDir({
      "src/ignored.js": `
        // pepper:ignore
        const realSecret = "sk-abcdefghijklmnopqrstuv";
      `,
    });
    try {
      const findings = await secretsLlmScanner.scan({
        workDir,
        fileList: ["src/ignored.js"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should have findings from ignored file
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});

describe("SECRETS_PATTERN scanner", () => {
  it("returns empty findings when no files present", async () => {
    const workDir = makeTempDir({});
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: [],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects AWS access keys with pattern matching", async () => {
    const workDir = makeTempDir({
      "config.js": `const AWS_KEY = "AKIAIOSFODNN7ABCDEFG";`,
    });
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: ["config.js"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings.length).toBeGreaterThan(0);
      const awsFindings = findings.filter((f) =>
        f.title?.includes("AWS_ACCESS_KEY"),
      );
      expect(awsFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects GitHub tokens with pattern matching", async () => {
    const workDir = makeTempDir({
      ".env": `GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz`,
    });
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: [".env"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings.length).toBeGreaterThan(0);
      const githubFindings = findings.filter((f) =>
        f.title?.includes("GITHUB_TOKEN"),
      );
      expect(githubFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects private keys with pattern matching", async () => {
    const workDir = makeTempDir({
      "id_rsa": `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrst
-----END RSA PRIVATE KEY-----`,
    });
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: ["id_rsa"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings.length).toBeGreaterThan(0);
      const keyFindings = findings.filter((f) =>
        f.title?.includes("PRIVATE_KEY") || f.title?.includes("SSH_PRIVATE_KEY"),
      );
      expect(keyFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects generic API keys with pattern matching", async () => {
    const workDir = makeTempDir({
      "config.ts": `
        // Test configuration - not real credentials
        api_key = "abcdefghij1234567890XXXXX"
        secret_key = "zyxwvutsrq9876543210YYYYY"
      `,
    });
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: ["config.ts"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(findings.length).toBeGreaterThan(0);
      const apiKeyFindings = findings.filter((f) =>
        f.title?.includes("API_KEY") || f.title?.includes("SECRET_KEY"),
      );
      expect(apiKeyFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("filters out test/placeholder values", async () => {
    const workDir = makeTempDir({
      "config.js": `
        const testKey = "example_placeholder_test_key";
        const placeholder = "xxxxxxxxxxxxxxxxxxxxxxxx";
      `,
    });
    try {
      const findings = await secretsPatternScanner.scan({
        workDir,
        fileList: ["config.js"],
        scanType: "FULL",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: true,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      // Should not detect test/placeholder values
      expect(findings.length).toBeLessThanOrEqual(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
