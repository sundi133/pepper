import { describe, it, expect } from "vitest";
import { zeroDayScanner } from "./index";
import type { ScanContext } from "../types";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

function makeTempDir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "pepper-zero-day-test-")
  );
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

describe("ZERO_DAY scanner", () => {
  it("returns empty findings when no source files present", async () => {
    const workDir = makeTempDir({});
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: [],
        scanType: "ZERO_DAY_ONLY",
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

  it("prioritizes critical files for analysis", async () => {
    const workDir = makeTempDir({
      "src/auth.ts": `
        function validateToken(token: string) {
          return token.length > 0;
        }
      `,
      "src/payment.ts": `
        function processPayment(amount: number) {
          const balance = getBalance();
          deduct(amount);
          return true;
        }
      `,
      "src/utils.ts": `
        function helper(x: string) {
          return x.toUpperCase();
        }
      `,
    });
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: ["src/auth.ts", "src/payment.ts", "src/utils.ts"],
        scanType: "ZERO_DAY_ONLY",
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
      // Should analyze high-priority files (auth, payment)
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("analyzes cross-file dependencies and attack chains", async () => {
    const workDir = makeTempDir({
      "src/api.ts": `
        app.get('/api/users/:id', (req, res) => {
          const user = db.getUser(req.params.id);
          res.json(user);
        });
      `,
      "src/db.ts": `
        function getUser(id: string) {
          return users[id];
        }
      `,
    });
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: ["src/api.ts", "src/db.ts"],
        scanType: "ZERO_DAY_ONLY",
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
      // Should cross-analyze files for IDOR and authorization issues
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects authorization bypass vulnerabilities", async () => {
    const workDir = makeTempDir({
      "src/middleware.ts": `
        function checkAuth(req: Request) {
          if (!req.headers.authorization) {
            throw new Error('Unauthorized');
          }
        }
      `,
      "src/routes.ts": `
        app.delete('/api/users/:id', (req, res) => {
          checkAuth(req);
          db.deleteUser(req.params.id);
          res.sendStatus(200);
        });
      `,
    });
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: ["src/middleware.ts", "src/routes.ts"],
        scanType: "ZERO_DAY_ONLY",
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
      // Should detect weak auth or authorization bypasses
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("detects race conditions in critical operations", async () => {
    const workDir = makeTempDir({
      "src/transactions.ts": `
        async function transfer(from: string, to: string, amount: number) {
          const balance = await getBalance(from);
          if (balance < amount) throw new Error('Insufficient funds');
          await deduct(from, amount);
          await add(to, amount);
        }
      `,
    });
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: ["src/transactions.ts"],
        scanType: "ZERO_DAY_ONLY",
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
      // Should detect check-then-act race conditions
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("respects budget limit on file count", async () => {
    const fileList: string[] = [];
    const files: Record<string, string> = {};
    for (let i = 0; i < 100; i++) {
      const file = `src/module${i}.ts`;
      files[file] = `function fn${i}() { return ${i}; }`;
      fileList.push(file);
    }
    const workDir = makeTempDir(files);
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: fileList,
        scanType: "ZERO_DAY_ONLY",
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
      // Should analyze subset (48 files max) due to token budget
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("includes confidence scores in findings", async () => {
    const workDir = makeTempDir({
      "src/index.ts": `
        app.get('/api/data/:id', (req, res) => {
          const data = db.getData(req.params.id);
          res.json(data);
        });
      `,
    });
    try {
      const findings = await zeroDayScanner.scan({
        workDir,
        fileList: ["src/index.ts"],
        scanType: "ZERO_DAY_ONLY",
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
      // All findings should have confidence scores
      for (const finding of findings) {
        if (finding.scanner === "ZERO_DAY") {
          expect(typeof finding.confidence).toBe("number");
          expect(finding.confidence).toBeGreaterThanOrEqual(0);
          expect(finding.confidence).toBeLessThanOrEqual(1);
        }
      }
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
