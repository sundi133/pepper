import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanMissingHardeningHeaders } from "./hardening-headers";
import type { ScanContext } from "../types";

function makeCtx(files: Record<string, string>): { ctx: ScanContext; workDir: string } {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-headers-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(workDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return {
    workDir,
    ctx: {
      workDir,
      fileList: Object.keys(files),
      scanType: "SAST_ONLY",
      orgSettings: {
        llmProvider: "openai",
        llmBaseUrl: "",
        llmModel: "",
        enableLlmSast: true,
        enableLlmSecrets: false,
        osvApiUrl: "",
        vulnDbMode: "offline",
      },
    },
  };
}

describe("scanMissingHardeningHeaders", () => {
  it("flags Nest bootstrap with no helmet or CSP headers", () => {
    const { ctx, workDir } = makeCtx({
      "src/main.ts": `
        import { NestFactory } from '@nestjs/core';
        import { AppModule } from './app.module';
        async function bootstrap() {
          const app = await NestFactory.create(AppModule);
          await app.listen(3000);
        }
        bootstrap();
      `,
    });
    try {
      const findings = scanMissingHardeningHeaders(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].cweId).toBe("CWE-693");
      expect(findings[0].title).toMatch(/Helmet|CSP|HSTS/i);
      expect(findings[0].cweId).not.toBe("CWE-285");
      expect(findings[0].filePath).toBe("src/main.ts");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("does not flag when helmet() is applied", () => {
    const { ctx, workDir } = makeCtx({
      "src/main.ts": `
        import { NestFactory } from '@nestjs/core';
        import helmet from 'helmet';
        async function bootstrap() {
          const app = await NestFactory.create(AppModule);
          app.use(helmet());
          await app.listen(3000);
        }
      `,
    });
    try {
      expect(scanMissingHardeningHeaders(ctx)).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("does not confuse missing headers with an authorization guard", () => {
    const { ctx, workDir } = makeCtx({
      "src/admin.guard.ts": `
        export class AdminGuard {
          canActivate() { return true; }
        }
      `,
      "src/main.ts": `
        import { NestFactory } from '@nestjs/core';
        async function bootstrap() {
          const app = await NestFactory.create(AppModule);
          await app.listen(3000);
        }
      `,
    });
    try {
      const findings = scanMissingHardeningHeaders(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].description).toMatch(/authorization guard/i);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("does not flag non-HTTP libraries", () => {
    const { ctx, workDir } = makeCtx({
      "src/cli.ts": "export function add(a: number, b: number) { return a + b; }\n",
    });
    try {
      expect(scanMissingHardeningHeaders(ctx)).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
