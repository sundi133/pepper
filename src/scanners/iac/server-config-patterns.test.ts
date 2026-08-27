import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanServerConfigPatterns } from "./server-config-patterns";
import type { ScanContext } from "../types";

function makeCtx(files: Record<string, string>): { ctx: ScanContext; workDir: string } {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-nginx-"));
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

describe("scanServerConfigPatterns", () => {
  it("flags nginx autoindex on", () => {
    const { ctx, workDir } = makeCtx({
      "nginx.conf": "server {\n  location / {\n    autoindex on;\n  }\n}\n",
    });
    try {
      const findings = scanServerConfigPatterns(ctx, "SAST_LLM");
      expect(findings).toHaveLength(1);
      expect(findings[0].cweId).toBe("CWE-548");
      expect(findings[0].title).toMatch(/autoindex/i);
      expect(findings[0].startLine).toBe(3);
      expect(findings[0].scanner).toBe("SAST_LLM");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("does not flag autoindex off", () => {
    const { ctx, workDir } = makeCtx({
      "nginx.conf": "location / { autoindex off; }\n",
    });
    try {
      expect(scanServerConfigPatterns(ctx)).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("flags Apache Options Indexes and ignores -Indexes", () => {
    const { ctx, workDir } = makeCtx({
      "etc/apache2/httpd.conf": "Options Indexes FollowSymLinks\nOptions -Indexes\n",
    });
    try {
      const findings = scanServerConfigPatterns(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("IAC-APACHE-INDEXES");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("respects pepper:ignore on the autoindex line", () => {
    const { ctx, workDir } = makeCtx({
      "nginx.conf": "# pepper:ignore\nautoindex on;\n",
    });
    try {
      expect(scanServerConfigPatterns(ctx)).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("ignores application source files", () => {
    const { ctx, workDir } = makeCtx({
      "src/app.ts": "const autoindex = 'on';\n",
    });
    try {
      expect(scanServerConfigPatterns(ctx)).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
