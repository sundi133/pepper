import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { getRulesForLanguage } from "./pattern-rules";
import { runLlmSastScanner } from "./llm-analyzer";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_FILE_SIZE_BYTES,
} from "@/lib/constants";

export const sastPatternScanner: ScannerPlugin = {
  name: "SAST_PATTERN",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    for (const filePath of ctx.fileList) {
      if (ctx.signal?.aborted) break;

      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      const language = FILE_EXTENSIONS[ext];
      if (!language) continue;

      const parts = filePath.split(path.sep);
      if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

      const fullPath = path.join(ctx.workDir, filePath);

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE_BYTES) continue;

        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split("\n");
        const rules = getRulesForLanguage(language);

        for (const rule of rules) {
          for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];
            if (rule.pattern.test(line)) {
              if (rule.negative && rule.negative.test(line)) continue;

              const snippetStart = Math.max(0, lineNum - 2);
              const snippetEnd = Math.min(lines.length, lineNum + 3);
              const snippet = lines
                .slice(snippetStart, snippetEnd)
                .map((l, i) => `${snippetStart + i + 1}: ${l}`)
                .join("\n");

              findings.push({
                scanner: "SAST_PATTERN",
                severity: rule.severity,
                title: rule.title,
                description: rule.description,
                filePath,
                startLine: lineNum + 1,
                endLine: lineNum + 1,
                snippet,
                ruleId: rule.id,
                cweId: rule.cweId,
                confidence: 0.9,
              });

              // Reset lastIndex for global regexes
              rule.pattern.lastIndex = 0;
            }
            rule.pattern.lastIndex = 0;
          }
        }
      } catch {
        continue;
      }
    }

    ctx.onProgress?.(
      `SAST Pattern: found ${findings.length} issues in ${ctx.fileList.length} files`
    );
    return findings;
  },
};

export const sastLlmScanner: ScannerPlugin = {
  name: "SAST_LLM",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    return runLlmSastScanner(ctx);
  },
};
