import * as fs from "fs";
import * as path from "path";
import { detectIacFileType, SKIP_DIRECTORIES } from "@/lib/constants";
import { applySeverityCalibration } from "@/lib/severity-calibration";
import { enrichFinding } from "../shared/finding-normalize";
import type { RawFinding, ScanContext, ScannerType } from "../types";

const PEPPER_IGNORE = /pepper:ignore/i;
const MAX_FILE_BYTES = 1024 * 1024;

const AUTOINDEX_ON = /^\s*autoindex\s+on\s*;/i;
const APACHE_INDEXES =
  /^\s*Options\s+(?![^#\n]*-Indexes)(?=[^#\n]*\b\+?Indexes\b)/i;
const CADDY_BROWSE = /^\s*browse\b/i;

function pathParts(filePath: string): string[] {
  return filePath.split(/[/\\]/);
}

function isInlineSuppressed(lines: string[], startLine: number): boolean {
  const idx = startLine - 1;
  if (idx < 0 || idx >= lines.length) return false;
  if (PEPPER_IGNORE.test(lines[idx])) return true;
  if (idx > 0 && PEPPER_IGNORE.test(lines[idx - 1])) return true;
  return false;
}

function buildSnippet(
  lines: string[],
  startLine: number,
  endLine = startLine,
): string {
  const start = Math.max(0, startLine - 3);
  const end = Math.min(lines.length, endLine + 2);
  return lines
    .slice(start, end)
    .map((line, index) => `${start + index + 1}: ${line}`)
    .join("\n");
}

function makeFinding(opts: {
  scanner: ScannerType;
  title: string;
  filePath: string;
  startLine: number;
  lines: string[];
  cweId: string;
  ruleId: string;
  description: string;
  recommendation: string;
  attackPath: string;
  impact: string;
  weaknessClass: string;
}): RawFinding {
  const raw: RawFinding = {
    scanner: opts.scanner,
    severity: "MEDIUM",
    title: opts.title,
    description: opts.description,
    filePath: opts.filePath,
    startLine: opts.startLine,
    endLine: opts.startLine,
    snippet: buildSnippet(opts.lines, opts.startLine),
    cweId: opts.cweId,
    confidence: 0.95,
    ruleId: opts.ruleId,
    metadata: {
      weaknessClass: opts.weaknessClass,
      category: "IaC",
      findingLayer: "ci-or-deploy-config",
      remediation: opts.recommendation,
    },
  };
  const calibrated = applySeverityCalibration(raw);
  return enrichFinding(calibrated, calibrated.metadata as Record<string, unknown>, {
    whatIsWrong: opts.title,
    where: `${opts.filePath}:${opts.startLine}`,
    whyExploitable: opts.description,
    attackPath: opts.attackPath,
    impact: opts.impact,
    fix: opts.recommendation,
    validation: `Confirm ${opts.filePath}:${opts.startLine} no longer enables directory listing.`,
  });
}

function matchDirectoryListing(
  line: string,
  filePath: string,
): { title: string; cweId: string; ruleId: string } | null {
  if (AUTOINDEX_ON.test(line)) {
    return {
      title: "Nginx Directory Listing Enabled (autoindex on)",
      cweId: "CWE-548",
      ruleId: "IAC-NGINX-AUTOINDEX",
    };
  }
  if (APACHE_INDEXES.test(line)) {
    return {
      title: "Apache Directory Listing Enabled (Options Indexes)",
      cweId: "CWE-548",
      ruleId: "IAC-APACHE-INDEXES",
    };
  }
  const lower = filePath.toLowerCase();
  if (
    (path.basename(lower) === "caddyfile" || lower.includes("/caddy/")) &&
    CADDY_BROWSE.test(line)
  ) {
    return {
      title: "Caddy Directory Listing Enabled (browse)",
      cweId: "CWE-548",
      ruleId: "IAC-CADDY-BROWSE",
    };
  }
  return null;
}

/**
 * Deterministic checks for web-server configs that LLM SAST skips (.conf)
 * and that stack-level IaC analysis often under-reports.
 */
export function scanServerConfigPatterns(
  ctx: ScanContext,
  scanner: ScannerType = "IAC",
): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const filePath of ctx.fileList) {
    if (pathParts(filePath).some((p) => SKIP_DIRECTORIES.has(p))) {
      continue;
    }
    if (detectIacFileType(filePath) !== "server-config") continue;

    let content: string;
    try {
      const fullPath = path.join(ctx.workDir, filePath);
      const stat = fs.statSync(fullPath);
      if (stat.size > MAX_FILE_BYTES) continue;
      content = fs.readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }
    if (!content.trim()) continue;

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = matchDirectoryListing(line, filePath);
      if (!match) continue;
      const startLine = i + 1;
      if (isInlineSuppressed(lines, startLine)) continue;
      findings.push(
        makeFinding({
          scanner,
          title: match.title,
          filePath,
          startLine,
          lines,
          cweId: match.cweId,
          ruleId: match.ruleId,
          description:
            "Directory listing is explicitly enabled. An unauthenticated visitor can enumerate files under the served root, including backups, source, and secrets that were never meant to be public.",
          recommendation:
            "Set `autoindex off;` (nginx), `Options -Indexes` (Apache), or remove `browse` (Caddy) on every public location. Prefer an explicit deny for `/.git`, `/backup`, and similar paths.",
          attackPath:
            "Request a directory URL with no index file (e.g. /uploads/ or /static/) and read the generated file listing.",
          impact:
            "Source, backups, or configuration files become enumerable and downloadable without authentication.",
          weaknessClass: "Information Disclosure",
        }),
      );
    }
  }

  return findings;
}
