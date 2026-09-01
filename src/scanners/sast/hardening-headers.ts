import * as fs from "fs";
import * as path from "path";
import { SKIP_DIRECTORIES } from "@/lib/constants";
import { applySeverityCalibration } from "@/lib/severity-calibration";
import { enrichFinding } from "../shared/finding-normalize";
import type { RawFinding, ScanContext } from "../types";

const SOURCE_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const MAX_FILE_BYTES = 1024 * 1024;
const TEST_PATH =
  /(?:^|[/\\])(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:[/\\]|$)/i;

const WEB_FRAMEWORK =
  /\b(?:NestFactory\.create|express\s*\(|fastify\s*\(|new\s+Koa\s*\(|from\s+['"]express['"]|from\s+['"]@nestjs\/(?:core|common)['"]|require\(\s*['"]express['"]|createServer\s*\()/;

const HEADER_CONTROL =
  /\b(?:from\s+['"]helmet['"]|require\(\s*['"]helmet['"]|@fastify\/helmet|nestjs-helmet|fastify-helmet|koa-helmet|helmet-csp|secure-headers|helmet\s*\(|app\.use\(\s*helmet|Strict-Transport-Security|Content-Security-Policy|X-Content-Type-Options|X-Frame-Options|Referrer-Policy)\b/;

const COMMENTED_HELMET = /^\s*(?:\/\/|#|\*|\/\*).*\bhelmet\s*\(/i;

function isCommentLine(line: string): boolean {
  const t = line.trim();
  return (
    t.startsWith("//") ||
    t.startsWith("#") ||
    t.startsWith("*") ||
    t.startsWith("/*")
  );
}

function lineHasHeaderControl(line: string): boolean {
  return !isCommentLine(line) && HEADER_CONTROL.test(line);
}

function preferredBootstrapScore(filePath: string): number {
  const base = path.basename(filePath).toLowerCase();
  if (base === "main.ts" || base === "main.js") return 5;
  if (base === "app.module.ts") return 4;
  if (base === "server.ts" || base === "server.js") return 3;
  if (base === "app.ts" || base === "app.js") return 3;
  if (base === "index.ts" || base === "index.js") return 2;
  if (base.includes("bootstrap")) return 4;
  return 1;
}

/**
 * Repo-level absence check for HTTP hardening headers (Helmet/CSP/HSTS).
 * Distinct from authorization findings (CWE-285) — this is CWE-693/CWE-16.
 */
export function scanMissingHardeningHeaders(ctx: ScanContext): RawFinding[] {
  let frameworkFile: string | undefined;
  let frameworkLine = 1;
  let frameworkLines: string[] = [];
  let bestScore = -1;
  let commentedHelmet: { filePath: string; line: number; lines: string[] } | undefined;
  let hasActiveControl = false;

  for (const filePath of ctx.fileList) {
    const parts = filePath.split(/[/\\]/);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;
    if (TEST_PATH.test(filePath.replace(/\\/g, "/"))) continue;
    const ext = path.extname(filePath).toLowerCase();
    if (!SOURCE_EXT.has(ext)) continue;

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
      if (lineHasHeaderControl(line)) {
        hasActiveControl = true;
      }
      if (!commentedHelmet && COMMENTED_HELMET.test(line)) {
        commentedHelmet = { filePath, line: i + 1, lines };
      }
      if (WEB_FRAMEWORK.test(line)) {
        const score = preferredBootstrapScore(filePath);
        if (score > bestScore) {
          bestScore = score;
          frameworkFile = filePath;
          frameworkLine = i + 1;
          frameworkLines = lines;
        }
      }
    }
  }

  if (hasActiveControl || !frameworkFile) return [];

  const startLine = commentedHelmet?.line ?? frameworkLine;
  const filePath = commentedHelmet?.filePath ?? frameworkFile;
  const lines = commentedHelmet?.lines ?? frameworkLines;
  const evidence = commentedHelmet
    ? `helmet() is commented out at ${filePath}:${startLine}`
    : `HTTP framework bootstrap at ${frameworkFile}:${frameworkLine} has no helmet()/CSP/HSTS/X-Content-Type-Options/X-Frame-Options middleware in the scanned source`;

  const raw: RawFinding = {
    scanner: "SAST_LLM",
    severity: "MEDIUM",
    title: "Missing HTTP Security Hardening Headers (CSP/HSTS/Helmet)",
    description:
      "The application does not set browser hardening headers (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options). This is a security-misconfiguration finding (CWE-693), not an authorization bug.",
    filePath,
    startLine,
    endLine: startLine,
    snippet: lines
      .slice(Math.max(0, startLine - 3), Math.min(lines.length, startLine + 2))
      .map((line, index) => `${Math.max(0, startLine - 3) + index + 1}: ${line}`)
      .join("\n"),
    cweId: "CWE-693",
    confidence: 0.88,
    ruleId: "SAST-MISSING-HARDENING-HEADERS",
    metadata: {
      weaknessClass: "Security Misconfiguration",
      findingLayer: "application-code",
      category: "Headers",
      remediation:
        "Enable helmet() (Express/Nest/Fastify) or equivalent middleware so every response includes Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options (or frame-ancestors in CSP).",
    },
  };

  const calibrated = applySeverityCalibration(raw);
  return [
    enrichFinding(calibrated, calibrated.metadata as Record<string, unknown>, {
      whatIsWrong: raw.title,
      where: `${filePath}:${startLine}`,
      whyExploitable: evidence,
      attackPath:
        "Inspect any HTTP response (curl -I) and confirm CSP, HSTS, X-Content-Type-Options, and X-Frame-Options are absent.",
      impact:
        "Missing CSP/HSTS/XFO weakens XSS containment, clickjacking resistance, and HTTPS enforcement. This is independent of access-control (AdminGuard) issues.",
      stepsToReproduce: [
        `Confirm ${evidence}.`,
        "Issue an HTTP request to a public route and inspect response headers for CSP, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options.",
      ],
      fix: "Apply helmet() (or Nest/Fastify equivalent) in the HTTP bootstrap, or set the headers at the reverse proxy. Do not treat an authorization guard as a substitute for these headers.",
      validation:
        "curl -I a public URL and verify CSP, HSTS, X-Content-Type-Options, and X-Frame-Options (or CSP frame-ancestors) are present.",
    }),
  ];
}
