import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import {
  RawFinding,
  ScanContext,
  ScannerPlugin,
  SeverityLevel,
} from "../types";
import { enrichFinding } from "../shared/finding-normalize";
import { CONTAINER_CONFIG_PROMPT } from "../shared/prompts";
import {
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  LLM_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const execFileP = promisify(execFile);

const DOCKERFILE_NAMES = new Set(["Dockerfile", "dockerfile", "Containerfile"]);
const COMPOSE_NAMES = new Set([
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
]);

interface ImageRef {
  image: string;
  filePath: string;
  line: number;
}

function parseDockerfile(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)/i);
    if (m) {
      const image = m[1];
      if (image.toLowerCase() === "scratch") continue;
      if (image.startsWith("$")) continue;
      refs.push({ image, filePath, line: i + 1 });
    }
  }
  return refs;
}

function parseCompose(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*image:\s*["']?([^"'\s#]+)/);
    if (m) refs.push({ image: m[1], filePath, line: i + 1 });
  }
  return refs;
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  CweIDs?: string[];
}

interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVuln[];
}

interface TrivyOutput {
  Results?: TrivyResult[];
}

function mapSeverity(sev?: string): SeverityLevel {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    default:
      return "MEDIUM";
  }
}

async function trivyAvailable(): Promise<boolean> {
  try {
    await execFileP("trivy", ["--version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function scanImageWithTrivy(image: string): Promise<TrivyOutput | null> {
  try {
    const { stdout } = await execFileP(
      "trivy",
      [
        "image",
        "--quiet",
        "--no-progress",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--severity",
        "CRITICAL,HIGH,MEDIUM,LOW",
        image,
      ],
      { timeout: 300_000, maxBuffer: 64 * 1024 * 1024 },
    );
    return JSON.parse(stdout) as TrivyOutput;
  } catch {
    return null;
  }
}

function discoverImages(workDir: string, fileList: string[]): ImageRef[] {
  const refs: ImageRef[] = [];
  for (const rel of fileList) {
    const base = path.basename(rel);
    const isDockerfile =
      DOCKERFILE_NAMES.has(base) || /\.dockerfile$/i.test(base);
    const isCompose = COMPOSE_NAMES.has(base);
    if (!isDockerfile && !isCompose) continue;
    try {
      const content = fs.readFileSync(path.join(workDir, rel), "utf-8");
      if (isDockerfile) refs.push(...parseDockerfile(content, rel));
      else refs.push(...parseCompose(content, rel));
    } catch {
      continue;
    }
  }
  const seen = new Set<string>();
  return refs.filter((r) => {
    if (seen.has(r.image)) return false;
    seen.add(r.image);
    return true;
  });
}

interface ConfigLlmFinding {
  title: string;
  severity: string;
  description: string;
  startLine: number;
  endLine?: number;
  cweId?: string;
  confidence: number;
  remediation: string;
  validationSteps?: string[];
}

async function scanContainerConfig(
  ctx: ScanContext,
): Promise<RawFinding[]> {
  if (!ctx.orgSettings.enableLlmSast) return [];

  const configFiles: { path: string; content: string }[] = [];
  for (const rel of ctx.fileList) {
    const base = path.basename(rel);
    if (
      !DOCKERFILE_NAMES.has(base) &&
      !/\.dockerfile$/i.test(base) &&
      !COMPOSE_NAMES.has(base)
    ) {
      continue;
    }
    try {
      configFiles.push({
        path: rel,
        content: fs.readFileSync(path.join(ctx.workDir, rel), "utf-8"),
      });
    } catch {
      continue;
    }
  }
  if (configFiles.length === 0) return [];

  const client = createLlmClient({
    provider: ctx.orgSettings.llmProvider,
    baseUrl: ctx.orgSettings.llmBaseUrl,
    apiKey: ctx.orgSettings.llmApiKey,
    model: ctx.orgSettings.llmModel,
  });
  const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
  const maxTokens = isOllama
    ? OLLAMA_MAX_RESPONSE_TOKENS
    : LLM_MAX_RESPONSE_TOKENS;

  const findings: RawFinding[] = [];
  for (const file of configFiles) {
    try {
      const raw = await analyzeWithLlm(
        client,
        ctx.orgSettings.llmModel,
        CONTAINER_CONFIG_PROMPT,
        `File: ${file.path}\n\`\`\`\n${file.content}\n\`\`\``,
        { maxTokens },
      );
      const parsed = parseLlmJsonResponse<{ findings: ConfigLlmFinding[] }>(
        raw,
        { findings: [] },
      );
      for (const f of parsed.findings || []) {
        if ((f.confidence ?? 0) < LLM_MIN_CONFIDENCE_DEFAULT) continue;
        findings.push(
          enrichFinding(
            {
              scanner: "CONTAINER",
              severity: mapSeverity(f.severity),
              title: f.title,
              description: f.description,
              filePath: file.path,
              startLine: f.startLine,
              endLine: f.endLine || f.startLine,
              cweId: f.cweId,
              confidence: f.confidence,
              ruleId: `CONTAINER-CONFIG-${f.cweId || "MISC"}`,
              metadata: {
                category: "CONTAINER_CONFIG",
                remediation: f.remediation,
                validationSteps: f.validationSteps,
              },
            },
            { category: "CONTAINER_CONFIG", remediation: f.remediation },
            {
              whatIsWrong: f.title,
              where: `${file.path}:${f.startLine}`,
              whyExploitable: f.description,
              fix: f.remediation,
              validation: f.validationSteps?.join("; "),
            },
          ),
        );
      }
    } catch (err) {
      logger.warn({ err, file: file.path }, "Container config AI review failed");
    }
  }
  return findings;
}

export const containerScanner: ScannerPlugin = {
  name: "CONTAINER",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    await ctx.waitIfPaused?.();
    const images = discoverImages(ctx.workDir, ctx.fileList);
    const configFindings = await scanContainerConfig(ctx);

    if (images.length === 0) {
      ctx.onProgress?.("CONTAINER: no image references; config review only");
      return configFindings;
    }

    ctx.onProgress?.(
      `CONTAINER: scanning ${images.length} image(s) with Trivy when available`,
    );

    const hasTrivy = await trivyAvailable();
    if (!hasTrivy) {
      ctx.onProgress?.(
        "CONTAINER: Trivy not installed — skipping CVE scan (no findings emitted)",
      );
      return configFindings;
    }

    const findings: RawFinding[] = [...configFindings];

    for (const ref of images) {
      await ctx.waitIfPaused?.();
      ctx.onProgress?.(`CONTAINER: Trivy scanning ${ref.image}`);
      const trivyOutput = await scanImageWithTrivy(ref.image);
      if (!trivyOutput?.Results) {
        ctx.onProgress?.(
          `CONTAINER: could not scan ${ref.image} (private/unreachable) — logged only`,
        );
        continue;
      }

      for (const result of trivyOutput.Results) {
        for (const vuln of result.Vulnerabilities || []) {
          const base: RawFinding = {
            scanner: "CONTAINER",
            severity: mapSeverity(vuln.Severity),
            title: `${vuln.VulnerabilityID}: ${vuln.PkgName || "package"} in ${ref.image}`,
            description: "",
            filePath: ref.filePath,
            startLine: ref.line,
            ruleId: vuln.VulnerabilityID,
            cveId: vuln.VulnerabilityID.startsWith("CVE-")
              ? vuln.VulnerabilityID
              : undefined,
            cweId: vuln.CweIDs?.[0],
            confidence: 0.95,
            metadata: {
              image: ref.image,
              packageName: vuln.PkgName,
              packageVersion: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              target: result.Target,
              category: "CONTAINER_CVE",
            },
          };
          findings.push(
            enrichFinding(base, base.metadata as Record<string, unknown>, {
              whatIsWrong: vuln.Title || vuln.VulnerabilityID,
              where: `${ref.filePath}:${ref.line} (image ${ref.image})`,
              whyExploitable:
                vuln.Description ||
                `Vulnerable package ${vuln.PkgName}@${vuln.InstalledVersion} in runtime image.`,
              fix: vuln.FixedVersion
                ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion} or rebuild base image.`
                : "Rebuild image with patched base/packages per vendor advisory.",
              validation: `trivy image ${ref.image} — confirm ${vuln.VulnerabilityID} absent`,
            }),
          );
        }
      }
    }

    ctx.onProgress?.(`CONTAINER: ${findings.length} findings`);
    return findings;
  },
};
