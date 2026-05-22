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
import {
  discoverArtifactImages,
  isVmAmiRef,
  type ImageRef,
} from "./discover";

const execFileP = promisify(execFile);

const DOCKERFILE_NAMES = new Set(["Dockerfile", "dockerfile", "Containerfile"]);
const COMPOSE_NAMES = new Set([
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
]);

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

function artifactSummary(refs: ImageRef[]): string {
  const counts = { container: 0, serverless: 0, vm: 0 };
  for (const r of refs) counts[r.kind]++;
  const parts: string[] = [];
  if (counts.container) parts.push(`${counts.container} container`);
  if (counts.serverless) parts.push(`${counts.serverless} serverless`);
  if (counts.vm) parts.push(`${counts.vm} VM`);
  return parts.join(", ") || "0";
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
    const images = discoverArtifactImages(ctx.workDir, ctx.fileList);
    const configFindings = await scanContainerConfig(ctx);

    if (images.length === 0) {
      ctx.onProgress?.("CONTAINER: no artifact image references; config review only");
      return configFindings;
    }

    ctx.onProgress?.(
      `CONTAINER: ${artifactSummary(images)} artifact image(s); Trivy when available`,
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
      if (isVmAmiRef(ref)) {
        ctx.onProgress?.(
          `CONTAINER: VM AMI ${ref.image} (${ref.filePath}:${ref.line}) — inventory only`,
        );
        findings.push(
          enrichFinding(
            {
              scanner: "CONTAINER",
              severity: "INFO",
              title: `VM image reference ${ref.image}`,
              description: `AMI referenced in ${ref.filePath}. Pepper records the reference; scan the built AMI or exported image with Trivy separately when available.`,
              filePath: ref.filePath,
              startLine: ref.line,
              ruleId: "ARTIFACT-VM-REFERENCE",
              confidence: 1,
              metadata: {
                image: ref.image,
                artifactKind: ref.kind,
                category: "ARTIFACT_INVENTORY",
              },
            },
            {
              image: ref.image,
              artifactKind: ref.kind,
              category: "ARTIFACT_INVENTORY",
            },
            {
              whatIsWrong: "VM base AMI referenced in infrastructure code",
              where: `${ref.filePath}:${ref.line}`,
              whyExploitable:
                "Outdated or compromised AMIs can introduce vulnerabilities in deployed VMs.",
              fix: "Use a hardened, patched AMI and verify with image vulnerability scanning in your pipeline.",
              validation: `Confirm ${ref.image} is approved and patched in your cloud account`,
            },
          ),
        );
        continue;
      }

      ctx.onProgress?.(
        `CONTAINER: Trivy scanning ${ref.kind} artifact ${ref.image}`,
      );
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
              artifactKind: ref.kind,
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
