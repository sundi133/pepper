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

const PEPPER_IGNORE = /pepper:ignore/i;

function isInlineSuppressed(lines: string[], startLine?: number): boolean {
  if (!startLine || startLine < 1 || lines.length === 0) return false;
  const idx = startLine - 1;
  if (idx < lines.length && PEPPER_IGNORE.test(lines[idx])) return true;
  if (idx > 0 && PEPPER_IGNORE.test(lines[idx - 1])) return true;
  return false;
}

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

/** Trivy Target strings from OS package managers (base image layer). */
const OS_PKG_TARGETS =
  /\b(?:alpine|debian|ubuntu|centos|rhel|fedora|oracle|amazon|photon|wolfi|chainguard|suse|opensuse|mariner|cbl-mariner|rocky|alma)\b/i;

type ContainerLayer = "base-image-os" | "app-layer";

function classifyTarget(target?: string): ContainerLayer {
  if (!target) return "app-layer";
  // Trivy formats OS targets like "Alpine Linux 3.18" or "debian 11.8"
  // and language targets like "Node.js", "Python", "Go", "Rust", "Java",
  // "gobinary", "gomod", "pip", "npm", "yarn", "cargo", etc.
  if (OS_PKG_TARGETS.test(target)) return "base-image-os";
  return "app-layer";
}

const SEVERITY_DOWNGRADE: Record<string, SeverityLevel> = {
  CRITICAL: "HIGH",
  HIGH: "MEDIUM",
  MEDIUM: "LOW",
  LOW: "LOW",
};

async function trivyAvailable(): Promise<boolean> {
  try {
    await execFileP("trivy", ["--version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function buildRegistryEnv(
  orgSettings: ScanContext["orgSettings"],
): Record<string, string> | undefined {
  if (!orgSettings.containerRegistryType || !orgSettings.containerRegistryUsername) {
    return undefined;
  }
  switch (orgSettings.containerRegistryType) {
    case "ecr":
      return {
        AWS_ACCESS_KEY_ID: orgSettings.containerRegistryUsername,
        AWS_SECRET_ACCESS_KEY: orgSettings.containerRegistryPassword || "",
        ...(orgSettings.containerRegistryRegion
          ? { AWS_DEFAULT_REGION: orgSettings.containerRegistryRegion }
          : {}),
      };
    case "dockerhub":
    case "ghcr":
    case "custom":
    default:
      return {
        TRIVY_USERNAME: orgSettings.containerRegistryUsername,
        TRIVY_PASSWORD: orgSettings.containerRegistryPassword || "",
      };
  }
}

async function scanImageWithTrivy(
  image: string,
  registryEnv?: Record<string, string>,
): Promise<TrivyOutput | null> {
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
      {
        timeout: 300_000,
        maxBuffer: 64 * 1024 * 1024,
        env: registryEnv ? { ...process.env, ...registryEnv } : undefined,
      },
    );
    return JSON.parse(stdout) as TrivyOutput;
  } catch (err) {
    logger.warn({ err, image }, "Trivy image scan failed");
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
      const fileLines = file.content.split("\n");
      for (const f of parsed.findings || []) {
        if ((f.confidence ?? 0) < LLM_MIN_CONFIDENCE_DEFAULT) continue;
        if (isInlineSuppressed(fileLines, f.startLine)) continue;
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
      const registryEnv = buildRegistryEnv(ctx.orgSettings);
      const trivyOutput = await scanImageWithTrivy(ref.image, registryEnv);
      if (!trivyOutput?.Results) {
        ctx.onProgress?.(
          `CONTAINER: could not scan ${ref.image} (private/unreachable) — logged only`,
        );
        continue;
      }

      for (const result of trivyOutput.Results) {
        const layer = classifyTarget(result.Target);
        for (const vuln of result.Vulnerabilities || []) {
          let severity = mapSeverity(vuln.Severity);
          // Base-image OS packages (glibc, openssl, etc.) are owned by the
          // base image maintainer, not the app developer. Downgrade severity
          // by one level so they don't drown out actionable app-layer CVEs.
          if (layer === "base-image-os") {
            severity = SEVERITY_DOWNGRADE[severity] || severity;
          }

          const base: RawFinding = {
            scanner: "CONTAINER",
            severity,
            title: `${vuln.VulnerabilityID}: ${vuln.PkgName || "package"} in ${ref.image}`,
            description: "",
            filePath: ref.filePath,
            startLine: ref.line,
            ruleId: vuln.VulnerabilityID,
            cveId: vuln.VulnerabilityID.startsWith("CVE-")
              ? vuln.VulnerabilityID
              : undefined,
            cweId: vuln.CweIDs?.[0],
            confidence: layer === "base-image-os" ? 0.85 : 0.95,
            metadata: {
              image: ref.image,
              artifactKind: ref.kind,
              packageName: vuln.PkgName,
              packageVersion: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              target: result.Target,
              category: "CONTAINER_CVE",
              containerLayer: layer,
            },
          };
          findings.push(
            enrichFinding(base, base.metadata as Record<string, unknown>, {
              whatIsWrong: vuln.Title || vuln.VulnerabilityID,
              where: `${ref.filePath}:${ref.line} (image ${ref.image})`,
              whyExploitable:
                vuln.Description ||
                `Vulnerable package ${vuln.PkgName}@${vuln.InstalledVersion} in runtime image.`,
              fix:
                layer === "base-image-os"
                  ? `Rebuild with a patched base image or pin a newer tag that includes ${vuln.PkgName} >= ${vuln.FixedVersion || "patched version"}.`
                  : vuln.FixedVersion
                    ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion} or later.`
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
