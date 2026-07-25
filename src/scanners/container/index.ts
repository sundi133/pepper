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
import { applySeverityCalibration } from "@/lib/severity-calibration";
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
import { parseDockerfile, lintDockerfile } from "./dockerfile-parser";

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
  offline = false,
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
        // Air-gapped installs mount a pre-populated Trivy cache; without these
        // flags Trivy tries to refresh its database and fails with no network.
        ...(offline ? ["--skip-db-update", "--skip-java-db-update"] : []),
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

/**
 * Coverage-gap findings.
 *
 * When image CVE scanning cannot run, emitting nothing looks exactly like a
 * clean result. These findings make the gap explicit and queryable. They are
 * INFO so they never trip a build gate — they report missing coverage, not a
 * vulnerability — and they are aggregated into one finding per cause rather
 * than one per image.
 */
const COVERAGE_CATEGORY = "SCAN_COVERAGE_GAP";

function imageList(refs: ImageRef[]): string {
  const shown = refs.slice(0, 10).map((r) => `- ${r.image} (${r.filePath}:${r.line})`);
  const extra = refs.length - shown.length;
  return shown.join("\n") + (extra > 0 ? `\n- …and ${extra} more` : "");
}

function buildScannerUnavailableFinding(refs: ImageRef[]): RawFinding {
  const count = refs.length;
  const plural = count === 1 ? "" : "s";
  // enrichFinding() rebuilds `description` from the structured fields below, so
  // the warning against reading this as a clean result has to live in them —
  // anything only in `description` here would be discarded.
  return enrichFinding(
    {
      scanner: "CONTAINER",
      severity: "INFO",
      title: `Container image CVE scanning unavailable — ${count} image${plural} not scanned`,
      description: "",
      filePath: refs[0]?.filePath,
      startLine: refs[0]?.line,
      ruleId: "CONTAINER-SCANNER-UNAVAILABLE",
      confidence: 1,
      metadata: {
        category: COVERAGE_CATEGORY,
        unscannedImageCount: count,
        images: refs.map((r) => r.image),
      },
    },
    { category: COVERAGE_CATEGORY },
    {
      whatIsWrong:
        `Container image vulnerability scanning did not run: Trivy is not installed ` +
        `on the scanner host. ${count} discovered image reference${plural} ` +
        `${count === 1 ? "was" : "were"} not scanned.`,
      where: `${count} image reference${plural}:\n${imageList(refs)}`,
      whyExploitable:
        "The absence of container CVE findings in this scan does NOT mean these " +
        "images are free of vulnerabilities — they were never assessed. Unscanned " +
        "images may ship known-vulnerable OS and application packages.",
      fix:
        "Install Trivy on the scanner host so it is on PATH, or run the worker " +
        "image, which bundles it. For air-gapped installs, mount a pre-populated " +
        "Trivy cache at TRIVY_CACHE_DIR and set VULN_DB_MODE=offline.",
      validation: "Re-run the container scan and confirm image CVE results appear",
    },
  );
}

function buildUnscannableImagesFinding(refs: ImageRef[]): RawFinding {
  const count = refs.length;
  const plural = count === 1 ? "" : "s";
  return enrichFinding(
    {
      scanner: "CONTAINER",
      severity: "INFO",
      title: `${count} container image${plural} could not be scanned`,
      description: "",
      filePath: refs[0]?.filePath,
      startLine: refs[0]?.line,
      ruleId: "CONTAINER-IMAGE-UNSCANNABLE",
      confidence: 1,
      metadata: {
        category: COVERAGE_CATEGORY,
        unscannedImageCount: count,
        images: refs.map((r) => r.image),
      },
    },
    { category: COVERAGE_CATEGORY },
    {
      whatIsWrong:
        `Trivy ran but could not pull or read ${count} discovered image ` +
        `reference${plural} — typically a private registry without credentials, a ` +
        `tag that does not exist, or no network route to the registry.`,
      where: `${count} image reference${plural}:\n${imageList(refs)}`,
      whyExploitable:
        "These images were NOT assessed for vulnerabilities. Images that cannot be " +
        "pulled are never scanned, so anything vulnerable in them stays invisible " +
        "while the scan still reports success.",
      fix:
        "Configure registry credentials in organization settings, verify the image " +
        "tags exist, and confirm the scanner host can reach the registry.",
      validation: "Re-run the scan and confirm each image reports CVE results",
    },
  );
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
        const raw: RawFinding = {
          scanner: "CONTAINER",
          severity: mapSeverity(f.severity),
          title: f.title,
          description: f.description,
          filePath: file.path,
          startLine: f.startLine,
          endLine: (f.endLine && f.endLine > 0) ? f.endLine : f.startLine,
          cweId: f.cweId,
          confidence: f.confidence,
          ruleId: `CONTAINER-CONFIG-${f.cweId || "MISC"}`,
          metadata: {
            category: "CONTAINER_CONFIG",
            remediation: f.remediation,
            validationSteps: f.validationSteps,
          },
        };
        const calibrated = applySeverityCalibration(raw);
        findings.push(
          enrichFinding(
            calibrated,
            calibrated.metadata as Record<string, unknown>,
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

function scanDockerfileLints(ctx: ScanContext): RawFinding[] {
  const findings: RawFinding[] = [];
  const dockerfileFiles = ctx.fileList.filter(
    (f) => DOCKERFILE_NAMES.has(path.basename(f)) || /\.dockerfile$/i.test(f),
  );

  for (const filePath of dockerfileFiles) {
    try {
      const content = fs.readFileSync(path.join(ctx.workDir, filePath), "utf-8");
      const stages = parseDockerfile(content, filePath);
      const lints = lintDockerfile(stages);

      for (const lint of lints) {
        findings.push(
          enrichFinding(
            {
              scanner: "CONTAINER",
              severity: lint.severity,
              title: lint.title,
              description: lint.description,
              filePath,
              startLine: lint.line,
              ruleId: lint.ruleId,
              confidence: 1,
              metadata: {
                category: "DOCKERFILE_LINT",
              },
            },
            { category: "DOCKERFILE_LINT" },
            {
              whatIsWrong: lint.title,
              where: `${filePath}:${lint.line}`,
              whyExploitable: lint.description,
              fix: getDockerfileFix(lint.ruleId),
              validation: `Review Dockerfile and ensure ${lint.ruleId} rule is satisfied`,
            },
          ),
        );
      }
    } catch {
      // Skip files that cannot be parsed
    }
  }

  return findings;
}

function getDockerfileFix(ruleId: string): string {
  const fixes: Record<string, string> = {
    "DOCKERFILE-NO-USER": "Add USER directive with non-root user (e.g., USER app)",
    "DOCKERFILE-ROOT-USER":
      "Change USER to a non-root user (e.g., USER app). Create the user with RUN groupadd -r appgroup && useradd -r -g appgroup app",
    "DOCKERFILE-NO-HEALTHCHECK":
      "Add HEALTHCHECK directive to monitor container health. Example: HEALTHCHECK CMD curl http://localhost:3000 || exit 1",
    "DOCKERFILE-LATEST-TAG":
      "Pin base image to explicit version tag (e.g., node:20-alpine instead of node:latest)",
    "DOCKERFILE-NO-DIGEST-PIN":
      "Pin base image with SHA256 digest for reproducibility. Format: FROM image:tag@sha256:hash",
    "DOCKERFILE-HARDCODED-SECRET-ENV":
      "Use Docker secrets or build-time arguments instead of ENV variables. Never hardcode secrets in Dockerfile.",
    "DOCKERFILE-HARDCODED-SECRET-RUN":
      "Use docker secrets or multi-stage builds to avoid baking secrets in layers. Use --mount=type=secret in RUN.",
    "DOCKERFILE-NO-LABELS":
      "Add LABEL directives for metadata. Example: LABEL maintainer=name version=1.0.0 description='App description'",
  };
  return (
    fixes[ruleId] ||
    "Review Dockerfile best practices at https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
  );
}

export const containerScanner: ScannerPlugin = {
  name: "CONTAINER",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    await ctx.waitIfPaused?.();
    const images = discoverArtifactImages(ctx.workDir, ctx.fileList);
    const configFindings = await scanContainerConfig(ctx);

    // Dockerfile linting for best practices and security
    const dockerfileLintFindings = scanDockerfileLints(ctx);

    const allLintFindings = [...configFindings, ...dockerfileLintFindings];

    if (images.length === 0) {
      ctx.onProgress?.("CONTAINER: no artifact image references; config review only");
      return allLintFindings;
    }

    ctx.onProgress?.(
      `CONTAINER: ${artifactSummary(images)} artifact image(s); Trivy when available`,
    );

    const findings: RawFinding[] = [...allLintFindings];

    // First pass: record VM AMI references (always, regardless of Trivy availability)
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
      }
    }

    // Images that a CVE scan could actually cover (AMIs are inventory only).
    const scannableImages = images.filter((ref) => !isVmAmiRef(ref));

    const hasTrivy = await trivyAvailable();
    if (!hasTrivy) {
      ctx.onProgress?.(
        "CONTAINER: Trivy not installed — skipping CVE scan (no findings emitted)",
      );
      // Reporting nothing here would be indistinguishable from "these images are
      // clean". Record the coverage gap so the absence of CVEs is not read as
      // assurance.
      if (scannableImages.length > 0) {
        findings.push(buildScannerUnavailableFinding(scannableImages));
      }
      return findings;
    }

    const offline = ctx.orgSettings.vulnDbMode === "offline";
    if (offline) {
      ctx.onProgress?.(
        "CONTAINER: offline mode — Trivy will use its bundled database without updating",
      );
    }

    // Second pass: Trivy scans for container/serverless images only
    const unscannable: ImageRef[] = [];
    for (const ref of images) {
      await ctx.waitIfPaused?.();
      if (isVmAmiRef(ref)) {
        continue; // Already processed in first pass
      }

      ctx.onProgress?.(
        `CONTAINER: Trivy scanning ${ref.kind} artifact ${ref.image}`,
      );
      const registryEnv = buildRegistryEnv(ctx.orgSettings);
      const trivyOutput = await scanImageWithTrivy(ref.image, registryEnv, offline);
      if (!trivyOutput?.Results) {
        ctx.onProgress?.(
          `CONTAINER: could not scan ${ref.image} (private/unreachable) — logged only`,
        );
        unscannable.push(ref);
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

    // Images Trivy could not pull are a coverage gap, not a clean result.
    if (unscannable.length > 0) {
      findings.push(buildUnscannableImagesFinding(unscannable));
    }

    const scanned = scannableImages.length - unscannable.length;
    ctx.onProgress?.(
      `CONTAINER: ${findings.length} findings (${scanned}/${scannableImages.length} images scanned)`,
    );
    return findings;
  },
};
