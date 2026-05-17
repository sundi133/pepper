import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import {
  RawFinding,
  ScanContext,
  ScannerPlugin,
  SeverityLevel,
} from "../types";

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
      return "INFO";
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
  // dedupe by image
  const seen = new Set<string>();
  return refs.filter((r) => {
    if (seen.has(r.image)) return false;
    seen.add(r.image);
    return true;
  });
}

export const containerScanner: ScannerPlugin = {
  name: "CONTAINER",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    await ctx.waitIfPaused?.();
    const images = discoverImages(ctx.workDir, ctx.fileList);
    if (images.length === 0) {
      ctx.onProgress?.("CONTAINER: no container image references found");
      return [];
    }

    ctx.onProgress?.(
      `CONTAINER: scanning ${images.length} image reference(s): ${images
        .map((i) => i.image)
        .slice(0, 5)
        .join(", ")}`,
    );

    const hasTrivy = await trivyAvailable();
    const findings: RawFinding[] = [];

    if (!hasTrivy) {
      ctx.onProgress?.(
        "CONTAINER: trivy CLI not installed; emitting image inventory only",
      );
      for (const ref of images) {
        findings.push({
          scanner: "CONTAINER",
          severity: "INFO",
          title: `Container image referenced: ${ref.image}`,
          description: `Image \`${ref.image}\` referenced in ${ref.filePath}:${ref.line}. Install Trivy on the worker to enable vulnerability scanning of container images.`,
          filePath: ref.filePath,
          startLine: ref.line,
          endLine: ref.line,
          ruleId: "CONTAINER-INVENTORY",
          confidence: 1,
          metadata: { image: ref.image, trivyAvailable: false },
        });
      }
      return findings;
    }

    for (const ref of images) {
      await ctx.waitIfPaused?.();
      ctx.onProgress?.(`CONTAINER: scanning ${ref.image}`);
      const trivyOutput = await scanImageWithTrivy(ref.image);
      if (!trivyOutput || !trivyOutput.Results) {
        findings.push({
          scanner: "CONTAINER",
          severity: "INFO",
          title: `Could not scan container image ${ref.image}`,
          description: `Trivy failed to scan \`${ref.image}\`. The image may be private or unreachable.`,
          filePath: ref.filePath,
          startLine: ref.line,
          ruleId: "CONTAINER-SCAN-FAILED",
          confidence: 1,
          metadata: { image: ref.image },
        });
        continue;
      }
      for (const result of trivyOutput.Results) {
        for (const vuln of result.Vulnerabilities || []) {
          findings.push({
            scanner: "CONTAINER",
            severity: mapSeverity(vuln.Severity),
            title: `${vuln.VulnerabilityID}: ${vuln.PkgName || "package"} in ${ref.image}`,
            description:
              (vuln.Title ? `${vuln.Title}\n\n` : "") +
              (vuln.Description ||
                `Vulnerable package \`${vuln.PkgName}@${vuln.InstalledVersion}\` in container image \`${ref.image}\`.`) +
              (vuln.FixedVersion
                ? `\n\n**Fix:** upgrade to \`${vuln.FixedVersion}\`.`
                : ""),
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
            },
          });
        }
      }
    }

    ctx.onProgress?.(`CONTAINER: found ${findings.length} issues`);
    return findings;
  },
};
