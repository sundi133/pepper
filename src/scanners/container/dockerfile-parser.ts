import { SeverityLevel } from "../types";

/**
 * Advanced Dockerfile parser with multi-stage support, secret detection, and security analysis.
 * Parses complete Dockerfile structure including ARG, ENV, USER, HEALTHCHECK, RUN, COPY, etc.
 */

export interface DockerfileStage {
  stageName?: string; // e.g., "builder", or undefined if unnamed stage
  baseImage: string; // e.g., "node:20-alpine"
  baseLine: number; // Line number of FROM statement (1-indexed)
  baseHasTag: boolean; // false if untagged (implicitly :latest)
  baseHasDigest: boolean; // true if has @sha256:...
  copyFromStages: string[]; // Stage names this stage copies from (COPY --from=stageName)
  user?: string; // USER directive value if present
  userLine?: number;
  hasHealthcheck: boolean;
  healthcheckLine?: number;
  hasReadonlyFilesystem: boolean;
  readonlyLine?: number;
  exposedPorts: number[];
  envVars: Map<string, { value: string | undefined; line: number; masked?: boolean }>;
  args: Map<string, { value?: string; line: number }>;
  runCommands: { cmd: string; line: number }[];
  labels: Map<string, { value: string; line: number }>;
  allLines: string[];
}

interface DockerfileLint {
  ruleId: string;
  severity: SeverityLevel;
  line: number;
  title: string;
  description: string;
}

const DOCKERFILE_DIRECTIVES = new Set([
  "FROM",
  "RUN",
  "CMD",
  "LABEL",
  "EXPOSE",
  "ENV",
  "ADD",
  "COPY",
  "ENTRYPOINT",
  "VOLUME",
  "USER",
  "WORKDIR",
  "ARG",
  "ONBUILD",
  "STOPSIGNAL",
  "HEALTHCHECK",
  "SHELL",
]);

const SECRETS_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /auth/i,
  /credential/i,
  /AKIA[0-9A-Z]{16}/, // AWS access key format
  /^(-----BEGIN|ssh-rsa|ssh-ed25519)/,
];

/**
 * Parse a complete Dockerfile and extract all structural information.
 */
export function parseDockerfile(content: string, filePath: string): DockerfileStage[] {
  const lines = content.split(/\r?\n/);
  const stages: DockerfileStage[] = [];
  let currentStage: DockerfileStage | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    const directive = parseDirective(trimmed);
    if (!directive) continue;

    const [cmd, args] = directive;

    if (cmd === "FROM") {
      // New stage
      if (currentStage) {
        stages.push(currentStage);
      }

      const stageName = extractStageName(args);
      const baseImage = extractBaseImage(args);

      currentStage = {
        stageName,
        baseImage,
        baseLine: i + 1,
        baseHasTag: baseImage.includes(":"),
        baseHasDigest: baseImage.includes("@"),
        copyFromStages: [],
        hasHealthcheck: false,
        hasReadonlyFilesystem: false,
        exposedPorts: [],
        envVars: new Map(),
        args: new Map(),
        runCommands: [],
        labels: new Map(),
        allLines: lines,
      };
    }

    if (!currentStage) continue;

    switch (cmd) {
      case "USER":
        currentStage.user = args.trim();
        currentStage.userLine = i + 1;
        break;

      case "HEALTHCHECK":
        currentStage.hasHealthcheck = true;
        currentStage.healthcheckLine = i + 1;
        break;

      case "ENV": {
        const [key, value] = parseKeyValue(args);
        if (key) {
          const masked = SECRETS_PATTERNS.some((p) => p.test(key) || p.test(value || ""));
          currentStage.envVars.set(key, { value, line: i + 1, masked });
        }
        break;
      }

      case "ARG": {
        const [key, value] = parseKeyValue(args);
        if (key) {
          currentStage.args.set(key, { value, line: i + 1 });
        }
        break;
      }

      case "EXPOSE": {
        const ports = parseExposedPorts(args);
        currentStage.exposedPorts.push(...ports);
        break;
      }

      case "RUN": {
        currentStage.runCommands.push({ cmd: args, line: i + 1 });
        // Check for readonly filesystem flag
        if (/--mount=type=tmpfs.*ro\b|--security-opt.*readonly/.test(args)) {
          currentStage.hasReadonlyFilesystem = true;
          currentStage.readonlyLine = i + 1;
        }
        break;
      }

      case "COPY": {
        const fromMatch = args.match(/--from=(\S+)/i);
        if (fromMatch) {
          currentStage.copyFromStages.push(fromMatch[1]);
        }
        break;
      }

      case "LABEL": {
        const [key, value] = parseKeyValue(args);
        if (key) {
          currentStage.labels.set(key, { value, line: i + 1 });
        }
        break;
      }
    }
  }

  if (currentStage) {
    stages.push(currentStage);
  }

  return stages;
}

/**
 * Extract a Dockerfile directive and its arguments.
 * Handles line continuations (\). Returns null if line is not a directive.
 */
function parseDirective(line: string): [string, string] | null {
  // Remove line continuation character and join with next logical line
  // In Dockerfile, a backslash at end of line continues to next line
  let fullLine = line.replace(/\\\s*$/, " ");

  const match = fullLine.match(/^([A-Z_]+)(?:\s+(.*))?$/i);
  if (!match) return null;

  const cmd = match[1].toUpperCase();
  const args = (match[2] || "").trim();

  if (!DOCKERFILE_DIRECTIVES.has(cmd)) return null;

  return [cmd, args];
}

/**
 * Extract stage name from FROM --platform=... image AS name
 */
function extractStageName(args: string): string | undefined {
  const match = args.match(/\s+AS\s+(\S+)$/i);
  return match ? match[1] : undefined;
}

/**
 * Extract base image from FROM statement, handling --platform flag.
 */
function extractBaseImage(args: string): string {
  // Handle: FROM [--platform=<platform>] <image>[:<tag>][@<digest>] [AS <name>]
  const withoutPlatform = args.replace(/^--platform=\S+\s+/, "");
  const withoutStage = withoutPlatform.replace(/\s+AS\s+\S+$/i, "");
  return withoutStage.trim();
}

/**
 * Parse KEY=VALUE or KEY VALUE format used in ENV, ARG, LABEL directives.
 */
function parseKeyValue(args: string): [string, string | undefined] {
  const eqIdx = args.indexOf("=");
  if (eqIdx > 0) {
    return [args.substring(0, eqIdx).trim(), args.substring(eqIdx + 1).trim() || undefined];
  }
  const space = args.indexOf(" ");
  if (space > 0) {
    return [args.substring(0, space).trim(), args.substring(space + 1).trim() || undefined];
  }
  return [args.trim(), undefined];
}

/**
 * Parse EXPOSE directive to extract port numbers.
 */
function parseExposedPorts(args: string): number[] {
  const ports: number[] = [];
  const parts = args.split(/[\s/]+/);
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (!isNaN(num) && num > 0 && num < 65536) {
      ports.push(num);
    }
  }
  return ports;
}

/**
 * Analyze Dockerfile stages for security and best-practice issues.
 */
export function lintDockerfile(stages: DockerfileStage[]): DockerfileLint[] {
  const findings: DockerfileLint[] = [];

  for (const stage of stages) {
    // No user directive (runs as root by default)
    if (!stage.user) {
      findings.push({
        ruleId: "DOCKERFILE-NO-USER",
        severity: "HIGH",
        line: stage.baseLine,
        title: "No USER directive — container runs as root",
        description:
          "This stage does not specify a USER directive, meaning the container will run as root by default. This is a significant security risk.",
      });
    }

    // USER is explicitly root
    if (stage.user && /^root$/i.test(stage.user)) {
      findings.push({
        ruleId: "DOCKERFILE-ROOT-USER",
        severity: "MEDIUM",
        line: stage.userLine || stage.baseLine,
        title: "Container explicitly runs as root",
        description:
          "The USER directive is set to root. Consider using an unprivileged user instead.",
      });
    }

    // No HEALTHCHECK for services that likely run long-term
    if (!stage.hasHealthcheck && stage.exposedPorts.length > 0) {
      findings.push({
        ruleId: "DOCKERFILE-NO-HEALTHCHECK",
        severity: "MEDIUM",
        line: stage.baseLine,
        title: "No HEALTHCHECK directive",
        description:
          "This service exposes ports but has no HEALTHCHECK. Orchestrators need health status to restart failed containers.",
      });
    }

    // Base image untagged or uses :latest
    if (!stage.baseHasTag || stage.baseImage.endsWith(":latest")) {
      findings.push({
        ruleId: "DOCKERFILE-LATEST-TAG",
        severity: "MEDIUM",
        line: stage.baseLine,
        title: "Base image uses :latest or is untagged",
        description:
          `Base image '${stage.baseImage}' implicitly uses :latest, which causes non-deterministic builds. Use explicit version tags.`,
      });
    }

    // Base image lacks digest pin
    if (!stage.baseHasDigest) {
      findings.push({
        ruleId: "DOCKERFILE-NO-DIGEST-PIN",
        severity: "LOW",
        line: stage.baseLine,
        title: "Base image not pinned with SHA256 digest",
        description:
          "For maximum reproducibility and security, pin the base image using a digest: FROM node:20@sha256:...",
      });
    }

    // Check for hardcoded secrets in ENV variables
    for (const [key, env] of Array.from(stage.envVars)) {
      if (env.masked || SECRETS_PATTERNS.some((p) => p.test(key))) {
        findings.push({
          ruleId: "DOCKERFILE-HARDCODED-SECRET-ENV",
          severity: "CRITICAL",
          line: env.line,
          title: `Hardcoded secret in ENV variable: ${key}`,
          description:
            `ENV variable '${key}' appears to contain a secret. Use Docker secrets or build-time args instead.`,
        });
      }
    }

    // Check for secrets in RUN commands
    for (const run of stage.runCommands) {
      for (const pattern of SECRETS_PATTERNS) {
        if (pattern.test(run.cmd)) {
          findings.push({
            ruleId: "DOCKERFILE-HARDCODED-SECRET-RUN",
            severity: "CRITICAL",
            line: run.line,
            title: "Possible hardcoded secret in RUN command",
            description:
              "RUN command appears to contain a secret (password, token, API key). Use Docker secrets or multi-stage builds.",
          });
          break;
        }
      }
    }

    // Missing LABEL directives for metadata
    if (stage.labels.size === 0) {
      findings.push({
        ruleId: "DOCKERFILE-NO-LABELS",
        severity: "LOW",
        line: stage.baseLine,
        title: "No LABEL directives for metadata",
        description:
          "LABEL directives should document the image (version, maintainer, description). Add maintainer, version, and description labels.",
      });
    }
  }

  return findings;
}
