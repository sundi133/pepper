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
  hasEntrypoint?: boolean; // CMD or ENTRYPOINT present: the image runs something
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

/**
 * Parse a complete Dockerfile and extract all structural information.
 */
export function parseDockerfile(content: string, filePath: string): DockerfileStage[] {
  const rawLines = content.split(/\r?\n/);
  // Join backslash-continuation lines so directives spanning multiple physical
  // lines (e.g. a long RUN or ENV) are treated as a single logical line.
  const lines: string[] = [];
  for (const rl of rawLines) {
    const prev = lines[lines.length - 1];
    if (prev !== undefined && prev.endsWith("\\")) {
      lines[lines.length - 1] = prev.slice(0, -1).trimEnd() + " " + rl.trimStart();
    } else {
      lines.push(rl);
    }
  }

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

      case "CMD":
      case "ENTRYPOINT":
        currentStage.hasEntrypoint = true;
        break;

      case "HEALTHCHECK":
        currentStage.hasHealthcheck = true;
        currentStage.healthcheckLine = i + 1;
        break;

      case "ENV": {
        const [key, value] = parseKeyValue(args);
        if (key) {
          const masked = isHardcodedSecretEnv(key, value);
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
        if (key && value) {
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
  const fullLine = line.replace(/\\\s*$/, " ");

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

/** Names that hold a credential. "auth" alone is too broad (AUTHOR, OAUTH_URL). */
const SECRET_NAME = /passw(?:or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential/i;
/** Names that point at a secret rather than hold one, or only look like one. */
const NOT_A_SECRET_NAME = /(?:_FILE|_PATH|_DIR|_URL|_URI|_NAME|_ID|_HEADER|_ENDPOINT|_TTL|_EXPIR\w*|_LENGTH|_ENABLED)$|TOKENIZER/i;
/** Values that are a credential whatever the variable is called. */
const SECRET_VALUE = /AKIA[0-9A-Z]{16}|^-----BEGIN|\bgh[pous]_[A-Za-z0-9_]{36,}|\bsk_live_[A-Za-z0-9]{10,}/;

/** A literal that could be a credential: not empty, a reference, a path, a flag or a stand-in. */
function isLiteralSecretValue(raw: string | undefined): boolean {
  const value = (raw ?? "").trim().replace(/^["']|["']$/g, "");
  if (value.length < 4) return false;
  if (/[$<{]/.test(value)) return false; // $VAR, ${VAR}, <placeholder>, {{ template }}
  if (/^[./~]/.test(value)) return false; // a path to the secret, not the secret
  if (/^(?:true|false|yes|no|none|null|\d+)$/i.test(value)) return false;
  if (/^(?:changeme|change[_-]me|placeholder|example|dummy|xxx+|your[_-].*)$/i.test(value)) return false;
  return true;
}

/** ENV KEY=value bakes a credential into the image. */
function isHardcodedSecretEnv(key: string, value: string | undefined): boolean {
  if (SECRET_VALUE.test(value ?? "")) return true;
  return SECRET_NAME.test(key) && !NOT_A_SECRET_NAME.test(key) && isLiteralSecretValue(value);
}

/** A RUN command that passes a literal credential (password=…, --token …). */
function runHasHardcodedSecret(cmd: string): boolean {
  if (SECRET_VALUE.test(cmd)) return true;
  const assignment = /([A-Za-z_][\w.-]*)\s*[=:]\s*("[^"]*"|'[^']*'|[^\s"'&|;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = assignment.exec(cmd)) !== null) {
    // --mount=type=secret,id=npm_token is the safe way to use a secret.
    if (/^(?:type|id|target|source|src|dst|env)$/i.test(m[1])) continue;
    if (SECRET_NAME.test(m[1]) && !NOT_A_SECRET_NAME.test(m[1]) && isLiteralSecretValue(m[2])) return true;
  }
  const flag = /--(?:password|passwd|token|secret|api-key)\s+("[^"]*"|'[^']*'|[^\s"'&|;-][^\s"'&|;]*)/gi;
  while ((m = flag.exec(cmd)) !== null) {
    if (isLiteralSecretValue(m[1])) return true;
  }
  return false;
}

/**
 * Analyze Dockerfile stages for security and best-practice issues.
 *
 * Only the last stage becomes the image that runs, so runtime checks (user,
 * healthcheck) apply to it alone; build stages are checked for what affects
 * the build (base image, baked-in secrets).
 */
export function lintDockerfile(stages: DockerfileStage[]): DockerfileLint[] {
  const findings: DockerfileLint[] = [];
  const finalStage = stages[stages.length - 1];
  const byName = new Map<string, DockerfileStage>();
  let digestPinReported = false;

  /** Follow `FROM <earlier stage>` to what the stage inherits. */
  const inherited = <T>(stage: DockerfileStage, pick: (s: DockerfileStage) => T | undefined): T | undefined => {
    const seen = new Set<DockerfileStage>();
    let cur: DockerfileStage | undefined = stage;
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const v = pick(cur);
      if (v) return v;
      cur = byName.get(cur.baseImage.toLowerCase());
      if (cur === stage) break;
    }
    return undefined;
  };

  for (const stage of stages) {
    const isFinal = stage === finalStage;
    const fromEarlierStage = byName.has(stage.baseImage.toLowerCase());
    const isScratch = stage.baseImage.toLowerCase() === "scratch";
    // Nothing to tag or pin: an earlier stage, scratch, or an image chosen by a build ARG.
    const externalImage = !fromEarlierStage && !isScratch && !stage.baseImage.includes("$");
    // FROM scratch with no CMD/ENTRYPOINT only carries build output; it never runs.
    const runs = !(isScratch && !stage.hasEntrypoint);

    if (isFinal && runs) {
      const user = inherited(stage, (s) => s.user);
      // No user directive (runs as root by default)
      if (!user) {
        findings.push({
          ruleId: "DOCKERFILE-NO-USER",
          severity: "HIGH",
          line: stage.baseLine,
          title: "No USER directive — container runs as root",
          description:
            "The image does not specify a USER directive, meaning the container will run as root by default. This is a significant security risk.",
        });
      }

      // No HEALTHCHECK for services that likely run long-term
      const exposes = stage.exposedPorts.length > 0;
      if (exposes && !inherited(stage, (s) => s.hasHealthcheck || undefined)) {
        findings.push({
          ruleId: "DOCKERFILE-NO-HEALTHCHECK",
          severity: "LOW",
          line: stage.baseLine,
          title: "No HEALTHCHECK directive",
          description:
            "This service exposes ports but has no HEALTHCHECK. Docker and Swarm need health status to restart failed containers (Kubernetes uses its own probes instead).",
        });
      }
    }

    // USER is explicitly root
    if (isFinal && stage.user && /^(?:root|0)(?::.*)?$/i.test(stage.user)) {
      findings.push({
        ruleId: "DOCKERFILE-ROOT-USER",
        severity: "MEDIUM",
        line: stage.userLine || stage.baseLine,
        title: "Container explicitly runs as root",
        description:
          "The USER directive is set to root. Consider using an unprivileged user instead.",
      });
    }

    // Base image untagged or uses :latest
    const floatingTag = externalImage && !stage.baseHasDigest && (!stage.baseHasTag || stage.baseImage.endsWith(":latest"));
    if (floatingTag) {
      findings.push({
        ruleId: "DOCKERFILE-LATEST-TAG",
        severity: "MEDIUM",
        line: stage.baseLine,
        title: "Base image uses :latest or is untagged",
        description:
          `Base image '${stage.baseImage}' implicitly uses :latest, which causes non-deterministic builds. Use explicit version tags.`,
      });
    }

    // Base image lacks digest pin. Reported once per Dockerfile, and not on
    // top of the floating-tag finding, which already covers that image.
    if (externalImage && !stage.baseHasDigest && !floatingTag && !digestPinReported) {
      digestPinReported = true;
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
      if (env.masked) {
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
      if (runHasHardcodedSecret(run.cmd)) {
        findings.push({
          ruleId: "DOCKERFILE-HARDCODED-SECRET-RUN",
          severity: "CRITICAL",
          line: run.line,
          title: "Possible hardcoded secret in RUN command",
          description:
            "RUN command appears to contain a secret (password, token, API key). Use Docker secrets or multi-stage builds.",
        });
      }
    }

    if (stage.stageName) byName.set(stage.stageName.toLowerCase(), stage);
  }

  return findings;
}
