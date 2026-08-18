export const SEVERITY_ORDER = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
} as const;

export const SEVERITY_COLORS = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "secondary",
  INFO: "outline",
} as const;

/** Pattern-only findings: no synthetic LLM-style report blocks. */
// SAST_PATTERN is quarantined (returns zero findings). SECRETS_PATTERN
// findings reach the UI and need report enrichment like other scanners.
export const PATTERN_BASED_SCANNERS = new Set(["SAST_PATTERN"]);

export function isPatternBasedScanner(scanner: string | undefined): boolean {
  if (!scanner) return false;
  return PATTERN_BASED_SCANNERS.has(scanner);
}

export const SCANNER_LABELS = {
  SAST_PATTERN: "SAST (Pattern)",
  SAST_LLM: "SAST (AI)",
  SCA: "SCA",
  SECRETS_PATTERN: "Secrets (Pattern)",
  SECRETS_LLM: "Secrets (AI)",
  IAC: "IaC Security",
  MALICIOUS_PKG: "Supply Chain",
  ZERO_DAY: "Zero-Day (AI)",
  CONTAINER: "Container",
  K8S: "Kubernetes",
} as const;

export const SCAN_STATUS_LABELS = {
  QUEUED: "Queued",
  RUNNING: "Running",
  PAUSED: "Paused",
  STOPPED: "Stopped",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
} as const;

export const ROLE_HIERARCHY: Record<string, number> = {
  ADMIN: 40,
  SECURITY: 30,
  DEVELOPER: 20,
  VIEWER: 10,
};

export const FILE_EXTENSIONS: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".rs": "rust",
  ".c": "c",
  ".cpp": "cpp",
  ".h": "c",
  ".hpp": "cpp",
  ".swift": "swift",
  ".kt": "kotlin",
  ".scala": "scala",
  ".sh": "shell",
  ".bash": "shell",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".json": "json",
  ".xml": "xml",
  ".sql": "sql",
  ".tf": "terraform",
  ".hcl": "terraform",
  ".dockerfile": "docker",
  ".proto": "protobuf",
  ".ejs": "template",
  ".hbs": "template",
  ".handlebars": "template",
  ".njk": "template",
  ".nunjucks": "template",
  ".mustache": "template",
  ".twig": "template",
  ".pug": "template",
  ".jade": "template",
  ".vue": "template",
  ".svelte": "template",
  ".erb": "template",
  ".cshtml": "template",
  ".jinja": "template",
  ".jinja2": "template",
};

export const SKIP_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "vendor",
  "dist",
  "build",
  "target",
  "__pycache__",
  ".tox",
  ".eggs",
  "venv",
  ".venv",
  "env",
  ".next",
  ".nuxt",
  "coverage",
  ".nyc_output",
  ".cache",
  ".idea",
  ".vscode",
]);

export const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".otf",
  ".mp3",
  ".mp4",
  ".webm",
  ".ogg",
  ".wav",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".rar",
  ".7z",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".wasm",
  ".class",
  ".jar",
  ".pyc",
  ".pyo",
  ".o",
  ".a",
  ".lib",
]);

// IaC file type detection
export type IacFileType =
  | "dockerfile"
  | "docker-compose"
  | "terraform"
  | "kubernetes"
  | "helm"
  | "github-actions"
  | "gitlab-ci"
  | "cloudformation"
  | "ansible"
  | "server-config";

export function detectIacFileType(filePath: string): IacFileType | null {
  const lower = filePath.toLowerCase();
  const basename = lower.split("/").pop() || "";

  if (
    basename === "dockerfile" ||
    basename.startsWith("dockerfile.") ||
    basename.endsWith(".dockerfile")
  )
    return "dockerfile";
  if (basename.startsWith("docker-compose")) return "docker-compose";
  if (lower.endsWith(".tf") || lower.endsWith(".tfvars")) return "terraform";
  if (lower.includes(".github/workflows/")) return "github-actions";
  if (basename === ".gitlab-ci.yml") return "gitlab-ci";
  if (
    lower.includes("/helm/") ||
    basename === "chart.yaml" ||
    basename === "values.yaml"
  )
    return "helm";
  if (
    lower.includes("/k8s/") ||
    lower.includes("/kubernetes/") ||
    lower.includes("/manifests/") ||
    lower.includes("/deploy/") ||
    /^(deployment|service|ingress|configmap|secret|daemonset|statefulset|cronjob|job|pod|namespace|role|rolebinding|clusterrole|clusterrolebinding)\.ya?ml$/i.test(
      basename,
    )
  )
    return "kubernetes";
  if (
    lower.includes("/cloudformation/") ||
    lower.includes("/sam/") ||
    (basename.startsWith("template.") &&
      (lower.endsWith(".yaml") || lower.endsWith(".json")))
  )
    return "cloudformation";
  if (lower.includes("/ansible/") || lower.includes("/playbooks/"))
    return "ansible";

  // Web server / reverse-proxy / application-server config files that SAST and
  // the container scanner ignore, but which can expose data (directory listing,
  // missing TLS, debug/admin endpoints, weak auth). Common names and the
  // directories they conventionally live in.
  if (
    basename === "nginx.conf" ||
    basename === "httpd.conf" ||
    basename === "apache2.conf" ||
    basename === "apache.conf" ||
    basename === "caddyfile" ||
    basename === "haproxy.cfg" ||
    basename === "lighttpd.conf" ||
    basename === "nginx.conf.template" ||
    basename === ".htaccess" ||
    basename === "varnish.vcl" ||
    basename === "web.config" ||
    basename === "server.xml" ||
    basename === "application.properties" ||
    basename === "application.yml" ||
    basename === "application.yaml" ||
    lower.includes("/nginx/") ||
    lower.includes("/nginx.conf") ||
    lower.includes("/sites-available/") ||
    lower.includes("/sites-enabled/") ||
    lower.includes("/conf.d/") ||
    lower.includes("/httpd/") ||
    lower.includes("/apache2/") ||
    lower.includes("/apache/") ||
    lower.includes("/caddy/") ||
    lower.includes("/haproxy/") ||
    lower.includes("/lighttpd/") ||
    lower.includes("/varnish/")
  )
    return "server-config";

  return null;
}

export const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1MB — skip threshold for pattern scanners
export const LLM_MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024; // 8MB — LLM scanners chunk large files instead of skipping

// LLM context configuration — all configurable via env vars
// Chunk size = how much code is sent per LLM request (in estimated tokens)
// Response tokens = max tokens the LLM can generate in its response
export const MAX_CHUNK_TOKENS = parseInt(
  process.env.LLM_CHUNK_TOKENS || "4800",
);
export const CHUNK_OVERLAP_TOKENS = parseInt(
  process.env.LLM_CHUNK_OVERLAP_TOKENS || "800",
);
export const LLM_MAX_RESPONSE_TOKENS = parseInt(
  process.env.LLM_MAX_RESPONSE_TOKENS || "8192",
);

// Ollama/local model defaults — still smaller than cloud defaults but deeper than before
export const OLLAMA_MAX_CHUNK_TOKENS = parseInt(
  process.env.OLLAMA_CHUNK_TOKENS || "2400",
);
export const OLLAMA_CHUNK_OVERLAP_TOKENS = parseInt(
  process.env.OLLAMA_CHUNK_OVERLAP_TOKENS || "400",
);
export const OLLAMA_MAX_RESPONSE_TOKENS = parseInt(
  process.env.OLLAMA_MAX_RESPONSE_TOKENS || "6144",
);

/** Parallel LLM file/chunk requests inside a scanner (SAST / IaC / zero-day). */
export const MAX_LLM_CONCURRENCY = parseInt(
  process.env.MAX_LLM_CONCURRENCY || "4",
  10,
);


// ─── Web research (supply-chain corroboration) ───────────────────────────────
// Answers "has this package been publicly reported as malicious?", which no
// registry API covers. Flag-only: a result may raise suspicion, never dismiss a
// finding, because search results are attacker-influenceable.

// The on/off switch lives in web-research.ts as isWebResearchEnabled(), which
// reads the environment at call time; a constant here would freeze it at import.

export const WEB_RESEARCH_TIMEOUT_MS = parseInt(
  process.env.WEB_RESEARCH_TIMEOUT_MS || "12000",
  10,
);

export const WEB_RESEARCH_MAX_RESULTS = parseInt(
  process.env.WEB_RESEARCH_MAX_RESULTS || "5",
  10,
);

/** Whether a package has been reported is org-independent, so cache broadly. */
export const WEB_RESEARCH_CACHE_TTL_MS = parseInt(
  process.env.WEB_RESEARCH_CACHE_TTL_MS || String(24 * 60 * 60 * 1000),
  10,
);

/** Upper bound on searches per scan, so a large dependency set cannot fan out. */
export const WEB_RESEARCH_MAX_PER_SCAN = parseInt(
  process.env.WEB_RESEARCH_MAX_PER_SCAN || "10",
  10,
);

// ─── deps.dev (Open Source Insights) ─────────────────────────────────────────
// Supplies declared licenses, source repo, deprecation and provenance signals.
// Covers npm, PyPI, Maven, Go, crates.io, NuGet and RubyGems; Packagist, Pub,
// Hex and SwiftPM are skipped.

export const DEPS_DEV_API_URL =
  process.env.DEPS_DEV_API_URL || "https://api.deps.dev";

export const DEPS_DEV_TIMEOUT_MS = parseInt(
  process.env.DEPS_DEV_TIMEOUT_MS || "10000",
  10,
);

/** Parallel deps.dev requests. Matches the registry-metadata concurrency. */
export const DEPS_DEV_CONCURRENCY = parseInt(
  process.env.DEPS_DEV_CONCURRENCY || "10",
  10,
);

/** Package metadata is immutable per version, so it is cached for a long time. */
export const DEPS_DEV_CACHE_TTL_MS = parseInt(
  process.env.DEPS_DEV_CACHE_TTL_MS || String(6 * 60 * 60 * 1000),
  10,
);

export const DEPS_DEV_MAX_CACHE_ENTRIES = parseInt(
  process.env.DEPS_DEV_MAX_CACHE_ENTRIES || "20000",
  10,
);

/** Set to "false" to skip deps.dev enrichment entirely (air-gapped installs). */
export const ENABLE_DEPS_DEV = process.env.ENABLE_DEPS_DEV !== "false";

/**
 * Upper bound on dependency-graph fetches per scan when explaining why a
 * transitive dependency is present. Bounds cost on large monorepos; truncation
 * is always logged and surfaced rather than silently capping coverage.
 */
export const DEPS_DEV_MAX_GRAPH_FETCHES = parseInt(
  process.env.DEPS_DEV_MAX_GRAPH_FETCHES || "60",
  10,
);

// ─── License policy ──────────────────────────────────────────────────────────
// Patterns are SPDX IDs or `PREFIX-*` wildcards, matched case-insensitively.
// A bare ID also covers its `-only` / `-or-later` / `+` variants.
// Findings are emitted only for policy violations, never for every dependency.

function csvEnv(value: string | undefined, fallback: string[]): string[] {
  if (value === undefined) return fallback;
  const parsed = value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return parsed;
}

/** Strong copyleft and source-available licenses that usually block shipping. */
export const LICENSE_POLICY_DENY = csvEnv(process.env.LICENSE_POLICY_DENY, [
  "AGPL-*",
  "GPL-*",
  "SSPL-*",
  "BUSL-*",
  "CC-BY-NC-*",
  "Commons-Clause",
  "Elastic-2.0",
]);

/** Weak copyleft — usually allowed, but worth surfacing for review. */
export const LICENSE_POLICY_WARN = csvEnv(process.env.LICENSE_POLICY_WARN, [
  "LGPL-*",
  "MPL-*",
  "EPL-*",
  "CDDL-*",
  "OSL-*",
  "MS-RL",
  "CPAL-*",
]);

/** Off by default: unknown licenses are common and flagging them is noisy. */
export const LICENSE_POLICY_FLAG_UNKNOWN =
  process.env.LICENSE_POLICY_FLAG_UNKNOWN === "true";

// ─── SCA triage evidence budget ──────────────────────────────────────────────
// The triage LLM decides keep/drop and describes exploit preconditions, so it
// must be given the actual advisory text rather than inferring from the CVE ID.
// Budgets are per-vulnerability; the batch size is tuned so that
// (batch × advisory chars) stays inside the model's context window.
// Ollama does not set num_ctx, so local models often default to ~4k tokens.

/** Max advisory characters per vulnerability sent to the triage LLM (cloud). */
export const SCA_TRIAGE_ADVISORY_CHARS = parseInt(
  process.env.SCA_TRIAGE_ADVISORY_CHARS || "1500",
  10,
);

/** Max advisory characters per vulnerability for local/Ollama models. */
export const SCA_TRIAGE_ADVISORY_CHARS_OLLAMA = parseInt(
  process.env.SCA_TRIAGE_ADVISORY_CHARS_OLLAMA || "500",
  10,
);

/** Vulnerabilities per triage LLM request (cloud). */
export const SCA_TRIAGE_BATCH_SIZE = parseInt(
  process.env.SCA_TRIAGE_BATCH_SIZE || "20",
  10,
);

/** Vulnerabilities per triage LLM request for local/Ollama models. */
export const SCA_TRIAGE_BATCH_SIZE_OLLAMA = parseInt(
  process.env.SCA_TRIAGE_BATCH_SIZE_OLLAMA || "8",
  10,
);

/** Default minimum model confidence to keep an LLM finding (SAST / IaC / supply-chain LLM phases). */
export const LLM_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.LLM_MIN_CONFIDENCE || "0.75",
);

export const IAC_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.IAC_MIN_CONFIDENCE || "0.85",
);

export const ZERO_DAY_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.ZERO_DAY_MIN_CONFIDENCE || "0.72",
);

export const SECRETS_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.SECRETS_MIN_CONFIDENCE || "0.80",
);

export const MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.MALICIOUS_PKG_MIN_CONFIDENCE || "0.80",
);

export const K8S_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.K8S_MIN_CONFIDENCE || "0.80",
);

/** Zero-day: max high-priority paths before adding broader files. */
export const ZERO_DAY_PRIORITY_FILES = parseInt(
  process.env.ZERO_DAY_PRIORITY_FILES || "96",
  10,
);

/** Zero-day: total source files sent to the LLM (priority first, then others). */
export const ZERO_DAY_MAX_FILES = parseInt(
  process.env.ZERO_DAY_MAX_FILES || "160",
  10,
);

/**
 * Zero-day: how many of the highest-priority files are included in a single
 * LLM pass (bounded so the prompt stays inside the model context window).
 */
export const ZERO_DAY_LLM_FILES = parseInt(
  process.env.ZERO_DAY_LLM_FILES || "96",
  10,
);
