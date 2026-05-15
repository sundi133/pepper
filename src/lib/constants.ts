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
export const PATTERN_BASED_SCANNERS = new Set(["SAST_PATTERN", "SECRETS_PATTERN"]);

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
  | "ansible";

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
  process.env.LLM_CHUNK_OVERLAP_TOKENS || "360",
);
export const LLM_MAX_RESPONSE_TOKENS = parseInt(
  process.env.LLM_MAX_RESPONSE_TOKENS || "8192",
);

// Ollama/local model defaults — still smaller than cloud defaults but deeper than before
export const OLLAMA_MAX_CHUNK_TOKENS = parseInt(
  process.env.OLLAMA_CHUNK_TOKENS || "2400",
);
export const OLLAMA_CHUNK_OVERLAP_TOKENS = parseInt(
  process.env.OLLAMA_CHUNK_OVERLAP_TOKENS || "200",
);
export const OLLAMA_MAX_RESPONSE_TOKENS = parseInt(
  process.env.OLLAMA_MAX_RESPONSE_TOKENS || "6144",
);

/** Parallel LLM file/chunk requests inside a scanner (SAST / IaC / zero-day). */
export const MAX_LLM_CONCURRENCY = parseInt(
  process.env.MAX_LLM_CONCURRENCY || "4",
  10,
);

/** Default minimum model confidence to keep an LLM finding (SAST / IaC / supply-chain LLM phases). */
export const LLM_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.LLM_MIN_CONFIDENCE || "0.65",
);

export const IAC_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.IAC_MIN_CONFIDENCE || "0.65",
);

export const ZERO_DAY_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.ZERO_DAY_MIN_CONFIDENCE || "0.72",
);

export const MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT = parseFloat(
  process.env.MALICIOUS_PKG_MIN_CONFIDENCE || "0.65",
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
