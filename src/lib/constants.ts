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

export const SCANNER_LABELS = {
  SAST_PATTERN: "SAST (Pattern)",
  SAST_LLM: "SAST (AI)",
  SCA: "SCA",
  SECRETS_PATTERN: "Secrets (Pattern)",
  SECRETS_LLM: "Secrets (AI)",
} as const;

export const SCAN_STATUS_LABELS = {
  QUEUED: "Queued",
  RUNNING: "Running",
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

export const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1MB
export const MAX_CHUNK_TOKENS = 3000;
export const CHUNK_OVERLAP_TOKENS = 200;
