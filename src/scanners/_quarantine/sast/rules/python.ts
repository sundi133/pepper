import { PatternRule } from "../../types";

export const pythonRules: PatternRule[] = [
  {
    id: "PY-EXEC-001",
    title: "OS command execution with shell=True",
    description:
      "subprocess with shell=True or os.system() can lead to command injection. Use subprocess with a list of arguments and shell=False.",
    severity: "CRITICAL",
    cweId: "CWE-78",
    languages: ["python"],
    pattern:
      /(?:subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True|os\.system\s*\()/,
  },
  {
    id: "PY-EVAL-001",
    title: "Use of eval() or exec()",
    description:
      "eval() and exec() execute arbitrary Python code. If user input reaches these functions, it can lead to remote code execution.",
    severity: "HIGH",
    cweId: "CWE-95",
    languages: ["python"],
    pattern: /\b(?:eval|exec)\s*\(/,
    negative: /^\s*#/,
  },
  {
    id: "PY-SQL-001",
    title: "SQL query with string formatting",
    description:
      "SQL queries built with format strings or concatenation are vulnerable to SQL injection. Use parameterized queries.",
    severity: "HIGH",
    cweId: "CWE-89",
    languages: ["python"],
    pattern:
      /(?:execute|executemany)\s*\(\s*(?:f['"]|['"].*%|['"].*\.format\(|['"].*\+)/,
  },
  {
    id: "PY-PICKLE-001",
    title: "Unsafe deserialization with pickle",
    description:
      "pickle.loads() can execute arbitrary code during deserialization. Never unpickle data from untrusted sources.",
    severity: "HIGH",
    cweId: "CWE-502",
    languages: ["python"],
    pattern: /pickle\.(?:loads?|Unpickler)\s*\(/,
  },
  {
    id: "PY-YAML-001",
    title: "Unsafe YAML loading",
    description:
      "yaml.load() without SafeLoader can execute arbitrary Python code. Always use yaml.safe_load() or yaml.load(data, Loader=SafeLoader).",
    severity: "HIGH",
    cweId: "CWE-502",
    languages: ["python"],
    pattern:
      /yaml\.load\s*\([^)]*(?!\bLoader\s*=\s*(?:Safe|Base)Loader)[^)]*\)/,
  },
  {
    id: "PY-PATH-001",
    title: "Potential path traversal",
    description:
      "Constructing file paths with user input without proper validation can lead to path traversal. Use os.path.realpath() and verify the result.",
    severity: "MEDIUM",
    cweId: "CWE-22",
    languages: ["python"],
    pattern:
      /(?:open|os\.path\.join)\s*\([^)]*(?:request\.|args\.|form\.|params)/,
  },
  {
    id: "PY-ASSERT-001",
    title: "Assert used for security checks",
    description:
      "assert statements are removed when Python runs with -O flag. Never use assert for security-critical checks.",
    severity: "MEDIUM",
    cweId: "CWE-617",
    languages: ["python"],
    pattern: /\bassert\s+.*(?:auth|permission|role|admin|token|session|user)/i,
  },
  {
    id: "PY-DEBUG-001",
    title: "Flask debug mode enabled",
    description:
      "Flask debug mode exposes the Werkzeug debugger which allows code execution. Never enable debug mode in production.",
    severity: "MEDIUM",
    cweId: "CWE-489",
    languages: ["python"],
    pattern: /\.run\s*\(.*debug\s*=\s*True/,
  },
  {
    id: "PY-HASH-001",
    title: "Weak hash function for passwords",
    description:
      "MD5 and SHA1 are not suitable for password hashing. Use bcrypt, scrypt, or argon2 instead.",
    severity: "HIGH",
    cweId: "CWE-327",
    languages: ["python"],
    pattern: /hashlib\.(?:md5|sha1)\s*\(/,
    negative: /(?:checksum|file_hash|integrity|fingerprint)/i,
  },
  {
    id: "PY-SSRF-001",
    title: "Server-side request forgery (SSRF)",
    description:
      "Making HTTP requests with user-controlled URLs can lead to SSRF. Validate URLs against an allowlist.",
    severity: "HIGH",
    cweId: "CWE-918",
    languages: ["python"],
    pattern:
      /requests\.(?:get|post|put|delete|head)\s*\([^)]*(?:request\.|args\.|form\.|params)/,
  },
];
