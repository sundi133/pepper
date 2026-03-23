import { PatternRule } from "../../types";

export const phpRules: PatternRule[] = [
  {
    id: "PHP-SQL-001",
    title: "SQL injection via string interpolation",
    description:
      "SQL query built with variable interpolation is vulnerable to SQL injection. Use prepared statements with parameterized queries (PDO or mysqli_prepare).",
    severity: "CRITICAL",
    cweId: "CWE-89",
    languages: ["php"],
    pattern:
      /(?:mysql_query|mysqli_query|->query)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$/i,
  },
  {
    id: "PHP-SQL-002",
    title: "SQL query with string concatenation",
    description:
      "SQL query constructed with string concatenation. Use parameterized queries to prevent SQL injection.",
    severity: "CRITICAL",
    cweId: "CWE-89",
    languages: ["php"],
    pattern:
      /(?:mysql_query|mysqli_query|->query|->prepare)\s*\(.*\..*\$_(?:GET|POST|REQUEST|COOKIE)/i,
  },
  {
    id: "PHP-SQL-003",
    title: "Direct use of user input in SQL query",
    description:
      "User-supplied input ($_GET, $_POST, $_REQUEST) is used directly in a SQL query without proper sanitization. Use prepared statements.",
    severity: "CRITICAL",
    cweId: "CWE-89",
    languages: ["php"],
    pattern:
      /['"](?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
  },
  {
    id: "PHP-XSS-001",
    title: "Reflected XSS via direct output of user input",
    description:
      "User input is echoed directly without sanitization, enabling cross-site scripting. Use htmlspecialchars() or htmlentities() to encode output.",
    severity: "HIGH",
    cweId: "CWE-79",
    languages: ["php"],
    pattern:
      /(?:echo|print)\s+.*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/,
  },
  {
    id: "PHP-XSS-002",
    title: "Output without HTML encoding",
    description:
      "Echoing variables without htmlspecialchars() or htmlentities() can lead to XSS. Always encode output in HTML context.",
    severity: "MEDIUM",
    cweId: "CWE-79",
    languages: ["php"],
    pattern:
      /(?:echo|print)\s+\$(?!this\b)[a-zA-Z_]\w*\s*;/,
    negative: /htmlspecialchars|htmlentities|strip_tags|esc_html/,
  },
  {
    id: "PHP-EXEC-001",
    title: "Command injection via system/exec/passthru",
    description:
      "Executing system commands with user-controlled input enables command injection. Use escapeshellarg() and escapeshellcmd() for any user input.",
    severity: "CRITICAL",
    cweId: "CWE-78",
    languages: ["php"],
    pattern:
      /\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-EXEC-002",
    title: "Backtick command execution",
    description:
      "Backtick operators execute shell commands. If user input is involved, this allows command injection.",
    severity: "HIGH",
    cweId: "CWE-78",
    languages: ["php"],
    pattern: /`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)/,
  },
  {
    id: "PHP-EVAL-001",
    title: "Use of eval() with dynamic content",
    description:
      "eval() executes arbitrary PHP code. If user input reaches eval(), it enables remote code execution. Avoid eval() entirely.",
    severity: "CRITICAL",
    cweId: "CWE-95",
    languages: ["php"],
    pattern: /\beval\s*\(/,
    negative: /\/\/.*eval|\/\*.*eval/,
  },
  {
    id: "PHP-INCLUDE-001",
    title: "Dynamic file inclusion",
    description:
      "Using include/require with user-controlled paths enables Local/Remote File Inclusion (LFI/RFI). Validate paths against a whitelist.",
    severity: "CRITICAL",
    cweId: "CWE-98",
    languages: ["php"],
    pattern:
      /\b(?:include|include_once|require|require_once)\s*\(?.*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-INCLUDE-002",
    title: "Dynamic file inclusion with variable",
    description:
      "Using variables in include/require paths without validation can lead to file inclusion vulnerabilities.",
    severity: "HIGH",
    cweId: "CWE-98",
    languages: ["php"],
    pattern:
      /\b(?:include|include_once|require|require_once)\s*\(?\s*\$[a-zA-Z_]/,
    negative: /(?:__DIR__|dirname|ABSPATH|ROOT)/,
  },
  {
    id: "PHP-PATH-001",
    title: "Path traversal via user input",
    description:
      "File operations with user-controlled paths enable directory traversal. Validate and canonicalize paths, and check against a base directory.",
    severity: "HIGH",
    cweId: "CWE-22",
    languages: ["php"],
    pattern:
      /\b(?:file_get_contents|fopen|readfile|file|unlink|copy|rename|move_uploaded_file)\s*\(.*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-UPLOAD-001",
    title: "Insecure file upload handling",
    description:
      "File uploads without proper validation of type, size, and content can lead to remote code execution. Validate MIME type, extension, and store outside webroot.",
    severity: "HIGH",
    cweId: "CWE-434",
    languages: ["php"],
    pattern: /move_uploaded_file\s*\(/,
    negative: /(?:getimagesize|finfo_|mime_content_type|pathinfo.*PATHINFO_EXTENSION)/,
  },
  {
    id: "PHP-DESER-001",
    title: "Unsafe deserialization with unserialize()",
    description:
      "unserialize() on untrusted data can lead to object injection and remote code execution. Use json_decode() instead or restrict allowed classes.",
    severity: "CRITICAL",
    cweId: "CWE-502",
    languages: ["php"],
    pattern: /\bunserialize\s*\(/,
    negative: /allowed_classes\s*=>\s*false|allowed_classes.*\[\]/,
  },
  {
    id: "PHP-CRYPTO-001",
    title: "Weak hashing algorithm (MD5)",
    description:
      "MD5 is cryptographically broken and should not be used for passwords or security. Use password_hash() for passwords, or SHA-256+ for integrity.",
    severity: "HIGH",
    cweId: "CWE-328",
    languages: ["php"],
    pattern: /\bmd5\s*\(/,
    negative: /(?:checksum|cache|etag|hash_file|md5_file)/i,
  },
  {
    id: "PHP-CRYPTO-002",
    title: "Weak hashing algorithm (SHA1)",
    description:
      "SHA1 is considered weak for cryptographic purposes. Use SHA-256 or stronger algorithms.",
    severity: "MEDIUM",
    cweId: "CWE-328",
    languages: ["php"],
    pattern: /\bsha1\s*\(/,
    negative: /(?:checksum|cache|etag)/i,
  },
  {
    id: "PHP-CRYPTO-003",
    title: "Hardcoded password in source code",
    description:
      "Passwords should never be hardcoded. Use environment variables or a secrets manager.",
    severity: "CRITICAL",
    cweId: "CWE-798",
    languages: ["php"],
    pattern:
      /\$(?:password|passwd|pwd|pass)\s*=\s*['"][^'"]{3,}['"]/i,
    negative: /\$_(?:GET|POST|REQUEST)|password_hash|func_get_arg|getenv|empty/,
  },
  {
    id: "PHP-HEADER-001",
    title: "HTTP header injection",
    description:
      "User input in HTTP headers can lead to header injection and response splitting. Sanitize all header values.",
    severity: "HIGH",
    cweId: "CWE-113",
    languages: ["php"],
    pattern:
      /\bheader\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i,
  },
  {
    id: "PHP-SSRF-001",
    title: "Server-side request forgery",
    description:
      "User input in URL fetch functions can lead to SSRF. Validate and whitelist allowed URLs and hosts.",
    severity: "HIGH",
    cweId: "CWE-918",
    languages: ["php"],
    pattern:
      /\b(?:file_get_contents|curl_setopt.*CURLOPT_URL|fopen)\s*\(.*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-COOKIE-001",
    title: "Cookie set without secure flags",
    description:
      "Cookies should be set with Secure, HttpOnly, and SameSite flags to prevent session hijacking and CSRF.",
    severity: "MEDIUM",
    cweId: "CWE-614",
    languages: ["php"],
    pattern: /\bsetcookie\s*\([^)]+\)/,
    negative: /(?:true\s*,\s*true|httponly|secure|samesite)/i,
  },
  {
    id: "PHP-ERRDISPLAY-001",
    title: "Error display enabled in production",
    description:
      "Displaying errors exposes sensitive information about application internals. Disable display_errors in production.",
    severity: "MEDIUM",
    cweId: "CWE-209",
    languages: ["php"],
    pattern:
      /(?:display_errors|error_reporting)\s*[=(].*(?:E_ALL|1|true|on)/i,
    negative: /(?:ini_set.*0|off|false|test|dev)/i,
  },
  {
    id: "PHP-CSRF-001",
    title: "Form without CSRF token validation",
    description:
      "Forms that perform state-changing operations should validate CSRF tokens to prevent cross-site request forgery.",
    severity: "MEDIUM",
    cweId: "CWE-352",
    languages: ["php"],
    pattern:
      /\$_(?:POST|REQUEST)\s*\[/,
    negative: /(?:csrf|token|nonce|verify_nonce|check_admin_referer)/i,
  },
  {
    id: "PHP-REDIRECT-001",
    title: "Open redirect via user input",
    description:
      "Redirecting to user-supplied URLs without validation enables phishing. Validate redirect targets against a whitelist.",
    severity: "MEDIUM",
    cweId: "CWE-601",
    languages: ["php"],
    pattern:
      /\bheader\s*\(\s*['"]Location:\s*.*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-RAND-001",
    title: "Weak random number generation",
    description:
      "rand() and mt_rand() are not cryptographically secure. Use random_int() or random_bytes() for security-sensitive operations.",
    severity: "MEDIUM",
    cweId: "CWE-338",
    languages: ["php"],
    pattern: /\b(?:rand|mt_rand)\s*\(/,
    negative: /(?:test|example|seed|srand)/i,
  },
  {
    id: "PHP-EXTRACT-001",
    title: "Use of extract() on user input",
    description:
      "extract() on untrusted data can overwrite existing variables and lead to security bypasses. Use explicit variable assignment instead.",
    severity: "HIGH",
    cweId: "CWE-621",
    languages: ["php"],
    pattern: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
  },
  {
    id: "PHP-PREG-001",
    title: "Dangerous preg_replace with /e modifier",
    description:
      "The /e modifier in preg_replace evaluates the replacement as PHP code. Use preg_replace_callback() instead.",
    severity: "CRITICAL",
    cweId: "CWE-95",
    languages: ["php"],
    pattern: /preg_replace\s*\(\s*['"].*\/e['"]/,
  },
];
