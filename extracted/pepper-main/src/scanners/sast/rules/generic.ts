import { PatternRule } from "../../types";

export const genericRules: PatternRule[] = [
  {
    id: "GEN-HARDCODE-001",
    title: "Hardcoded IP address",
    description:
      "Hardcoded IP addresses make code environment-dependent and can expose internal infrastructure details.",
    severity: "LOW",
    cweId: "CWE-798",
    languages: ["*"],
    pattern:
      /['"](?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)['"]/,
    negative:
      /(?:127\.0\.0\.1|0\.0\.0\.0|localhost|example|test|mock|255\.255\.255)/,
  },
  {
    id: "GEN-TODO-001",
    title: "Security-related TODO/FIXME comment",
    description:
      "A TODO, FIXME, or HACK comment related to security was found. This may indicate an unresolved security issue.",
    severity: "INFO",
    languages: ["*"],
    pattern:
      /(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:security|vuln|auth|permission|password|secret|token|inject|sanitiz|escap|xss|csrf|sql)/i,
  },
  {
    id: "GEN-DISABLE-001",
    title: "Security check suppression",
    description:
      "A security linting rule or check has been explicitly disabled. Review whether this suppression is justified.",
    severity: "LOW",
    languages: ["*"],
    pattern:
      /(?:nosec|nolint:gosec|@SuppressWarnings.*security|eslint-disable.*security|# noqa.*S\d|NOSONAR|bandit:.*skip)/i,
  },
  {
    id: "GEN-HTTP-001",
    title: "Insecure HTTP URL",
    description:
      "HTTP URLs transmit data in plaintext. Use HTTPS for all network communications.",
    severity: "LOW",
    cweId: "CWE-319",
    languages: ["*"],
    pattern:
      /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test)/,
    negative: /(?:\/\/.*http:|schema|spec|xmlns|dtd|doctype|w3\.org)/i,
  },
  {
    id: "GEN-CORS-001",
    title: "Wildcard CORS origin",
    description:
      "Allowing all origins (*) in CORS can expose your API to any domain. Restrict to specific trusted origins.",
    severity: "MEDIUM",
    cweId: "CWE-942",
    languages: ["*"],
    pattern: /(?:cors|origin|allow[_-]?origin)\s*[:=]\s*['"]\*['"]/i,
  },
  {
    id: "GEN-TEMPFILE-001",
    title: "Insecure temporary file creation",
    description:
      "Creating temporary files with predictable names or in shared directories can lead to symlink attacks.",
    severity: "MEDIUM",
    cweId: "CWE-377",
    languages: ["*"],
    pattern: /(?:\/tmp\/|\\temp\\|tempnam|tmpnam)\s*[+.]/i,
  },
  {
    id: "GEN-DEBUGGER-001",
    title: "Debugger statement left in code",
    description:
      "Debugger statements should not be present in production code.",
    severity: "LOW",
    languages: ["*"],
    pattern: /\bdebugger\b/,
    negative: /(?:\/\/.*debugger|\/\*.*debugger)/,
  },
  {
    id: "GEN-COOKIE-001",
    title: "Cookie without HttpOnly flag",
    description:
      "Cookies accessible via JavaScript are vulnerable to XSS-based session theft. Set the HttpOnly flag on session and sensitive cookies.",
    severity: "MEDIUM",
    cweId: "CWE-1004",
    languages: ["*"],
    pattern:
      /(?:Set-Cookie|setCookie|set_cookie|cookie)\s*[:=(].*(?!HttpOnly)/i,
    negative: /(?:httponly|HttpOnly|http_only)/i,
  },
  {
    id: "GEN-COOKIE-002",
    title: "Cookie without Secure flag",
    description:
      "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, exposing session data.",
    severity: "MEDIUM",
    cweId: "CWE-614",
    languages: ["*"],
    pattern: /(?:Set-Cookie|setCookie|set_cookie)\s*[:=(]/i,
    negative: /(?:Secure|secure|SECURE)/,
  },
  {
    id: "GEN-WEAKHASH-001",
    title: "Use of weak cryptographic hash (MD5/SHA1)",
    description:
      "MD5 and SHA1 are cryptographically broken. Use SHA-256 or stronger algorithms for integrity and security purposes.",
    severity: "MEDIUM",
    cweId: "CWE-328",
    languages: ["*"],
    pattern: /\b(?:md5|sha1|MD5|SHA1)\s*\(/,
    negative: /(?:checksum|etag|cache_key|test|spec|\.md5sum)/i,
  },
  {
    id: "GEN-CLEARTEXT-001",
    title: "Cleartext storage of sensitive data",
    description:
      "Sensitive data such as passwords or tokens should be encrypted or hashed before storage.",
    severity: "HIGH",
    cweId: "CWE-312",
    languages: ["*"],
    pattern: /(?:password|passwd|secret|token)\s*=\s*['"][^'"]{4,}['"]\s*;/i,
    negative:
      /(?:hash|encrypt|bcrypt|scrypt|argon|placeholder|example|changeme|test|process\.env|getenv|os\.environ|\$\{)/i,
  },
  {
    id: "GEN-ERRINFO-001",
    title: "Detailed error information exposed",
    description:
      "Stack traces and detailed error messages expose internal implementation details. Show generic error messages to users.",
    severity: "MEDIUM",
    cweId: "CWE-209",
    languages: ["*"],
    pattern:
      /(?:printStackTrace|traceback\.format_exc|console\.error\(err|res\.(?:send|json)\s*\(.*(?:stack|message|err))/i,
    negative: /(?:log(?:ger)?\.error|console\.error.*\blog\b|test|spec)/i,
  },
  {
    id: "GEN-SSRF-001",
    title: "Potential SSRF via user-controlled URL",
    description:
      "Fetching URLs from user input without validation can lead to Server-Side Request Forgery. Validate and whitelist allowed hosts.",
    severity: "HIGH",
    cweId: "CWE-918",
    languages: ["*"],
    pattern:
      /\b(?:fetch|axios|requests?\.get|http\.get|urllib|curl_exec|file_get_contents|HttpClient)\s*\(.*(?:req\.|params\.|query\.|body\.|args\.|input|\$_GET|\$_POST|\$_REQUEST)/i,
  },
  {
    id: "GEN-DOCKERFILE-001",
    title: "Dockerfile running as root",
    description:
      "Containers running as root have elevated privileges. Add a USER instruction to run as a non-root user.",
    severity: "MEDIUM",
    cweId: "CWE-250",
    languages: ["*"],
    pattern: /^FROM\s+\S+/,
    negative: /(?:USER\s+\w|as\s+builder|scratch)/i,
  },
  {
    id: "GEN-DOCKERFILE-002",
    title: "Dockerfile uses latest tag",
    description:
      "Using 'latest' or no tag on base images creates non-reproducible builds and may pull images with known vulnerabilities.",
    severity: "LOW",
    cweId: "CWE-1104",
    languages: ["*"],
    pattern: /^FROM\s+\S+(?::latest|\s+(?:AS|as)\b)/,
  },
  {
    id: "GEN-MISSINGENC-001",
    title: "Missing encryption for sensitive transport",
    description:
      "Sensitive data should be transmitted over encrypted channels (TLS/HTTPS). Plain HTTP or unencrypted sockets expose data to eavesdropping.",
    severity: "HIGH",
    cweId: "CWE-311",
    languages: ["*"],
    pattern:
      /(?:verify\s*[:=]\s*false|VERIFY_NONE|verify_ssl\s*[:=]\s*false|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*[:=]\s*true)/i,
  },
  {
    id: "GEN-CSRF-001",
    title: "Missing CSRF protection on state-changing endpoint",
    description:
      "State-changing operations (POST, PUT, DELETE) should include CSRF token validation to prevent cross-site request forgery.",
    severity: "MEDIUM",
    cweId: "CWE-352",
    languages: ["*"],
    pattern:
      /\b(?:app\.post|app\.put|app\.delete|router\.post|router\.put|router\.delete)\s*\(/i,
    negative: /(?:csrf|csurf|csrfProtection|_token|authenticity_token)/i,
  },
  {
    id: "GEN-XXE-001",
    title: "XML parsing without disabling external entities",
    description:
      "XML parsers that allow external entities can be exploited for XXE attacks, leading to file disclosure or SSRF.",
    severity: "HIGH",
    cweId: "CWE-611",
    languages: ["*"],
    pattern:
      /(?:XMLParser|DOMParser|xml\.parse|parseXML|simplexml_load|xml2js|lxml\.etree)\s*[.(]/i,
    negative:
      /(?:resolve_entities\s*=\s*False|FEATURE_EXTERNAL_GENERAL_ENTITIES.*false|disallow.*dtd|noent\s*=\s*false|defusedxml)/i,
  },
  {
    id: "GEN-REDIRECT-001",
    title: "Open redirect vulnerability",
    description:
      "Redirecting users based on unvalidated input can be exploited for phishing. Validate redirect URLs against a whitelist of allowed domains.",
    severity: "MEDIUM",
    cweId: "CWE-601",
    languages: ["*"],
    pattern:
      /(?:redirect|location\.href|window\.location|res\.redirect)\s*[=(].*(?:req\.|params\.|query\.|input|\$_GET|\$_POST)/i,
  },
];
