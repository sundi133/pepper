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
];
