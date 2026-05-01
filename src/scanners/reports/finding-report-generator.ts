import type { RawFinding, SeverityLevel } from "@/scanners/types";

export type FindingReport = {
  markdown: string;
  title: string;
  severityLabel: string;
  summary: string;
  reproductionSteps: string[];
  exploitExample: string;
  impact: string;
  recommendedFix: string;
  betterFix?: string;
  unsafeFixWarning?: string;
  validationTest: string;
};

type FindingCategory =
  | "COMMAND_INJECTION"
  | "XSS"
  | "SQL_INJECTION"
  | "NOSQL_INJECTION"
  | "SSRF"
  | "PATH_TRAVERSAL"
  | "OPEN_REDIRECT"
  | "INSECURE_DESERIALIZATION"
  | "XXE"
  | "TEMPLATE_INJECTION"
  | "PROTOTYPE_POLLUTION"
  | "CRYPTO_WEAKNESS"
  | "AUTHZ_BYPASS"
  | "AUTHN_WEAKNESS"
  | "CSRF"
  | "COOKIE_SECURITY"
  | "DANGEROUS_FILE_UPLOAD"
  | "INFO_DISCLOSURE"
  | "INSECURE_CONFIG"
  | "REDOS"
  | "HARDCODED_SECRET"
  | "GENERIC";

type ReportContext = {
  category: FindingCategory;
  language: string;
  framework?: string;
  route?: string;
  httpMethod?: string;
  cweName?: string;
  owasp?: string;
  sourceLine?: string;
  sinkLine?: string;
};

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

const CWE_NAMES: Record<string, string> = {
  "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
  "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
  "CWE-79": "Improper Neutralization of Input During Web Page Generation",
  "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
  "CWE-94": "Improper Control of Generation of Code",
  "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code",
  "CWE-200": "Exposure of Sensitive Information",
  "CWE-287": "Improper Authentication",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator",
  "CWE-352": "Cross-Site Request Forgery",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-434": "Unrestricted Upload of File with Dangerous Type",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-601": "URL Redirection to Untrusted Site",
  "CWE-611": "Improper Restriction of XML External Entity Reference",
  "CWE-639": "Authorization Bypass Through User-Controlled Key",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-862": "Missing Authorization",
  "CWE-863": "Incorrect Authorization",
  "CWE-918": "Server-Side Request Forgery",
  "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
  "CWE-614": "Sensitive Cookie in HTTPS Session Without Secure Attribute",
  "CWE-1004": "Sensitive Cookie Without HttpOnly Flag",
  "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes",
};

export function generateFindingReport(input: {
  finding: RawFinding;
  scan?: {
    id?: string;
    scanType?: string;
    sourceType?: string | null;
    sourceRef?: string | null;
    branch?: string | null;
    commitSha?: string | null;
  };
  project?: {
    name?: string;
    repoUrl?: string | null;
  };
  allFindings?: RawFinding[];
}): FindingReport {
  const finding = {
    ...input.finding,
    snippet: maskSecrets(input.finding.snippet || ""),
    description: maskSecrets(input.finding.description),
  };
  const category = detectCategory(finding);
  const language = detectLanguage(finding.filePath, finding);
  const metadata = metadataOf(finding);
  const context: ReportContext = {
    category,
    language,
    framework: detectFramework(finding.filePath, finding.snippet, metadata),
    route: extractRoute(finding.snippet, metadata),
    httpMethod: extractHttpMethod(finding.snippet, metadata),
    cweName: getCweName(finding.cweId),
    owasp: getOwaspCategory(category, finding.cweId),
    sourceLine: extractSourceLine(finding.snippet, category),
    sinkLine: extractSinkLine(finding.snippet, category),
  };

  const severityLabel = SEVERITY_LABELS[finding.severity] || finding.severity;
  const title = finding.title || "Security finding";
  const summary = buildSummary(finding, context);
  const reproductionSteps = getReproductionSteps(category, language, context.framework, finding);
  const exploitExample = getExploitPayload(category, language, context.framework, finding);
  const impact = getImpact(category, finding, context);
  const recommendedFix = getRecommendedFix(category, language, context.framework, finding);
  const betterFix = getBetterFix(category, language, context.framework, finding);
  const unsafeFixWarning = getUnsafeFixWarning(category, language, context.framework, finding);
  const validationTest = getValidationTest(category, language, context.framework, finding);

  const lines: string[] = [];
  lines.push(`### ${severityLabel}: ${title}`);
  lines.push("");
  const location = formatFileAndLine(finding);
  if (location) lines.push(location);
  if (context.route) lines.push(`**Route:** \`${context.route}\``);
  if (finding.cweId) {
    lines.push(
      `**CWE:** ${finding.cweId}${context.cweName ? ` — ${context.cweName}` : ""}`,
    );
  }
  if (context.owasp) lines.push(`**OWASP:** ${context.owasp}`);
  lines.push("");
  const snippet = formatSnippet(finding, language);
  if (snippet) {
    lines.push(snippet);
    lines.push("");
  }
  lines.push("### What I found");
  lines.push("");
  lines.push(summary);
  lines.push("");
  lines.push("### Steps to reproduce");
  lines.push("");
  for (const [index, step] of reproductionSteps.entries()) {
    lines.push(`${index + 1}. ${step}`);
  }
  lines.push("");
  lines.push("### Exploit example");
  lines.push("");
  lines.push(exploitExample);
  lines.push("");
  lines.push("### Impact");
  lines.push("");
  lines.push(impact);
  lines.push("");
  lines.push("### Recommended fix");
  lines.push("");
  lines.push(recommendedFix);
  lines.push("");
  if (betterFix) {
    lines.push("### Even better fix");
    lines.push("");
    lines.push(betterFix);
    lines.push("");
  }
  if (unsafeFixWarning) {
    lines.push("### Avoid this unsafe fix");
    lines.push("");
    lines.push(unsafeFixWarning);
    lines.push("");
  }
  lines.push("### Validation test");
  lines.push("");
  lines.push(validationTest);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(summaryTable(input.allFindings || [input.finding]));
  lines.push("");
  lines.push(`**Overall risk:** ${overallRisk(input.allFindings || [input.finding])}.`);
  lines.push(finalRiskSentence(input.allFindings || [input.finding]));

  return {
    markdown: lines.join("\n"),
    title,
    severityLabel,
    summary,
    reproductionSteps,
    exploitExample,
    impact,
    recommendedFix,
    betterFix,
    unsafeFixWarning,
    validationTest,
  };
}

export function detectLanguage(filePath?: string, finding?: RawFinding): string {
  const meta = metadataOf(finding);
  const metadataLanguage = stringField(meta, "language");
  if (metadataLanguage) return metadataLanguage.toLowerCase();
  const ext = (filePath || "").toLowerCase().split(".").pop();
  const map: Record<string, string> = {
    js: "javascript",
    jsx: "javascript",
    ts: "typescript",
    tsx: "typescript",
    py: "python",
    php: "php",
    java: "java",
    go: "go",
    rb: "ruby",
    cs: "csharp",
    rs: "rust",
    sql: "sql",
    yml: "yaml",
    yaml: "yaml",
    json: "json",
  };
  return (ext && map[ext]) || "text";
}

export function detectFramework(
  filePath?: string,
  snippet?: string,
  metadata: Record<string, unknown> = {},
): string | undefined {
  const explicit = stringField(metadata, "framework");
  if (explicit) return explicit;
  const haystack = `${filePath || ""}\n${snippet || ""}`;
  if (/flask|@app\.route|request\.args/i.test(haystack)) return "Flask";
  if (/django|render\(|urlpatterns/i.test(haystack)) return "Django";
  if (/express|app\.(get|post|put|delete)|req\.|res\./i.test(haystack)) return "Express";
  if (/next\/|NextRequest|app\/api|route\.ts/i.test(haystack)) return "Next.js";
  if (/react|dangerouslySetInnerHTML/i.test(haystack)) return "React";
  if (/spring|RequestMapping|GetMapping|PostMapping/i.test(haystack)) return "Spring";
  return undefined;
}

export function extractRoute(
  snippet?: string,
  metadata: Record<string, unknown> = {},
): string | undefined {
  const route = stringField(metadata, "route") || stringField(objectField(metadata, "httpSurface"), "routePattern");
  if (route) return route;
  if (!snippet) return undefined;
  const patterns = [
    /@app\.route\s*\(\s*["'`]([^"'`]+)["'`]/,
    /\bapp\.(?:get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/,
    /@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["'`]([^"'`]+)["'`]/,
  ];
  for (const pattern of patterns) {
    const match = snippet.match(pattern);
    if (match?.[1]) return match[1];
  }
  return undefined;
}

export function extractHttpMethod(
  snippet?: string,
  metadata: Record<string, unknown> = {},
): string | undefined {
  const explicit =
    stringField(metadata, "method") ||
    stringField(metadata, "httpMethod") ||
    stringField(objectField(metadata, "httpSurface"), "method");
  if (explicit) return explicit.toUpperCase();
  if (!snippet) return undefined;
  const express = snippet.match(/\bapp\.(get|post|put|patch|delete)\s*\(/i);
  if (express?.[1]) return express[1].toUpperCase();
  const spring = snippet.match(/@(Get|Post|Put|Patch|Delete)Mapping\s*\(/);
  if (spring?.[1]) return spring[1].replace("Mapping", "").toUpperCase();
  if (/@app\.route\s*\(/.test(snippet)) {
    const methods = snippet.match(/methods\s*=\s*\[([^\]]+)\]/i);
    const method = methods?.[1]?.match(/["'`](GET|POST|PUT|PATCH|DELETE)["'`]/i)?.[1];
    return method?.toUpperCase() || "GET";
  }
  return undefined;
}

export function extractSourceLine(snippet: string | undefined, category: FindingCategory): string | undefined {
  if (!snippet) return undefined;
  const lines = rawLines(snippet);
  const sourceRegex = sourceRegexFor(category);
  return lines.find((line) => sourceRegex.test(line));
}

export function extractSinkLine(snippet: string | undefined, category: FindingCategory): string | undefined {
  if (!snippet) return undefined;
  const lines = rawLines(snippet);
  const sinkRegex = sinkRegexFor(category);
  return lines.find((line) => sinkRegex.test(line));
}

export function getCweName(cweId?: string): string | undefined {
  return cweId ? CWE_NAMES[cweId.toUpperCase()] : undefined;
}

export function getOwaspCategory(category: FindingCategory, cweId?: string): string | undefined {
  if (cweId === "CWE-79" || cweId === "CWE-89" || category.includes("INJECTION") || category === "XSS") {
    return "A03:2021 Injection";
  }
  if (["AUTHZ_BYPASS", "AUTHN_WEAKNESS", "OPEN_REDIRECT"].includes(category)) return "A01:2021 Broken Access Control";
  if (["HARDCODED_SECRET", "INFO_DISCLOSURE"].includes(category)) return "A02:2021 Cryptographic Failures";
  if (["INSECURE_CONFIG", "XXE"].includes(category)) return "A05:2021 Security Misconfiguration";
  if (category === "INSECURE_DESERIALIZATION") return "A08:2021 Software and Data Integrity Failures";
  if (category === "SSRF") return "A10:2021 Server-Side Request Forgery";
  return undefined;
}

export function formatFileAndLine(finding: RawFinding): string {
  const lines: string[] = [];
  if (finding.filePath) lines.push(`**File:** \`${finding.filePath}\``);
  if (finding.startLine != null && finding.endLine != null && finding.startLine !== finding.endLine) {
    lines.push(`**Lines:** \`${finding.startLine}-${finding.endLine}\``);
  } else if (finding.startLine != null) {
    lines.push(`**Line:** \`${finding.startLine}\``);
  }
  return lines.join("\n");
}

export function formatSnippet(finding: RawFinding, language: string): string {
  const snippet = maskSecrets(finding.snippet || "");
  if (!snippet.trim()) return "";
  const cleaned = rawLines(snippet).join("\n");
  return `\`\`\`${language}\n${cleaned}\n\`\`\``;
}

export function maskSecrets(text: string): string {
  return text
    .replace(/AKIA[0-9A-Z]{16}/g, "AKIA****************")
    .replace(/(?<=api[_-]?key\s*[:=]\s*["'`]?)[A-Za-z0-9_\-]{12,}/gi, "[MASKED_SECRET]")
    .replace(/(?<=secret\s*[:=]\s*["'`]?)[A-Za-z0-9_\-./+=]{12,}/gi, "[MASKED_SECRET]")
    .replace(/(?<=password\s*[:=]\s*["'`]?)[^"'`\s]{6,}/gi, "[MASKED_PASSWORD]")
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "gh*_****************")
    .replace(/sk_(?:live|test)_[A-Za-z0-9_]{12,}/g, "[MASKED_SECRET]")
    .replace(/xox[baprs]-[A-Za-z0-9-]{20,}/g, "xox*-****************");
}

export function getExploitPayload(
  category: FindingCategory,
  language: string,
  framework: string | undefined,
  finding: RawFinding,
): string {
  const route = extractRoute(finding.snippet, metadataOf(finding));
  switch (category) {
    case "COMMAND_INJECTION":
      return "Use a harmless shell metacharacter probe such as `test; id` or `test && id` in the affected input and verify it is not interpreted by a shell.";
    case "XSS": {
      const payload = "`<img src=x onerror=alert(1)>`";
      return route ? `For route \`${route}\`, submit ${payload} in the reflected or stored field and verify the browser renders it as text, not executable HTML.` : `Submit ${payload} in the affected field and verify the browser renders it as text, not executable HTML.`;
    }
    case "SQL_INJECTION":
      return "Use a safe SQL metacharacter probe such as `' OR '1'='1` and verify it is treated as data through bind parameters.";
    case "NOSQL_INJECTION":
      return "Submit an object/operator-style value such as `{ \"$ne\": null }` to the affected parameter and verify the query rejects it or treats it as plain data.";
    case "SSRF":
      return "Attempt a blocked internal target such as `http://127.0.0.1/` or the cloud metadata address in a non-production environment and verify the request is denied before connection.";
    case "PATH_TRAVERSAL":
      return "Use traversal strings such as `../` and encoded variants and verify the resolved path remains inside the allowed base directory.";
    case "OPEN_REDIRECT":
      return "Provide an external absolute URL and a protocol-relative URL as the redirect target and verify both are rejected.";
    case "HARDCODED_SECRET":
      return "Search the repository history and current tree for the masked credential pattern, then verify the credential has been rotated without using it against production services.";
    case "CSRF":
      return route
        ? `Submit a state-changing request to \`${route}\` from a page that does not include the application's CSRF token and verify the server rejects it.`
        : "Submit the affected state-changing handler without a CSRF token and verify the server rejects it.";
    case "COOKIE_SECURITY":
      return "Inspect the Set-Cookie header or cookie creation call and verify sensitive cookies include `HttpOnly`, `Secure`, and an appropriate `SameSite` value.";
    default:
      return `Exercise the cited input path for this ${language}${framework ? `/${framework}` : ""} finding with a safe non-destructive probe and verify the unsafe behavior is blocked.`;
  }
}

export function getReproductionSteps(
  category: FindingCategory,
  language: string,
  framework: string | undefined,
  finding: RawFinding,
): string[] {
  const aiSteps = getAiReproductionSteps(finding);
  if (aiSteps.length > 0) return aiSteps;

  const metadata = metadataOf(finding);
  const route = extractRoute(finding.snippet, metadata);
  const method = extractHttpMethod(finding.snippet, metadata);
  const source = extractSourceLine(finding.snippet, category);
  const sink = extractSinkLine(finding.snippet, category);
  const location = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : "the cited file";
  const inputStep = route
    ? `Open the real affected route \`${route}\`${method ? ` with HTTP method \`${method}\`` : ""} in an authorized test environment.`
    : `Review \`${location}\` and identify the input reaching the cited code path.`;
  const evidenceStep = source && sink
    ? `Confirm the source line \`${source.trim()}\` can influence the sink line \`${sink.trim()}\`.`
    : sink
      ? `Confirm execution reaches the sink line \`${sink.trim()}\`.`
      : "Confirm the vulnerable code path is reachable with normal application inputs.";

  switch (category) {
    case "INSECURE_CONFIG":
      if (/debug\s*=\s*true|flask debug|werkzeug/i.test(`${finding.title}\n${finding.description}\n${finding.snippet || ""}`)) {
        return [
          `Open \`${location}\` and confirm the application starts Flask with debug mode enabled, for example \`app.run(debug=True)\`.`,
          "Run the application only in a local or disposable test environment, never on a public host.",
          "Trigger any unhandled error in the app, such as sending malformed input to an endpoint that reaches the vulnerable code path.",
          "The finding is reproduced if the Werkzeug debug error page or interactive debugger is exposed instead of a normal production error response.",
          "Direct verification is enough for this issue; do not use curl unless the real route that triggers the error is known from the source.",
        ];
      }
      return [
        inputStep,
        evidenceStep,
        "Run the application with production-like configuration and verify the unsafe option is active.",
        "The finding is reproduced if the risky setting remains enabled in a production or externally reachable runtime.",
      ];
    case "COMMAND_INJECTION":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "cmd=test%3B%20id")}\`. Use only a sandbox or disposable environment.`
          : "Verify directly by calling the handler/function with the affected input set to a harmless metacharacter probe such as `test; id` or `test && id`.",
        "The finding is reproduced if the application passes the probe into shell command construction instead of rejecting it or treating it as a literal argument.",
      ];
    case "XSS":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")}\`. Change \`name\` only if the source line shows a different parameter.`
          : "Verify directly by invoking the handler/render path with the affected value set to `<img src=x onerror=alert(1)>`.",
        "The finding is reproduced if the response or DOM interprets the probe as HTML/JavaScript instead of displaying escaped text.",
      ];
    case "SQL_INJECTION":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "id=%27%20OR%20%271%27%3D%271")}\`. Change \`id\` only if the source line shows a different parameter.`
          : "Verify directly by calling the data-access path with the affected value set to `' OR '1'='1`.",
        "The finding is reproduced if the query behavior changes, errors with SQL syntax, or returns records that should not match the original input.",
      ];
    case "NOSQL_INJECTION":
      return [
        inputStep,
        evidenceStep,
        "Submit an operator-shaped value such as `{ \"$ne\": null }` to the affected parameter.",
        "The finding is reproduced if the application accepts the operator as query logic instead of validating the request shape.",
      ];
    case "SSRF":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "url=http%3A%2F%2F127.0.0.1%2F")}\`. Use a controlled test service or blocked internal target only.`
          : "Verify directly by calling the fetch/request function with `http://127.0.0.1/` or a controlled callback URL.",
        "The finding is reproduced if the server attempts the outbound request before enforcing host, scheme, DNS, and private IP restrictions.",
      ];
    case "PATH_TRAVERSAL":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "file=..%2F..%2Fetc%2Fpasswd")}\`. Change \`file\` only if the source line shows a different path parameter.`
          : "Verify directly by calling the file access function with traversal input such as `../../etc/passwd` and an encoded variant.",
        "The finding is reproduced if the resolved path can leave the intended base directory or reaches an unexpected file.",
      ];
    case "OPEN_REDIRECT":
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with: \`${curlCommand(method, route, "next=https%3A%2F%2Fattacker.example")}\`. Change \`next\` only if the source line shows a different redirect parameter.`
          : "Verify directly by calling the redirect path with `https://attacker.example` and `//attacker.example` as the target value.",
        "The finding is reproduced if the response redirects outside the trusted origin.",
      ];
    case "HARDCODED_SECRET":
      return [
        `Inspect \`${location}\` and verify the report evidence contains a masked credential-like value.`,
        "Search the repository and build artifacts for the same masked value pattern without printing the raw secret.",
        "The finding is reproduced if the secret is present in source-controlled or packaged code instead of being loaded from a secret manager or protected environment variable.",
      ];
    case "CSRF":
      return [
        route && method
          ? `Send the real state-changing request without a CSRF token: \`${curlCommand(method, route, "title=test&body=csrf-check")}\`. Use only a local or authorized test environment.`
          : `Review \`${location}\` and confirm the state-changing handler does not validate a CSRF token, SameSite-only defense, or equivalent anti-CSRF control.`,
        "From another local HTML page, create a form that posts to the same route with harmless test values.",
        "The finding is reproduced if the request succeeds without a valid CSRF token tied to the user's session.",
      ];
    case "COOKIE_SECURITY": {
      const missingHttpOnly = /httponly/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-1004";
      const missingSecure = /secure/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-614";
      const missingFlag = missingHttpOnly ? "HttpOnly" : missingSecure ? "Secure" : "required security flags";
      return [
        route && method
          ? `Request the real route and inspect cookies: \`${curlCommand(method, route)}\`.`
          : `Open \`${location}\` and inspect the cookie creation call shown in the evidence.`,
        `Confirm the sensitive cookie is created without the \`${missingFlag}\` attribute.`,
        missingHttpOnly
          ? "The finding is reproduced if JavaScript-readable cookie creation is possible because `httpOnly: true` or `HttpOnly` is missing."
          : missingSecure
            ? "The finding is reproduced if the cookie can be sent over plain HTTP because `secure: true` or `Secure` is missing."
            : "The finding is reproduced if a sensitive cookie is missing required browser security attributes.",
      ];
    }
    default:
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Verify over HTTP with a safe request to the real route: \`${curlCommand(method, route)}\`. Add the affected parameter from the source line if one is shown.`
          : `Verify directly with a ${framework || language} unit/integration test that calls the function shown in the snippet.`,
        "The finding is reproduced if the unsafe sink or missing security control is reached before validation, encoding, authorization, or other required protection.",
      ];
  }
}

export function getRecommendedFix(
  category: FindingCategory,
  language: string,
  framework: string | undefined,
  finding: RawFinding,
): string {
  const metadataFix = stringField(metadataOf(finding), "fix");
  if (metadataFix) return metadataFix;
  switch (category) {
    case "COMMAND_INJECTION":
      return "Remove shell command construction. Use fixed executables with argument arrays (`execFile`/`spawn` in Node, `subprocess.run([...], shell=False)` in Python) and allowlist every user-controlled argument.";
    case "XSS":
      if (framework === "Flask") return "Return rendered templates with autoescaping enabled and pass user input as template data instead of concatenating HTML strings.";
      if (framework === "React") return "Render untrusted data as JSX text. If HTML is required, sanitize with DOMPurify before `dangerouslySetInnerHTML`.";
      return "Use contextual output encoding or framework autoescaping. Do not concatenate untrusted input into HTML or DOM sinks.";
    case "SQL_INJECTION":
      return "Use parameterized queries, prepared statements, or safe ORM APIs. Keep SQL syntax static and pass user input only as bound values.";
    case "NOSQL_INJECTION":
      return "Validate request shapes against a schema and reject query operators from user input. Build database filters from allowlisted fields only.";
    case "SSRF":
      return "Parse the URL, enforce an allowlist of hosts/schemes, resolve DNS, block private/link-local IP ranges, disable unsafe redirects, and set tight timeouts.";
    case "PATH_TRAVERSAL":
      return "Canonicalize the requested path, join it to a fixed base directory, and reject it unless the resolved path remains under that base. Prefer allowlisted file IDs.";
    case "OPEN_REDIRECT":
      return "Allow only same-origin relative paths or server-side allowlisted destinations. Reject absolute and protocol-relative URLs.";
    case "INSECURE_DESERIALIZATION":
      return "Do not deserialize untrusted objects. Use JSON or another simple data format plus schema validation.";
    case "XXE":
      return "Disable external entity resolution and DTD processing in the XML parser, or use a hardened parser configuration.";
    case "TEMPLATE_INJECTION":
      return "Do not build templates from user input. Pass user data as escaped template variables and restrict template helpers.";
    case "PROTOTYPE_POLLUTION":
      return "Reject dangerous keys such as `__proto__`, `constructor`, and `prototype` before merging user-controlled objects.";
    case "CRYPTO_WEAKNESS":
      return "Replace weak crypto with modern primitives appropriate for the use case, such as bcrypt/argon2 for passwords and CSPRNG APIs for tokens.";
    case "AUTHZ_BYPASS":
      return "Enforce authorization on the server using the authenticated principal and resource ownership checks before returning or mutating data.";
    case "AUTHN_WEAKNESS":
      return "Use proven authentication/session libraries, strong token entropy, secure cookie flags, and explicit session invalidation.";
    case "CSRF":
      return "Add CSRF token validation to every state-changing route. For Express, use a maintained CSRF middleware or signed per-session tokens and reject POST/PUT/PATCH/DELETE requests without a valid token.";
    case "COOKIE_SECURITY":
      if (/httponly/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-1004") {
        return "Mark sensitive cookies as `HttpOnly` so browser JavaScript cannot read them. In Express/Puppeteer-style cookie objects, set `httpOnly: true`.";
      }
      if (/secure/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-614") {
        return "Mark sensitive cookies as `Secure` so they are only sent over HTTPS. In Express/Puppeteer-style cookie objects, set `secure: true` and serve production traffic over HTTPS.";
      }
      return "Set sensitive cookies with `HttpOnly`, `Secure`, and an appropriate `SameSite` attribute.";
    case "DANGEROUS_FILE_UPLOAD":
      return "Enforce file size and type allowlists, store uploads outside the web root, randomize names, and scan or transform uploaded content.";
    case "INFO_DISCLOSURE":
      return "Remove sensitive data from responses/logs and expose only the minimum required fields.";
    case "INSECURE_CONFIG":
      if (/debug\s*=\s*true|flask debug|werkzeug/i.test(`${finding.title}\n${finding.description}\n${finding.snippet || ""}`)) {
        return "Disable Flask debug mode outside local development. Remove `debug=True`, set `FLASK_DEBUG=0`, and run behind a production WSGI server such as gunicorn or uWSGI.";
      }
      return "Disable unsafe development settings in production and enforce secure defaults through configuration validation.";
    case "REDOS":
      return "Replace catastrophic regular expressions with bounded patterns or a safe regex engine and enforce input length limits.";
    case "HARDCODED_SECRET":
      return "Rotate the exposed secret, remove it from source and history where practical, and load future values from a secret manager or protected environment variable.";
    default:
      return "Add the missing security control at the source, sink, or authorization boundary and rerun the scan.";
  }
}

export function getBetterFix(
  category: FindingCategory,
  _language: string,
  _framework: string | undefined,
  _finding: RawFinding,
): string | undefined {
  void _language;
  void _framework;
  void _finding;
  if (category === "COMMAND_INJECTION") return "Move the operation behind a dedicated service API so users choose from predefined actions instead of influencing process arguments.";
  if (category === "PATH_TRAVERSAL") return "Use opaque file IDs mapped server-side to known safe paths instead of accepting filenames from clients.";
  if (category === "SSRF") return "Route all outbound requests through a hardened egress proxy with network policy enforcement and audit logging.";
  if (category === "HARDCODED_SECRET") return "Adopt automated secret scanning in pre-commit and CI so credentials cannot be introduced again.";
  if (category === "CSRF") return "Use same-site cookies plus token validation, not SameSite alone, so older browsers and same-site attacks are still covered.";
  if (category === "COOKIE_SECURITY") return "Centralize cookie creation in one helper that always applies secure defaults for session and admin cookies.";
  return undefined;
}

export function getUnsafeFixWarning(
  category: FindingCategory,
  _language: string,
  _framework: string | undefined,
  _finding: RawFinding,
): string | undefined {
  void _language;
  void _framework;
  void _finding;
  if (category === "COMMAND_INJECTION") return "Do not try to escape shell metacharacters manually and keep using a shell string. Shell escaping is fragile and context-dependent.";
  if (category === "XSS") return "Do not rely on blocklisting `<script>` only. Event handlers, SVG, encoded payloads, and URL contexts can still execute.";
  if (category === "SQL_INJECTION") return "Do not concatenate sanitized strings into SQL. Escaping is not a substitute for bind parameters.";
  if (category === "PATH_TRAVERSAL") return "Do not only remove `../`; encoded traversal and absolute paths can bypass simple replacement.";
  if (category === "SSRF") return "Do not block only `localhost`; attackers can use private IPs, DNS rebinding, redirects, and encoded addresses.";
  if (category === "CSRF") return "Do not rely only on checking the Referer header; it can be absent and is not a complete CSRF defense.";
  if (category === "COOKIE_SECURITY") return "Do not set flags only in production branches that can be skipped by tests or preview deployments.";
  return undefined;
}

export function getValidationTest(
  category: FindingCategory,
  language: string,
  framework: string | undefined,
  finding: RawFinding,
): string {
  switch (category) {
    case "XSS":
      return "Add a test that sends an HTML probe to the affected field and asserts the response contains escaped text, not executable markup.";
    case "SQL_INJECTION":
      return "Add a test with SQL metacharacters and assert the database call uses bind parameters or the ORM safe API.";
    case "COMMAND_INJECTION":
      return "Add a test that passes shell metacharacters and asserts the command runner receives a fixed executable plus argument array, or rejects the input.";
    case "HARDCODED_SECRET":
      return "Rerun secret scanning and confirm the old value is absent. Verify rotation in the provider audit log without using the secret.";
    case "CSRF":
      return "Add an integration test that sends the state-changing request without a CSRF token and expects rejection, then sends it with a valid token and expects success.";
    case "COOKIE_SECURITY":
      return "Add a test that inspects the emitted cookie and asserts the expected `HttpOnly`, `Secure`, and `SameSite` attributes are present.";
    default:
      return `Add a ${framework || language} regression test around ${finding.filePath || "the affected code"} that fails before the fix and passes after the unsafe path is blocked.`;
  }
}

function buildSummary(finding: RawFinding, context: ReportContext): string {
  const sourceSink = sourceSinkEvidence(finding);
  if (sourceSink) return sourceSink;
  const source = context.sourceLine ? ` Source evidence: \`${context.sourceLine.trim()}\`.` : "";
  const sink = context.sinkLine ? ` Sink evidence: \`${context.sinkLine.trim()}\`.` : "";
  const description = cleanDescription(maskSecrets(finding.description));
  return `${description || categorySentence(context.category)}${source}${sink}`.trim();
}

function getImpact(category: FindingCategory, finding: RawFinding, context: ReportContext): string {
  switch (category) {
    case "COMMAND_INJECTION":
      return "Successful exploitation can execute unintended commands with the privileges of the application process.";
    case "XSS":
      return "Successful exploitation can run attacker-controlled JavaScript in a victim browser, enabling session theft, account actions, or data exposure visible to that user.";
    case "SQL_INJECTION":
      return "Successful exploitation can read, modify, or delete database records and may bypass application-level authorization around the affected query.";
    case "SSRF":
      return "Successful exploitation can make the server connect to internal services, metadata endpoints, or protected network locations.";
    case "HARDCODED_SECRET":
      return "Anyone with repository or artifact access may reuse the credential until it is revoked, depending on the secret's permissions.";
    case "CSRF":
      return "An attacker can cause a signed-in user's browser to perform unwanted state-changing actions if the endpoint accepts requests without a valid anti-CSRF token.";
    case "COOKIE_SECURITY":
      if (/httponly/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-1004") {
        return "If XSS exists anywhere in the app, JavaScript can read the cookie and steal or abuse the sensitive value.";
      }
      if (/secure/i.test(finding.title) || finding.cweId?.toUpperCase() === "CWE-614") {
        return "The cookie can be exposed on unencrypted HTTP requests or downgrade paths, putting sensitive session or admin state at risk.";
      }
      return "Weak cookie attributes reduce browser-side protection for sensitive session or admin state.";
    default:
      return `This ${context.cweName || finding.title} weakness can undermine the security boundary around the affected code path.`;
  }
}

function detectCategory(finding: RawFinding): FindingCategory {
  const metaCategory = stringField(metadataOf(finding), "category").toUpperCase().replace(/[\s-]+/g, "_");
  if (isCategory(metaCategory)) return metaCategory;
  const text = `${finding.title} ${finding.description} ${finding.ruleId || ""} ${finding.cweId || ""}`.toLowerCase();
  if (/cwe-352|csrf|cross-site request forgery/.test(text)) return "CSRF";
  if (/cwe-1004|cwe-614|cookie|httponly|same.?site/.test(text)) return "COOKIE_SECURITY";
  if (/cwe-78|command|exec|shell/.test(text)) return "COMMAND_INJECTION";
  if (/cwe-79|xss|innerhtml|html/.test(text)) return "XSS";
  if (/cwe-89|sql/.test(text)) return "SQL_INJECTION";
  if (/cwe-943|nosql|\$where|mongo/.test(text)) return "NOSQL_INJECTION";
  if (/cwe-918|ssrf|server.side.request/.test(text)) return "SSRF";
  if (/cwe-22|path traversal|directory traversal/.test(text)) return "PATH_TRAVERSAL";
  if (/cwe-601|open redirect|redirect/.test(text)) return "OPEN_REDIRECT";
  if (/cwe-502|deserialize|deserialization|pickle|unserialize/.test(text)) return "INSECURE_DESERIALIZATION";
  if (/cwe-611|xxe|xml external/.test(text)) return "XXE";
  if (/template injection|ssti/.test(text)) return "TEMPLATE_INJECTION";
  if (/cwe-1321|prototype pollution|__proto__/.test(text)) return "PROTOTYPE_POLLUTION";
  if (/crypto|md5|sha1|random|cwe-327|cwe-338/.test(text)) return "CRYPTO_WEAKNESS";
  if (/authz|authorization|access control|idor|cwe-862|cwe-863|cwe-639/.test(text)) return "AUTHZ_BYPASS";
  if (/authn|authentication|session|jwt/.test(text)) return "AUTHN_WEAKNESS";
  if (/upload|cwe-434/.test(text)) return "DANGEROUS_FILE_UPLOAD";
  if (/info disclosure|information disclosure|cwe-200/.test(text)) return "INFO_DISCLOSURE";
  if (/config|debug|cors|misconfiguration/.test(text)) return "INSECURE_CONFIG";
  if (/redos|regular expression|catastrophic/.test(text)) return "REDOS";
  if (/secret|credential|password|token|api key|cwe-798/.test(text)) return "HARDCODED_SECRET";
  return "GENERIC";
}

function isCategory(value: string): value is FindingCategory {
  return [
    "COMMAND_INJECTION", "XSS", "SQL_INJECTION", "NOSQL_INJECTION", "SSRF", "PATH_TRAVERSAL",
    "OPEN_REDIRECT", "INSECURE_DESERIALIZATION", "XXE", "TEMPLATE_INJECTION", "PROTOTYPE_POLLUTION",
    "CRYPTO_WEAKNESS", "AUTHZ_BYPASS", "AUTHN_WEAKNESS", "CSRF", "COOKIE_SECURITY", "DANGEROUS_FILE_UPLOAD", "INFO_DISCLOSURE",
    "INSECURE_CONFIG", "REDOS", "HARDCODED_SECRET", "GENERIC",
  ].includes(value);
}

function summaryTable(findings: RawFinding[]): string {
  const counts = new Map<SeverityLevel, number>();
  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as SeverityLevel[]) counts.set(severity, 0);
  for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) || 0) + 1);
  return [
    "| Severity | Count |",
    "| -------- | ----: |",
    `| Critical | ${String(counts.get("CRITICAL") || 0).padStart(5)} |`,
    `| High     | ${String(counts.get("HIGH") || 0).padStart(5)} |`,
    `| Medium   | ${String(counts.get("MEDIUM") || 0).padStart(5)} |`,
    `| Low      | ${String(counts.get("LOW") || 0).padStart(5)} |`,
    `| Info     | ${String(counts.get("INFO") || 0).padStart(5)} |`,
  ].join("\n");
}

function overallRisk(findings: RawFinding[]): string {
  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as SeverityLevel[]) {
    if (findings.some((finding) => finding.severity === severity)) return SEVERITY_LABELS[severity];
  }
  return "Informational";
}

function finalRiskSentence(findings: RawFinding[]): string {
  const risk = overallRisk(findings);
  if (risk === "Critical" || risk === "High") return "Fix the highest severity exploitable paths first, then rerun the scan.";
  if (risk === "Medium") return "Address the confirmed issues before release and add regression coverage.";
  return "Review informational findings and keep scanning future changes.";
}

function sourceRegexFor(category: FindingCategory): RegExp {
  if (category === "HARDCODED_SECRET") return /(?:secret|password|token|api[_-]?key)\s*[:=]/i;
  return /(?:req\.|request\.|\$_GET|\$_POST|params|query|body|args|getParameter|input)/i;
}

function sinkRegexFor(category: FindingCategory): RegExp {
  const map: Partial<Record<FindingCategory, RegExp>> = {
    COMMAND_INJECTION: /(?:exec|spawn|system|subprocess|shell_exec|passthru)/i,
    XSS: /(?:innerHTML|dangerouslySetInnerHTML|return\s+["'`].*<|render_template_string)/i,
    SQL_INJECTION: /(?:query|execute|raw|select|insert|update|delete)/i,
    SSRF: /(?:fetch|axios|requests\.|http\.get|curl)/i,
    PATH_TRAVERSAL: /(?:readFile|open|createReadStream|path\.join|file_get_contents)/i,
    OPEN_REDIRECT: /(?:redirect|location\.href|sendRedirect)/i,
  };
  return map[category] || /(?:exec|query|open|redirect|fetch|innerHTML|return)/i;
}

function sourceSinkEvidence(finding: RawFinding): string {
  const meta = metadataOf(finding);
  const evidence =
    stringField(meta, "sourceSinkEvidence") ||
    stringField(objectField(meta, "sastFlow"), "reachability") ||
    stringField(objectField(meta, "llmEvidence"), "sourceToSink");
  return evidence ? maskSecrets(evidence) : "";
}

function curlCommand(method: string, route: string, encodedParams?: string): string {
  const normalizedMethod = method.toUpperCase();
  const url = route.startsWith("/") ? route : `/${route}`;
  if (!encodedParams) return `curl -i -X ${normalizedMethod} "http://localhost${url}"`;
  if (normalizedMethod === "GET") {
    const separator = url.includes("?") ? "&" : "?";
    return `curl -i "http://localhost${url}${separator}${encodedParams}"`;
  }
  return `curl -i -X ${normalizedMethod} "http://localhost${url}" -H "Content-Type: application/x-www-form-urlencoded" --data "${encodedParams}"`;
}

function getAiReproductionSteps(finding: RawFinding): string[] {
  const metadata = metadataOf(finding);
  const report = objectField(metadata, "report");
  const hints = objectField(metadata, "reportHints");
  const sources = [report.stepsToReproduce, hints.stepsToReproduce];
  for (const source of sources) {
    if (!Array.isArray(source)) continue;
    const steps = source
      .filter((step): step is string => typeof step === "string")
      .map((step) => maskSecrets(step.trim()))
      .filter(Boolean)
      .filter((step) => !/localhost:3000\/example|fake endpoint|example endpoint/i.test(step));
    if (steps.length > 0) return steps;
  }
  const poc = stringField(report, "proofOfConcept") || stringField(hints, "proofOfConcept");
  if (poc && !/localhost:3000\/example/i.test(poc)) {
    return [
      "Use the scanner-provided AI reproduction note for this exact finding.",
      maskSecrets(poc),
      "Confirm the behavior only in an authorized test environment and preserve the result as evidence.",
    ];
  }
  return [];
}

function categorySentence(category: FindingCategory): string {
  return `The scanner identified a ${category.toLowerCase().replace(/_/g, " ")} issue in the cited code.`;
}

function cleanDescription(description: string): string {
  return description.replace(/\nRecommendation:[\s\S]*$/i, "").trim();
}

function rawLines(snippet: string): string[] {
  return snippet
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\d+:\s?/, ""))
    .filter((line) => line.trim().length > 0);
}

function metadataOf(finding?: RawFinding): Record<string, unknown> {
  return finding?.metadata && typeof finding.metadata === "object" ? finding.metadata : {};
}

function objectField(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const child = value[key];
  return child && typeof child === "object" && !Array.isArray(child) ? (child as Record<string, unknown>) : {};
}

function stringField(value: Record<string, unknown>, key: string): string {
  const raw = value[key];
  return typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : "";
}
