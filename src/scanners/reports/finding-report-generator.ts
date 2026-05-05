import type { RawFinding } from "@/scanners/types";

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
  vulnerabilityDescription: string[];
  weaknessClassification: Array<[string, string]>;
  expectedBehavior: string;
  actualBehavior: string;
  proofOfConceptPayload: string;
  scopeLimitations: string[];
  remediationGuidance: string[];
  references: string[];
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
  "CWE-532": "Insertion of Sensitive Information into Log File",
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
  const reportId = reportIdFor(input.scan?.id);
  const target = targetFor(finding, context, input.scan, input.project);
  const affectedField = affectedFieldOf(finding);
  const affectedComponent = affectedComponentOf(finding, context);
  const vulnerabilityDescription = vulnerabilityDescriptionFor(finding, summary);
  const weaknessClassification = weaknessClassificationFor(category, finding, context);
  const expectedBehavior = expectedBehaviorFor(category, finding);
  const actualBehavior = actualBehaviorFor(category, finding, summary);
  const proofOfConceptPayload = proofPayload(reproductionSteps, exploitExample);
  const scopeLimitations = scopeLimitationsFor(finding);
  const remediationGuidance = remediationGuidanceFor(betterFix, unsafeFixWarning, validationTest);
  const references = referencesFor(finding, context);

  const lines: string[] = [];
  lines.push("# Vulnerability Report");
  lines.push("");
  lines.push(title);
  lines.push("");
  lines.push(`${target} | ${reportId}`);
  lines.push("");
  lines.push("## Report Summary");
  lines.push("");
  lines.push(markdownTable([
    ["Report ID", reportId],
    ["Title", title],
    ["Target", target],
    ["Affected Field", affectedField],
    ["Affected Component", affectedComponent],
    ["Severity", severityLabel],
    ["Status", "Open"],
    ["Bounty Awarded", "Not applicable - internal SAST finding"],
    ["Reported", "Generated during scan"],
    ["Resolved", "Not resolved"],
    ["Reported By", "Votal AI SAST"],
    ["CVE ID", finding.cveId || "None assigned"],
  ]));
  lines.push("");
  lines.push("## Vulnerability Description");
  lines.push("");
  for (const paragraph of vulnerabilityDescription) {
    lines.push(paragraph);
    lines.push("");
  }
  lines.push("## Weakness Classification");
  lines.push("");
  lines.push(markdownTable(weaknessClassification));
  lines.push("");
  const location = formatFileAndLine(finding);
  const snippet = formatSnippet(finding, language);
  if (snippet) {
    lines.push("## Affected Code");
    lines.push("");
    if (location) lines.push(location);
    if (context.route) lines.push(`**Route:** \`${context.route}\``);
    lines.push("");
    lines.push(snippet);
    lines.push("");
  }
  lines.push("## Steps to Reproduce");
  lines.push("");
  lines.push("Prerequisites: Run the application in an authorized local or staging environment with test data and logs visible.");
  lines.push("");
  for (const [index, step] of reproductionSteps.entries()) {
    lines.push(`${index + 1}. **Step ${index + 1} —** ${step}`);
  }
  lines.push("");
  lines.push("## Expected Behaviour");
  lines.push("");
  lines.push(expectedBehavior);
  lines.push("");
  lines.push("## Actual Behaviour");
  lines.push("");
  lines.push(actualBehavior);
  lines.push("");
  lines.push("## Proof of Concept Payload");
  lines.push("");
  lines.push(`Payload used (${proofOfConceptPayload.length} bytes):`);
  lines.push("");
  lines.push("```");
  lines.push(proofOfConceptPayload);
  lines.push("```");
  lines.push("");
  lines.push(exploitExample);
  lines.push("");
  lines.push("## Impact");
  lines.push("");
  lines.push(`### ${impactHeadingFor(category, finding)}`);
  lines.push("");
  lines.push(impact);
  lines.push("");
  lines.push("### Scope Limitations");
  lines.push("");
  for (const limitation of scopeLimitations) {
    lines.push(`- ${limitation}`);
  }
  lines.push("");
  lines.push("## Remediation");
  lines.push("");
  lines.push("### Fix Applied by Application Team");
  lines.push("");
  lines.push(recommendedFix);
  lines.push("");
  lines.push("### General Remediation Guidance");
  lines.push("");
  for (const item of remediationGuidance) {
    lines.push(`- ${item}`);
  }
  lines.push("");
  lines.push("## Disclosure Timeline");
  lines.push("");
  lines.push(markdownTable([
    ["Date", "Event"],
    ["Scan generated", "Finding identified by Votal AI SAST during source-code analysis."],
    ["Pending", "Application team validates exploitability, applies remediation, and reruns the scan."],
  ]));
  lines.push("");
  lines.push("## References");
  lines.push("");
  for (const reference of references) {
    lines.push(`- ${reference}`);
  }

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
    vulnerabilityDescription,
    weaknessClassification,
    expectedBehavior,
    actualBehavior,
    proofOfConceptPayload,
    scopeLimitations,
    remediationGuidance,
    references,
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
    case "COMMAND_INJECTION": {
      const assignment = sourceDerivedFormAssignment(finding);
      if (assignment) {
        return `Use the source-derived input \`${assignment}\` only in an authorized test environment and verify whether it reaches command execution.`;
      }
      return "No standalone proof-of-concept payload was generated because the scanner did not identify a concrete attacker-controlled field. Use the source-grounded Steps to Reproduce and confirm the exact input before testing.";
    }
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
    case "INFO_DISCLOSURE":
      if (isSensitiveLoggingFinding(finding)) {
        return "Trigger the affected payment/account action with harmless test data, then verify the application log does not print full customer objects, tokens, email addresses, card metadata, or other PII.";
      }
      return "Exercise the affected endpoint or function and verify sensitive values are not exposed in responses, logs, exceptions, or client-visible output.";
    case "XXE":
      return "Use a harmless external-entity proof in a local test environment and verify the XML parser blocks DTD and external entity resolution before any file read or callback attempt.";
    case "PROTOTYPE_POLLUTION":
      return "Submit a safe object-key probe such as `{ \"__proto__\": { \"polluted\": \"yes\" } }` and verify it is rejected before any merge or assignment.";
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

  if (aiSteps.length > 0) {
    if (category === "COMMAND_INJECTION") {
      return appendConcreteCurlIfAvailable(aiSteps, finding, route, method);
    }
    if (category === "INFO_DISCLOSURE" && isSensitiveLoggingFinding(finding)) {
      return [
        ...aiSteps,
        ...sensitiveLoggingVerificationSteps(finding, location, route, method),
      ];
    }
    return aiSteps;
  }

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
    case "COMMAND_INJECTION": {
      const assignment = sourceDerivedFormAssignment(finding);
      return [
        inputStep,
        evidenceStep,
        route && method && assignment
          ? `Verify over HTTP with the source-derived request: \`${commandInjectionCurl(finding, method, route)}\`. Use only a sandbox or disposable environment.`
          : "Direct verification: call the handler/function with the exact attacker-controlled field shown in the source. Do not use a generic payload unless the source or AI evidence identifies the real field and execution path.",
        "The finding is reproduced if the application passes the probe into shell command construction instead of rejecting it or treating it as a literal argument.",
      ];
    }
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
    case "INFO_DISCLOSURE":
      if (isSensitiveLoggingFinding(finding)) {
        return sensitiveLoggingVerificationSteps(finding, location, route, method);
      }
      return [
        inputStep,
        evidenceStep,
        route && method
          ? `Send a safe request to the real route and inspect the response/logs: \`${curlCommand(method, route)}\`.`
          : `Run the handler or function shown in \`${location}\` with harmless test data.`,
        "The finding is reproduced if sensitive data is written to logs, errors, responses, or client-visible output.",
      ];
    case "XXE":
      return [
        inputStep,
        evidenceStep,
        "Confirm the XML input is attacker-controlled, such as a request body, uploaded XML file, webhook payload, or imported document.",
        "In a local test environment, send XML with a harmless external entity pointing to a controlled callback URL or a temporary local file you own.",
        "The finding is reproduced if the parser resolves the external entity or attempts the callback before rejecting DTD/external entity processing.",
      ];
    case "PROTOTYPE_POLLUTION":
      return [
        inputStep,
        evidenceStep,
        "Submit a safe object containing `{\"__proto__\":{\"polluted\":\"yes\"}}` or `{\"constructor\":{\"prototype\":{\"polluted\":\"yes\"}}}` to the affected endpoint/function.",
        "After processing, create a fresh empty object and check whether it unexpectedly contains the `polluted` property.",
        "The finding is reproduced if user-controlled keys modify `Object.prototype` or another shared prototype.",
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
      if (isSensitiveLoggingFinding(finding)) {
        return "Do not log raw payment/customer objects. Log only a stable non-sensitive identifier, such as the internal order id or the last 4 characters of a provider id, and redact email, card, token, and customer fields before logging.";
      }
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
    case "INFO_DISCLOSURE":
      if (isSensitiveLoggingFinding(finding)) {
        return "Anyone with access to application logs can view or retain sensitive customer/payment data longer than intended, increasing breach impact and compliance risk.";
      }
      return "Sensitive information can be exposed to users, logs, caches, or monitoring systems where it may be retained or accessed by unauthorized parties.";
    case "XXE":
      return "Successful exploitation can read local files, force server-side callbacks, or disclose internal network information through XML entity resolution.";
    case "PROTOTYPE_POLLUTION":
      return "Successful exploitation can alter shared object behavior, bypass authorization checks, or corrupt application state depending on how polluted properties are later used.";
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
  if (/info disclosure|information disclosure|cwe-200|cwe-532|sensitive.*log|log.*sensitive|pii.*log|customer.*log|stripe.*log/.test(text)) return "INFO_DISCLOSURE";
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

function reportIdFor(scanId?: string): string {
  return scanId ? `${scanId}-001` : "SAST-001";
}

function targetFor(
  finding: RawFinding,
  context: ReportContext,
  scan?: { sourceRef?: string | null },
  project?: { name?: string; repoUrl?: string | null },
): string {
  if (context.route) {
    return context.route.startsWith("http")
      ? context.route
      : `http://localhost${context.route.startsWith("/") ? context.route : `/${context.route}`}`;
  }
  return project?.repoUrl || scan?.sourceRef || project?.name || finding.filePath || "Source code scan";
}

function affectedFieldOf(finding: RawFinding): string {
  const metadata = metadataOf(finding);
  const fromMetadata =
    stringField(metadata, "affectedField") ||
    stringField(metadata, "parameter") ||
    stringField(metadata, "field");
  if (fromMetadata) return fromMetadata;
  const snippet = finding.snippet || "";
  const patterns = [
    /req\.(?:body|query|params)\.([A-Za-z0-9_]+)/,
    /request\.(?:GET|POST)\[['"]([^'"]+)['"]\]/,
    /request\.(?:args|form)\.get\(['"]([^'"]+)['"]/,
    /\$_(?:GET|POST|REQUEST)\[['"]([^'"]+)['"]\]/,
    /params\[['"]([^'"]+)['"]\]/,
  ];
  for (const pattern of patterns) {
    const match = snippet.match(pattern);
    if (match?.[1]) return match[1];
  }
  return "Derived from the cited source/sink evidence";
}

function affectedComponentOf(finding: RawFinding, context: ReportContext): string {
  const file = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : "Source code component";
  return context.route ? `${file} (${context.route})` : file;
}

function vulnerabilityDescriptionFor(finding: RawFinding, summary: string): string[] {
  const evidence = finding.filePath
    ? `The scanner identified the vulnerable code in ${finding.filePath}${finding.startLine ? ` at line ${finding.startLine}` : ""}.`
    : "The scanner identified the vulnerable code path in the uploaded source.";
  return [
    summary,
    `${evidence} The issue is reported from the source evidence available in the scan, including the affected snippet, scanner metadata, and weakness classification.`,
    "A tester can reproduce the behavior by reaching the affected input path with controlled test data and observing whether the unsafe sink executes before validation, encoding, authorization, or redaction is applied.",
  ];
}

function weaknessClassificationFor(
  category: FindingCategory,
  finding: RawFinding,
  context: ReportContext,
): Array<[string, string]> {
  const classification = classifyWeakness(category, finding);
  return [
    ["CWE", finding.cweId ? `${finding.cweId}${context.cweName ? `: ${context.cweName}` : ""}` : "Not mapped"],
    ["OWASP", context.owasp || "Not mapped"],
    ["Attack Vector", classification.attackVector],
    ["Attack Complexity", classification.attackComplexity],
    ["User Interaction", classification.userInteraction],
    ["Scope", classification.scope],
  ];
}

function classifyWeakness(
  category: FindingCategory,
  finding: RawFinding,
): {
  attackVector: string;
  attackComplexity: string;
  userInteraction: string;
  scope: string;
} {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  return {
    attackVector: category === "HARDCODED_SECRET" || /log|secret|credential/.test(text)
      ? "Local/source or log access"
      : "Network",
    attackComplexity: /race|toctou|business logic/.test(text) ? "High" : "Low",
    userInteraction: category === "XSS" || category === "CSRF" || /click|phishing|stored/.test(text)
      ? "Required"
      : "None",
    scope: ["XSS", "SSRF", "OPEN_REDIRECT", "PROTOTYPE_POLLUTION"].includes(category)
      ? "Changed"
      : "Unchanged",
  };
}

function expectedBehaviorFor(category: FindingCategory, finding: RawFinding): string {
  if (category === "INFO_DISCLOSURE" && isSensitiveLoggingFinding(finding)) {
    return "Sensitive objects and PII should be redacted before logging, with only non-sensitive identifiers retained.";
  }
  if (category === "XSS") return "User-controlled input should be encoded or sanitized so it is rendered as inert text.";
  if (category === "SQL_INJECTION") return "Database queries should use bound parameters or safe ORM APIs with static query structure.";
  if (category === "CSRF") return "State-changing requests should be rejected unless a valid CSRF protection mechanism is present.";
  if (category === "COMMAND_INJECTION") return "User input should never be passed to shell parsing; commands should use fixed executables and argument arrays.";
  return "The application should validate untrusted input before it reaches the sensitive operation.";
}

function actualBehaviorFor(category: FindingCategory, finding: RawFinding, summary: string): string {
  if (category === "INFO_DISCLOSURE" && isSensitiveLoggingFinding(finding)) {
    return "The cited code path can log sensitive objects or PII during normal application flow.";
  }
  if (category === "XSS") return "The cited code path can place user-controlled input into an executable HTML or browser context.";
  if (category === "SQL_INJECTION") return "The cited code path can construct database behavior from user-controlled input.";
  if (category === "COMMAND_INJECTION") return "The cited code path can pass user-controlled input into command execution.";
  return summary;
}

function proofPayload(steps: string[], exploitExample: string): string {
  for (const step of steps) {
    const code = step.match(/`([^`]*(?:curl|<|>|http:\/\/localhost|__proto__|\.\.\/|%27|%3C)[^`]*)`/i)?.[1];
    if (code) return code;
  }
  const code = exploitExample.match(/`([^`]+)`/)?.[1];
  return code || "No standalone payload was generated. Use the source-grounded Steps to Reproduce for verification.";
}

function impactHeadingFor(category: FindingCategory, finding: RawFinding): string {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  if (category === "XSS" || /html injection|cwe-80/.test(text)) return "Client-Side Content Injection";
  if (category === "INFO_DISCLOSURE" && isSensitiveLoggingFinding(finding)) return "Sensitive Data Exposure Through Logs";
  if (category === "COMMAND_INJECTION") return "Server-Side Command Execution Risk";
  if (category === "SQL_INJECTION" || category === "NOSQL_INJECTION") return "Data Access and Query Manipulation";
  if (category === "CSRF") return "Unauthorized State-Changing Action";
  if (category === "SSRF") return "Server-Side Network Access";
  if (category === "HARDCODED_SECRET") return "Credential Exposure";
  return "Security Boundary Weakness";
}

function scopeLimitationsFor(finding: RawFinding): string[] {
  return [
    "The report is based on static analysis of the uploaded source and scanner-provided evidence.",
    "Exploitability should be confirmed only in an authorized local, staging, or bug-bounty test environment.",
    finding.filePath
      ? `The confirmed scope is limited to ${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""} unless related call paths are identified.`
      : "The confirmed scope is limited to the cited finding evidence.",
  ];
}

function remediationGuidanceFor(
  betterFix: string | undefined,
  unsafeFixWarning: string | undefined,
  validationTest: string,
): string[] {
  return [
    betterFix || "Add regression coverage that proves the vulnerable path is blocked after the fix.",
    unsafeFixWarning || "Avoid partial fixes that only block one payload shape while leaving the underlying unsafe pattern in place.",
    validationTest,
  ];
}

function referencesFor(finding: RawFinding, context: ReportContext): string[] {
  const refs = new Set<string>();
  if (finding.cweId) {
    refs.add(`${finding.cweId}: https://cwe.mitre.org/data/definitions/${finding.cweId.replace(/CWE-/i, "")}.html`);
  }
  if (context.owasp) refs.add(`OWASP ${context.owasp}`);
  const metadataRefs = metadataOf(finding).references;
  if (Array.isArray(metadataRefs)) {
    for (const ref of metadataRefs) {
      if (typeof ref === "string" && ref.trim()) refs.add(ref.trim());
    }
  }
  return [...refs];
}

function markdownTable(rows: Array<[string, string]>): string {
  return [
    "| Field | Value |",
    "| --- | --- |",
    ...rows.map(([field, value]) => `| ${escapeMarkdownTableCell(field)} | ${escapeMarkdownTableCell(value)} |`),
  ].join("\n");
}

function escapeMarkdownTableCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
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

function commandInjectionCurl(
  finding: RawFinding,
  method: string,
  routeOrUrl: string,
): string {
  const assignment = sourceDerivedFormAssignment(finding);
  if (!assignment) {
    return "No source-derived curl command available";
  }
  return curlFormAssignment(method, routeOrUrl, assignment);
}

function curlFormAssignment(
  method: string,
  routeOrUrl: string,
  assignment: string,
): string {
  const normalizedMethod = method.toUpperCase();
  const url = routeOrUrl.startsWith("http")
    ? routeOrUrl
    : `http://localhost${routeOrUrl.startsWith("/") ? routeOrUrl : `/${routeOrUrl}`}`;
  if (normalizedMethod === "GET") {
    const separator = url.includes("?") ? "&" : "?";
    return `curl -i "${url}${separator}${encodeFormAssignment(assignment)}"`;
  }
  return `curl -i -X ${normalizedMethod} "${url}" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode ${quoteShellArg(assignment)}`;
}

function appendConcreteCurlIfAvailable(
  steps: string[],
  finding: RawFinding,
  route?: string,
  method?: string,
): string[] {
  if (steps.some((step) => /\bcurl\b/i.test(step))) return steps;
  const fromSteps = curlFromStepEvidence(steps);
  if (fromSteps) {
    return [
      ...steps,
      `Run this exact request to verify the finding: \`${fromSteps}\`.`,
    ];
  }
  if (route && method) {
    const assignment = sourceDerivedFormAssignment(finding);
    if (!assignment) return steps;
    return [
      ...steps,
      `Run this source-derived request to verify the finding: \`${commandInjectionCurl(finding, method, route)}\`.`,
    ];
  }
  return steps;
}

function curlFromStepEvidence(steps: string[]): string | undefined {
  const text = steps.join("\n");
  const method =
    text.match(/\b(GET|POST|PUT|PATCH|DELETE)\s+request\b/i)?.[1]?.toUpperCase() ||
    text.match(/\b-X\s+(GET|POST|PUT|PATCH|DELETE)\b/i)?.[1]?.toUpperCase();
  const url =
    text.match(/`(https?:\/\/[^`]+)`/)?.[1] ||
    text.match(/\b(https?:\/\/[^\s`"')]+)/)?.[1];
  const assignment =
    text.match(/form data\s+`([^`]+)`/i)?.[1] ||
    text.match(/(?:data|payload)\s+`([^`]+)`/i)?.[1];
  if (!method || !url || !assignment || !assignment.includes("=")) return undefined;
  return curlFormAssignment(method, url, assignment);
}

function sourceDerivedFormAssignment(finding: RawFinding): string | undefined {
  const text = `${finding.title}\n${finding.description}\n${finding.snippet || ""}`;
  const explicit =
    text.match(/\b(code)=/i)?.[1] ||
    text.match(/request\.form\.get\(["']([^"']+)["']/)?.[1] ||
    text.match(/request\.form\[['"]([^'"]+)['"]\]/)?.[1] ||
    text.match(/req\.body\.([A-Za-z0-9_]+)/)?.[1];
  const field = explicit || affectedFieldOf(finding);
  if (!field || /derived from/i.test(field)) return undefined;
  if (/python|subprocess|compile|exec|code/i.test(text) && /\bcode\b/i.test(field)) {
    return `${field}=import os; print(os.system('id'))`;
  }
  return undefined;
}

function encodeFormAssignment(assignment: string): string {
  const [key, ...rest] = assignment.split("=");
  return `${encodeURIComponent(key)}=${encodeURIComponent(rest.join("="))}`;
}

function quoteShellArg(value: string): string {
  return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}

function curlJsonCommand(
  method: string,
  route: string,
  body: Record<string, unknown>,
): string {
  const normalizedMethod = method.toUpperCase();
  const url = route.startsWith("/") ? route : `/${route}`;
  const json = JSON.stringify(body).replace(/'/g, "'\\''");
  return `curl -i -X ${normalizedMethod} "http://localhost${url}" -H "Content-Type: application/json" --data '${json}'`;
}

function sensitiveLoggingVerificationSteps(
  finding: RawFinding,
  location: string,
  route?: string,
  method?: string,
): string[] {
  const paymentBody = {
    save_card: true,
    payment_method: "pm_card_visa",
    email: "security-test@example.com",
  };
  const text = `${finding.title}\n${finding.description}\n${finding.snippet || ""}`;
  const isStripe = /stripe|customer|payment|card|checkout/i.test(text);

  if (route && method) {
    return [
      `Start the application locally with debug/application logs visible and use only Stripe/test payment data.`,
      isStripe
        ? `Trigger the real affected route with a safe test request: \`${curlJsonCommand(method, route, paymentBody)}\`. Adjust field names only if the source code shows different parameter names.`
        : `Trigger the real affected route with safe test data: \`${curlCommand(method, route)}\`.`,
      "Watch the application logs produced during that request.",
      "The finding is reproduced if logs contain full customer/payment objects, email, token, card metadata, or other PII instead of a redacted identifier.",
    ];
  }

  return [
    `Open \`${location}\` and identify the view/function that performs the sensitive action and writes to logs.`,
    "Find the real URL mapping for that view/function in the framework routing file, such as Django `urls.py`, Express route registration, or Rails routes.",
    isStripe
      ? `After the real route is known, send a safe local request shaped like: \`curl -i -X POST "http://localhost/<real-route>" -H "Content-Type: application/json" --data '${JSON.stringify(paymentBody)}'\`. Replace \`<real-route>\` and field names with the values from the source code.`
      : "Call the handler through the real route with harmless test data, or invoke the function directly in a local test.",
    "Watch application logs during the request/function call.",
    "The finding is reproduced if logs print full sensitive objects or PII. If only redacted IDs are logged, mark it as not exploitable.",
  ];
}

function isSensitiveLoggingFinding(finding: RawFinding): boolean {
  return /cwe-532|log|logger|console\.|pii|stripe|customer|payment|card|token|email/i.test(
    `${finding.title}\n${finding.description}\n${finding.cweId || ""}\n${finding.snippet || ""}`,
  );
}

function getAiReproductionSteps(finding: RawFinding): string[] {
  const metadata = metadataOf(finding);
  const report = objectField(metadata, "report");
  const hints = objectField(metadata, "reportHints");
  const sources = [
    metadata.reproductionHint,
    report.stepsToReproduce,
    hints.stepsToReproduce,
  ];
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
