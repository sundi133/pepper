import { isPatternBasedScanner } from "@/lib/constants";

export interface FindingReportInput {
  title: string;
  severity: string;
  description: string;
  scanner?: string;
  filePath?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  snippet?: string | null;
  ruleId?: string | null;
  cweId?: string | null;
  cveId?: string | null;
  confidence?: number | null;
  metadata?: unknown;
}

export interface StoredFindingReport {
  vulnerabilityName: string;
  summary: string;
  stepsToReproduce: string[];
  impact: string;
  remediation: string[];
}

const CURRENT_REPORT_VERSION = 9;

export function enrichFindingWithReport<T extends FindingReportInput>(
  finding: T,
): T {
  if (isPatternBasedScanner(finding.scanner)) {
    return finding;
  }

  const metadata = normalizeMetadata(finding.metadata);
  if (
    metadata.reportSections &&
    metadata.reportMarkdown &&
    metadata.reportVersion === CURRENT_REPORT_VERSION
  )
    return finding;

  const report = buildStoredFindingReport(finding);
  return {
    ...finding,
    metadata: {
      ...metadata,
      reportVersion: CURRENT_REPORT_VERSION,
      reportSections: report,
      reportMarkdown: renderReportMarkdown(report),
    },
  };
}

export function findingHasStoredReport(finding: FindingReportInput): boolean {
  const metadata = normalizeMetadata(finding.metadata);
  return Boolean(
    metadata.reportSections &&
      metadata.reportMarkdown &&
      metadata.reportVersion === CURRENT_REPORT_VERSION,
  );
}

export function buildStoredFindingReport(
  finding: FindingReportInput,
): StoredFindingReport {
  const metadata = normalizeMetadata(finding.metadata);
  const location = formatLocation(finding);
  const sink = readString(metadata.sink) || inferSink(finding);
  const parameter = readString(metadata.parameter) || inferParameter(finding);
  const route = readString(metadata.route, metadata.endpoint) || inferRoute(finding);
  const method = readString(metadata.method) || inferMethod(finding);
  const payload = safeMetadataPayload(metadata) || inferSafePayload(finding);
  const description = sanitizeReportText(
    readString(metadata.summary) || stripGeneratedSections(finding.description),
  );
  const metadataSteps = readStringArray(metadata.stepsToReproduce)
    .map(sanitizeReportText)
    .filter(isSafeReportText);
  const metadataRemediation = readStringArray(metadata.remediation)
    .map(sanitizeReportText)
    .filter(Boolean);
  const recommendation = extractRecommendation(finding.description);
  const structured = parseStructuredSummaryFields(finding.description);

  return {
    vulnerabilityName:
      readString(metadata.vulnerabilityName, metadata.accurateVulnerabilityName) ||
      buildVulnerabilityName(finding),
    summary: buildReportSummary({
      finding,
      location,
      parameter,
      sink,
      description,
      structured,
      metadata,
    }),
    stepsToReproduce:
      metadataSteps.length > 0
        ? metadataSteps
        : buildSteps({ finding, route, method, parameter, payload, sink, location }),
    impact: sanitizeReportText(readString(metadata.impact) || buildImpact(finding)),
    remediation:
      metadataRemediation.length > 0
        ? metadataRemediation
        : buildRemediation(finding, recommendation),
  };
}

/** Plain-text security report (no Markdown). */
export function renderReportPlainText(report: StoredFindingReport): string {
  const sections: string[] = [
    "Security Finding Report",
    "",
    "Bug / Vulnerability Name",
    "",
    stripReportMarkdown(report.vulnerabilityName),
    "",
    "Summary",
    "",
    stripReportMarkdown(report.summary),
  ];

  if (report.stepsToReproduce.length > 0) {
    sections.push(
      "",
      "Steps to Reproduce",
      ...report.stepsToReproduce.map((step) => stripReportMarkdown(step)),
    );
  }

  sections.push(
    "",
    "Impact",
    "",
    stripReportMarkdown(report.impact),
  );

  if (report.remediation.length > 0) {
    sections.push(
      "",
      "Remediation",
      ...report.remediation.map((step) => stripReportMarkdown(step)),
    );
  }

  return sections.join("\n").trim();
}

/** @deprecated Use renderReportPlainText — kept for stored metadata field name compatibility. */
export function renderReportMarkdown(report: StoredFindingReport): string {
  return renderReportPlainText(report);
}

/** Remove markdown markers (paired or stray) from report text. */
export function stripReportMarkdown(text: string): string {
  return text
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__(?!_)([^_]+)__/g, "$1")
    .replace(/\*([^*\n]+)\*/g, "$1")
    .replace(/_([^_\n]+)_/g, "$1")
    .replace(/\*\*/g, "")
    .replace(/__/g, "")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/```[\w-]*\n?([\s\S]*?)```/g, "$1")
    .replace(/^\s*#{1,6}\s+/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/^\s*\d+[\.)]\s+/gm, "")
    .trim();
}

function buildReportSummary(input: {
  finding: FindingReportInput;
  location: string;
  parameter?: string;
  sink?: string;
  description: string;
  structured: Record<string, string>;
  metadata: Record<string, unknown>;
}): string {
  const { finding, location, parameter, sink, description, structured, metadata } =
    input;
  const lead = buildSummaryLead({ finding, parameter, sink, location });
  const what =
    structured["What is wrong"] || inferWhatIsWrong(finding, location);
  const where = normalizeLocationDisplay(
    structured.Where || location || "",
  );
  const why =
    structured["Why it is exploitable"] ||
    readString(metadata.evidence, metadata.confidenceReason) ||
    description;
  const validation =
    structured["How to validate the fix"] || inferValidationSteps(finding);

  const body: string[] = [lead];
  if (what) body.push(`What is wrong: ${stripReportMarkdown(what)}`);
  if (where) body.push(`Where: ${stripReportMarkdown(where)}`);
  if (why && why !== what) {
    body.push(`Why it is exploitable: ${stripReportMarkdown(why)}`);
  }
  if (validation) {
    body.push(`How to validate the fix: ${stripReportMarkdown(validation)}`);
  }

  const consequence = buildConsequenceSentence(finding);
  if (consequence) body.push(consequence);

  const justification = readString(metadata.severityJustification);
  const llmLabel = readString(metadata.llmSeverity);
  const calibratedNote =
    metadata.severityCalibrated && llmLabel && llmLabel !== finding.severity
      ? ` (calibrated from ${llmLabel} using weakness class and CWE matrix)`
      : "";
  body.push(
    `Severity ${finding.severity}${calibratedNote}${justification ? `: ${justification}` : " based on the reachable impact and available evidence."}`,
  );

  return body.filter(Boolean).join("\n\n");
}

function inferWhatIsWrong(
  finding: FindingReportInput,
  location: string,
): string | undefined {
  const family = scannerFamily(finding);
  if (family === "secrets") {
    const credential = finding.title.includes(":")
      ? finding.title.split(":").slice(1).join(":").trim() || finding.title
      : finding.title;
    return `Exposed ${credential} in source code or configuration.`;
  }
  if (family === "sca") {
    return finding.title;
  }
  if (location) return finding.title;
  return undefined;
}

function inferValidationSteps(finding: FindingReportInput): string | undefined {
  switch (scannerFamily(finding)) {
    case "secrets":
      return "Rotate or revoke the credential and verify that it no longer appears in repository history scans.";
    case "sca":
      return "Upgrade the dependency, regenerate the lockfile, and confirm the vulnerable version is no longer resolved.";
    case "iac":
      return "Re-run IaC or policy scanning on the updated configuration before deployment.";
    default:
      return undefined;
  }
}

function parseStructuredSummaryFields(description: string): Record<string, string> {
  const labels = [
    "What is wrong",
    "Where",
    "Why it is exploitable",
    "Attack path",
    "Impact",
    "How to validate the fix",
    "Fix",
  ];
  const fields: Record<string, string> = {};
  for (const label of labels) {
    const value = extractLabeledSection(description, label);
    if (value) fields[label] = value;
  }
  return fields;
}

function buildSummaryLead(input: {
  finding: FindingReportInput;
  parameter?: string;
  sink?: string;
  location: string;
}): string {
  const { finding, parameter, sink, location } = input;
  const where = location ? ` in ${location}` : "";

  if (scannerFamily(finding) === "iac") {
    return location
      ? `Misconfiguration in infrastructure-as-code at ${location}.`
      : "Misconfiguration in infrastructure-as-code.";
  }

  if (scannerFamily(finding) === "zero-day") {
    return location
      ? `Potential business-logic or authorization issue at ${location}.`
      : "Potential business-logic or authorization issue in the reported code.";
  }

  switch (scannerFamily(finding)) {
    case "sca":
      return `A vulnerable dependency was identified${where}.`;
    case "secrets":
      return `A secret or credential-like value was identified${where}.`;
    default: {
      if (!parameter && !sink) {
        return location
          ? `Security finding at ${location}.`
          : "Security finding in the reported application code.";
      }
      return `${parameter ? `User-controlled input from ${parameter}` : "A user-controlled input source"} reaches ${sink || "the vulnerable operation"}${where}.`;
    }
  }
}

/** Client-safe summary opener (matches stored report lead logic). */
export function findingReportSummaryLead(finding: FindingReportInput): string {
  const metadata = normalizeMetadata(finding.metadata);
  const location = formatLocation(finding);
  const sink = readString(metadata.sink) || inferSink(finding);
  const parameter = readString(metadata.parameter) || inferParameter(finding);
  return buildSummaryLead({ finding, parameter, sink, location });
}

function buildSteps(input: {
  finding: FindingReportInput;
  route?: string;
  method: string;
  parameter?: string;
  payload: string;
  sink?: string;
  location: string;
}): string[] {
  const { route, method, parameter, payload, sink, location } = input;
  const family = scannerFamily(input.finding);

  if (family === "sca") {
    return [
      "Inspect the dependency manifest or lockfile in a safe local or test environment.",
      "Confirm the reported package name and version are present in the dependency graph.",
      "Compare the installed version with the advisory or fixed version from the scanner output.",
      location
        ? `Confirm the finding maps to ${location}.`
        : "Confirm the finding maps to the reported dependency evidence.",
    ];
  }

  if (family === "secrets") {
    return [
      "Inspect the reported file in a safe local or test environment.",
      "Confirm the scanner evidence contains a secret-like value or credential assignment.",
      "Verify whether the value is active only through the owning account, organization settings, or approved secret management system. Do not attempt to use the credential.",
      location
        ? `Confirm the finding maps to ${location}.`
        : "Confirm the finding maps to the reported source location.",
    ];
  }

  if (family === "iac") {
    const fp = input.finding.filePath || "the configuration file";
    const start = input.finding.startLine ?? 1;
    const end = Math.max(
      input.finding.endLine ?? start,
      start + 6,
    );
    const sedRange = `${start},${end}`;
    const loc =
      location || (input.finding.startLine != null ? `${fp}:${start}` : fp);
    return [
      `Open ${loc} in your editor and read a few lines above and below the reference so you see the full directive or block (for example COPY, ENV, a Kubernetes securityContext, or an ingress rule).`,
      `State the concrete risk in one plain sentence (what is exposed, overprivileged, or leaked if this ships as written).`,
      `From your repository root in a terminal, run sed -n '${sedRange}p' with that file path substituted (add quotes around the path if it contains spaces). This only prints lines; it does not modify files.`,
      `Change the configuration to match your security baseline, then re-run your usual IaC or pipeline check on this file to confirm the issue is gone.`,
    ];
  }

  if (family === "zero-day") {
    const fp = input.finding.filePath || "the affected source file";
    const start = input.finding.startLine ?? 1;
    const end = Math.max(input.finding.endLine ?? start, start + 8);
    const sedRange = `${start},${end}`;
    const loc =
      location || (input.finding.startLine != null ? `${fp}:${start}` : fp);
    const metadata = normalizeMetadata(input.finding.metadata);
    const attackVector = sanitizeReportText(
      readString(metadata.attackVector) ||
        extractLabeledSection(input.finding.description, "Attack Vector") ||
        "",
    );
    const printContext = `From the repository root in a terminal, run sed -n '${sedRange}p' with that file path substituted (add quotes around the path if it contains spaces). This only prints lines; it does not modify files.`;
    const base: string[] = [
      `Open ${loc} in your editor. Trace from the entry point (handler, resolver, job, or query) to where a trust boundary should apply (ownership, role, tenant, payment, or workflow state).`,
      `In one sentence, describe the gap: what check is missing or wrong compared to what the business rule should enforce?`,
      printContext,
    ];
    if (attackVector) {
      return [
        ...base,
        `Reviewer walkthrough (stay within visible code; do not invent URLs or fields): ${attackVector}`,
        `Validate only in an authorized local or staging app, or with a focused unit/integration test. If a route or parameter is not in the repository, document that gap instead of guessing a HTTP request.`,
      ];
    }
    return [
      ...base,
      `Follow imports and router wiring until you see where authentication, object-level authorization, or tenant filters should run — then confirm whether they actually run on this path.`,
      `Add or adjust a regression test that fails when the bug returns, rather than relying only on manual checks.`,
    ];
  }

  if (route && parameter) {
    return [
      "Start the application in a safe local or test environment.",
      `Send a ${method} request to the ${route} endpoint with a safe proof payload:\n\n${buildCurl(method, route, parameter, payload)}`,
      "Observe the response or server-side behavior for the fixed test output or controlled behavior.",
      location
        ? `Confirm that the vulnerable behavior maps to ${location}.`
        : "Confirm that the vulnerable behavior maps to the reported source location.",
    ];
  }

  if (parameter) {
    return [
      "The exact route could not be confirmed from the available evidence.",
      `Exercise the code path that reads ${parameter} in a safe local or test environment.`,
      `Provide this safe proof input: ${payload}.`,
      sink
        ? `Verify that ${parameter} reaches ${sink} without the expected security control.`
        : "Verify that the input reaches the vulnerable operation without the expected security control.",
      location
        ? `Confirm that the vulnerable behavior maps to ${location}.`
        : "Confirm that the vulnerable behavior maps to the reported source location.",
    ];
  }

  return [
    "The exact route and parameter could not be confirmed from the available evidence.",
    location
      ? `Review ${location} and execute the reachable application flow in a safe local or test environment.`
      : "Execute the reachable application flow in a safe local or test environment.",
    `Use this safe proof input when the relevant input source is reached: ${payload}.`,
    "The issue is reproduced if the input reaches the vulnerable operation without the expected security control.",
  ];
}

function buildCurl(
  method: string,
  route: string,
  parameter: string,
  payload: string,
): string {
  const url = route.startsWith("http") ? route : `http://127.0.0.1:5000${route}`;
  if (method === "GET") {
    const separator = url.includes("?") ? "&" : "?";
    return `curl "${url}${separator}${encodeURIComponent(parameter)}=${encodeURIComponent(payload)}"`;
  }
  return `curl -X ${method} ${url} \\\n  --data-urlencode ${JSON.stringify(`${parameter}=${payload}`)}`;
}

function buildVulnerabilityName(finding: FindingReportInput): string {
  const cwe = finding.cweId ? ` — ${finding.cweId}` : "";
  return finding.title.includes("—") || finding.title.includes(finding.cweId || "")
    ? finding.title
    : `${finding.title}${cwe}`;
}

function scannerFamily(
  finding: FindingReportInput,
): "sast" | "sca" | "secrets" | "iac" | "zero-day" {
  const scanner = finding.scanner || "";
  if (scanner === "SCA" || scanner === "MALICIOUS_PKG") return "sca";
  if (scanner.startsWith("SECRETS")) return "secrets";
  if (scanner === "IAC") return "iac";
  if (scanner === "ZERO_DAY") return "zero-day";
  return "sast";
}

function buildConsequenceSentence(finding: FindingReportInput): string {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  switch (scannerFamily(finding)) {
    case "sca":
      return "Exploitability depends on whether the vulnerable package and affected code path are reachable in this application.";
    case "secrets":
      return "Exposure risk remains until the value is confirmed inactive and rotated or revoked.";
    case "iac":
      return "The weakness can affect the deployed environment if this configuration is applied.";
    case "zero-day":
      return "The issue is based on code-flow evidence rather than a simple pattern match and should be validated against the reachable application path.";
  }

  if (/command|rce|remote code|exec|code execution/.test(text)) {
    return "Because the submitted input is executed by the server-side runtime, an attacker can run arbitrary application code. This can also be used to execute operating system commands through available runtime modules.";
  }
  if (/xss|cross-site/.test(text)) {
    return "Because the user-controlled value is rendered without the correct output encoding, an attacker can execute script in another user's browser.";
  }
  if (/idor|access|authorization|privilege/.test(text)) {
    return "Because the resource access is not tied to the authenticated principal or tenant, an attacker can reach data or actions outside their authorization boundary.";
  }
  return "Based on the available evidence, the vulnerable behavior can affect the confidentiality, integrity, or availability of the application.";
}

function buildImpact(finding: FindingReportInput): string {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  switch (scannerFamily(finding)) {
    case "sca":
      return "A vulnerable dependency can expose the application to known attacks when the affected package and code path are reachable. Impact depends on the advisory class and how the package is used.";
    case "secrets": {
      const credential = finding.title.split(":")[0]?.trim();
      if (/github/i.test(`${finding.title} ${text}`)) {
        return "A leaked GitHub Personal Access Token can grant an attacker access to the associated GitHub account and repositories. Depending on token permissions, this may allow the attacker to read or modify code, manage issues, access private repositories, trigger workflows, or inject malicious code.";
      }
      if (credential) {
        return `An exposed ${credential} can allow unauthorized access to internal systems, cloud services, third-party APIs, or user data until the value is revoked and rotated.`;
      }
      return "An exposed secret can allow unauthorized access to internal systems, cloud services, third-party APIs, or user data until the value is revoked and rotated.";
    }
    case "iac":
      return "A misconfigured infrastructure, container, or CI/CD control can weaken the deployed environment and affect confidentiality, integrity, or availability.";
    case "zero-day":
      return "A reachable logic or authorization flaw can allow unauthorized business actions, cross-user or cross-tenant access, or bypass of intended workflow controls.";
  }

  if (/command|rce|remote code|exec|code execution/.test(text)) {
    return `An attacker may cause the server to run unintended code or commands.

Successful exploitation can allow an attacker to:

- Execute arbitrary application-language code
- Execute operating system commands through exposed runtime APIs
- Access application secrets or environment variables
- Modify application state or files accessible to the process
- Disrupt service availability
- Pivot further within the runtime environment`;
  }
  if (/idor|access|authorization|privilege/.test(text)) {
    return "An attacker may access or modify data that belongs to another user, tenant, or role. This can cause data exposure, privilege escalation, and unauthorized business actions.";
  }
  if (/secret|credential|token|password|key/.test(text)) {
    return "Exposed credentials may allow attackers to access internal systems, cloud services, third-party APIs, or user data until the credential is revoked and rotated.";
  }
  return stripGeneratedSections(finding.description);
}

function buildRemediation(
  finding: FindingReportInput,
  recommendation?: string,
): string[] {
  if (recommendation) return [sanitizeReportText(recommendation)];
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  switch (scannerFamily(finding)) {
    case "sca": {
      const metadata = normalizeMetadata(finding.metadata);
      const fixVersion = readString(metadata.fixVersion);
      return [
        fixVersion
          ? `Upgrade the affected dependency to version ${fixVersion} or later.`
          : "Upgrade the affected dependency to a patched version or remove it if it is not required.",
        "Regenerate and commit the lockfile so builds resolve to the patched dependency.",
        "Review whether the vulnerable package API is reachable in application code.",
      ];
    }
    case "secrets":
      return [
        "Remove the secret from source code and replace it with a secret manager or environment-specific configuration.",
        "Revoke or rotate the exposed value before considering the issue resolved.",
        "Purge the value from Git history if it was committed.",
        "Add secret scanning to pre-commit hooks and CI to prevent recurrence.",
      ];
    case "iac":
      return [
        "Update the affected configuration to enforce the intended security control.",
        "Apply least privilege for identities, networks, containers, and CI/CD jobs.",
        "Validate the fixed configuration with IaC/security policy scanning before deployment.",
      ];
    case "zero-day":
      return [
        "Enforce the missing authorization, state, tenant, or workflow control server-side.",
        "Centralize the control so related code paths cannot bypass it.",
        "Add regression tests for authorized, unauthorized, and edge-case flows.",
      ];
  }

  if (/command|rce|remote code|exec|code execution/.test(text)) {
    return [
      "Do not execute user-provided code or commands directly on the server.",
      "Replace dynamic execution with a limited parser/interpreter or a fixed allowlist of supported operations.",
      "If code execution is required, run it in a dedicated disposable sandbox with no host filesystem mounts, no network access, a non-root user, CPU/memory limits, a short timeout, and a read-only filesystem where possible.",
      "Add regression tests that submit the safe proof payload and verify no unintended command or code execution occurs.",
      "Do not rely on blocklists for dangerous strings because they are usually bypassable.",
    ];
  }
  return [
    "Validate and sanitize the exact input source before it reaches the vulnerable operation.",
    "Add the missing server-side security control in the affected file.",
    "Add automated tests that cover the reproduction path and fail if the vulnerability reappears.",
  ];
}

function inferSink(finding: FindingReportInput): string | undefined {
  const family = scannerFamily(finding);
  if (family === "sca") return "dependency resolution";
  if (family === "secrets") return "source-controlled secret";
  if (family === "iac") return "deployed configuration";

  const text = `${finding.title}\n${finding.description}\n${finding.snippet || ""}`;
  const sink = text.match(
    /\b(subprocess\.check_output|subprocess\.run|os\.system|exec|eval|spawn|popen|child_process\.(?:exec|spawn|execFile)|dangerouslySetInnerHTML|innerHTML|raw|execute|query)\b/i,
  )?.[1];
  if (sink) return sink;
  if (/subprocess|os\.system|exec|spawn|popen|check_output/i.test(text)) {
    return "server-side code execution";
  }
  if (/render_template|innerHTML|dangerouslySetInnerHTML|template|html/i.test(text)) {
    return "HTML rendering";
  }
  if (/execute|query|SELECT|INSERT|UPDATE|DELETE/i.test(text)) {
    return "database query execution";
  }
  return undefined;
}

function inferParameter(finding: FindingReportInput): string | undefined {
  const text = `${finding.description}\n${finding.snippet || ""}`;
  const patterns = [
    /request\.form(?:\.get)?\(\s*['"]([^'"]+)['"]/i,
    /request\.args\.get\(\s*['"]([^'"]+)['"]/i,
    /req\.body\.([A-Za-z0-9_]+)/i,
    /req\.query\.([A-Za-z0-9_]+)/i,
    /parameter\s+['"`]([A-Za-z0-9_-]+)['"`]/i,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) return match[1];
  }
  if (/user[- ]provided (?:python )?code|submitted (?:python )?code|code from the user/i.test(text)) {
    return "code";
  }
  return undefined;
}

function inferRoute(finding: FindingReportInput): string | undefined {
  const text = `${finding.description}\n${finding.snippet || ""}`;
  const explicitRoute = text.match(
    /\b(?:GET|POST|PUT|PATCH|DELETE)\s+((?:\/|https?:\/\/)[^\s`'")]+)/i,
  )?.[1];
  if (explicitRoute) return explicitRoute;
  return text.match(/@(?:app|router)\.route\(\s*['"]([^'"]+)['"]/)?.[1];
}

function inferMethod(finding: FindingReportInput): string {
  const text = `${finding.description}\n${finding.snippet || ""}`;
  const method = text.match(
    /\b(GET|POST|PUT|PATCH|DELETE)\s+(?:\/|https?:\/\/)/i,
  )?.[1];
  if (method) return method.toUpperCase();
  const flaskMethod = text.match(/methods\s*=\s*\[[^\]]*['"](GET|POST|PUT|PATCH|DELETE)['"]/i)
    ?.[1];
  if (flaskMethod) return flaskMethod.toUpperCase();
  if (/request\.form|req\.body|post\(/i.test(text)) return "POST";
  return "GET";
}

function inferSafePayload(finding: FindingReportInput): string {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  if (/command|rce|remote code|exec|code execution/.test(text)) {
    return `print("SAST_SAFE_EXECUTION_TEST")`;
  }
  if (/xss|cross-site/.test(text)) return `<b>SAST_SAFE_TEST</b>`;
  if (/sql/.test(text)) return `SAST_SAFE_TEST`;
  return "SAST_SAFE_TEST";
}

function safeMetadataPayload(metadata: Record<string, unknown>): string | undefined {
  const payload = readString(metadata.payload, metadata.poc);
  return payload && isSafeReportText(payload) && !looksLikeCodeApi(payload)
    ? payload
    : undefined;
}

function formatLocation(finding: FindingReportInput): string {
  if (!finding.filePath) return "";
  if (!finding.startLine) return finding.filePath;
  const end = finding.endLine ?? finding.startLine;
  if (end !== finding.startLine) {
    return normalizeLocationDisplay(
      `${finding.filePath}:${finding.startLine}-${end}`,
    );
  }
  return `${finding.filePath}:${finding.startLine}`;
}

/** Collapse redundant single-line ranges like path:6-6 → path:6. */
function normalizeLocationDisplay(location: string): string {
  return stripReportMarkdown(location).replace(/:(\d+)-\1\b/g, ":$1");
}

function extractRecommendation(description: string): string | undefined {
  return extractLabeledSection(description, "Recommendation");
}

function extractLabeledSection(
  description: string,
  label: string,
): string | undefined {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const stopLabels =
    "What is wrong|Where|Why it is exploitable|Attack path|Impact|Steps to reproduce safely|Fix|How to validate the fix|Attack Vector|Category|Recommendation|Code evidence";
  const raw = description
    .match(
      new RegExp(
        `(?:\\n|^)(?:\\*\\*)?${escaped}(?:\\*\\*)?:\\s*([\\s\\S]*?)(?=\\n(?:\\*\\*)?(?:${stopLabels}):|$)`,
        "i",
      ),
    )?.[1]
    ?.trim();
  return raw ? stripReportMarkdown(raw) : undefined;
}

function stripGeneratedSections(description: string): string {
  return sanitizeReportText(
    description
      .split(/\nCode evidence:\s*/i)[0]
      .split(/\nRecommendation:\s*/i)[0]
      .split(/\nAttack Vector:\s*/i)[0]
      .split(/\nExample Request:\s*/i)[0]
      .split(/\nCategory:\s*/i)[0]
      .trim(),
  );
}

function sanitizeReportText(text: string): string {
  return stripReportMarkdown(
    text
      .split(/(?<=[.!?])\s+/)
      .filter(isSafeReportText)
      .join(" ")
      .replace(/\bcat\s+\/etc\/passwd\b/gi, "print a fixed test string")
      .replace(/\brm\s+-rf\s+\/\b/gi, "print a fixed test string"),
  );
}

function isSafeReportText(text: string): boolean {
  return !/(rm\s+-rf|\/etc\/passwd|\/etc\/shadow|reverse shell|nc\s+-e|bash\s+-i|curl\s+[^|]*\|\s*sh|wget\s+[^|]*\|\s*sh)/i.test(
    text,
  );
}

function looksLikeCodeApi(value: string): boolean {
  return /^(subprocess\.check_output|subprocess\.run|os\.system|exec|eval|spawn|popen|open|readFile|writeFile)$/i.test(
    value.trim(),
  );
}

function normalizeMetadata(metadata: unknown): Record<string, unknown> {
  return metadata && typeof metadata === "object" && !Array.isArray(metadata)
    ? (metadata as Record<string, unknown>)
    : {};
}

function readString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}
