import type { RawFinding } from "./types";
import { generateFindingReport } from "./reports/finding-report-generator";
import type { ProjectLike, ScanLike } from "./reports/scan-markdown-report-builder";

type HtmlScanLike = ScanLike & {
  startedAt?: Date | null;
  completedAt?: Date | null;
  filesScanned?: number;
  depsScanned?: number;
  gateResult?: string;
};

export function buildHtmlFindingsReport(input: {
  scan: HtmlScanLike;
  project: ProjectLike;
  findings: RawFinding[];
}): string {
  const findings = [...input.findings].sort(compareFindings);
  const content = findings.length
    ? findings.map((finding, index) => renderFindingReport(finding, index, input)).join("\n")
    : renderNoFindings(input);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vulnerability Report</title>
  <style>${css()}</style>
</head>
<body>
  <main class="report">
    ${content}
  </main>
</body>
</html>`;
}

function renderFindingReport(
  finding: RawFinding,
  index: number,
  input: {
    scan: HtmlScanLike;
    project: ProjectLike;
    findings: RawFinding[];
  },
): string {
  const report = generateFindingReport({
    finding,
    scan: input.scan,
    project: input.project,
    allFindings: input.findings,
  });
  const meta = metadataOf(finding);
  const reportId = `${input.scan.id || "SAST"}-${String(index + 1).padStart(3, "0")}`;
  const target = targetUrl(finding, input.scan, input.project);
  const affectedField = affectedFieldOf(finding);
  const affectedComponent = affectedComponentOf(finding);
  const status = statusOf(meta);
  const cwe = finding.cweId ? `${finding.cweId}${cweName(finding.cweId) ? ` - ${cweName(finding.cweId)}` : ""}` : "Not mapped";
  const owasp = stringField(meta, "owasp") || owaspFor(finding);
  const classification = classifyWeakness(finding);
  const payload = proofPayload(report.reproductionSteps, report.exploitExample);
  const description = vulnerabilityDescription(finding, report.summary);
  const scopeLimitations = scopeLimitationsFor(finding);
  const references = referencesFor(finding, owasp);

  return `
    <article class="vulnerability-report">
      <section class="title-block">
        <h1>Vulnerability Report</h1>
        <p class="subtitle">${escapeHtml(report.title)}</p>
        <p class="report-id">${escapeHtml(target)} &nbsp;|&nbsp; ${escapeHtml(reportId)}</p>
      </section>

      <section>
        <h2>Report Summary</h2>
        ${renderTable([
          ["Report ID", reportId],
          ["Title", report.title],
          ["Target URL", target],
          ["Affected Field", affectedField],
          ["Affected Component", affectedComponent],
          ["Severity", badge(report.severityLabel, severityClass(finding.severity))],
          ["Status", badge(status, statusClass(status))],
          ["Bounty Awarded", "Not applicable - internal SAST finding"],
          ["Reported", formatDate(input.scan.startedAt) || "Generated during scan"],
          ["Resolved", status.toLowerCase() === "resolved" || status.toLowerCase() === "fixed" ? formatDate(input.scan.completedAt) || "Marked resolved" : "Not resolved"],
          ["Reported By", "Votal AI SAST"],
          ["CVE ID", finding.cveId || "None assigned"],
        ])}
      </section>

      <section>
        <h2>Vulnerability Description</h2>
        ${description.map((paragraph) => `<p>${escapeHtml(paragraph)}</p>`).join("\n")}
      </section>

      <section>
        <h2>Weakness Classification</h2>
        ${renderTable([
          ["CWE", cwe],
          ["OWASP", owasp],
          ["Attack Vector", classification.attackVector],
          ["Attack Complexity", classification.attackComplexity],
          ["User Interaction", classification.userInteraction],
          ["Scope", classification.scope],
        ])}
      </section>

      <section>
        <h2>Steps to Reproduce</h2>
        <p class="prereq"><strong>Prerequisites:</strong> Run the application in an authorized local or staging environment with test data and logs visible.</p>
        <ol class="steps">
          ${report.reproductionSteps.map((step, stepIndex) => renderStep(step, stepIndex)).join("\n")}
        </ol>
      </section>

      <section>
        <h2>Expected vs Actual Behaviour</h2>
        <table class="comparison-table">
          <thead>
            <tr>
              <th class="expected-header">Expected Behaviour</th>
              <th class="actual-header">Actual Behaviour</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>${escapeHtml(expectedBehaviorFor(finding))}</td>
              <td>${escapeHtml(actualBehaviorFor(finding, report.summary))}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section>
        <h2>Proof of Concept Payload</h2>
        <p class="code-label">Exact verification payload</p>
        ${renderCodeBlock(payload)}
        <p>${escapeHtml(report.exploitExample)}</p>
      </section>

      <section>
        <h2>Impact</h2>
        <h3>${escapeHtml(impactHeadingFor(finding))}</h3>
        <p>${escapeHtml(report.impact)}</p>
        <h3>Scope Limitations</h3>
        <ul>
          ${scopeLimitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("\n")}
        </ul>
      </section>

      <section>
        <h2>Remediation</h2>
        <h3>Fix Applied by Application Team</h3>
        <p>${escapeHtml(report.recommendedFix)}</p>
        <h3>General Remediation Guidance</h3>
        <ul>
          ${remediationBullets(report).map((item) => `<li>${escapeHtml(item)}</li>`).join("\n")}
        </ul>
      </section>

      <section>
        <h2>Disclosure Timeline</h2>
        ${renderTable([
          ["Date", "Event"],
          [formatDate(input.scan.startedAt) || "Scan started", "Finding identified by Votal AI SAST during source-code analysis."],
          [formatDate(input.scan.completedAt) || "Scan completed", "Report artifact generated from confirmed scanner evidence."],
          ["Pending", "Application team validates exploitability, applies remediation, and reruns the scan."],
        ])}
      </section>

      <section>
        <h2>References</h2>
        <ul>
          ${references.map((reference) => `<li>${escapeHtml(reference)}</li>`).join("\n")}
        </ul>
      </section>
    </article>`;
}

function css(): string {
  return `
    @page{size:Letter;margin:1in}
    :root{--navy:#2C3E50;--ink:#1f2937;--muted:#667085;--line:#d7dee8;--row:#f6f8fb;--code-bg:#fff3f3;--payload:#b42318;--green:#1f7a4d;--actual:#c05621}
    *{box-sizing:border-box}
    body{margin:0;background:#eef2f7;color:var(--ink);font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.58}
    .report{max-width:8.5in;margin:0 auto;padding:28px 0}
    .vulnerability-report{background:#fff;margin:0 auto 28px;padding:1in;box-shadow:0 16px 50px rgba(44,62,80,.16);page-break-after:always}
    .vulnerability-report:last-child{page-break-after:auto}
    .title-block{text-align:center;border:2px solid var(--navy);padding:28px 22px;margin-bottom:32px}
    .eyebrow{margin:0 0 8px;color:var(--navy);font-size:12px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}
    h1{margin:0;color:var(--navy);font-size:30px;line-height:1.2;text-transform:uppercase}
    .subtitle{margin:12px 0 4px;color:#34495e;font-size:18px;font-weight:700}
    .report-id{margin:0;color:var(--muted);font-size:12px}
    h2{margin:28px 0 14px;padding-bottom:8px;border-bottom:3px solid var(--navy);color:var(--navy);font-size:20px;line-height:1.25}
    h3{margin:18px 0 8px;color:var(--navy);font-size:15px}
    p{margin:8px 0 12px}
    table{width:100%;margin:10px 0 22px;border-collapse:collapse;border:1px solid var(--line)}
    th,td{border:1px solid var(--line);padding:10px 12px;vertical-align:top}
    tr:nth-child(even) td{background:var(--row)}
    td:first-child{width:34%;font-weight:700;color:var(--navy)}
    .comparison-table th{color:#fff;text-align:left;font-size:14px}
    .comparison-table td:first-child{width:50%;font-weight:400;color:var(--ink)}
    .expected-header{background:var(--green)}
    .actual-header{background:var(--actual)}
    .badge{display:inline-block;border-radius:999px;padding:4px 10px;color:#fff;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
    .severity-critical{background:#7f1d1d}.severity-high{background:#b42318}.severity-medium{background:#c05621}.severity-low{background:#2f6fed}.severity-info{background:#516171}
    .status-open{background:#b42318}.status-triaged{background:#c05621}.status-fixed{background:#1f7a4d}.status-muted{background:#516171}
    .prereq{padding:10px 12px;border-left:4px solid var(--navy);background:#f7f9fc}
    .steps{padding-left:22px}.steps li{margin:10px 0}.step-label{font-weight:700;color:var(--navy)}
    .code-label{margin-bottom:6px;font-weight:700;color:var(--navy)}
    pre{margin:8px 0 14px;overflow:auto;border:1px solid #f2c2bd;background:var(--code-bg);padding:14px}
    pre code,code.payload{color:var(--payload);font-family:"Courier New",Courier,monospace;font-size:13px;white-space:pre-wrap;word-break:break-word}
    ul{margin:8px 0 16px;padding-left:22px}li{margin:6px 0}
    @media print{body{background:#fff}.report{max-width:none;padding:0}.vulnerability-report{margin:0;padding:0;box-shadow:none}table,pre,.title-block{break-inside:avoid}}
  `;
}

function renderNoFindings(input: { scan: ScanLike; project: ProjectLike }): string {
  return `
    <article class="vulnerability-report">
      <section class="title-block">
        <h1>Vulnerability Report</h1>
        <p class="subtitle">No confirmed findings</p>
        <p class="report-id">${escapeHtml(input.project.repoUrl || input.scan.sourceRef || input.project.name || "Source code scan")} &nbsp;|&nbsp; ${escapeHtml(input.scan.id || "SAST")}</p>
      </section>
      <section>
        <h2>Report Summary</h2>
        ${renderTable([
          ["Report ID", input.scan.id || "SAST"],
          ["Title", "No confirmed findings"],
          ["Target URL", input.project.repoUrl || input.scan.sourceRef || input.project.name || "Source code scan"],
          ["Affected Field", "None"],
          ["Affected Component", "None"],
          ["Severity", badge("Info", "severity-info")],
          ["Status", badge("Closed", "status-fixed")],
        ])}
      </section>
      <section><h2>Vulnerability Description</h2><p>No vulnerabilities were reported by the enabled scanners for this scan.</p></section>
    </article>`;
}

function renderTable(rows: Array<[string, string]>): string {
  return `<table><tbody>${rows
    .map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${value.startsWith("<span") ? value : escapeHtml(value)}</td></tr>`)
    .join("")}</tbody></table>`;
}

function renderStep(step: string, index: number): string {
  const parts = splitCodeFragments(step);
  return `<li><span class="step-label">Step ${index + 1} —</span> ${parts
    .map((part) => (part.code ? renderInlineCode(part.value) : escapeHtml(part.value)))
    .join("")}</li>`;
}

function renderCodeBlock(value: string): string {
  return `<pre><code>${escapeHtml(value)}</code></pre>`;
}

function renderInlineCode(value: string): string {
  return `<code class="payload">${escapeHtml(value)}</code>`;
}

function splitCodeFragments(value: string): Array<{ value: string; code: boolean }> {
  const parts: Array<{ value: string; code: boolean }> = [];
  const pattern = /`([^`]+)`/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value))) {
    if (match.index > lastIndex) parts.push({ value: value.slice(lastIndex, match.index), code: false });
    parts.push({ value: match[1], code: true });
    lastIndex = pattern.lastIndex;
  }
  if (lastIndex < value.length) parts.push({ value: value.slice(lastIndex), code: false });
  return parts.length ? parts : [{ value, code: false }];
}

function badge(label: string, className: string): string {
  return `<span class="badge ${className}">${escapeHtml(label)}</span>`;
}

function compareFindings(a: RawFinding, b: RawFinding): number {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  return (
    order.indexOf(a.severity) - order.indexOf(b.severity) ||
    (a.filePath || "").localeCompare(b.filePath || "") ||
    (a.startLine || 0) - (b.startLine || 0)
  );
}

function targetUrl(finding: RawFinding, scan: ScanLike, project: ProjectLike): string {
  const route = stringField(metadataOf(finding), "route") || extractRoute(finding.snippet || "");
  if (route) return route.startsWith("http") ? route : `http://localhost${route.startsWith("/") ? route : `/${route}`}`;
  return project.repoUrl || scan.sourceRef || project.name || "Source code scan";
}

function affectedFieldOf(finding: RawFinding): string {
  const meta = metadataOf(finding);
  const fromMeta = stringField(meta, "affectedField") || stringField(meta, "parameter") || stringField(meta, "field");
  if (fromMeta) return fromMeta;
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

function affectedComponentOf(finding: RawFinding): string {
  const route = stringField(metadataOf(finding), "route") || extractRoute(finding.snippet || "");
  const file = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : "Source code component";
  return route ? `${file} (${route})` : file;
}

function statusOf(meta: Record<string, unknown>): string {
  return stringField(meta, "status") || "Open";
}

function classifyWeakness(finding: RawFinding): {
  attackVector: string;
  attackComplexity: string;
  userInteraction: string;
  scope: string;
} {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  const isStoredOrCsrf = /stored|csrf|cross-site request forgery/.test(text);
  return {
    attackVector: /secret|hardcoded|log/.test(text) ? "Local/source or log access" : "Network",
    attackComplexity: /race|toctou|business logic/.test(text) ? "High" : "Low",
    userInteraction: /xss|csrf|click|phishing/.test(text) || isStoredOrCsrf ? "Required" : "None",
    scope: /xss|ssrf|redirect|prototype/.test(text) ? "Changed" : "Unchanged",
  };
}

function vulnerabilityDescription(finding: RawFinding, summary: string): string[] {
  const evidence = finding.filePath
    ? `The scanner identified the vulnerable code in ${finding.filePath}${finding.startLine ? ` at line ${finding.startLine}` : ""}.`
    : "The scanner identified the vulnerable code path in the uploaded source.";
  return [
    summary,
    `${evidence} The issue is reported only from the source evidence available in the scan, including the affected snippet, metadata, and scanner classification.`,
    "An attacker can reproduce the behavior by reaching the affected input path with controlled test data and observing whether the unsafe sink executes before validation, encoding, authorization, or redaction is applied.",
  ];
}

function expectedBehaviorFor(finding: RawFinding): string {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  if (/log|cwe-532/.test(text)) return "Sensitive objects and PII should be redacted before logging, with only non-sensitive identifiers retained.";
  if (/xss|cwe-79/.test(text)) return "User-controlled input should be encoded or sanitized so it is rendered as inert text.";
  if (/sql|cwe-89/.test(text)) return "Database queries should use bound parameters or safe ORM APIs with static query structure.";
  if (/csrf|cwe-352/.test(text)) return "State-changing requests should be rejected unless a valid CSRF protection mechanism is present.";
  return "The application should validate untrusted input before it reaches the sensitive operation.";
}

function actualBehaviorFor(finding: RawFinding, summary: string): string {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  if (/log|cwe-532/.test(text)) return "The cited code path can log sensitive objects or PII during normal application flow.";
  if (/xss|cwe-79/.test(text)) return "The cited code path can place user-controlled input into an executable HTML or browser context.";
  if (/sql|cwe-89/.test(text)) return "The cited code path can construct database behavior from user-controlled input.";
  return summary;
}

function proofPayload(steps: string[], exploitExample: string): string {
  for (const step of steps) {
    const code = step.match(/`([^`]*(?:curl|<|>|http:\/\/localhost|__proto__|\.\.\/)[^`]*)`/i)?.[1];
    if (code) return code;
  }
  const code = exploitExample.match(/`([^`]+)`/)?.[1];
  return code || exploitExample;
}

function scopeLimitationsFor(finding: RawFinding): string[] {
  return [
    "The report is based on static analysis of the uploaded source and scanner-provided evidence.",
    "Exploitability should be confirmed only in an authorized local, staging, or bug-bounty test environment.",
    finding.filePath ? `The confirmed scope is limited to ${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""} unless related call paths are identified.` : "The confirmed scope is limited to the cited finding evidence.",
  ];
}

function impactHeadingFor(finding: RawFinding): string {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  if (/xss|html injection|cwe-79|cwe-80/.test(text)) return "Client-Side Content Injection";
  if (/log|cwe-532|pii|customer|stripe/.test(text)) return "Sensitive Data Exposure Through Logs";
  if (/command|cwe-78/.test(text)) return "Server-Side Command Execution Risk";
  if (/sql|nosql|cwe-89|cwe-943/.test(text)) return "Data Access and Query Manipulation";
  if (/csrf|cwe-352/.test(text)) return "Unauthorized State-Changing Action";
  if (/ssrf|cwe-918/.test(text)) return "Server-Side Network Access";
  if (/secret|credential|cwe-798/.test(text)) return "Credential Exposure";
  return "Security Boundary Weakness";
}

function remediationBullets(report: ReturnType<typeof generateFindingReport>): string[] {
  return [
    report.betterFix || "Add regression coverage that proves the vulnerable path is blocked after the fix.",
    report.unsafeFixWarning || "Avoid partial fixes that only block one payload shape while leaving the underlying unsafe pattern in place.",
    report.validationTest,
  ];
}

function referencesFor(finding: RawFinding, owasp: string): string[] {
  const refs = new Set<string>();
  if (finding.cweId) {
    refs.add(`${finding.cweId}: https://cwe.mitre.org/data/definitions/${finding.cweId.replace(/CWE-/i, "")}.html`);
  }
  refs.add(`OWASP ${owasp}`);
  const metadataRefs = metadataOf(finding).references;
  if (Array.isArray(metadataRefs)) {
    for (const ref of metadataRefs) {
      if (typeof ref === "string" && ref.trim()) refs.add(ref.trim());
    }
  }
  return [...refs];
}

function formatDate(date?: Date | string | null): string | undefined {
  if (!date) return undefined;
  const parsed = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    year: "numeric",
  }).format(parsed);
}

function metadataOf(finding: RawFinding): Record<string, unknown> {
  return finding.metadata && typeof finding.metadata === "object" && !Array.isArray(finding.metadata)
    ? finding.metadata
    : {};
}

function stringField(value: Record<string, unknown>, key: string): string | undefined {
  const field = value[key];
  return typeof field === "string" && field.trim() ? field.trim() : undefined;
}

function extractRoute(snippet: string): string | undefined {
  const patterns = [
    /@app\.route\(["']([^"']+)["']/,
    /\.(?:get|post|put|patch|delete)\(["']([^"']+)["']/i,
    /path\(["']([^"']+)["']/,
    /Route::(?:get|post|put|patch|delete)\(["']([^"']+)["']/i,
  ];
  for (const pattern of patterns) {
    const match = snippet.match(pattern);
    if (match?.[1]) return match[1].startsWith("/") ? match[1] : `/${match[1]}`;
  }
  return undefined;
}

function owaspFor(finding: RawFinding): string {
  const text = `${finding.title} ${finding.description} ${finding.cweId || ""}`.toLowerCase();
  if (/xss|sql|command|injection|cwe-78|cwe-79|cwe-89|cwe-943/.test(text)) return "A03:2021 - Injection";
  if (/auth|idor|cwe-862|cwe-863|cwe-639/.test(text)) return "A01:2021 - Broken Access Control";
  if (/crypto|secret|credential|cwe-798|cwe-327/.test(text)) return "A02:2021 - Cryptographic Failures";
  if (/ssrf|cwe-918/.test(text)) return "A10:2021 - Server-Side Request Forgery";
  if (/config|debug|cookie|cwe-614|cwe-1004/.test(text)) return "A05:2021 - Security Misconfiguration";
  return "A06:2021 - Vulnerable and Outdated Components / Security Weakness";
}

function cweName(cweId: string): string | undefined {
  const names: Record<string, string> = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-532": "Sensitive Information in Log File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity",
    "CWE-798": "Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-943": "NoSQL Injection",
    "CWE-1004": "Cookie Without HttpOnly",
    "CWE-1321": "Prototype Pollution",
  };
  return names[cweId.toUpperCase()];
}

function severityClass(severity: string): string {
  return `severity-${severity.toLowerCase()}`;
}

function statusClass(status: string): string {
  const normalized = status.toLowerCase();
  if (/fixed|resolved|closed/.test(normalized)) return "status-fixed";
  if (/triage|review|accepted/.test(normalized)) return "status-triaged";
  if (/open|new/.test(normalized)) return "status-open";
  return "status-muted";
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
