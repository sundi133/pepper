import * as assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildHtmlFindingsReport } from "../../html-report-builder";
import { buildScanMarkdownReport } from "../scan-markdown-report-builder";
import { generateFindingReport } from "../finding-report-generator";
import type { RawFinding } from "../../types";

function finding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    scanner: "SAST_PATTERN",
    severity: "HIGH",
    title: "User input reaches command execution",
    description: "User-controlled input is used to build a shell command.",
    filePath: "src/run.ts",
    startLine: 8,
    endLine: 8,
    snippet: "const cmd = req.body.cmd;\nexec(cmd);",
    ruleId: "CMD-001",
    cweId: "CWE-78",
    confidence: 0.9,
    metadata: { category: "COMMAND_INJECTION", language: "typescript" },
    ...overrides,
  };
}

describe("finding report generator", () => {
  it("individual finding markdown starts with a finding heading and not SAST result", () => {
    const markdown = generateFindingReport({ finding: finding() }).markdown;
    assert.match(markdown, /^### /);
    assert.doesNotMatch(markdown, /SAST result/i);
  });

  it("command injection report is command-specific", () => {
    const markdown = generateFindingReport({ finding: finding() }).markdown;
    assert.match(markdown, /shell command|shell parsing|argument arrays/i);
    assert.match(markdown, /### Steps to reproduce/);
    assert.match(markdown, /1\. Review `src\/run\.ts:8`|1\. Open the real affected route/);
    assert.match(markdown, /2\. Confirm/);
  });

  it("XSS report is XSS-specific", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "Reflected Cross-Site Scripting",
        description: "User input reaches HTML output.",
        filePath: "app/app.py",
        startLine: 6,
        endLine: 9,
        snippet:
          '@app.route("/hello")\ndef hello():\n    name = request.args.get("name", "")\n    return "<h1>Hello " + name + "</h1>"',
        cweId: "CWE-79",
        metadata: { category: "XSS", language: "python", framework: "Flask" },
      }),
    }).markdown;
    assert.match(markdown, /browser|HTML|autoescaping/i);
    assert.match(markdown, /\*\*Route:\*\* `\/hello`/);
    assert.match(markdown, /curl -i "http:\/\/localhost\/hello\?name=/);
  });

  it("uses actual HTTP method from metadata for curl reproduction", () => {
    const markdown = generateFindingReport({
      finding: finding({
        snippet: "const cmd = req.body.cmd;\nexec(cmd);",
        metadata: {
          category: "COMMAND_INJECTION",
          route: "/run",
          method: "POST",
        },
      }),
    }).markdown;
    assert.match(markdown, /HTTP method `POST`/);
    assert.match(markdown, /curl -i -X POST "http:\/\/localhost\/run"/);
    assert.doesNotMatch(markdown, /\/example/);
  });

  it("SQL injection report is SQLi-specific", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "SQL injection",
        description: "Request input reaches raw SQL.",
        snippet: "const id = req.query.id;\ndb.query('select * from users where id=' + id);",
        cweId: "CWE-89",
        metadata: { category: "SQL_INJECTION", language: "javascript" },
      }),
    }).markdown;
    assert.match(markdown, /parameterized queries|prepared statements|bound values/i);
  });

  it("SSRF report is SSRF-specific", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "Server-side request forgery",
        description: "User URL is fetched by the server.",
        snippet: "const url = req.query.url;\nawait fetch(url);",
        cweId: "CWE-918",
        metadata: { category: "SSRF", language: "typescript" },
      }),
    }).markdown;
    assert.match(markdown, /metadata|private|allowlist|DNS/i);
  });

  it("CSRF report is CSRF-specific and does not use secret guidance", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "Missing CSRF protection on state-changing endpoint",
        description:
          "State-changing operations should include CSRF token validation.",
        filePath: "app.js",
        startLine: 28,
        snippet: 'app.post("/note", (req, res) => {\n  save(req.body);\n});',
        cweId: "CWE-352",
        ruleId: "GEN-CSRF-001",
        metadata: { language: "javascript" },
      }),
    }).markdown;
    assert.match(markdown, /CSRF token|anti-CSRF|state-changing/i);
    assert.match(markdown, /curl -i -X POST "http:\/\/localhost\/note"/);
    assert.doesNotMatch(markdown, /secret manager|credential/i);
  });

  it("cookie report is cookie-specific and not rendered as XSS", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "Cookie without HttpOnly flag",
        description:
          "Cookies accessible via JavaScript are vulnerable to XSS-based session theft.",
        filePath: "bot.js",
        startLine: 19,
        snippet: 'await page.setCookie({\n  name: "admin",\n  value: "true",\n});',
        cweId: "CWE-1004",
        ruleId: "GEN-COOKIE-001",
        metadata: { language: "javascript" },
      }),
    }).markdown;
    assert.match(markdown, /HttpOnly|cookie creation/i);
    assert.match(markdown, /httpOnly: true|HttpOnly/);
    assert.doesNotMatch(markdown, /<img src=x onerror|autoescaping/i);
  });

  it("hardcoded secret report masks secret value", () => {
    const markdown = generateFindingReport({
      finding: finding({
        title: "Hardcoded API key",
        description: "Secret found.",
        snippet: 'const apiKey = "sk_live_1234567890abcdef";',
        cweId: "CWE-798",
        metadata: { category: "HARDCODED_SECRET" },
      }),
    }).markdown;
    assert.doesNotMatch(markdown, /1234567890abcdef/);
    assert.match(markdown, /\[MASKED_SECRET\]/);
  });

  it("unknown route and method are not invented", () => {
    const markdown = generateFindingReport({ finding: finding({ snippet: "exec(req.body.cmd);" }) }).markdown;
    assert.doesNotMatch(markdown, /\*\*Route:\*\*/);
    assert.doesNotMatch(markdown, /\bPOST\b|\/example/);
  });

  it("uses AI reproduction steps when present and safe", () => {
    const markdown = generateFindingReport({
      finding: finding({
        metadata: {
          category: "XSS",
          report: {
            stepsToReproduce: [
              "Open the scanned route from metadata.",
              "Submit the exact reflected field shown in evidence.",
            ],
          },
        },
      }),
    }).markdown;
    assert.match(markdown, /1\. Open the scanned route from metadata\./);
    assert.match(markdown, /2\. Submit the exact reflected field shown in evidence\./);
  });

  it("uses singular and plural line formatting", () => {
    assert.match(generateFindingReport({ finding: finding({ startLine: 8, endLine: 8 }) }).markdown, /\*\*Line:\*\* `8`/);
    assert.match(generateFindingReport({ finding: finding({ startLine: 6, endLine: 9 }) }).markdown, /\*\*Lines:\*\* `6-9`/);
  });

  it("includes actual file path, snippet, and optional CWE", () => {
    const markdown = generateFindingReport({ finding: finding() }).markdown;
    assert.match(markdown, /src\/run\.ts/);
    assert.match(markdown, /exec\(cmd\)/);
    assert.match(markdown, /CWE-78/);
    assert.doesNotMatch(generateFindingReport({ finding: finding({ cweId: undefined }) }).markdown, /\*\*CWE:\*\*/);
  });

  it("does not include noisy phrases", () => {
    const markdown = generateFindingReport({ finding: finding() }).markdown;
    for (const phrase of [
      "Advanced attack chain",
      "Chainability",
      "Privileges required",
      "Sensitive data exposure",
      "Authentication required",
      "User interaction required",
      "Privilege escalation potential",
      "Regression prevention",
    ]) {
      assert.doesNotMatch(markdown, new RegExp(phrase, "i"));
    }
  });

  it("HTML report escapes dynamic HTML safely", () => {
    const html = buildHtmlFindingsReport({
      scan: { id: "scan-1", scanType: "SAST" },
      project: { name: "<script>alert(1)</script>" },
      findings: [finding({ title: "<img src=x onerror=alert(1)>", snippet: "<script>alert(1)</script>" })],
    });
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  });

  it("Markdown full scan report uses the correct title", () => {
    const markdown = buildScanMarkdownReport({
      scan: { id: "scan-1", scanType: "SAST" },
      project: { name: "Pepper" },
      findings: [finding()],
    });
    assert.match(markdown, /^# SAST Findings Report/);
    assert.doesNotMatch(markdown, /# SAST result/i);
  });
});
