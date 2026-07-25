import { describe, expect, it } from "vitest";
import {
  buildStoredFindingReport,
  renderReportPlainText,
  stripReportMarkdown,
} from "./finding-report";

describe("stripReportMarkdown", () => {
  it("removes stray asterisks from partial bold markers", () => {
    expect(stripReportMarkdown("** Exposed GitHub in source/config")).toBe(
      "Exposed GitHub in source/config",
    );
    expect(stripReportMarkdown("** secret.js:6-6")).toBe("secret.js:6-6");
  });

  it("unwraps asterisk emphasis", () => {
    expect(stripReportMarkdown("**bold** and *italic*")).toBe("bold and italic");
  });

  it("unwraps underscore emphasis at word boundaries", () => {
    expect(stripReportMarkdown("this is _emphasised_ text")).toBe(
      "this is emphasised text",
    );
    expect(stripReportMarkdown("_leading_ word")).toBe("leading word");
  });

  // Findings must name identifiers exactly; stripping underscores produced
  // names that do not exist and made remediation advice wrong.
  it("preserves environment variable names", () => {
    expect(
      stripReportMarkdown("Set TRIVY_CACHE_DIR and VULN_DB_MODE=offline"),
    ).toBe("Set TRIVY_CACHE_DIR and VULN_DB_MODE=offline");
  });

  it("preserves snake_case identifiers", () => {
    expect(stripReportMarkdown("call snake_case_name here")).toBe(
      "call snake_case_name here",
    );
    expect(stripReportMarkdown("use os_system() not os.system")).toBe(
      "use os_system() not os.system",
    );
  });

  it("preserves Python dunder names", () => {
    expect(stripReportMarkdown("Python __init__ and __name__ methods")).toBe(
      "Python __init__ and __name__ methods",
    );
  });

  it("preserves leading and trailing underscore identifiers", () => {
    expect(stripReportMarkdown("the _private field")).toBe("the _private field");
    expect(stripReportMarkdown("column user_id_ here")).toBe(
      "column user_id_ here",
    );
  });

  it("still strips backticks and headings", () => {
    expect(stripReportMarkdown("use `foo_bar()` now")).toBe("use foo_bar() now");
    expect(stripReportMarkdown("## Heading")).toBe("Heading");
  });
});

describe("renderReportPlainText", () => {
  it("renders plain-text sections without markdown", () => {
    const finding = {
      scanner: "SECRETS_LLM",
      severity: "CRITICAL",
      title: "GitHub: GitHub Personal Access Token",
      description: [
        "What is wrong: Exposed GitHub Personal Access Token in source code or configuration.",
        "Where: secret.js:6",
        "Why it is exploitable: The value matches a GitHub PAT pattern.",
        "How to validate the fix: Rotate or revoke the credential and verify that it no longer appears in repository history scans.",
      ].join("\n\n"),
      filePath: "secret.js",
      startLine: 6,
      cweId: "CWE-798",
    };

    const report = buildStoredFindingReport(finding);
    const text = renderReportPlainText(report);

    expect(text).toMatch(/^Security Finding Report/);
    expect(text).toContain("Bug / Vulnerability Name");
    expect(text).toContain("Summary");
    expect(text).toContain("What is wrong:");
    expect(text).toContain("Where: secret.js:6");
    expect(text).toContain("Impact");
    expect(text).toContain("Remediation");
    expect(text).not.toMatch(/^## /m);
    expect(text).not.toContain("---");
    expect(text).not.toContain("**");
  });

  it("strips markdown from legacy descriptions with partial bold", () => {
    const finding = {
      scanner: "SECRETS_LLM",
      severity: "CRITICAL",
      title: "GitHub: GitHub Personal Access Token",
      description: [
        "**What is wrong:** ** Exposed GitHub in source/config",
        "**Where:** ** secret.js:6",
        "**Why it is exploitable:** ** Token pattern match.",
        "**How to validate the fix:** ** Rotate credential and verify it no longer appears in repo history scans",
      ].join("\n\n"),
      filePath: "secret.js",
      startLine: 6,
      cweId: "CWE-798",
    };

    const text = renderReportPlainText(buildStoredFindingReport(finding));
    expect(text).not.toContain("**");
    expect(text).toContain("What is wrong: Exposed");
    expect(text).toContain("Where: secret.js:6");
  });
});
