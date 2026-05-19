import { describe, it, expect } from "vitest";
import {
  buildPrMarker,
  findExistingCommentId,
  renderPrSummary,
} from "./github-pr-summary";

describe("buildPrMarker", () => {
  it("embeds the project id between the marker fences", () => {
    const marker = buildPrMarker("proj_abc123");
    expect(marker).toBe("<!-- pepper-pr-review:proj_abc123 -->");
  });
});

describe("findExistingCommentId", () => {
  const marker = buildPrMarker("proj_x");

  it("returns the id of the comment containing the marker", () => {
    const id = findExistingCommentId(
      [
        { id: 1, body: "looks good!" },
        { id: 2, body: `${marker}\n## Security Review by Pepper` },
        { id: 3, body: "another comment" },
      ],
      marker,
    );
    expect(id).toBe(2);
  });

  it("returns null when no comment has the marker", () => {
    expect(
      findExistingCommentId(
        [
          { id: 1, body: "looks good!" },
          { id: 2, body: "other bot summary" },
        ],
        marker,
      ),
    ).toBeNull();
  });

  it("does not match a marker for a different project", () => {
    const other = buildPrMarker("proj_other");
    expect(
      findExistingCommentId([{ id: 7, body: other }], marker),
    ).toBeNull();
  });

  it("tolerates comments with null bodies", () => {
    expect(
      findExistingCommentId([{ id: 1, body: null }], marker),
    ).toBeNull();
  });
});

describe("renderPrSummary - completed scan", () => {
  const marker = buildPrMarker("proj_x");
  const base = {
    scanId: "scan_1",
    projectName: "demo",
    commitSha: "abcdef1234567890",
    branch: "feature/x",
    gateResult: "PASSED" as const,
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    topFindings: [],
    reviewUrl: "https://pepper.example.com/scans/scan_1",
    status: "COMPLETED" as const,
  };

  it("includes the marker at the top so the comment is updatable", () => {
    const body = renderPrSummary(base, marker);
    expect(body.startsWith(marker)).toBe(true);
  });

  it("reports a clean scan when there are no findings", () => {
    const body = renderPrSummary(base, marker);
    expect(body).toContain("No security findings detected");
    expect(body).toContain("`abcdef1`");
  });

  it("renders a severity table and the build gate result", () => {
    const body = renderPrSummary(
      {
        ...base,
        counts: { critical: 2, high: 5, medium: 3, low: 1, info: 0 },
        gateResult: "FAILED",
      },
      marker,
    );
    expect(body).toContain("| Critical | 2 |");
    expect(body).toContain("| High | 5 |");
    expect(body).toContain("**Build gate:** Failed");
    expect(body).toContain("found **11** issues");
  });

  it("singularizes the issue count when there is exactly one", () => {
    const body = renderPrSummary(
      {
        ...base,
        counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      },
      marker,
    );
    expect(body).toContain("found **1** issue.");
  });

  it("lists top findings with file path, line, and rule id", () => {
    const body = renderPrSummary(
      {
        ...base,
        counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        topFindings: [
          {
            severity: "CRITICAL",
            title: "SQL injection via user input",
            filePath: "src/api/users.ts",
            startLine: 42,
            ruleId: "sast/sql-injection",
          },
        ],
      },
      marker,
    );
    expect(body).toContain("**CRITICAL** — SQL injection via user input");
    expect(body).toContain("`src/api/users.ts:42`");
    expect(body).toContain("_(sast/sql-injection)_");
  });

  it("links to the Pepper review page", () => {
    const body = renderPrSummary(base, marker);
    expect(body).toContain(
      "[Open full security review on Pepper](https://pepper.example.com/scans/scan_1)",
    );
  });

  it("escapes angle brackets in finding titles to prevent HTML injection", () => {
    const body = renderPrSummary(
      {
        ...base,
        counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        topFindings: [
          {
            severity: "HIGH",
            title: "XSS via <script> tag",
            filePath: null,
            startLine: null,
            ruleId: null,
          },
        ],
      },
      marker,
    );
    expect(body).toContain("XSS via &lt;script&gt; tag");
    expect(body).not.toContain("<script>");
  });
});

describe("renderPrSummary - failed scan", () => {
  const marker = buildPrMarker("proj_x");

  it("explains the scan failed and includes the error message", () => {
    const body = renderPrSummary(
      {
        scanId: "scan_2",
        projectName: "demo",
        commitSha: "deadbeef",
        branch: "main",
        gateResult: "PENDING",
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        topFindings: [],
        reviewUrl: "https://pepper.example.com/scans/scan_2",
        status: "FAILED",
        errorMessage: "Clone failed: repository not found",
      },
      marker,
    );
    expect(body).toContain("Pepper could not complete the security scan");
    expect(body).toContain("Clone failed: repository not found");
    expect(body).toContain("[Open scan details on Pepper]");
  });

  it("does not render the severity table when the scan failed", () => {
    const body = renderPrSummary(
      {
        scanId: "scan_2",
        projectName: "demo",
        commitSha: null,
        branch: null,
        gateResult: "PENDING",
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        topFindings: [],
        reviewUrl: null,
        status: "FAILED",
        errorMessage: null,
      },
      marker,
    );
    expect(body).not.toContain("| Severity |");
    expect(body).not.toContain("Build gate");
  });
});
