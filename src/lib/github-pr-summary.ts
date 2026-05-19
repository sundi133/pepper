/**
 * Pure helpers for building the Pepper PR summary comment. No I/O — kept
 * separate from github-pr-comment.ts so it can be unit-tested without
 * pulling in prisma / network modules.
 */

const MARKER_PREFIX = "<!-- pepper-pr-review:";
const MARKER_SUFFIX = " -->";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface PrSummaryInput {
  scanId: string;
  projectName: string;
  commitSha: string | null;
  branch: string | null;
  gateResult: "PENDING" | "PASSED" | "FAILED";
  counts: SeverityCounts;
  topFindings: Array<{
    severity: string;
    title: string;
    filePath: string | null;
    startLine: number | null;
    ruleId: string | null;
  }>;
  reviewUrl: string | null;
  status: "COMPLETED" | "FAILED";
  errorMessage?: string | null;
}

export function buildPrMarker(projectId: string): string {
  return `${MARKER_PREFIX}${projectId}${MARKER_SUFFIX}`;
}

export function findExistingCommentId(
  comments: Array<{ id: number; body?: string | null }>,
  marker: string,
): number | null {
  for (const c of comments) {
    if (typeof c.body === "string" && c.body.includes(marker)) {
      return c.id;
    }
  }
  return null;
}

function shortSha(sha: string | null): string {
  if (!sha) return "";
  return sha.slice(0, 7);
}

function totalIssues(counts: SeverityCounts): number {
  return (
    counts.critical + counts.high + counts.medium + counts.low + counts.info
  );
}

function escapeMd(s: string): string {
  return s.replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;"));
}

export function renderPrSummary(
  input: PrSummaryInput,
  marker: string,
): string {
  const lines: string[] = [];
  lines.push(marker);
  lines.push("## Security Review by Pepper");
  lines.push("");

  const sha = shortSha(input.commitSha);
  if (input.status === "FAILED") {
    lines.push(
      `Pepper could not complete the security scan${sha ? ` at commit \`${sha}\`` : ""}.`,
    );
    if (input.errorMessage) {
      lines.push("");
      lines.push("> " + input.errorMessage.replace(/\n/g, " ").slice(0, 400));
    }
    if (input.reviewUrl) {
      lines.push("");
      lines.push(`[Open scan details on Pepper](${input.reviewUrl})`);
    }
    return lines.join("\n");
  }

  const total = totalIssues(input.counts);
  if (total === 0) {
    lines.push(
      `No security findings detected${sha ? ` at commit \`${sha}\`` : ""}.`,
    );
  } else {
    lines.push(
      `Pepper scanned this pull request${sha ? ` at commit \`${sha}\`` : ""} and found **${total}** ${total === 1 ? "issue" : "issues"}.`,
    );
  }

  lines.push("");
  lines.push("### Summary");
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`| --- | ---: |`);
  lines.push(`| Critical | ${input.counts.critical} |`);
  lines.push(`| High | ${input.counts.high} |`);
  lines.push(`| Medium | ${input.counts.medium} |`);
  lines.push(`| Low | ${input.counts.low} |`);
  lines.push(`| Info | ${input.counts.info} |`);
  lines.push("");

  const gateLabel =
    input.gateResult === "PASSED"
      ? "Passed"
      : input.gateResult === "FAILED"
        ? "Failed"
        : "Not evaluated";
  lines.push(`**Build gate:** ${gateLabel}`);
  lines.push("");

  if (input.topFindings.length > 0) {
    lines.push("### Top findings");
    lines.push("");
    for (const f of input.topFindings) {
      const loc = f.filePath
        ? `\`${f.filePath}${f.startLine ? `:${f.startLine}` : ""}\``
        : "";
      const rule = f.ruleId ? ` _(${f.ruleId})_` : "";
      lines.push(
        `- **${f.severity}** — ${escapeMd(f.title)}${loc ? ` in ${loc}` : ""}${rule}`,
      );
    }
    lines.push("");
  }

  if (input.reviewUrl) {
    lines.push(`[Open full security review on Pepper](${input.reviewUrl})`);
  }

  lines.push("");
  lines.push(
    "<sub>Posted by Pepper SAST. Re-runs on every push update this comment.</sub>",
  );

  return lines.join("\n");
}
