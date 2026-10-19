/**
 * Command steps shared by the Azure DevOps and GitLab review bots.
 */
import { prisma } from "@/lib/prisma";
import { buildFindingMarker, extractFindingMarkers } from "@/lib/github-pr-inline-format";
import { startRemediationRun } from "@/lib/remediation/start-run";

export async function setPrPaused(projectId: string, prNumber: number, paused: boolean, who: string): Promise<string> {
  await prisma.prReviewState.upsert({
    where: { projectId_prNumber: { projectId, prNumber } },
    create: { projectId, prNumber, paused, pausedBy: paused ? who : null },
    update: { paused, pausedBy: paused ? who : null },
  });
  return paused
    ? `Automatic reviews are paused on this PR (by ${who}). Comment \`@pepper resume\` to restart them.`
    : "Automatic reviews are back on for this PR.";
}

export async function isPrPaused(projectId: string, prNumber: number): Promise<boolean> {
  const row = await prisma.prReviewState.findUnique({ where: { projectId_prNumber: { projectId, prNumber } }, select: { paused: true } });
  return Boolean(row?.paused);
}

/**
 * `@pepper fix` under a Pepper inline comment (`firstBody` is that comment):
 * a remediation run for its finding, into the PR's branch. Returns the reply.
 */
export async function fixForInlineComment(
  project: { id: string; organizationId: string },
  prNumber: number,
  firstBody: string | null | undefined,
): Promise<string> {
  const marker = extractFindingMarkers(firstBody)[0];
  if (!marker) return "Reply `@pepper fix` in one of Pepper's inline threads to fix that finding.";
  const scan = await prisma.scan.findFirst({
    where: { projectId: project.id, prNumber, status: "COMPLETED" },
    orderBy: { completedAt: "desc" },
    select: { id: true, findings: { select: { id: true, title: true, description: true, severity: true, filePath: true, startLine: true, ruleId: true, cweId: true } } },
  });
  const finding = scan?.findings.find((f) => buildFindingMarker(f) === marker);
  if (!scan || !finding) return "That finding isn't in this PR's latest review any more. Comment `@pepper review` and try again.";
  const run = await startRemediationRun({ organizationId: project.organizationId, userId: null, scanId: scan.id, findingIds: [finding.id], via: "pr-comment" });
  if (!run.ok) return `Couldn't start a fix: ${run.error}`;
  const base = process.env.NEXTAUTH_URL?.replace(/\/+$/, "");
  return `Working on a fix${base ? ` ([follow it in Pepper](${base}/scans/${scan.id}))` : ""}. Its pull request into this PR's branch will appear here when it's ready.`;
}
