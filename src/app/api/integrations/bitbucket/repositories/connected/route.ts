import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import {
  deriveRepoScanStatus,
  formatBranch,
  formatCoverage,
  formatLanguage,
} from "@/lib/github-repo-dashboard";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const projects = await prisma.project.findMany({
    where: {
      organizationId: orgId,
      connectedViaBitbucket: true,
    },
    include: {
      scans: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: {
          id: true,
          status: true,
          gateResult: true,
          branch: true,
          criticalCount: true,
          highCount: true,
          mediumCount: true,
          lowCount: true,
          infoCount: true,
          filesScanned: true,
          completedAt: true,
          createdAt: true,
        },
      },
    },
    orderBy: { updatedAt: "desc" },
  });

  const repositories = projects.map((p) => {
    const scan = p.scans[0];
    const findingsCount = scan
      ? scan.criticalCount +
        scan.highCount +
        scan.mediumCount +
        scan.lowCount +
        scan.infoCount
      : 0;
    const scanStatus = deriveRepoScanStatus(scan);

    return {
      projectId: p.id,
      name: p.bitbucketRepoSlug || p.name,
      workspace: p.bitbucketWorkspace || "—",
      fullName:
        p.bitbucketWorkspace && p.bitbucketRepoSlug
          ? `${p.bitbucketWorkspace}/${p.bitbucketRepoSlug}`
          : p.name,
      defaultBranch: formatBranch(p.defaultBranch),
      branch: formatBranch(scan?.branch ?? p.defaultBranch),
      language: formatLanguage(p.primaryLanguage),
      coverage: formatCoverage(scan),
      scanStatus,
      lastScanAt:
        scan?.completedAt?.toISOString() ??
        (scan?.status === "RUNNING" || scan?.status === "QUEUED"
          ? scan.createdAt.toISOString()
          : null),
      findingsCount,
      scanId: scan?.id ?? null,
      repoUrl: p.repoUrl,
    };
  });

  return NextResponse.json({ repositories });
}
