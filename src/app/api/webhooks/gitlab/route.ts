import { NextRequest, NextResponse } from "next/server";
import { requireGitlabWebhookAuth } from "@/lib/webhook-secrets";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";

export async function POST(req: NextRequest) {
  const token = req.headers.get("x-gitlab-token");
  const authResult = await requireGitlabWebhookAuth(token);
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }

  const payload = await req.json();
  const eventType = payload.object_kind;

  if (
    eventType === "merge_request" &&
    ["open", "update"].includes(payload.object_attributes?.action)
  ) {
    const repoUrl = payload.project?.git_http_url;
    const branch = payload.object_attributes?.source_branch;
    const baseSha = payload.object_attributes?.last_commit?.id;
    const prNumber = payload.object_attributes?.iid;

    const gitlabProjectId: number | undefined =
      typeof payload.project?.id === "number" ? payload.project.id : undefined;
    const gitlabNamespace: string | undefined = payload.project?.path_with_namespace;

    const project = await prisma.project.findFirst({
      where: {
        repoUrl: { contains: payload.project?.path_with_namespace },
        ...(authResult.organizationId
          ? { organizationId: authResult.organizationId }
          : {}),
      },
      include: {
        buildGate: true,
        organization: { include: { settings: true } },
      },
    });

    if (!project) {
      return NextResponse.json({ message: "No matching project found" });
    }

    // Store the GitLab project ID so the PR bot can post MR notes
    if (gitlabProjectId && !project.gitlabProjectId) {
      await prisma.project.update({
        where: { id: project.id },
        data: { gitlabProjectId, gitlabNamespace: gitlabNamespace ?? null },
      });
    }

    const { removeAllScansForProject } = await import(
      "@/lib/remove-project-scans"
    );
    await removeAllScansForProject(project.id);

    const settings = project.organization.settings;

    const scan = await prisma.scan.create({
      data: {
        projectId: project.id,
        scanType: "INCREMENTAL",
        sourceType: "WEBHOOK",
        sourceRef: repoUrl,
        branch,
        commitSha: baseSha,
        prNumber,
        status: "QUEUED",
      },
    });

    const jobData: ScanJobData = {
      scanId: scan.id,
      projectId: project.id,
      sourceType: "GIT_CLONE",
      sourceRef: repoUrl,
      scanType: "INCREMENTAL",
      commitSha: baseSha,
      repoUrl,
      branch,
      orgSettings: buildOrgSettingsForJob(settings, project.organizationId),
      dastTargetUrl: project.dastTargetUrl || undefined,
      buildGate: project.buildGate
        ? {
            maxCritical: project.buildGate.maxCritical,
            maxHigh: project.buildGate.maxHigh,
            maxMedium: project.buildGate.maxMedium,
            maxLow: project.buildGate.maxLow,
            failOnNew: project.buildGate.failOnNew,
          }
        : undefined,
    };

    const job = await scanQueue.add("scan", jobData, { jobId: scan.id });

    await prisma.scan.update({
      where: { id: scan.id },
      data: { jobId: job.id },
    });

    return NextResponse.json({ scanId: scan.id, status: "QUEUED" });
  }

  return NextResponse.json({ message: "Event ignored" });
}
