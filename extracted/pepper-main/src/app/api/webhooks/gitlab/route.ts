import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";

export async function POST(req: NextRequest) {
  const token = req.headers.get("x-gitlab-token");
  const webhookSecret = process.env.GITLAB_WEBHOOK_SECRET;

  if (webhookSecret && token !== webhookSecret) {
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

    const project = await prisma.project.findFirst({
      where: { repoUrl: { contains: payload.project?.path_with_namespace } },
      include: {
        buildGate: true,
        organization: { include: { settings: true } },
      },
    });

    if (!project) {
      return NextResponse.json({ message: "No matching project found" });
    }

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
      orgSettings: {
        llmProvider: settings?.llmProvider || "openai",
        llmBaseUrl: settings?.llmBaseUrl || "https://api.openai.com/v1",
        llmModel: settings?.llmModel || "gpt-4o-mini",
        llmApiKey: settings?.llmApiKey || undefined,
        enableLlmSast: settings?.enableLlmSast ?? true,
        enableLlmSecrets: settings?.enableLlmSecrets ?? true,
        osvApiUrl: settings?.osvApiUrl || "https://api.osv.dev",
      },
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

    await scanQueue.add("scan", jobData, { jobId: scan.id });

    return NextResponse.json({ scanId: scan.id, status: "QUEUED" });
  }

  return NextResponse.json({ message: "Event ignored" });
}
