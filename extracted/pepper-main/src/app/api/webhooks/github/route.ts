import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import crypto from "crypto";

export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-hub-signature-256");
  const event = req.headers.get("x-github-event");
  const body = await req.text();

  // Verify webhook signature if secret is configured
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
  if (webhookSecret && signature) {
    const expected = `sha256=${crypto
      .createHmac("sha256", webhookSecret)
      .update(body)
      .digest("hex")}`;
    if (signature !== expected) {
      return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
    }
  }

  const payload = JSON.parse(body);

  if (
    event === "pull_request" &&
    ["opened", "synchronize"].includes(payload.action)
  ) {
    const repoUrl = payload.repository?.clone_url;
    const branch = payload.pull_request?.head?.ref;
    const baseSha = payload.pull_request?.base?.sha;
    const headSha = payload.pull_request?.head?.sha;
    const prNumber = payload.pull_request?.number;

    // Find project by repo URL
    const project = await prisma.project.findFirst({
      where: { repoUrl: { contains: payload.repository?.full_name } },
      include: {
        buildGate: true,
        organization: { include: { settings: true } },
      },
    });

    if (!project) {
      return NextResponse.json({ message: "No matching project found" });
    }

    const settings = project.organization.settings;

    // Create scan
    const scan = await prisma.scan.create({
      data: {
        projectId: project.id,
        scanType: "INCREMENTAL",
        sourceType: "WEBHOOK",
        sourceRef: repoUrl,
        branch,
        commitSha: headSha,
        baseSha,
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
      baseSha,
      commitSha: headSha,
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
