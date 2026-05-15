import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  parseGithubRepo,
  resolveGithubRepoUrlForOpenPr,
} from "@/lib/github-source-link";
import { openGithubSecurityFixPr } from "@/lib/github-open-fix-pr";
import { resolveGithubPrTokenForOrg } from "@/lib/github-pr-token-resolve";
import { normalizeRepoFilePath } from "@/lib/github-api";
import {
  githubHttpsCloneUrl,
  parseGithubRepoInput,
} from "@/lib/parse-github-repo-input";

const bodySchema = z
  .object({
    repoUrl: z.string().max(500).optional(),
    branch: z.string().max(200).optional(),
  })
  .optional();

export async function POST(
  req: NextRequest,
  {
    params,
  }: { params: Promise<{ scanId: string; findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId, findingId } = await params;

  let body: z.infer<typeof bodySchema>;
  try {
    const raw = await req.json().catch(() => ({}));
    body = bodySchema.parse(raw);
  } catch {
    body = undefined;
  }

  const finding = await prisma.finding.findFirst({
    where: {
      id: findingId,
      scanId,
      scan: { project: { organizationId: orgId } },
    },
    include: {
      scan: {
        select: {
          id: true,
          branch: true,
          commitSha: true,
          sourceType: true,
          sourceRef: true,
          projectId: true,
          project: {
            select: {
              id: true,
              repoUrl: true,
              name: true,
              defaultBranch: true,
            },
          },
        },
      },
    },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  if (!finding.filePath?.trim()) {
    return NextResponse.json(
      { error: "Finding has no file path; cannot target a file for a PR." },
      { status: 400 },
    );
  }

  if (body?.repoUrl?.trim()) {
    const manual = parseGithubRepoInput(body.repoUrl);
    if (!manual) {
      return NextResponse.json(
        {
          error:
            "Invalid repository. Use owner/repo or https://github.com/owner/repo",
        },
        { status: 400 },
      );
    }
    const cloneUrl = githubHttpsCloneUrl(manual.owner, manual.repo);
    await prisma.project.update({
      where: { id: finding.scan.projectId },
      data: {
        repoUrl: cloneUrl,
        defaultBranch: body.branch?.trim() || finding.scan.project?.defaultBranch,
        githubOwner: manual.owner,
        githubRepoName: manual.repo,
      },
    });
    finding.scan.project = {
      ...finding.scan.project!,
      repoUrl: cloneUrl,
      defaultBranch: body.branch?.trim() || finding.scan.project?.defaultBranch || "main",
    };
  }

  const repoUrl = resolveGithubRepoUrlForOpenPr({
    projectRepoUrl: finding.scan.project?.repoUrl,
    scanSourceType: finding.scan.sourceType,
    scanSourceRef: finding.scan.sourceRef,
  });
  const parsed = parseGithubRepo(repoUrl);
  if (!parsed) {
    return NextResponse.json(
      {
        error:
          "No GitHub repository for this scan. Connect GitHub, import the repo under Repositories, paste a repo URL when connecting, or provide owner/repo when opening the PR.",
        code: "GITHUB_REPO_REQUIRED",
      },
      { status: 400 },
    );
  }

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  const { token: githubToken } = await resolveGithubPrTokenForOrg(orgId);
  if (!githubToken) {
    return NextResponse.json(
      {
        error:
          "GitHub is not connected. Authorize GitHub to open a fix pull request.",
        code: "GITHUB_OAUTH_REQUIRED",
      },
      { status: 401 },
    );
  }

  const apiKey =
    orgSettings?.llmApiKey?.trim() ||
    process.env.LLM_API_KEY?.trim() ||
    process.env.OPENAI_API_KEY?.trim();

  if (!apiKey) {
    return NextResponse.json(
      {
        error:
          "No LLM API key configured. The PR workflow needs the model to rewrite the file. Set the organization LLM key or LLM_API_KEY / OPENAI_API_KEY.",
      },
      { status: 503 },
    );
  }

  const provider = orgSettings?.llmProvider || "openai";
  const baseUrl =
    orgSettings?.llmBaseUrl ||
    (provider.toLowerCase() === "ollama"
      ? process.env.OLLAMA_HOST || "http://localhost:11434"
      : "https://api.openai.com/v1");
  const model = orgSettings?.llmModel || "gpt-4o-mini";

  const baseBranch =
    body?.branch?.trim() ||
    finding.scan.branch?.trim() ||
    finding.scan.project?.defaultBranch?.trim() ||
    "main";

  const result = await openGithubSecurityFixPr({
    githubToken,
    llm: { provider, baseUrl, model, apiKey },
    owner: parsed.owner,
    repo: parsed.repo,
    baseBranch,
    filePath: normalizeRepoFilePath(finding.filePath),
    finding: {
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      scanner: finding.scanner,
      snippet: finding.snippet,
      cweId: finding.cweId,
      ruleId: finding.ruleId,
    },
  });

  if (!result.ok) {
    return NextResponse.json(
      { error: result.error },
      { status: result.status >= 400 && result.status < 600 ? result.status : 502 },
    );
  }

  return NextResponse.json({
    pullRequestUrl: result.pullRequestUrl,
    pullRequestNumber: result.pullRequestNumber,
    branch: result.branch,
  });
}
