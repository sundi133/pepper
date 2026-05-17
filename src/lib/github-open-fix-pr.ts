import {
  createBranchRefWithRetry,
  createPullRequest,
  fetchGithubRepo,
  getFileOnRef,
  getHeadShaForBranch,
  githubRepoAllowsPush,
  humanizeGithubApiError,
  normalizeRepoFilePath,
  putFileOnBranch,
} from "@/lib/github-api";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";

const MAX_FILE_CHARS = 200_000;

const FILE_FIX_SYSTEM = `You are a senior security engineer. You will receive ONE source file's full text and one security finding.

Return JSON only with this exact shape:
{
  "fixedFile": "<the complete corrected file as a single JSON string — every line of the file, properly escaped for JSON>",
  "commitMessage": "<one line, conventional commit style, max 72 chars, e.g. fix(security): validate input before exec>"
}

Rules:
- Output the ENTIRE file with the minimal change set that addresses the finding. Do not omit unchanged parts.
- The finding may come from any scanner type (e.g. SAST pattern/AI, secrets, SCA, IaC, supply chain). Apply the appropriate fix: dependency/manifest bumps for SCA, config hardening for IaC, remove or replace leaked secret material for secrets, code changes for injection/auth issues, etc.
- Preserve encoding, line endings style, imports, and unrelated code unless they must change for the fix.
- Do not add comments that reveal internal scan product names unless generic.
- If you cannot safely fix without more context, return the original file unchanged and set commitMessage to "chore: document security review needed" — but prefer a real fix when the issue is clear from the file.
- The fixedFile string must be valid JSON string escaping (use \\n for newlines, \\" for quotes).`;

export type OpenFixPrInput = {
  githubToken: string;
  llm: {
    provider: string;
    baseUrl: string;
    model: string;
    apiKey: string;
  };
  owner: string;
  repo: string;
  /** Branch to merge into (e.g. main). */
  baseBranch: string;
  filePath: string;
  finding: {
    title: string;
    description: string;
    severity: string;
    scanner: string;
    snippet?: string | null;
    cweId?: string | null;
    ruleId?: string | null;
  };
};

export type OpenFixPrResult =
  | { ok: true; pullRequestUrl: string; pullRequestNumber: number; branch: string }
  | { ok: false; status: number; error: string };

function sanitizeBranchPart(s: string): string {
  return s.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 20) || "finding";
}

function ghApiError(
  message: string | undefined,
  owner: string,
  repo: string,
  fallback: string,
): string {
  return humanizeGithubApiError(message, owner, repo, fallback);
}

export async function openGithubSecurityFixPr(
  input: OpenFixPrInput,
): Promise<OpenFixPrResult> {
  const { githubToken: token, owner, repo, baseBranch, filePath, finding, llm } =
    input;

  const repoMeta = await fetchGithubRepo(token, owner, repo);
  if (!repoMeta.ok || !repoMeta.info) {
    return {
      ok: false,
      status: 502,
      error: ghApiError(
        repoMeta.message,
        owner,
        repo,
        "Could not read repository from GitHub",
      ),
    };
  }

  if (!githubRepoAllowsPush(repoMeta.info)) {
    return {
      ok: false,
      status: 403,
      error:
        `Your GitHub account cannot push to ${owner}/${repo}. ` +
        "Open fix PR needs write access (create branch + commit + pull request). " +
        "Use a repository you own, a fork where you have push access, or ask for collaborator write access. " +
        "Public repos you do not own are read-only even after OAuth connect.",
    };
  }

  let resolvedBase = baseBranch.trim() || repoMeta.info.default_branch;
  let head = await getHeadShaForBranch(token, owner, repo, resolvedBase);
  if (!head.ok || !head.sha) {
    resolvedBase = repoMeta.info.default_branch;
    head = await getHeadShaForBranch(token, owner, repo, resolvedBase);
  }
  if (!head.ok || !head.sha) {
    return {
      ok: false,
      status: 400,
      error: ghApiError(
        head.message,
        owner,
        repo,
        `Could not resolve branch "${baseBranch}" on GitHub. Use a valid default or scan branch.`,
      ),
    };
  }

  const repoRelativePath = normalizeRepoFilePath(filePath);
  const fileReadFallback =
    `Could not read "${repoRelativePath}" on ${owner}/${repo} (branch "${resolvedBase}"). ` +
    "The path must match the repository layout on GitHub (same as in the scan). " +
    "For upload-only scans, enter the correct owner/repo when opening the PR. " +
    "If the repo is private, connect GitHub under Repositories with an account that has read access.";

  let file = await getFileOnRef(
    token,
    owner,
    repo,
    repoRelativePath,
    resolvedBase,
  );
  if ((!file.ok || file.content == null) && head.sha) {
    file = await getFileOnRef(token, owner, repo, repoRelativePath, head.sha);
  }
  if (!file.ok || file.content == null || !file.sha) {
    return {
      ok: false,
      status: file.status === 404 ? 404 : 502,
      error: ghApiError(file.message, owner, repo, fileReadFallback),
    };
  }

  const branchSuffix = `${sanitizeBranchPart(finding.title)}-${Date.now().toString(36)}`;
  const branchCreateFallback =
    `Could not create a branch on ${owner}/${repo}. ` +
    "Your GitHub login must have push (write) access—not read-only. " +
    "If this is an organization repo, authorize SAML SSO for the org on GitHub. " +
    "Some repos block certain branch name patterns; try again or open the PR from a fork you control.";

  const created = await createBranchRefWithRetry(
    token,
    owner,
    repo,
    `pepper-security-${branchSuffix}`.slice(0, 200),
    head.sha,
  );
  if (!created.ok) {
    return {
      ok: false,
      status: created.status >= 400 ? created.status : 502,
      error: ghApiError(created.message, owner, repo, branchCreateFallback),
    };
  }
  const newBranch = created.branchName;

  if (file.content.length > MAX_FILE_CHARS) {
    return {
      ok: false,
      status: 413,
      error: `File exceeds ${MAX_FILE_CHARS} characters; open PR from a smaller file or fix manually.`,
    };
  }

  const userPayload = {
    filePath,
    finding,
    originalFile: file.content,
  };

  const client = createLlmClient({
    provider: llm.provider,
    baseUrl: llm.baseUrl,
    apiKey: llm.apiKey,
    model: llm.model,
  });

  let raw: string;
  try {
    raw = await analyzeWithLlm(
      client,
      llm.model,
      FILE_FIX_SYSTEM,
      JSON.stringify(userPayload),
      { temperature: 0.1, maxTokens: 32768 },
    );
  } catch (e) {
    return {
      ok: false,
      status: 502,
      error: e instanceof Error ? e.message : "LLM request failed",
    };
  }

  const parsed = parseLlmJsonResponse<{
    fixedFile?: string;
    commitMessage?: string;
  }>(raw, {});

  const fixedFile =
    typeof parsed.fixedFile === "string" ? parsed.fixedFile : "";
  const commitMessage =
    typeof parsed.commitMessage === "string" && parsed.commitMessage.trim()
      ? parsed.commitMessage.trim().slice(0, 72)
      : "fix(security): address scanner finding";

  if (!fixedFile) {
    return {
      ok: false,
      status: 502,
      error: "The model did not return fixedFile content",
    };
  }

  if (fixedFile.length > MAX_FILE_CHARS * 2) {
    return {
      ok: false,
      status: 502,
      error: "Fixed file from model is unreasonably large",
    };
  }

  const put = await putFileOnBranch(
    token,
    owner,
    repo,
    repoRelativePath,
    newBranch,
    commitMessage,
    fixedFile,
    file.sha,
  );
  if (!put.ok) {
    return {
      ok: false,
      status: put.status >= 400 ? put.status : 502,
      error: ghApiError(
        put.message,
        owner,
        repo,
        "Failed to commit fix to GitHub",
      ),
    };
  }

  const prTitle = `[Pepper] ${finding.title}`.slice(0, 240);
  const prBody = [
    `Automated security fix suggestion from **Pepper**.`,
    ``,
    `- **Scanner:** ${finding.scanner}`,
    `- **Severity:** ${finding.severity}`,
    finding.cweId ? `- **CWE:** ${finding.cweId}` : "",
    finding.ruleId ? `- **Rule:** ${finding.ruleId}` : "",
    ``,
    `### Finding`,
    finding.description.slice(0, 8000),
    ``,
    `_Review carefully before merging. Branch \`${newBranch}\` was created from \`${resolvedBase}\`._`,
  ]
    .filter(Boolean)
    .join("\n");

  const pr = await createPullRequest(token, owner, repo, {
    title: prTitle,
    head: newBranch,
    base: resolvedBase,
    body: prBody,
  });

  if (!pr.ok || !pr.html_url) {
    return {
      ok: false,
      status: pr.status >= 400 ? pr.status : 502,
      error: ghApiError(
        pr.message,
        owner,
        repo,
        "Commit succeeded but opening the pull request failed. Delete the orphan branch in GitHub if needed.",
      ),
    };
  }

  return {
    ok: true,
    pullRequestUrl: pr.html_url,
    pullRequestNumber: pr.number ?? 0,
    branch: newBranch,
  };
}
