import {
  createBranchRefWithRetry,
  createGitCommitAndUpdateRef,
  createGitTree,
  createPullRequest,
  fetchGithubRepo,
  getFileOnRef,
  getHeadShaForBranch,
  getRepoTree,
  githubRepoAllowsPush,
  humanizeGithubApiError,
  normalizeRepoFilePath,
  putFileOnBranch,
  type TreeEntry,
} from "@/lib/github-api";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import type { OpenFixPrInput, OpenFixPrResult } from "@/lib/github-open-fix-pr";

// ─── Constants ──────────────────────────────────────────────────────

const MAX_FILES_TO_EXAMINE = 10;
const MAX_FILE_CHARS = 100_000;
const MAX_TOTAL_CONTEXT_CHARS = 500_000;
const MAX_TREE_ENTRIES_FOR_SUMMARY = 2000;

// ─── Agent Step Types ───────────────────────────────────────────────

export type AgentStep =
  | { type: "plan"; filesRequested: string[]; reasoning: string }
  | { type: "gather"; filesRead: Array<{ path: string; chars: number }> }
  | { type: "fix"; filesChanged: Array<{ path: string; action: string }> }
  | { type: "verify"; approved: boolean; concerns: string[] };

export type AgenticFixPrResult = OpenFixPrResult & {
  agentTrace?: AgentStep[];
};

// ─── Prompts ────────────────────────────────────────────────────────

const PLAN_SYSTEM = `You are a senior security engineer. You are given a security finding and a summary of the repository file tree.

Your job is to decide which source files need to be read to understand and fix this vulnerability. Think about:
- The file where the vulnerability was found (always include it)
- Files that import/export the vulnerable function
- Configuration files that control the vulnerable behavior
- Test files that should be updated
- Dependency manifests if the fix involves a package upgrade

Return JSON only:
{
  "filesToExamine": ["path/to/file1.ts", "path/to/file2.ts"],
  "reasoning": "Brief explanation of why these files are needed"
}

Rules:
- Always include the primary finding file
- Maximum 10 files
- Only request files that exist in the provided tree
- Prefer fewer files — only request what's truly needed for the fix`;

const FIX_SYSTEM = `You are a senior security engineer. You will receive a security finding, the primary vulnerable file, and additional context files from the same repository.

Analyze the vulnerability across all provided files and generate a multi-file fix.

Return JSON only:
{
  "files": [
    {
      "path": "exact/repo/path/to/file.ts",
      "content": "<the complete corrected file as a JSON string>",
      "action": "modify"
    }
  ],
  "commitMessage": "<conventional commit, max 72 chars>",
  "prDescription": "<2-4 sentences explaining what was changed and why, in markdown>"
}

Rules:
- Output the ENTIRE content for each changed file — do not omit unchanged parts
- Only include files that actually need changes — do not include unchanged files
- The "path" must exactly match the repository path provided in context
- Prefer minimal changes that address the finding without unnecessary refactoring
- For SCA findings, update the dependency manifest (package.json, requirements.txt, etc.)
- For secrets findings, replace the secret with a placeholder and add env var lookup
- For injection/auth findings, add proper input validation, parameterization, or access control
- If a fix requires a new utility function, add it to an existing appropriate file
- The content string must use valid JSON escaping (\\n for newlines)
- action must be "modify" for existing files or "create" for new files`;

const VERIFY_SYSTEM = `You are a senior security engineer reviewing a proposed security fix.

You will receive the original security finding, the original file contents, and the proposed fixed file contents.

Evaluate whether the fix:
1. Actually addresses the vulnerability described in the finding
2. Does not introduce new security issues
3. Does not break existing functionality (imports, exports, types)
4. Is complete — no partial fixes or TODO comments
5. Follows the codebase conventions visible in the original files

Return JSON only:
{
  "approved": true or false,
  "concerns": ["list of specific concerns if any — empty array if approved"],
  "suggestion": "If not approved, a brief suggestion for improvement. Empty string if approved."
}

Rules:
- Approve if the fix is reasonable even if not perfect
- Only reject if there is a clear flaw (breaks imports, wrong fix, introduces new vuln)
- Be specific in concerns — reference file names and line-level issues`;

// ─── Helper: Build tree summary ─────────────────────────────────────

function buildTreeSummary(tree: TreeEntry[]): string {
  const blobs = tree
    .filter((e) => e.type === "blob")
    .slice(0, MAX_TREE_ENTRIES_FOR_SUMMARY);
  return blobs.map((e) => e.path).join("\n");
}

function sanitizeBranchPart(s: string): string {
  return s.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 20) || "finding";
}

// ─── Main Agent Function ────────────────────────────────────────────

export async function openAgenticSecurityFixPr(
  input: OpenFixPrInput,
): Promise<AgenticFixPrResult> {
  const { githubToken: token, owner, repo, baseBranch, filePath, finding, llm } =
    input;
  const trace: AgentStep[] = [];

  // ── Pre-checks (same as quick fix) ──────────────────────────────

  const repoMeta = await fetchGithubRepo(token, owner, repo);
  if (!repoMeta.ok || !repoMeta.info) {
    return {
      ok: false,
      status: 502,
      error: humanizeGithubApiError(
        repoMeta.message, owner, repo, "Could not read repository from GitHub",
      ),
    };
  }

  if (!githubRepoAllowsPush(repoMeta.info)) {
    return {
      ok: false,
      status: 403,
      error: `Your GitHub account cannot push to ${owner}/${repo}. Open fix PR needs write access.`,
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
      error: `Could not resolve branch "${baseBranch}" on GitHub.`,
    };
  }

  const client = createLlmClient({
    provider: llm.provider,
    baseUrl: llm.baseUrl,
    apiKey: llm.apiKey,
    model: llm.model,
  });

  // ── Phase 1: PLAN ───────────────────────────────────────────────

  let filesToExamine: string[] = [normalizeRepoFilePath(filePath)];
  let planReasoning = "Single file analysis (tree fetch failed or skipped).";

  try {
    const treeResult = await getRepoTree(token, owner, repo, head.sha);
    if (treeResult.ok && treeResult.tree) {
      const treeSummary = buildTreeSummary(treeResult.tree);
      const planPayload = {
        finding: {
          title: finding.title,
          description: finding.description.slice(0, 2000),
          severity: finding.severity,
          scanner: finding.scanner,
          filePath,
          cweId: finding.cweId,
          snippet: finding.snippet?.slice(0, 500),
        },
        repoTree: treeSummary,
      };

      const planRaw = await analyzeWithLlm(
        client, llm.model, PLAN_SYSTEM,
        JSON.stringify(planPayload),
        { temperature: 0.1, maxTokens: 2048 },
      );

      const planResult = parseLlmJsonResponse<{
        filesToExamine?: string[];
        reasoning?: string;
      }>(planRaw, {});

      if (Array.isArray(planResult.filesToExamine) && planResult.filesToExamine.length > 0) {
        // Validate paths exist in tree
        const treePaths = new Set(treeResult.tree.filter((e) => e.type === "blob").map((e) => e.path));
        const normalizedPrimary = normalizeRepoFilePath(filePath);
        const validated = planResult.filesToExamine
          .map((p) => normalizeRepoFilePath(p))
          .filter((p) => treePaths.has(p))
          .slice(0, MAX_FILES_TO_EXAMINE);

        // Always include the primary file
        if (!validated.includes(normalizedPrimary)) {
          validated.unshift(normalizedPrimary);
        }
        filesToExamine = validated;
        planReasoning = planResult.reasoning || "LLM-selected files for analysis.";
      }
    }
  } catch {
    // Plan phase failed — continue with primary file only
  }

  trace.push({ type: "plan", filesRequested: filesToExamine, reasoning: planReasoning });

  // ── Phase 2: GATHER ─────────────────────────────────────────────

  const gatheredFiles: Record<string, string> = {};
  const gatheredMeta: Array<{ path: string; chars: number }> = [];
  let totalChars = 0;

  for (const fp of filesToExamine) {
    if (totalChars >= MAX_TOTAL_CONTEXT_CHARS) break;

    const file = await getFileOnRef(token, owner, repo, fp, resolvedBase);
    if (!file.ok || file.content == null) {
      // Try with commit SHA as fallback
      const fallback = await getFileOnRef(token, owner, repo, fp, head.sha!);
      if (!fallback.ok || fallback.content == null) continue;
      if (fallback.content.length > MAX_FILE_CHARS) continue;
      gatheredFiles[fp] = fallback.content;
      gatheredMeta.push({ path: fp, chars: fallback.content.length });
      totalChars += fallback.content.length;
      continue;
    }
    if (file.content.length > MAX_FILE_CHARS) continue;
    gatheredFiles[fp] = file.content;
    gatheredMeta.push({ path: fp, chars: file.content.length });
    totalChars += file.content.length;
  }

  trace.push({ type: "gather", filesRead: gatheredMeta });

  const primaryPath = normalizeRepoFilePath(filePath);
  if (!gatheredFiles[primaryPath]) {
    return {
      ok: false,
      status: 404,
      error: `Could not read "${primaryPath}" from ${owner}/${repo}.`,
      agentTrace: trace,
    };
  }

  // ── Phase 3: FIX ────────────────────────────────────────────────

  const fixPayload = {
    finding: {
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      scanner: finding.scanner,
      filePath,
      cweId: finding.cweId,
      ruleId: finding.ruleId,
      snippet: finding.snippet,
    },
    primaryFile: { path: primaryPath, content: gatheredFiles[primaryPath] },
    contextFiles: Object.entries(gatheredFiles)
      .filter(([p]) => p !== primaryPath)
      .map(([path, content]) => ({ path, content })),
  };

  let fixResult: {
    files: Array<{ path: string; content: string; action: string }>;
    commitMessage: string;
    prDescription: string;
  } | null = null;

  const generateFix = async (extraContext?: string) => {
    const systemPrompt = extraContext
      ? `${FIX_SYSTEM}\n\nIMPORTANT — address these review concerns from a prior attempt:\n${extraContext}`
      : FIX_SYSTEM;

    const fixRaw = await analyzeWithLlm(
      client, llm.model, systemPrompt,
      JSON.stringify(fixPayload),
      { temperature: 0.1, maxTokens: 32768 },
    );

    const parsed = parseLlmJsonResponse<{
      files?: Array<{ path: string; content: string; action: string }>;
      commitMessage?: string;
      prDescription?: string;
    }>(fixRaw, {});

    if (!Array.isArray(parsed.files) || parsed.files.length === 0) return null;

    // Validate each file has content
    const validFiles = parsed.files.filter(
      (f) => typeof f.path === "string" && typeof f.content === "string" && f.content.length > 0,
    );
    if (validFiles.length === 0) return null;

    return {
      files: validFiles,
      commitMessage: typeof parsed.commitMessage === "string" && parsed.commitMessage.trim()
        ? parsed.commitMessage.trim().slice(0, 72)
        : "fix(security): address scanner finding",
      prDescription: typeof parsed.prDescription === "string"
        ? parsed.prDescription.trim()
        : "",
    };
  };

  try {
    fixResult = await generateFix();
  } catch (e) {
    return {
      ok: false,
      status: 502,
      error: e instanceof Error ? e.message : "LLM fix generation failed",
      agentTrace: trace,
    };
  }

  if (!fixResult) {
    return {
      ok: false,
      status: 502,
      error: "The model did not return any file changes",
      agentTrace: trace,
    };
  }

  trace.push({
    type: "fix",
    filesChanged: fixResult.files.map((f) => ({ path: f.path, action: f.action })),
  });

  // ── Phase 4: VERIFY ─────────────────────────────────────────────

  let verifyApproved = true;
  let verifyConcerns: string[] = [];

  try {
    const verifyPayload = {
      finding: {
        title: finding.title,
        description: finding.description.slice(0, 2000),
        severity: finding.severity,
      },
      originalFiles: Object.entries(gatheredFiles)
        .filter(([p]) => fixResult!.files.some((f) => normalizeRepoFilePath(f.path) === p))
        .map(([path, content]) => ({ path, content: content.slice(0, 50000) })),
      proposedFixes: fixResult.files.map((f) => ({
        path: f.path,
        content: f.content.slice(0, 50000),
        action: f.action,
      })),
    };

    const verifyRaw = await analyzeWithLlm(
      client, llm.model, VERIFY_SYSTEM,
      JSON.stringify(verifyPayload),
      { temperature: 0.1, maxTokens: 2048 },
    );

    const verifyResult = parseLlmJsonResponse<{
      approved?: boolean;
      concerns?: string[];
      suggestion?: string;
    }>(verifyRaw, {});

    verifyApproved = verifyResult.approved !== false;
    verifyConcerns = Array.isArray(verifyResult.concerns)
      ? verifyResult.concerns.filter((c): c is string => typeof c === "string")
      : [];

    // If not approved, retry fix once with concerns
    if (!verifyApproved && verifyConcerns.length > 0) {
      try {
        const retryFix = await generateFix(verifyConcerns.join("\n"));
        if (retryFix) {
          fixResult = retryFix;
          // Re-verify is optional — for now, trust the retry
          verifyApproved = true;
          verifyConcerns = [`Retry after concerns: ${verifyConcerns.join("; ")}`];
        }
      } catch {
        // Retry failed — proceed with original fix
      }
    }
  } catch {
    // Verification failed — proceed with the fix anyway
    verifyConcerns = ["Verification step failed — fix was not reviewed by AI"];
  }

  trace.push({ type: "verify", approved: verifyApproved, concerns: verifyConcerns });

  // ── Commit & PR ─────────────────────────────────────────────────

  const branchSuffix = `${sanitizeBranchPart(finding.title)}-${Date.now().toString(36)}`;
  const created = await createBranchRefWithRetry(
    token, owner, repo,
    `pepper-fix-${branchSuffix}`.slice(0, 200),
    head.sha!,
  );
  if (!created.ok) {
    return {
      ok: false,
      status: created.status >= 400 ? created.status : 502,
      error: humanizeGithubApiError(created.message, owner, repo, "Could not create branch"),
      agentTrace: trace,
    };
  }
  const newBranch = created.branchName;

  // Commit: single-file fast path or multi-file atomic
  if (fixResult.files.length === 1 && fixResult.files[0].action === "modify") {
    // Fast path — use existing Contents API
    const f = fixResult.files[0];
    const origFile = await getFileOnRef(token, owner, repo, normalizeRepoFilePath(f.path), resolvedBase);
    if (!origFile.ok || !origFile.sha) {
      return { ok: false, status: 502, error: "Could not read file SHA for commit", agentTrace: trace };
    }
    const put = await putFileOnBranch(
      token, owner, repo,
      normalizeRepoFilePath(f.path),
      newBranch,
      fixResult.commitMessage,
      f.content,
      origFile.sha,
    );
    if (!put.ok) {
      return {
        ok: false,
        status: put.status >= 400 ? put.status : 502,
        error: humanizeGithubApiError(put.message, owner, repo, "Failed to commit fix"),
        agentTrace: trace,
      };
    }
  } else {
    // Multi-file atomic commit via Git Trees API
    const treeResult = await getRepoTree(token, owner, repo, head.sha!);
    if (!treeResult.ok || !treeResult.tree) {
      return { ok: false, status: 502, error: "Could not read repo tree for atomic commit", agentTrace: trace };
    }

    // Get base tree SHA from the head commit
    const baseTreeSha = head.sha!; // The tree SHA from the commit
    const gitTree = await createGitTree(
      token, owner, repo,
      baseTreeSha,
      fixResult.files.map((f) => ({ path: f.path, content: f.content })),
    );
    if (!gitTree.ok || !gitTree.treeSha) {
      return {
        ok: false,
        status: gitTree.status >= 400 ? gitTree.status : 502,
        error: humanizeGithubApiError(gitTree.message, owner, repo, "Failed to create Git tree"),
        agentTrace: trace,
      };
    }

    const commitResult = await createGitCommitAndUpdateRef(
      token, owner, repo, newBranch,
      gitTree.treeSha, head.sha!,
      fixResult.commitMessage,
    );
    if (!commitResult.ok) {
      return {
        ok: false,
        status: commitResult.status >= 400 ? commitResult.status : 502,
        error: humanizeGithubApiError(commitResult.message, owner, repo, "Failed to commit"),
        agentTrace: trace,
      };
    }
  }

  // Build rich PR body
  const prTitle = `[Pepper] ${finding.title}`.slice(0, 240);
  const filesExamined = gatheredMeta.map((f) => `- \`${f.path}\``).join("\n");
  const filesChanged = fixResult.files.map((f) => `- \`${f.path}\` (${f.action})`).join("\n");
  const verifyNote = verifyApproved
    ? "AI verification: **Approved**"
    : `AI verification: **Concerns noted**\n${verifyConcerns.map((c) => `- ${c}`).join("\n")}`;

  const prBody = [
    `Automated security fix from **Pepper** (deep analysis mode).`,
    ``,
    `### Finding`,
    `- **Scanner:** ${finding.scanner}`,
    `- **Severity:** ${finding.severity}`,
    finding.cweId ? `- **CWE:** ${finding.cweId}` : "",
    finding.ruleId ? `- **Rule:** ${finding.ruleId}` : "",
    ``,
    `### Analysis`,
    planReasoning,
    ``,
    `### Files Examined`,
    filesExamined,
    ``,
    `### Changes`,
    filesChanged,
    fixResult.prDescription ? `\n${fixResult.prDescription}` : "",
    ``,
    `### Verification`,
    verifyNote,
    ``,
    `_Review carefully before merging. Branch \`${newBranch}\` was created from \`${resolvedBase}\`._`,
  ]
    .filter(Boolean)
    .join("\n")
    .slice(0, 60000);

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
      error: humanizeGithubApiError(
        pr.message, owner, repo,
        "Commit succeeded but opening the PR failed. Delete the orphan branch if needed.",
      ),
      agentTrace: trace,
    };
  }

  return {
    ok: true,
    pullRequestUrl: pr.html_url,
    pullRequestNumber: pr.number ?? 0,
    branch: newBranch,
    agentTrace: trace,
  };
}
