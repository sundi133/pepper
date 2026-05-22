import { execFileSync } from "child_process";
import { githubGet } from "@/lib/github-api";
import {
  filterToChangedFiles,
  parseDiffNameStatus,
  type DiffFile,
} from "@/scanners/diff-parser";

/** Basenames and extensions treated as dependency manifests for incremental SCA. */
export const SCA_MANIFEST_BASENAMES = new Set([
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements-test.txt",
  "Pipfile.lock",
  "pyproject.toml",
  "go.mod",
  "Cargo.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
  "packages.config",
  "pubspec.yaml",
  "mix.lock",
  "Package.resolved",
]);

const SCA_MANIFEST_EXTENSIONS = new Set([".csproj", ".fsproj", ".vbproj"]);

export function normalizeRepoPath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function isScaManifestPath(filePath: string): boolean {
  const norm = normalizeRepoPath(filePath);
  const base = norm.split("/").pop() ?? norm;
  if (SCA_MANIFEST_BASENAMES.has(base)) return true;
  const ext = base.includes(".") ? `.${base.split(".").pop()}` : "";
  return SCA_MANIFEST_EXTENSIONS.has(ext);
}

export interface IncrementalFileFilterResult {
  /** Files for SAST / secrets scanners. */
  sastAndSecretsFiles: string[];
  /** Manifest / lockfiles for SCA (empty when none changed). */
  scaFiles: string[];
  changedPathCount: number;
  usedDiff: boolean;
  method?: string;
}

/**
 * Apply PR diff paths to the enumerated worktree file list.
 * When `changedPaths` is null, returns the full list (safe fallback).
 */
export function applyIncrementalFileFilter(
  allFiles: string[],
  changedPaths: string[] | null,
): IncrementalFileFilterResult {
  if (!changedPaths || changedPaths.length === 0) {
    if (changedPaths && changedPaths.length === 0) {
      return {
        sastAndSecretsFiles: [],
        scaFiles: [],
        changedPathCount: 0,
        usedDiff: true,
        method: "empty-diff",
      };
    }
    return {
      sastAndSecretsFiles: allFiles,
      scaFiles: allFiles.filter(isScaManifestPath),
      changedPathCount: allFiles.length,
      usedDiff: false,
    };
  }

  const diffFiles: DiffFile[] = changedPaths.map((p) => ({
    status: "M" as const,
    path: normalizeRepoPath(p),
  }));
  const matched = filterToChangedFiles(allFiles, diffFiles);
  const scaFiles = matched.filter(isScaManifestPath);
  const sastAndSecretsFiles = matched.filter((f) => !isScaManifestPath(f));

  return {
    sastAndSecretsFiles,
    scaFiles,
    changedPathCount: changedPaths.length,
    usedDiff: true,
    method: "diff-filter",
  };
}

/**
 * Resolve changed paths with `git diff --name-status` (and merge-base when possible).
 * Returns null on failure so the caller can fall back or try the GitHub API.
 */
export function resolveGitPrChangedPaths(
  repoDir: string,
  baseSha: string,
  commitSha: string,
): string[] | null {
  const base = baseSha.trim();
  const head = commitSha.trim();
  if (!base || !head) return null;

  try {
    execFileSync("git", ["fetch", "origin", base, "--depth", "1"], {
      cwd: repoDir,
      timeout: 120_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    try {
      execFileSync("git", ["fetch", "origin", head, "--depth", "1"], {
        cwd: repoDir,
        timeout: 120_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      return null;
    }
  }

  let diffBase = base;
  try {
    diffBase = execFileSync("git", ["merge-base", base, head], {
      cwd: repoDir,
      encoding: "utf-8",
      timeout: 30_000,
    }).trim();
    if (!diffBase) diffBase = base;
  } catch {
    diffBase = base;
  }

  try {
    const out = execFileSync(
      "git",
      ["diff", "--name-status", diffBase, head],
      {
        cwd: repoDir,
        encoding: "utf-8",
        timeout: 60_000,
      },
    );
    return diffFilesToPaths(parseDiffNameStatus(out));
  } catch {
    return null;
  }
}

function diffFilesToPaths(files: DiffFile[]): string[] {
  return files.map((f) => normalizeRepoPath(f.path));
}

interface GithubPrFileRow {
  filename?: string;
  status?: string;
  previous_filename?: string;
}

/**
 * Fetch changed file paths from the GitHub pull request files API.
 */
export async function resolveGithubPrChangedPaths(params: {
  token: string;
  owner: string;
  repo: string;
  prNumber: number;
}): Promise<string[] | null> {
  const paths: string[] = [];
  for (let page = 1; page <= 10; page++) {
    const r = await githubGet<GithubPrFileRow[]>(
      params.token,
      `/repos/${encodeURIComponent(params.owner)}/${encodeURIComponent(params.repo)}/pulls/${params.prNumber}/files?per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;

    for (const row of r.data) {
      const status = row.status ?? "modified";
      if (status === "removed") continue;
      const path = row.filename?.trim();
      if (!path) continue;
      paths.push(normalizeRepoPath(path));
    }
    if (r.data.length < 100) break;
  }

  return paths.length > 0 ? paths : [];
}

export type ResolveIncrementalPathsInput = {
  repoDir?: string;
  baseSha?: string;
  commitSha?: string;
  github?: {
    token: string;
    owner: string;
    repo: string;
    prNumber: number;
  };
};

export type ResolveIncrementalPathsResult = {
  paths: string[] | null;
  method?: string;
};

/**
 * Resolve PR changed paths: git diff first, then GitHub PR files API.
 */
export async function resolveIncrementalChangedPaths(
  input: ResolveIncrementalPathsInput,
): Promise<ResolveIncrementalPathsResult> {
  if (input.repoDir && input.baseSha && input.commitSha) {
    const gitPaths = resolveGitPrChangedPaths(
      input.repoDir,
      input.baseSha,
      input.commitSha,
    );
    if (gitPaths !== null) {
      return { paths: gitPaths, method: "git-diff" };
    }
  }

  if (input.github) {
    const apiPaths = await resolveGithubPrChangedPaths(input.github);
    if (apiPaths !== null) {
      return {
        paths: apiPaths,
        method: apiPaths.length === 0 ? "github-pr-files-empty" : "github-pr-files",
      };
    }
  }

  return { paths: null };
}

/** Load project GitHub coordinates and resolve PR diff paths for the worker. */
export async function resolveIncrementalPathsForScanJob(params: {
  repoDir: string;
  baseSha?: string;
  commitSha?: string;
  prNumber?: number;
  projectId: string;
  useOrgGithubToken?: boolean;
  orgId?: string;
}): Promise<ResolveIncrementalPathsResult> {
  const github =
    params.prNumber != null &&
    params.useOrgGithubToken &&
    params.orgId
      ? await loadGithubPrContext(params.projectId, params.orgId, params.prNumber)
      : undefined;

  return resolveIncrementalChangedPaths({
    repoDir: params.repoDir,
    baseSha: params.baseSha,
    commitSha: params.commitSha,
    github: github ?? undefined,
  });
}

async function loadGithubPrContext(
  projectId: string,
  orgId: string,
  prNumber: number,
): Promise<
  | {
      token: string;
      owner: string;
      repo: string;
      prNumber: number;
    }
  | undefined
> {
  const { prisma } = await import("@/lib/prisma");
  const { getOrgGithubAccessToken } = await import("@/lib/github-connection");

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { githubOwner: true, githubRepoName: true },
  });
  if (!project?.githubOwner || !project.githubRepoName) return undefined;

  const token = await getOrgGithubAccessToken(orgId);
  if (!token) return undefined;

  return {
    token,
    owner: project.githubOwner,
    repo: project.githubRepoName,
    prNumber,
  };
}
