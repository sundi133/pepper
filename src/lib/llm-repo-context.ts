import * as path from "path";

/** Basenames (lowercase) that usually carry supply-chain or deploy risk signals */
const MANIFEST_BASENAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "requirements.txt",
  "pipfile",
  "pipfile.lock",
  "pyproject.toml",
  "poetry.lock",
  "go.mod",
  "go.sum",
  "gemfile",
  "gemfile.lock",
  "composer.json",
  "composer.lock",
  "cargo.toml",
  "cargo.lock",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "dockerfile",
  "containerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
]);

function basenameNorm(p: string): string {
  return path.basename(p).toLowerCase();
}

function isManifestPath(p: string): boolean {
  const b = basenameNorm(p);
  if (MANIFEST_BASENAMES.has(b)) return true;
  if (/^dockerfile(\.|$)/i.test(path.basename(p))) return true;
  if (b.endsWith(".tf") || b.endsWith(".tfvars")) return true;
  if (
    p.includes(".github/workflows/") &&
    (b.endsWith(".yml") || b.endsWith(".yaml"))
  ) {
    return true;
  }
  return false;
}

export interface RepoContextOptions {
  maxManifestPaths?: number;
  maxSamplePaths?: number;
  maxChars?: number;
}

/**
 * Compact path-only summary so the LLM can reason about repo layout (nested apps,
 * duplicate manifests, IaC entrypoints) the way interactive tools do after unzip.
 */
export function buildRepoContextSummary(
  fileList: string[],
  options?: RepoContextOptions,
): string {
  const maxManifest = options?.maxManifestPaths ?? 45;
  const maxSample = options?.maxSamplePaths ?? 70;
  const maxChars = options?.maxChars ?? 5500;

  const manifests = fileList.filter(isManifestPath).sort();

  const watchDupBases = new Set([
    "requirements.txt",
    "package.json",
    "dockerfile",
    "pyproject.toml",
    "go.mod",
  ]);
  const byBase = new Map<string, string[]>();
  for (const p of fileList) {
    const b = basenameNorm(p);
    if (!watchDupBases.has(b)) continue;
    const list = byBase.get(b) ?? [];
    list.push(p);
    byBase.set(b, list);
  }
  const duplicateNotes: string[] = [];
  for (const [base, paths] of byBase) {
    if (paths.length <= 1) continue;
    const shown = paths.slice(0, 8).join("; ");
    duplicateNotes.push(
      `${base}: ${paths.length} paths — ${shown}${paths.length > 8 ? " …" : ""}`,
    );
  }

  const sorted = [...fileList].sort();
  const sample = sorted.slice(0, maxSample);

  let out = `REPOSITORY CONTEXT (paths only; relative to project root)\n`;
  out += `- Total listed files: ${fileList.length}\n`;
  if (manifests.length > 0) {
    out += `- Manifest / lockfile / IaC / workflow paths (${manifests.length}):\n`;
    for (const m of manifests.slice(0, maxManifest)) {
      out += `  • ${m}\n`;
    }
    if (manifests.length > maxManifest) {
      out += `  • … and ${manifests.length - maxManifest} more\n`;
    }
  } else {
    out += `- No common manifest filenames detected in path list\n`;
  }
  if (duplicateNotes.length > 0) {
    out += `- Same-name manifests or Dockerfiles in multiple directories (review drift between trees):\n`;
    for (const d of duplicateNotes.slice(0, 14)) {
      out += `  • ${d}\n`;
    }
  }
  out += `- Alphabetic path sample (first ${sample.length} of ${sorted.length}):\n`;
  for (const s of sample) {
    out += `  ${s}\n`;
  }
  if (sorted.length > maxSample) {
    out += `  … ${sorted.length - maxSample} additional paths omitted\n`;
  }
  out += `\nUse this layout when inferring nested copies, split dependency trees, or sibling deploy configs. Each finding must still cite concrete lines from the code chunk below — do not invent files or versions not shown in the chunk.\n`;

  if (out.length > maxChars) {
    return `${out.slice(0, maxChars - 24)}\n… [repo context truncated]\n`;
  }
  return out;
}
