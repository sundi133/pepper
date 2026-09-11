import * as path from "path";
import { detectIacFileType, type IacFileType } from "@/lib/constants";

export interface IacStack {
  id: string;
  kind: string;
  files: { filePath: string; iacType: IacFileType }[];
}

function stackKeyFor(filePath: string, iacType: IacFileType): string {
  const dir = path.dirname(filePath) || ".";
  const parts = dir.split(path.sep);
  const root = parts.slice(0, Math.min(3, parts.length)).join("/") || ".";

  switch (iacType) {
    case "dockerfile":
    case "docker-compose":
      return `docker:${root}`;
    case "terraform":
      return `tf:${root}`;
    case "kubernetes":
    case "helm":
      return `k8s:${root}`;
    case "github-actions":
    case "gitlab-ci":
      return `cicd:${root}`;
    case "cloudformation":
      return `cfn:${root}`;
    case "ansible":
      return `ansible:${root}`;
    case "server-config":
      return `server:${root}`;
    default:
      return `iac:${root}`;
  }
}

/** Group related IaC files for stack-level analysis. */
export function groupIacStacks(
  fileList: string[],
): IacStack[] {
  const map = new Map<string, IacStack>();

  for (const filePath of fileList) {
    const iacType = detectIacFileType(filePath);
    if (!iacType) continue;
    const key = stackKeyFor(filePath, iacType);
    const existing = map.get(key);
    if (existing) {
      existing.files.push({ filePath, iacType });
    } else {
      map.set(key, {
        id: key,
        kind: iacType,
        files: [{ filePath, iacType }],
      });
    }
  }

  return [...map.values()].filter((s) => s.files.length > 0);
}

function normPath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

/**
 * When a PR touches one IaC file, include the rest of that stack so
 * Dockerfile+compose / Terraform module+vars still analyze together.
 */
export function filesInTouchedIacStacks(
  allFiles: string[],
  changedFiles: string[],
): string[] {
  if (changedFiles.length === 0) return [];
  const changed = new Set(changedFiles.map(normPath));
  const stacks = groupIacStacks(allFiles.map(normPath));
  const extra: string[] = [];
  const seen = new Set<string>();
  for (const stack of stacks) {
    if (!stack.files.some((f) => changed.has(normPath(f.filePath)))) continue;
    for (const f of stack.files) {
      const key = normPath(f.filePath);
      if (seen.has(key)) continue;
      seen.add(key);
      extra.push(f.filePath);
    }
  }
  return extra;
}
