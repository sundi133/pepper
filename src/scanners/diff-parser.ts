export interface DiffFile {
  status: "A" | "M" | "D" | "R";
  path: string;
}

/**
 * Parse `git diff --name-status` output into a list of changed files.
 */
export function parseDiffNameStatus(output: string): DiffFile[] {
  return output
    .trim()
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const parts = line.split("\t");
      const status = parts[0].charAt(0) as DiffFile["status"];
      const path = parts[parts.length - 1]; // handle renames (R100\told\tnew)
      return { status, path };
    })
    .filter((f) => f.status !== "D"); // skip deleted files
}

/**
 * Filter a full file list to only include files that changed.
 */
export function filterToChangedFiles(
  allFiles: string[],
  diffFiles: DiffFile[]
): string[] {
  const changedPaths = new Set(diffFiles.map((f) => f.path));
  return allFiles.filter((f) => changedPaths.has(f));
}
