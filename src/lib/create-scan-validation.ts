export type CreateScanSourceMode = "upload" | "git" | "svn";

/** Select value meaning: create a new project from this scan’s source. */
export const CREATE_PROJECT_ON_SCAN_VALUE = "__new__";

export function isExistingProjectSelection(projectId: string): boolean {
  const t = projectId?.trim();
  if (!t || t === CREATE_PROJECT_ON_SCAN_VALUE) return false;
  return true;
}

export type CreateScanFieldErrors = {
  project?: string;
  source?: string;
};

export function validateCreateScanFields(input: {
  projectId: string;
  sourceMode: CreateScanSourceMode;
  file: File | null;
  repoUrl: string;
  svnUrl: string;
}): CreateScanFieldErrors {
  const errors: CreateScanFieldErrors = {};

  if (input.sourceMode === "upload") {
    if (!input.file) {
      errors.source = "Source Code is required.";
    }
  } else if (input.sourceMode === "git") {
    if (!input.repoUrl?.trim()) {
      errors.source = "Source Code is required.";
    }
  } else if (input.sourceMode === "svn") {
    if (!input.svnUrl?.trim()) {
      errors.source = "Source Code is required.";
    }
  }

  return errors;
}

/** Toggle expanded finding: same id closes, different id opens. */
export function nextFindingSelection<T extends { id: string }>(
  current: T | null,
  clicked: T,
): T | null {
  if (current?.id === clicked.id) return null;
  return clicked;
}
