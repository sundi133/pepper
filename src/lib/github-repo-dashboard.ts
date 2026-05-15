export type RepoScanStatus =
  | "PENDING"
  | "SCANNING"
  | "ISSUES"
  | "PASSED"
  | "FAILED";

type ScanSnapshot = {
  status: string;
  gateResult: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  filesScanned: number;
  completedAt: Date | null;
  createdAt: Date;
};

export function deriveRepoScanStatus(
  scan: ScanSnapshot | null | undefined,
): RepoScanStatus {
  if (!scan) return "PENDING";
  if (scan.status === "QUEUED") return "PENDING";
  if (scan.status === "RUNNING" || scan.status === "PAUSED") return "SCANNING";
  if (
    scan.status === "FAILED" ||
    scan.status === "CANCELLED" ||
    scan.status === "STOPPED"
  ) {
    return "FAILED";
  }
  if (scan.status === "COMPLETED") {
    const total =
      scan.criticalCount +
      scan.highCount +
      scan.mediumCount +
      scan.lowCount +
      scan.infoCount;
    if (scan.gateResult === "FAILED" || scan.criticalCount > 0) {
      return "ISSUES";
    }
    if (scan.highCount > 0 || total > 0) return "ISSUES";
    return "PASSED";
  }
  return "PENDING";
}

export function formatCoverage(scan: ScanSnapshot | null | undefined): string {
  if (!scan || scan.status !== "COMPLETED") return "—";
  if (scan.filesScanned > 0) {
    return `${scan.filesScanned.toLocaleString()} files`;
  }
  return "—";
}

export function formatLanguage(lang: string | null | undefined): string {
  if (!lang?.trim()) return "Unknown";
  return lang;
}

export function formatBranch(branch: string | null | undefined): string {
  if (!branch?.trim()) return "—";
  return branch;
}
