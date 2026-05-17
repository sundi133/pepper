/** Repository vs upload label for project cards. */
export function projectSourceLabel(
  repoUrl: string | null | undefined,
  scanSourceType?: string | null,
): "Repository" | "Uploaded" {
  if (repoUrl) return "Repository";
  if (scanSourceType === "UPLOAD" || scanSourceType == null) return "Uploaded";
  return "Repository";
}

/** Letter grade from latest completed scan severity totals (dashboard-style). */
export function letterGradeFromCounts(
  critical: number,
  high: number,
  medium: number,
  low: number,
): "A" | "B" | "C" | "D" | "F" {
  if (critical + high + medium + low === 0) return "A";
  const penalty = critical * 18 + high * 6 + medium * 2 + low * 0.5;
  const score = Math.max(0, 100 - penalty);
  if (score >= 90) return "A";
  if (score >= 78) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}
