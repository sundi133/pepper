export const SCAN_STATUS_LABEL: Record<
  string,
  { label: string; variant: "default" | "secondary" | "destructive" | "outline" }
> = {
  PENDING: { label: "Pending", variant: "secondary" },
  SCANNING: { label: "Scanning", variant: "default" },
  ISSUES: { label: "Issues", variant: "destructive" },
  PASSED: { label: "Passed", variant: "outline" },
  FAILED: { label: "Failed", variant: "destructive" },
};

export const PROVIDER_LABEL: Record<string, string> = {
  github: "GitHub",
  bitbucket: "Bitbucket",
  azure: "Azure DevOps",
};

export type FindingSeverity = "High" | "Medium" | "Low" | "—";

export function severityFromFindings(findingsCount: number): FindingSeverity {
  if (findingsCount === 0) return "—";
  if (findingsCount >= 5) return "High";
  if (findingsCount >= 1) return "Medium";
  return "Low";
}

export const SEVERITY_STYLES: Record<
  FindingSeverity,
  string
> = {
  High: "bg-red-50 text-red-700 border-red-200/80 dark:bg-red-950/40 dark:text-red-300 dark:border-red-900/50",
  Medium:
    "bg-amber-50 text-amber-800 border-amber-200/80 dark:bg-amber-950/40 dark:text-amber-200 dark:border-amber-900/50",
  Low: "bg-slate-50 text-slate-600 border-slate-200/80 dark:bg-slate-900 dark:text-slate-400",
  "—": "bg-slate-50 text-slate-500 border-slate-200/60 dark:bg-slate-900/50 dark:text-slate-500",
};

export function formatLastScan(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}
