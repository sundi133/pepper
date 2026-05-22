"use client";

import { useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  ExternalLink,
  GitBranch,
  Loader2,
  MoreHorizontal,
  RefreshCw,
  RotateCcw,
  Search,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  formatLastScan,
  PROVIDER_LABEL,
  SCAN_STATUS_LABEL,
  SEVERITY_STYLES,
  severityFromFindings,
} from "./constants";
import type { ScanJobData } from "@/lib/queue";
import type { ScanProject } from "@/components/scans/types";
import type { RepoProvider, UnifiedConnectedRepo } from "./types";

type RepositoryInventoryProps = {
  repos: UnifiedConnectedRepo[];
  projects: ScanProject[];
  scanType: ScanJobData["scanType"];
  loading: boolean;
  providerFilter: "all" | RepoProvider;
  onProviderFilterChange: (f: "all" | RepoProvider) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onRefresh: () => void;
  stats: { total: number; scanning: number; withIssues: number };
};

export function RepositoryInventory({
  repos,
  projects,
  scanType,
  loading,
  providerFilter,
  onProviderFilterChange,
  searchQuery,
  onSearchChange,
  onRefresh,
  stats,
}: RepositoryInventoryProps) {
  const [rescanningId, setRescanningId] = useState<string | null>(null);

  async function handleRescan(repo: UnifiedConnectedRepo) {
    const key = repo.scanId ?? repo.projectId;
    setRescanningId(key);
    try {
      const project = projects.find((p) => p.id === repo.projectId);
      const repoUrl = project?.repoUrl?.trim();

      if (repoUrl) {
        const res = await fetch("/api/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            projectId: repo.projectId,
            scanType,
            repoUrl,
            branch: repo.branch || project?.defaultBranch || undefined,
          }),
        });
        const data = (await res.json()) as { scanId?: string; error?: string };
        if (!res.ok) throw new Error(data.error || "Failed to start scan");
        toast.success("Scan queued");
        onRefresh();
        return;
      }

      if (!repo.scanId) {
        toast.error("No scan history for this repository.");
        return;
      }

      const res = await fetch(`/api/scans/${repo.scanId}/rescan`, {
        method: "POST",
      });
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(data.error || "Failed to start rescan");
      toast.success("Rescan queued");
      onRefresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to start rescan");
    } finally {
      setRescanningId(null);
    }
  }

  const filterPill = (value: "all" | RepoProvider, label: string) => (
    <button
      type="button"
      onClick={() => onProviderFilterChange(value)}
      className={cn(
        "rounded-full border px-3 py-1 text-xs font-medium transition-all",
        providerFilter === value
          ? "border-slate-800 bg-slate-900 text-white dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900"
          : "border-slate-200 bg-white text-slate-600 hover:border-slate-300 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400",
      )}
    >
      {label}
    </button>
  );

  const withFindingsCount = stats.withIssues;

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200/90 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
      <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-800">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-base font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              Repository Inventory
            </h2>
            <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
              Monitored repositories and latest scan results
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center rounded-full border border-teal-200/80 bg-teal-50 px-3 py-1 text-xs font-medium text-teal-800 dark:border-teal-900/50 dark:bg-teal-950/40 dark:text-teal-200">
              {stats.total} Connected
            </span>
            {withFindingsCount > 0 && (
              <span className="inline-flex items-center rounded-full border border-red-200/80 bg-red-50 px-3 py-1 text-xs font-medium text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200">
                {withFindingsCount} with Findings
              </span>
            )}
          </div>
        </div>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-1.5">
            {filterPill("all", "All")}
            {filterPill("github", "GitHub")}
            {filterPill("bitbucket", "Bitbucket")}
            {filterPill("azure", "Azure DevOps")}
          </div>
          <div className="flex items-center gap-2">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <Input
                placeholder="Search repositories"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                className="h-9 border-slate-200 bg-slate-50/50 pl-9 dark:border-slate-700 dark:bg-slate-900/50"
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              className="h-9 shrink-0 gap-1.5 border-slate-200"
              onClick={() => void onRefresh()}
              disabled={loading}
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", loading && "animate-spin")}
              />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <div className="px-2 pb-2 pt-1">
        {loading && repos.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-20 text-slate-500">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading inventory…
          </div>
        ) : repos.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-20 text-center">
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
              No repositories in inventory
            </p>
            <p className="max-w-sm text-xs text-slate-500">
              Add a source above to connect repositories and populate this table.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-slate-100 hover:bg-transparent dark:border-slate-800">
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Repository
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Owner / path
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Provider
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Branch
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Status
                  </TableHead>
                  <TableHead className="text-right text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Findings
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Severity
                  </TableHead>
                  <TableHead className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Last scan
                  </TableHead>
                  <TableHead className="w-[120px] text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {repos.map((repo) => {
                  const st =
                    SCAN_STATUS_LABEL[repo.scanStatus] ??
                    SCAN_STATUS_LABEL.PENDING;
                  const severity = severityFromFindings(repo.findingsCount);
                  const href = repo.scanId
                    ? `/scans/${repo.scanId}`
                    : `/projects/${repo.projectId}`;

                  return (
                    <TableRow
                      key={repo.projectId}
                      className="border-slate-100 dark:border-slate-800/80"
                    >
                      <TableCell className="py-3">
                        <Link
                          href={href}
                          className="font-medium text-slate-900 hover:text-teal-700 dark:text-slate-100 dark:hover:text-teal-400"
                        >
                          {repo.name}
                        </Link>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-600 dark:text-slate-400">
                        {repo.fullName}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="border-slate-200 font-normal text-[11px] text-slate-700 dark:border-slate-700"
                        >
                          {PROVIDER_LABEL[repo.provider]}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-600">
                          <GitBranch className="h-3 w-3 text-slate-400" />
                          {repo.branch}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={st.variant} className="font-normal">
                          {st.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                        {repo.findingsCount}
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            "inline-flex rounded-full border px-2 py-0.5 text-[11px] font-medium",
                            SEVERITY_STYLES[severity],
                          )}
                        >
                          {severity}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-slate-500">
                        {formatLastScan(repo.lastScanAt)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          {repo.scanId && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-8 gap-1 border-slate-200 text-xs"
                              disabled={
                                rescanningId === (repo.scanId ?? repo.projectId)
                              }
                              onClick={() => void handleRescan(repo)}
                            >
                              <RotateCcw
                                className={cn(
                                  "h-3 w-3",
                                  rescanningId ===
                                    (repo.scanId ?? repo.projectId) &&
                                    "animate-spin",
                                )}
                              />
                              Rescan
                            </Button>
                          )}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8 text-slate-500"
                              >
                                <MoreHorizontal className="h-4 w-4" />
                                <span className="sr-only">Actions</span>
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-44">
                              <DropdownMenuItem asChild>
                                <Link href={href}>View latest scan</Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`/projects/${repo.projectId}`}>
                                  Open project
                                </Link>
                              </DropdownMenuItem>
                              {repo.scanId && (
                                <>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem
                                    onClick={() => void handleRescan(repo)}
                                  >
                                    <RotateCcw className="mr-2 h-3.5 w-3.5" />
                                    Rescan
                                  </DropdownMenuItem>
                                </>
                              )}
                              <DropdownMenuSeparator />
                              <DropdownMenuItem asChild>
                                <Link
                                  href="/settings/integrations"
                                  className="gap-2"
                                >
                                  <ExternalLink className="mr-2 h-3.5 w-3.5" />
                                  Integrations
                                </Link>
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </section>
  );
}
