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
  selectedRepo?: UnifiedConnectedRepo | null;
  onSelectRepo?: (repo: UnifiedConnectedRepo) => void;
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
  selectedRepo,
  onSelectRepo,
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
    <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
      <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
              Connected Repositories
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Monitored repositories and latest scan results
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center rounded-full border border-teal-200 bg-teal-50/80 px-3 py-1.5 text-xs font-medium text-teal-800 dark:border-teal-900/50 dark:bg-teal-950/50 dark:text-teal-300">
              {stats.total} Connected
            </span>
            {withFindingsCount > 0 && (
              <span className="inline-flex items-center rounded-full border border-red-200 bg-red-50/80 px-3 py-1.5 text-xs font-medium text-red-800 dark:border-red-900/50 dark:bg-red-950/50 dark:text-red-300">
                {withFindingsCount} with Issues
              </span>
            )}
          </div>
        </div>

        <div className="mt-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-2">
            {filterPill("all", "All")}
            {filterPill("github", "GitHub")}
            {filterPill("bitbucket", "Bitbucket")}
            {filterPill("azure", "Azure DevOps")}
          </div>
          <div className="flex items-center gap-2">
            <div className="relative flex-1 sm:w-64">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <Input
                placeholder="Search repositories…"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                className="h-10 border-slate-200 bg-slate-50 pl-10 dark:border-slate-700 dark:bg-slate-900/50"
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              className="h-10 shrink-0 gap-2 border-slate-200 px-3"
              onClick={() => void onRefresh()}
              disabled={loading}
            >
              <RefreshCw
                className={cn("h-4 w-4", loading && "animate-spin")}
              />
              <span className="hidden sm:inline">Refresh</span>
            </Button>
          </div>
        </div>
      </div>

      <div className="px-1 pb-1 pt-0">
        {loading && repos.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-20 text-slate-500">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading repositories…
          </div>
        ) : repos.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-20 text-center">
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
              No repositories connected yet
            </p>
            <p className="max-w-sm text-xs text-slate-600 dark:text-slate-400">
              Use the form above to add repositories from your integrations.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-slate-200 hover:bg-transparent dark:border-slate-800">
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Repository
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Owner / Path
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Provider
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Branch
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Status
                  </TableHead>
                  <TableHead className="text-right text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Issues
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Severity
                  </TableHead>
                  <TableHead className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    Last Scan
                  </TableHead>
                  <TableHead className="w-[120px] text-xs font-semibold text-slate-600 dark:text-slate-400">
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
                  const isSelected = selectedRepo?.projectId === repo.projectId;

                  return (
                    <TableRow
                      key={repo.projectId}
                      className={cn(
                        "border-slate-100 cursor-pointer transition-colors dark:border-slate-800/80",
                        isSelected
                          ? "bg-purple-50/50 dark:bg-purple-950/20 border-purple-200 dark:border-purple-800/50"
                          : "hover:bg-slate-50/50 dark:hover:bg-slate-900/30"
                      )}
                      onClick={() => onSelectRepo?.(repo)}
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
