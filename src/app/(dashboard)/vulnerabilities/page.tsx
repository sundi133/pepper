"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/scans/scan-status-badge";
import { FindingDetailInline } from "@/components/scans/finding-detail-panel";
import { SCANNER_LABELS } from "@/lib/constants";
import { cn } from "@/lib/utils";
import {
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  FolderOpen,
  FileCode,
  Search,
} from "lucide-react";

interface Vulnerability {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  status?: string;
  filePath?: string;
  startLine?: number;
  cweId?: string;
  cveId?: string;
  riskScore?: number | null;
  metadata?: Record<string, unknown>;
  projectId: string;
  projectName: string;
  scanId: string;
}

interface Project {
  id: string;
  name: string;
  scanId: string;
}

interface ApiResponse {
  findings: Vulnerability[];
  scannerCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  projects: Project[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const SEVERITY_CARDS = [
  { key: "CRITICAL", label: "Critical", tone: "text-red-600 dark:text-red-400" },
  { key: "HIGH", label: "High", tone: "text-orange-600 dark:text-orange-400" },
  { key: "MEDIUM", label: "Medium", tone: "text-amber-600 dark:text-amber-400" },
  { key: "LOW", label: "Low", tone: "text-blue-600 dark:text-blue-400" },
];

const STATUS_LABELS: Record<string, string> = {
  OPEN: "Open",
  IN_PROGRESS: "In Progress",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False Positive",
  ACCEPTED_RISK: "Accepted",
};

export default function VulnerabilitiesPage() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [scanner, setScanner] = useState("all");
  const [status, setStatus] = useState("all");
  const [projectId, setProjectId] = useState("all");
  const [sort, setSort] = useState("risk");
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<string | null>(null);

  // Debounce the search box so we don't query on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350);
    return () => clearTimeout(t);
  }, [search]);

  // Reset to page 1 whenever a filter changes.
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, severity, scanner, status, projectId, sort]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (debouncedSearch) params.set("q", debouncedSearch);
      if (severity !== "all") params.set("severity", severity);
      if (scanner !== "all") params.set("scanner", scanner);
      if (status !== "all") params.set("status", status);
      if (projectId !== "all") params.set("projectId", projectId);
      params.set("sort", sort);
      params.set("page", String(page));
      params.set("limit", "50");
      const res = await fetch(`/api/vulnerabilities?${params.toString()}`);
      if (!res.ok) throw new Error(`Failed to load (${res.status})`);
      setData(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load vulnerabilities");
    } finally {
      setLoading(false);
    }
  }, [debouncedSearch, severity, scanner, status, projectId, sort, page]);

  useEffect(() => {
    void load();
  }, [load]);

  const findings = data?.findings ?? [];
  const sev = data?.severityCounts ?? {};
  const projects = data?.projects ?? [];
  const scannerCounts = data?.scannerCounts ?? {};
  const pagination = data?.pagination;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-100 dark:bg-indigo-900/40">
          <ShieldAlert className="h-5 w-5 text-indigo-700 dark:text-indigo-300" aria-hidden />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            Vulnerabilities
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Every open finding across your repositories, from each repo&apos;s latest scan.
          </p>
        </div>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {SEVERITY_CARDS.map((c) => (
          <button
            key={c.key}
            onClick={() => setSeverity((s) => (s === c.key ? "all" : c.key))}
            className={cn(
              "rounded-xl border bg-white px-4 py-3 text-left shadow-sm transition-colors dark:bg-slate-950",
              severity === c.key
                ? "border-indigo-400 ring-1 ring-indigo-300 dark:border-indigo-600"
                : "border-slate-200 hover:border-slate-300 dark:border-slate-800",
            )}
          >
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">{c.label}</p>
            <p className={cn("mt-1 text-2xl font-bold", c.tone)}>{sev[c.key] ?? 0}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, file, CWE, CVE…"
            className="pl-9"
          />
        </div>
        <Select value={projectId} onValueChange={setProjectId}>
          <SelectTrigger className="w-[180px]"><SelectValue placeholder="Repository" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All repositories</SelectItem>
            {projects.map((p) => (
              <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={scanner} onValueChange={setScanner}>
          <SelectTrigger className="w-[160px]"><SelectValue placeholder="Scanner" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All scanners</SelectItem>
            {Object.entries(SCANNER_LABELS).map(([key, label]) => (
              <SelectItem key={key} value={key} disabled={!scannerCounts[key]}>
                {label as string}{scannerCounts[key] ? ` (${scannerCounts[key]})` : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-[150px]"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Open & active</SelectItem>
            {Object.entries(STATUS_LABELS).map(([key, label]) => (
              <SelectItem key={key} value={key}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={sort} onValueChange={setSort}>
          <SelectTrigger className="w-[150px]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="risk">By risk</SelectItem>
            <SelectItem value="severity">By severity</SelectItem>
            <SelectItem value="recent">Most recent</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
        <div className="grid grid-cols-[auto_90px_1fr_180px_130px_110px] items-center gap-3 border-b border-slate-200 px-4 py-2.5 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
          <span className="w-4" />
          <span>Severity</span>
          <span>Vulnerability</span>
          <span>Repository</span>
          <span>Scanner</span>
          <span>Status</span>
        </div>

        {loading ? (
          <p className="px-4 py-10 text-center text-sm text-slate-500">Loading…</p>
        ) : error ? (
          <p className="px-4 py-10 text-center text-sm text-red-600">{error}</p>
        ) : findings.length === 0 ? (
          <div className="px-4 py-12 text-center">
            <ShieldAlert className="mx-auto h-8 w-8 text-slate-300" aria-hidden />
            <p className="mt-2 text-sm font-medium text-slate-700 dark:text-slate-300">No vulnerabilities</p>
            <p className="text-xs text-slate-500">Nothing matches these filters across your latest scans.</p>
          </div>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800/70">
            {findings.map((f) => {
              const isOpen = expanded === f.id;
              return (
                <li key={f.id}>
                  <button
                    onClick={() => setExpanded(isOpen ? null : f.id)}
                    className="grid w-full grid-cols-[auto_90px_1fr_180px_130px_110px] items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-900/40"
                  >
                    {isOpen ? (
                      <ChevronDown className="h-4 w-4 text-slate-400" aria-hidden />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-slate-400" aria-hidden />
                    )}
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                        {f.title}
                      </span>
                      <span className="flex items-center gap-2 text-xs text-slate-500">
                        {f.cweId ? <span>{f.cweId}</span> : null}
                        {f.filePath ? (
                          <span className="flex min-w-0 items-center gap-1 truncate">
                            <FileCode className="h-3 w-3 shrink-0" aria-hidden />
                            <span className="truncate">{f.filePath}{f.startLine ? `:${f.startLine}` : ""}</span>
                          </span>
                        ) : null}
                      </span>
                    </span>
                    <Link
                      href={`/scans/${f.scanId}`}
                      onClick={(e) => e.stopPropagation()}
                      className="flex min-w-0 items-center gap-1 truncate text-sm text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      <FolderOpen className="h-3.5 w-3.5 shrink-0" aria-hidden />
                      <span className="truncate">{f.projectName}</span>
                    </Link>
                    <span className="truncate text-xs text-slate-600 dark:text-slate-400">
                      {(SCANNER_LABELS as Record<string, string>)[f.scanner] ?? f.scanner}
                    </span>
                    <span className="text-xs text-slate-600 dark:text-slate-400">
                      {STATUS_LABELS[f.status ?? "OPEN"] ?? f.status}
                    </span>
                  </button>
                  {isOpen && (
                    <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-4 dark:border-slate-800/70 dark:bg-slate-900/30">
                      <FindingDetailInline
                        finding={f}
                        onStatusChange={() => void load()}
                      />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Pagination */}
      {pagination && pagination.totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-slate-500">
          <span>
            {pagination.total} finding{pagination.total === 1 ? "" : "s"} · page {pagination.page} of {pagination.totalPages}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded-md border border-slate-200 px-3 py-1.5 disabled:opacity-40 dark:border-slate-800"
            >Previous</button>
            <button
              disabled={page >= pagination.totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded-md border border-slate-200 px-3 py-1.5 disabled:opacity-40 dark:border-slate-800"
            >Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
