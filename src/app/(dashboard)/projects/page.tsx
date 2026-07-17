"use client";

import { cn } from "@/lib/utils";
import { useProjects, type ProjectListFilters } from "@/hooks/use-scan-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CreateScanDialog } from "@/components/scans/create-scan-dialog";
import {
  FolderOpen,
  Plus,
  Upload,
  FolderGit2,
  MoreVertical,
  Trash2,
  KeyRound,
  Package,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

type Grade = "A" | "B" | "C" | "D" | "F";

type ProjectCardData = {
  id: string;
  name: string;
  description: string | null;
  repoUrl: string | null;
  defaultBranch: string;
  _count: { scans: number };
  scans?: Array<{ id: string }>;
  card: {
    sourceLabel: string;
    lastScanAt: string | null;
    grade: Grade | null;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    secretsCount: number;
    depsCount: number;
    totalFindings: number;
  };
};

function formatRelative(iso: string | null): string {
  if (!iso) return "Never";
  const t = Date.now() - new Date(iso).getTime();
  const s = Math.floor(t / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

function gradeBadgeClass(grade: Grade | null): string {
  if (!grade)
    return "border-border/60 bg-muted/40 text-muted-foreground ring-0";
  switch (grade) {
    case "A":
      return "border-emerald-500/50 bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/20";
    case "B":
      return "border-sky-500/50 bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/20";
    case "C":
      return "border-amber-500/50 bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/20";
    case "D":
      return "border-orange-500/50 bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/20";
    default:
      return "border-red-500/50 bg-red-500/15 text-red-400 ring-1 ring-red-500/25";
  }
}

export default function ProjectsPage() {
  const [searchInput, setSearchInput] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [source, setSource] = useState<ProjectListFilters["source"]>("all");
  const [sort, setSort] = useState<ProjectListFilters["sort"]>("recent");

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const filters = useMemo(
    () => ({ q: debouncedQ || undefined, source, sort }),
    [debouncedQ, source, sort],
  );

  const { projects, isLoading, refresh } = useProjects(filters);
  const typedProjects = projects as ProjectCardData[];

  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    id: string;
    name: string;
  } | null>(null);

  async function confirmDeleteProject() {
    if (!deleteTarget) return;
    const { id } = deleteTarget;
    setDeletingId(id);
    try {
      const res = await fetch(`/api/projects/${id}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete project");
      toast.success("Project deleted");
      setDeleteTarget(null);
      refresh();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete project",
      );
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="relative mx-auto w-full max-w-7xl space-y-5 pb-6 sm:space-y-6">
      <div
        className="pointer-events-none absolute inset-0 -z-10 opacity-[0.22]"
        style={{
          backgroundImage: `linear-gradient(to right, oklch(1 0 0 / 0.04) 1px, transparent 1px),
            linear-gradient(to bottom, oklch(1 0 0 / 0.04) 1px, transparent 1px)`,
          backgroundSize: "24px 24px",
        }}
        aria-hidden
      />

      {/* Header */}
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
        <div className="min-w-0 space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900 sm:text-3xl dark:text-slate-50">
            Projects
          </h1>
          <p className="text-sm text-slate-500 sm:text-base dark:text-slate-400">
            Manage and monitor your security scan projects
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center sm:justify-end">
          <CreateScanDialog
            triggerLabel="New Scan"
            triggerClassName="w-full bg-indigo-600 font-semibold text-white shadow-lg shadow-indigo-500/25 hover:bg-indigo-700 sm:w-auto"
            onScanCreated={() => refresh()}
          />
          <Button variant="outline" className="w-full border-slate-300 sm:w-auto dark:border-slate-700" asChild>
            <Link href="/projects/new">
              <Plus className="mr-2 h-4 w-4" />
              New project
            </Link>
          </Button>
        </div>
      </header>

      {/* Toolbar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative w-full sm:max-w-md">
          <Input
            placeholder="Search projects…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="h-10 border-slate-300 bg-white pr-3 dark:border-slate-600 dark:bg-slate-950"
            aria-label="Search projects"
          />
        </div>
        <div className="flex w-full flex-wrap gap-2 sm:w-auto sm:justify-end">
          <Select
            value={source}
            onValueChange={(v) =>
              setSource(v as ProjectListFilters["source"])
            }
          >
            <SelectTrigger className="h-10 w-full border-slate-300 bg-white sm:w-[140px] dark:border-slate-600 dark:bg-slate-950">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="repo">Repository</SelectItem>
              <SelectItem value="upload">Uploaded</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={sort}
            onValueChange={(v) => setSort(v as ProjectListFilters["sort"])}
          >
            <SelectTrigger className="h-10 w-full border-slate-300 bg-white sm:w-[160px] dark:border-slate-600 dark:bg-slate-950">
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="recent">Most recent</SelectItem>
              <SelectItem value="name">Name (A–Z)</SelectItem>
              <SelectItem value="vulns">Most vulnerabilities</SelectItem>
              <SelectItem value="grade">Best grade first</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center gap-2 py-20 text-slate-500">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
          <span className="text-sm">Loading projects…</span>
        </div>
      ) : typedProjects.length === 0 ? (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="flex flex-col items-center justify-center py-16">
            <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500">
              <FolderOpen className="h-7 w-7" />
            </div>
            <h3 className="mt-4 text-base font-semibold text-slate-900 dark:text-slate-50">No projects</h3>
            <p className="mt-1 mb-6 max-w-sm text-center text-sm text-slate-500 dark:text-slate-400">
              {searchInput || source !== "all"
                ? "No projects match your filters. Try adjusting search or type."
                : "Create your first project to start scanning code."}
            </p>
            {!searchInput && source === "all" ? (
              <Button className="bg-indigo-600 text-white hover:bg-indigo-700" asChild>
                <Link href="/projects/new">Create project</Link>
              </Button>
            ) : null}
          </div>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="hidden border-b border-slate-100 bg-slate-50/80 px-6 py-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/50 md:flex md:items-center">
            <div className="w-[44px]" />
            <div className="flex-1 min-w-0">Project</div>
            <div className="w-[160px] shrink-0">Vulnerabilities</div>
            <div className="w-[160px] shrink-0">Secrets / Deps</div>
            <div className="w-[80px] shrink-0">Grade</div>
            <div className="w-[120px] shrink-0">Last scan</div>
            <div className="w-10 shrink-0" />
          </div>
          <ul className="list-none p-0">
            {typedProjects.map((project, i) => (
              <li
                key={project.id}
                className={cn(
                  "border-b border-slate-100 last:border-b-0 dark:border-slate-800",
                  i % 2 === 0 ? "bg-white dark:bg-slate-950" : "bg-slate-50/50 dark:bg-slate-900/30",
                )}
              >
                <ProjectCard
                  project={project}
                  onDelete={() =>
                    setDeleteTarget({ id: project.id, name: project.name })
                  }
                  deleting={deletingId === project.id}
                />
              </li>
            ))}
          </ul>
        </div>
      )}

      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open && deletingId === null) setDeleteTarget(null);
        }}
      >
        <DialogContent showCloseButton={deletingId === null}>
          <DialogHeader>
            <DialogTitle>Delete project?</DialogTitle>
            <DialogDescription>
              {deleteTarget ? (
                <>
                  Delete project{" "}
                  <span className="font-medium text-foreground">
                    &quot;{deleteTarget.name}&quot;
                  </span>{" "}
                  and all of its scans? This cannot be undone.
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              disabled={deletingId !== null}
              onClick={() => setDeleteTarget(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={deletingId !== null}
              onClick={confirmDeleteProject}
            >
              {deletingId !== null ? "Deleting…" : "Delete project"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ProjectCard({
  project,
  onDelete,
  deleting,
}: {
  project: ProjectCardData;
  onDelete: () => void;
  deleting: boolean;
}) {
  const { card } = project;
  const Icon = card.sourceLabel === "Uploaded" ? Upload : FolderGit2;
  const hasVulns = card.totalFindings > 0;
  const latestScanId = project.scans?.[0]?.id ?? null;
  const primaryHref = latestScanId
    ? `/scans/${latestScanId}#scan-findings`
    : `/projects/${project.id}`;

  return (
    <div
      className="group relative flex items-center gap-6 px-6 py-4 transition-colors hover:bg-indigo-50/50 dark:hover:bg-indigo-950/20"
    >
      <Link
        href={primaryHref}
        className="absolute inset-0 z-0"
        aria-label={
          latestScanId
            ? `View findings for ${project.name}`
            : `Open project ${project.name}`
        }
      />
      <div className="w-[44px] shrink-0">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600 ring-1 ring-indigo-200 dark:bg-indigo-950/40 dark:text-indigo-300 dark:ring-indigo-800">
          <Icon className="h-4 w-4" aria-hidden />
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <p className="truncate text-sm font-semibold text-slate-900 group-hover:text-indigo-600 dark:text-slate-100">
          {project.name}
        </p>
        <p className="truncate text-xs text-slate-500 dark:text-slate-400">{card.sourceLabel}</p>
      </div>
      <div className="hidden w-[160px] shrink-0 md:flex md:items-center md:gap-1.5">
        {hasVulns ? (
          <>
            {card.criticalCount > 0 && (
              <span className="inline-flex items-center rounded-md border border-red-200 bg-red-50 px-2 py-0.5 text-xs font-bold tabular-nums text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-300">
                {card.criticalCount}C
              </span>
            )}
            {card.highCount > 0 && (
              <span className="inline-flex items-center rounded-md border border-orange-200 bg-orange-50 px-2 py-0.5 text-xs font-bold tabular-nums text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/30 dark:text-orange-300">
                {card.highCount}H
              </span>
            )}
            {card.mediumCount > 0 && (
              <span className="inline-flex items-center rounded-md border border-yellow-200 bg-yellow-50 px-2 py-0.5 text-xs font-bold tabular-nums text-yellow-800 dark:border-yellow-900/50 dark:bg-yellow-950/30 dark:text-yellow-300">
                {card.mediumCount}M
              </span>
            )}
            {card.lowCount > 0 && (
              <span className="inline-flex items-center rounded-md border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-xs font-bold tabular-nums text-emerald-800 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-300">
                {card.lowCount}L
              </span>
            )}
          </>
        ) : (
          <span className="text-xs text-slate-400">None</span>
        )}
      </div>
      <div className="hidden w-[160px] shrink-0 md:flex md:items-center md:gap-4">
        <span className="inline-flex items-center gap-1.5 text-sm text-slate-500 dark:text-slate-400">
          <KeyRound className="h-3.5 w-3.5 text-indigo-500/70" />
          <span className="tabular-nums font-medium text-slate-700 dark:text-slate-300">{card.secretsCount}</span>
        </span>
        <span className="inline-flex items-center gap-1.5 text-sm text-slate-500 dark:text-slate-400">
          <Package className="h-3.5 w-3.5 text-indigo-500/70" />
          <span className="tabular-nums font-medium text-slate-700 dark:text-slate-300">{card.depsCount}</span>
        </span>
      </div>
      <div className="hidden w-[80px] shrink-0 md:block">
        <span
          className={`flex h-8 w-8 items-center justify-center rounded-md text-sm font-bold tabular-nums ${gradeBadgeClass(card.grade)}`}
          title={card.grade ? `Grade ${card.grade}` : "No completed scan"}
        >
          {card.grade ?? "—"}
        </span>
      </div>
      <div className="hidden w-[120px] shrink-0 md:block">
        <span className="text-sm text-slate-500 dark:text-slate-400">
          {formatRelative(card.lastScanAt)}
        </span>
      </div>
      <div className="relative z-10 shrink-0 pointer-events-auto">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
              aria-label="Project actions"
            >
              <MoreVertical className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-[10rem]">
            <DropdownMenuItem asChild>
              <Link href={`/projects/${project.id}`}>
                <ExternalLink className="mr-2 h-4 w-4" />
                Open project
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              disabled={deleting}
              onClick={onDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}
