"use client";

import { useProjects, type ProjectListFilters } from "@/hooks/use-scan-polling";
import { Card, CardContent } from "@/components/ui/card";
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
  AlertTriangle,
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
          <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            Projects
          </h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            Manage and monitor your security scan projects
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center sm:justify-end">
          <CreateScanDialog
            triggerLabel="New Scan"
            triggerClassName="w-full bg-primary font-semibold text-primary-foreground shadow-lg shadow-primary/20 hover:bg-primary/90 sm:w-auto"
            onScanCreated={() => refresh()}
          />
          <Button variant="outline" className="w-full border-border/80 sm:w-auto" asChild>
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
            className="h-10 border-border/60 bg-card/60 pr-3"
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
            <SelectTrigger className="h-10 w-full border-border/60 bg-card/60 sm:w-[140px]">
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
            <SelectTrigger className="h-10 w-full border-border/60 bg-card/60 sm:w-[160px]">
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
        <p className="py-16 text-center text-sm text-muted-foreground">
          Loading projects…
        </p>
      ) : typedProjects.length === 0 ? (
        <Card className="border-border/60 bg-card/80">
          <CardContent className="flex flex-col items-center justify-center py-14">
            <FolderOpen className="mb-4 h-12 w-12 text-muted-foreground" />
            <h3 className="text-lg font-medium text-foreground">No projects</h3>
            <p className="mb-6 max-w-sm text-center text-sm text-muted-foreground">
              {searchInput || source !== "all"
                ? "No projects match your filters. Try adjusting search or type."
                : "Create your first project to start scanning code."}
            </p>
            {!searchInput && source === "all" ? (
              <Button asChild>
                <Link href="/projects/new">Create project</Link>
              </Button>
            ) : null}
          </CardContent>
        </Card>
      ) : (
        <ul className="grid list-none grid-cols-1 gap-3 p-0 sm:grid-cols-2 sm:gap-4 xl:grid-cols-3">
          {typedProjects.map((project) => (
            <li key={project.id}>
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
    <Card className="group relative h-full overflow-hidden border-border/60 bg-card/90 shadow-sm transition-colors hover:border-primary/30">
      <Link
        href={primaryHref}
        className="absolute inset-0 z-0 rounded-xl"
        aria-label={
          latestScanId
            ? `View findings for ${project.name}`
            : `Open project ${project.name}`
        }
      />
      <CardContent className="relative z-10 flex h-full flex-col p-4 sm:p-5 pointer-events-none">
        <div className="flex items-start justify-between gap-2">
          <div className="flex min-w-0 flex-1 items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/25">
              <Icon className="h-5 w-5" aria-hidden />
            </div>
            <div className="min-w-0">
              <p className="truncate font-semibold text-foreground group-hover:text-primary">
                {project.name}
              </p>
              <p className="text-xs text-muted-foreground">{card.sourceLabel}</p>
            </div>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative z-20 h-8 w-8 shrink-0 pointer-events-auto text-muted-foreground hover:text-foreground"
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

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="flex items-center gap-1 text-xs font-medium text-muted-foreground">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500/90" />
            Vulnerabilities:
          </span>
          {hasVulns ? (
            <div className="flex flex-wrap items-center gap-1">
              {card.criticalCount > 0 && (
                <span className="rounded px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-white bg-[#ef4444]">
                  {card.criticalCount}C
                </span>
              )}
              {card.highCount > 0 && (
                <span className="rounded px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-white bg-[#f97316]">
                  {card.highCount}H
                </span>
              )}
              {card.mediumCount > 0 && (
                <span className="rounded px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-foreground bg-[#eab308]">
                  {card.mediumCount}M
                </span>
              )}
              {card.lowCount > 0 && (
                <span className="rounded px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-emerald-950 bg-emerald-400">
                  {card.lowCount}L
                </span>
              )}
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">None</span>
          )}
        </div>

        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <KeyRound className="h-3.5 w-3.5 text-primary/80" />
            <span className="tabular-nums">{card.secretsCount}</span> secrets
          </span>
          <span className="inline-flex items-center gap-1">
            <Package className="h-3.5 w-3.5 text-primary/80" />
            <span className="tabular-nums">{card.depsCount}</span> deps
          </span>
        </div>

        <div className="mt-auto flex items-end justify-between gap-3 pt-3">
          <p className="text-xs text-muted-foreground">
            Last scan:{" "}
            <span className="font-medium text-foreground/90">
              {formatRelative(card.lastScanAt)}
            </span>
          </p>
          <span
            className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-sm font-bold tabular-nums ${gradeBadgeClass(card.grade)}`}
            title={card.grade ? `Grade ${card.grade}` : "No completed scan"}
          >
            {card.grade ?? "—"}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
