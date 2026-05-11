"use client";

import { useProjects } from "@/hooks/use-scan-polling";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import {
  FolderOpen,
  Plus,
  GitBranch,
  AlertTriangle,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function ProjectsPage() {
  const { projects, isLoading, refresh } = useProjects();
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
    <div className="space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Projects" },
        ]}
      />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Projects</h1>
          <p className="text-muted-foreground">
            Manage your scanned repositories
          </p>
        </div>
        <Link href="/projects/new">
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            New Project
          </Button>
        </Link>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground text-center py-12">Loading...</p>
      ) : projects.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FolderOpen className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No projects yet</h3>
            <p className="text-muted-foreground mb-4">
              Create your first project to start scanning code.
            </p>
            <Link href="/projects/new">
              <Button>Create Project</Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          {projects.map((project: any) => {
            const lastScan = (
              project.scans as Array<Record<string, unknown>>
            )?.[0];
            const scanCount = (project._count as { scans: number })?.scans || 0;
            return (
              <Card
                key={project.id as string}
                className="hover:border-primary/50 transition-colors"
              >
                <CardHeader>
                  <div className="flex items-start justify-between gap-3">
                    <Link href={`/projects/${project.id}`}>
                      <CardTitle className="text-lg hover:underline">
                        {project.name as string}
                      </CardTitle>
                    </Link>
                    <Button
                      variant="outline"
                      size="sm"
                      className="group h-8 min-w-8 shrink-0 overflow-hidden border-destructive/40 px-2 text-destructive transition-[padding,gap] duration-200 hover:border-destructive hover:bg-destructive/10 hover:px-2.5"
                      disabled={deletingId === project.id}
                      aria-label="Delete project"
                      onClick={() =>
                        setDeleteTarget({
                          id: project.id as string,
                          name: project.name as string,
                        })
                      }
                    >
                      <span className="flex items-center gap-0 transition-[gap] duration-200 group-hover:gap-1.5">
                        <Trash2 className="h-4 w-4 shrink-0" aria-hidden />
                        <span className="max-w-0 overflow-hidden text-xs font-semibold whitespace-nowrap transition-[max-width] duration-200 group-hover:max-w-14">
                          Delete
                        </span>
                      </span>
                    </Button>
                  </div>
                  <CardDescription>
                    {(project.description as string) || "No description"}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {project.repoUrl && (
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <GitBranch className="h-4 w-4" />
                        <span className="truncate">
                          {project.repoUrl as string}
                        </span>
                      </div>
                    )}
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">
                        {scanCount} scans
                      </span>
                      {lastScan && (
                        <div className="flex items-center gap-2">
                          <ScanStatusBadge status={lastScan.status as string} />
                          {lastScan.status === "COMPLETED" && (
                            <>
                              {(lastScan.criticalCount as number) +
                                (lastScan.highCount as number) >
                                0 && (
                                <span className="flex items-center gap-1 text-sm text-destructive">
                                  <AlertTriangle className="h-3 w-3" />
                                  {(lastScan.criticalCount as number) +
                                    (lastScan.highCount as number)}
                                </span>
                              )}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
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
