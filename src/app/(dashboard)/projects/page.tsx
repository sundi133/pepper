"use client";

import { useState } from "react";
import { useProjects } from "@/hooks/use-scan-polling";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import { FolderOpen, Plus, GitBranch, AlertTriangle, Trash2 } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

export default function ProjectsPage() {
  const { projects, isLoading, refresh } = useProjects();
  const [pendingDelete, setPendingDelete] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function confirmDeleteProject() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/projects/${pendingDelete.id}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const err = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(err.error || "Failed to delete project");
      }
      toast.success("Project deleted");
      setPendingDelete(null);
      await refresh();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete project",
      );
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
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
            const id = project.id as string;
            const name = project.name as string;
            return (
              <Card
                key={id}
                className="flex flex-row overflow-hidden transition-colors hover:border-primary/50"
              >
                <Link
                  href={`/projects/${id}`}
                  className="flex min-w-0 flex-1 flex-col hover:bg-muted/30"
                >
                  <CardHeader>
                    <CardTitle className="text-lg">{name}</CardTitle>
                    <CardDescription>
                      {(project.description as string) || "No description"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {project.repoUrl && (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <GitBranch className="h-4 w-4 shrink-0" />
                          <span className="truncate">
                            {project.repoUrl as string}
                          </span>
                        </div>
                      )}
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm text-muted-foreground">
                          {scanCount} scans
                        </span>
                        {lastScan && (
                          <div className="flex shrink-0 items-center gap-2">
                            <ScanStatusBadge
                              status={lastScan.status as string}
                            />
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
                </Link>
                <div className="flex shrink-0 flex-col border-l border-border bg-muted/20">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="mt-2 mr-1 h-9 w-9 rounded-md text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                    aria-label={`Delete project ${name}`}
                    onClick={(e) => {
                      e.preventDefault();
                      setPendingDelete({ id, name });
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      <Dialog
        open={pendingDelete != null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete project?</DialogTitle>
            <DialogDescription>
              This will permanently remove{" "}
              <span className="font-semibold text-foreground">
                {pendingDelete?.name}
              </span>{" "}
              and all associated scans and findings. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setPendingDelete(null)}
              disabled={deleting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={confirmDeleteProject}
              disabled={deleting}
            >
              {deleting ? "Deleting…" : "Delete project"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
