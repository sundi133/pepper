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

export default function ProjectsPage() {
  const { projects, isLoading, refresh } = useProjects();
  const [deletingId, setDeletingId] = useState<string | null>(null);

  async function handleDeleteProject(projectId: string, projectName: string) {
    if (
      !confirm(
        `Delete project "${projectName}" and all of its scans? This cannot be undone.`,
      )
    ) {
      return;
    }

    setDeletingId(projectId);
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete project");
      toast.success("Project deleted");
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
                      disabled={deletingId === project.id}
                      onClick={() =>
                        handleDeleteProject(
                          project.id as string,
                          project.name as string,
                        )
                      }
                    >
                      <Trash2 className="h-4 w-4" />
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
    </div>
  );
}
