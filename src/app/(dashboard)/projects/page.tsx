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
import { ScanStatusBadge, GateResultBadge } from "@/components/scans/scan-status-badge";
import { FolderOpen, Plus, GitBranch, AlertTriangle } from "lucide-react";
import Link from "next/link";

export default function ProjectsPage() {
  const { projects, isLoading } = useProjects();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Projects</h1>
          <p className="text-muted-foreground">Manage your scanned repositories</p>
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
            const lastScan = (project.scans as Array<Record<string, unknown>>)?.[0];
            const scanCount = (project._count as { scans: number })?.scans || 0;
            return (
              <Link key={project.id as string} href={`/projects/${project.id}`}>
                <Card className="hover:border-primary/50 transition-colors cursor-pointer">
                  <CardHeader>
                    <CardTitle className="text-lg">{project.name as string}</CardTitle>
                    <CardDescription>
                      {project.description as string || "No description"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {project.repoUrl && (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <GitBranch className="h-4 w-4" />
                          <span className="truncate">{project.repoUrl as string}</span>
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
                                {((lastScan.criticalCount as number) + (lastScan.highCount as number)) > 0 && (
                                  <span className="flex items-center gap-1 text-sm text-destructive">
                                    <AlertTriangle className="h-3 w-3" />
                                    {(lastScan.criticalCount as number) + (lastScan.highCount as number)}
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
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
