"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
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
import {
  ScanStatusBadge,
  GateResultBadge,
} from "@/components/scans/scan-status-badge";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Settings, Trash2 } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

export default function ProjectDetailPage() {
  const params = useParams();
  const projectId = params.projectId as string;
  const router = useRouter();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [project, setProject] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);
  const [deletingScanId, setDeletingScanId] = useState<string | null>(null);
  const [projectDeleteOpen, setProjectDeleteOpen] = useState(false);
  const [scanToDelete, setScanToDelete] = useState<string | null>(null);

  function fetchProject() {
    fetch(`/api/projects/${projectId}`)
      .then((res) => res.json())
      .then(setProject)
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    fetchProject();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  if (loading) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb
          items={[
            { label: "Dashboard", href: "/dashboard" },
            { label: "Projects", href: "/projects" },
            { label: "Loading…" },
          ]}
        />
        <p className="text-muted-foreground py-12 text-center">Loading...</p>
      </div>
    );
  }
  if (!project) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb
          items={[
            { label: "Dashboard", href: "/dashboard" },
            { label: "Projects", href: "/projects" },
            { label: "Project not found" },
          ]}
        />
        <p className="text-destructive py-12 text-center">Project not found</p>
      </div>
    );
  }

  const scans = (project.scans as Array<Record<string, unknown>>) || [];
  const scan = scans[0] as Record<string, unknown> | undefined;

  async function executeDeleteProject() {
    setDeleting(true);
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete project");
      toast.success("Project deleted");
      setProjectDeleteOpen(false);
      router.push("/projects");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete project",
      );
      setDeleting(false);
    }
  }

  async function executeDeleteScan() {
    if (!scanToDelete) return;
    const scanId = scanToDelete;
    setDeletingScanId(scanId);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete scan");
      toast.success("Scan deleted");
      setScanToDelete(null);
      fetchProject();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete scan",
      );
    } finally {
      setDeletingScanId(null);
    }
  }

  return (
    <TooltipProvider>
    <div className="space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Projects", href: "/projects" },
          { label: project.name as string },
        ]}
      />
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold">{project.name as string}</h1>
          <p className="text-muted-foreground">
            {(project.description as string) || "No description"}
          </p>
        </div>
        <div className="flex flex-wrap gap-2 shrink-0">
          <Button
            variant="destructive"
            disabled={deleting}
            onClick={() => setProjectDeleteOpen(true)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
          <Link href={`/projects/${projectId}/settings`}>
            <Button variant="outline">
              <Settings className="mr-2 h-4 w-4" />
              Settings
            </Button>
          </Link>
        </div>
      </div>

      {/* Build Gate */}
      {project.buildGate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Build Gate Policy</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-6 text-sm">
              <div>
                <span className="text-muted-foreground">Max Critical:</span>{" "}
                <span className="font-medium">
                  {(project.buildGate as Record<string, number>).maxCritical}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Max High:</span>{" "}
                <span className="font-medium">
                  {(project.buildGate as Record<string, number>).maxHigh}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Max Medium:</span>{" "}
                <span className="font-medium">
                  {(project.buildGate as Record<string, number>).maxMedium}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Single project scan */}
      <Card>
        <CardHeader>
          <CardTitle>Project scan</CardTitle>
          <CardDescription>
            One scan per project. Start or replace it from{" "}
            <Link href="/scans/new" className="font-medium text-primary hover:underline">
              New Scan
            </Link>{" "}
            in the sidebar (this page is view-only for scanning).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!scan ? (
            <p className="text-center text-sm text-muted-foreground py-8">
              No scan yet. Go to{" "}
              <Link
                href="/scans/new"
                className="font-medium text-primary hover:underline"
              >
                New Scan
              </Link>{" "}
              in the sidebar, select this project, and start a scan (one per
              project).
            </p>
          ) : (
            <div className="flex flex-col gap-4 rounded-lg border border-border/60 bg-muted/20 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0 space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Link
                    href={`/scans/${scan.id as string}`}
                    className="font-semibold text-foreground hover:text-primary hover:underline"
                  >
                    {scan.scanType as string}
                  </Link>
                  <ScanStatusBadge status={scan.status as string} />
                </div>
                <p className="text-sm text-muted-foreground">
                  Branch: {(scan.branch as string) || "—"} · Files scanned:{" "}
                  {scan.filesScanned as number} ·{" "}
                  {new Date(scan.createdAt as string).toLocaleString()}
                </p>
                <p className="text-sm">
                  Findings:{" "}
                  <span className="font-medium">
                    {(scan.criticalCount as number) +
                      (scan.highCount as number) +
                      (scan.mediumCount as number) +
                      (scan.lowCount as number) +
                      (scan.infoCount as number)}
                  </span>
                  {scan.status === "COMPLETED" ? (
                    <span className="ml-2 inline-flex align-middle">
                      <GateResultBadge result={scan.gateResult as string} />
                    </span>
                  ) : null}
                </p>
              </div>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="shrink-0"
                    disabled={
                      deletingScanId === (scan.id as string) ||
                      scan.status === "RUNNING" ||
                      scan.status === "PAUSED"
                    }
                    onClick={() => setScanToDelete(scan.id as string)}
                    aria-label="Delete scan"
                  >
                    <Trash2 className="h-4 w-4" aria-hidden />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Delete scan</TooltipContent>
              </Tooltip>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={projectDeleteOpen}
        onOpenChange={(open) => {
          if (!open && !deleting) setProjectDeleteOpen(false);
        }}
      >
        <DialogContent showCloseButton={!deleting}>
          <DialogHeader>
            <DialogTitle>Delete project?</DialogTitle>
            <DialogDescription>
              Delete project{" "}
              <span className="font-medium text-foreground">
                &quot;{project.name as string}&quot;
              </span>{" "}
              and all of its scans? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              disabled={deleting}
              onClick={() => setProjectDeleteOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={deleting}
              onClick={executeDeleteProject}
            >
              {deleting ? "Deleting…" : "Delete project"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={scanToDelete !== null}
        onOpenChange={(open) => {
          if (!open && deletingScanId === null) setScanToDelete(null);
        }}
      >
        <DialogContent showCloseButton={deletingScanId === null}>
          <DialogHeader>
            <DialogTitle>Delete scan?</DialogTitle>
            <DialogDescription>
              Delete this scan and all of its findings? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              disabled={deletingScanId !== null}
              onClick={() => setScanToDelete(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={deletingScanId !== null}
              onClick={executeDeleteScan}
            >
              {deletingScanId !== null ? "Deleting…" : "Delete scan"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </TooltipProvider>
  );
}
