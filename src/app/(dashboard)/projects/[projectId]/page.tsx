"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ScanStatusBadge,
  GateResultBadge,
} from "@/components/scans/scan-status-badge";
import { CreateScanDialog } from "@/components/scans/create-scan-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Settings } from "lucide-react";
import Link from "next/link";

export default function ProjectDetailPage() {
  const params = useParams();
  const projectId = params.projectId as string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [project, setProject] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/projects/${projectId}`)
      .then((res) => res.json())
      .then(setProject)
      .finally(() => setLoading(false));
  }, [projectId]);

  if (loading)
    return (
      <p className="text-muted-foreground py-12 text-center">Loading...</p>
    );
  if (!project)
    return (
      <p className="text-destructive py-12 text-center">Project not found</p>
    );

  const scans = (project.scans as Array<Record<string, unknown>>) || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{project.name as string}</h1>
          <p className="text-muted-foreground">
            {(project.description as string) || "No description"}
          </p>
        </div>
        <div className="flex gap-2">
          <Link href={`/projects/${projectId}/settings`}>
            <Button variant="outline">
              <Settings className="mr-2 h-4 w-4" />
              Settings
            </Button>
          </Link>
          <CreateScanDialog
            projects={[{ id: projectId, name: project.name as string }]}
          />
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

      {/* Scan History */}
      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
          <CardDescription>Recent scans for this project</CardDescription>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">
              No scans yet. Start your first scan.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Branch</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Gate</TableHead>
                  <TableHead>Files</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id as string}>
                    <TableCell>
                      <Link
                        href={`/scans/${scan.id}`}
                        className="font-medium hover:underline"
                      >
                        {scan.scanType as string}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {(scan.branch as string) || "-"}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status as string} />
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">
                        {(scan.criticalCount as number) +
                          (scan.highCount as number) +
                          (scan.mediumCount as number) +
                          (scan.lowCount as number) +
                          (scan.infoCount as number)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <GateResultBadge result={scan.gateResult as string} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {scan.filesScanned as number}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(scan.createdAt as string).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
