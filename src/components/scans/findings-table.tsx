"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { SCANNER_LABELS } from "@/lib/constants";
import { FileCode, ChevronRight } from "lucide-react";

interface Finding {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string;
  startLine?: number;
  ruleId?: string;
  cweId?: string;
  confidence?: number;
}

interface FindingsTableProps {
  findings: Finding[];
  onSelect?: (finding: Finding) => void;
  selectedId?: string;
}

export function FindingsTable({
  findings,
  onSelect,
  selectedId,
}: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <FileCode className="h-12 w-12 mb-4" />
        <p className="text-lg font-medium">No findings</p>
        <p className="text-sm">This scan did not detect any issues.</p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-24">Severity</TableHead>
          <TableHead>Finding</TableHead>
          <TableHead className="w-32">Scanner</TableHead>
          <TableHead className="w-48">File</TableHead>
          <TableHead className="w-8" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((finding) => (
          <TableRow
            key={finding.id}
            className={`cursor-pointer ${selectedId === finding.id ? "bg-muted" : ""}`}
            onClick={() => onSelect?.(finding)}
          >
            <TableCell>
              <SeverityBadge severity={finding.severity} />
            </TableCell>
            <TableCell>
              <div>
                <p className="font-medium text-sm">{finding.title}</p>
                {finding.cweId && (
                  <span className="text-xs text-muted-foreground">
                    {finding.cweId}
                  </span>
                )}
              </div>
            </TableCell>
            <TableCell>
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
            </TableCell>
            <TableCell>
              {finding.filePath && (
                <span className="text-xs text-muted-foreground font-mono">
                  {finding.filePath}
                  {finding.startLine ? `:${finding.startLine}` : ""}
                </span>
              )}
            </TableCell>
            <TableCell>
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
