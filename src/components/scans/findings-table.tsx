"use client";

import { Fragment, useState } from "react";
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
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { SCANNER_LABELS } from "@/lib/constants";
import { FileCode, ChevronRight, ChevronDown } from "lucide-react";
import {
  FindingDetailContent,
  type FindingDetailFinding,
} from "@/components/scans/finding-detail-panel";
import { toast } from "sonner";

interface Finding {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  status?: string;
  filePath?: string;
  startLine?: number;
  ruleId?: string;
  cweId?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
  snippet?: string;
  endLine?: number;
  cveId?: string;
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  OPEN: {
    label: "Open",
    color:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-400",
  },
  IN_PROGRESS: {
    label: "In Progress",
    color: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-400",
  },
  FALSE_POSITIVE: {
    label: "False Positive",
    color: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  },
  ACCEPTED_RISK: {
    label: "Accepted",
    color:
      "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-400",
  },
  RESOLVED: {
    label: "Resolved",
    color: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-400",
  },
};

interface FindingsTableProps {
  findings: Finding[];
  /** Which finding row is expanded to show full detail below */
  expandedId?: string | null;
  onExpandedChange?: (id: string | null) => void;
  onBulkStatusChange?: () => void;
}

export function FindingsTable({
  findings,
  expandedId,
  onExpandedChange,
  onBulkStatusChange,
}: FindingsTableProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<string>("");
  const [bulkLoading, setBulkLoading] = useState(false);

  const allSelected = findings.length > 0 && selected.size === findings.length;
  const someSelected = selected.size > 0 && selected.size < findings.length;

  function toggleAll() {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.id)));
    }
  }

  function toggleOne(id: string) {
    const next = new Set(selected);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelected(next);
  }

  async function handleBulkUpdate() {
    if (!bulkStatus || selected.size === 0) return;
    setBulkLoading(true);

    try {
      const res = await fetch("/api/findings/bulk", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findingIds: Array.from(selected),
          status: bulkStatus,
        }),
      });

      if (!res.ok) throw new Error("Failed to update");
      const result = await res.json();
      toast.success(
        `Updated ${result.updated} findings to ${bulkStatus.replace("_", " ").toLowerCase()}`,
      );
      setSelected(new Set());
      setBulkStatus("");
      onBulkStatusChange?.();
    } catch {
      toast.error("Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  }

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
    <div>
      {/* Bulk Action Bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 mb-3 rounded-lg border bg-muted/50 px-4 py-2">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <Select value={bulkStatus} onValueChange={setBulkStatus}>
            <SelectTrigger className="h-8 w-[160px] text-xs">
              <SelectValue placeholder="Set status..." />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="OPEN">Open</SelectItem>
              <SelectItem value="IN_PROGRESS">In Progress</SelectItem>
              <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
              <SelectItem value="ACCEPTED_RISK">Accepted Risk</SelectItem>
              <SelectItem value="RESOLVED">Resolved</SelectItem>
            </SelectContent>
          </Select>
          <Button
            size="sm"
            className="h-8 text-xs"
            onClick={handleBulkUpdate}
            disabled={!bulkStatus || bulkLoading}
          >
            {bulkLoading ? "Updating..." : "Apply"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-8 text-xs"
            onClick={() => setSelected(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <Checkbox
                checked={allSelected}
                ref={(el) => {
                  if (el) {
                    (el as unknown as HTMLInputElement).indeterminate =
                      someSelected;
                  }
                }}
                onCheckedChange={toggleAll}
              />
            </TableHead>
            <TableHead className="w-24">Severity</TableHead>
            <TableHead>Finding</TableHead>
            <TableHead className="w-24">Status</TableHead>
            <TableHead className="w-32">Scanner</TableHead>
            <TableHead className="w-48">File</TableHead>
            <TableHead className="w-8" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((finding) => {
            const isOpen = expandedId === finding.id;
            return (
              <Fragment key={finding.id}>
                <TableRow
                  data-state={isOpen ? "open" : "closed"}
                  className={`cursor-pointer transition-colors ${isOpen ? "bg-muted/80" : "hover:bg-muted/50"}`}
                  onClick={(e) => {
                    const el = e.target as HTMLElement;
                    if (el.closest("[data-checkbox-cell]")) return;
                    onExpandedChange?.(isOpen ? null : finding.id);
                  }}
                >
                  <TableCell
                    data-checkbox-cell
                    onClick={(e) => e.stopPropagation()}
                  >
                    <Checkbox
                      checked={selected.has(finding.id)}
                      onCheckedChange={() => toggleOne(finding.id)}
                    />
                  </TableCell>
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
                    {finding.status && STATUS_LABELS[finding.status] && (
                      <span
                        className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${STATUS_LABELS[finding.status].color}`}
                      >
                        {STATUS_LABELS[finding.status].label}
                      </span>
                    )}
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
                  <TableCell className="w-10 text-right">
                    {isOpen ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground inline" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground inline" />
                    )}
                  </TableCell>
                </TableRow>
                {isOpen && (
                  <TableRow className="hover:bg-transparent border-b">
                    <TableCell
                      colSpan={7}
                      className="p-0 align-top bg-muted/15 border-t border-primary/15"
                    >
                      <div className="min-w-0 max-w-full overflow-x-hidden p-3 sm:p-4">
                        <FindingDetailContent
                          finding={finding as FindingDetailFinding}
                          onCollapse={() => onExpandedChange?.(null)}
                          onStatusChange={() => onBulkStatusChange?.()}
                        />
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
