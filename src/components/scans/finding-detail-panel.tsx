"use client";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SCANNER_LABELS } from "@/lib/constants";
import { FileCode, Shield, Info, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface Finding {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  ruleId?: string;
  cweId?: string;
  cveId?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
}

interface FindingDetailPanelProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
}

export function FindingDetailPanel({
  finding,
  open,
  onClose,
}: FindingDetailPanelProps) {
  if (!finding) return null;

  const copyDescription = () => {
    navigator.clipboard.writeText(finding.description);
    toast.success("Copied to clipboard");
  };

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-xl">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <Badge variant="outline">
              {SCANNER_LABELS[finding.scanner as keyof typeof SCANNER_LABELS] || finding.scanner}
            </Badge>
          </div>
          <SheetTitle className="text-left">{finding.title}</SheetTitle>
          <SheetDescription className="text-left">
            {finding.ruleId && <span className="font-mono">{finding.ruleId}</span>}
            {finding.cweId && <span className="ml-2">{finding.cweId}</span>}
            {finding.cveId && <span className="ml-2">{finding.cveId}</span>}
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="h-[calc(100vh-12rem)] mt-4">
          <div className="space-y-6 pr-4">
            {/* Location */}
            {finding.filePath && (
              <div>
                <h4 className="text-sm font-medium flex items-center gap-2 mb-2">
                  <FileCode className="h-4 w-4" />
                  Location
                </h4>
                <div className="rounded-md bg-muted p-3">
                  <p className="font-mono text-sm">
                    {finding.filePath}
                    {finding.startLine && (
                      <span className="text-muted-foreground">
                        :{finding.startLine}
                        {finding.endLine && finding.endLine !== finding.startLine
                          ? `-${finding.endLine}`
                          : ""}
                      </span>
                    )}
                  </p>
                </div>
              </div>
            )}

            {/* Code Snippet */}
            {finding.snippet && (
              <div>
                <h4 className="text-sm font-medium flex items-center gap-2 mb-2">
                  <Shield className="h-4 w-4" />
                  Code
                </h4>
                <pre className="rounded-md bg-zinc-950 p-4 text-sm text-zinc-100 overflow-x-auto font-mono leading-relaxed">
                  {finding.snippet}
                </pre>
              </div>
            )}

            <Separator />

            {/* Description */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <Info className="h-4 w-4" />
                  Description
                </h4>
                <Button variant="ghost" size="sm" onClick={copyDescription}>
                  <Copy className="h-3 w-3 mr-1" />
                  Copy
                </Button>
              </div>
              <div className="text-sm text-muted-foreground whitespace-pre-wrap">
                {finding.description}
              </div>
            </div>

            {/* Confidence */}
            {finding.confidence !== undefined && (
              <div>
                <h4 className="text-sm font-medium mb-2">Confidence</h4>
                <div className="flex items-center gap-2">
                  <div className="h-2 flex-1 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full"
                      style={{ width: `${(finding.confidence * 100).toFixed(0)}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono">
                    {(finding.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            )}

            {/* Metadata */}
            {finding.metadata && Object.keys(finding.metadata).length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2">Details</h4>
                <div className="rounded-md bg-muted p-3 space-y-1">
                  {Object.entries(finding.metadata).map(([key, value]) => (
                    <div key={key} className="flex gap-2 text-sm">
                      <span className="font-medium text-muted-foreground min-w-[120px]">
                        {key}:
                      </span>
                      <span className="font-mono break-all">
                        {typeof value === "object"
                          ? JSON.stringify(value)
                          : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
