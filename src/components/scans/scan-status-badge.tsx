"use client";

import { Badge } from "@/components/ui/badge";
import { Loader2, CheckCircle2, XCircle, Clock, Ban } from "lucide-react";

const statusConfig: Record<
  string,
  { label: string; variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ElementType }
> = {
  QUEUED: { label: "Queued", variant: "secondary", icon: Clock },
  RUNNING: { label: "Running", variant: "default", icon: Loader2 },
  COMPLETED: { label: "Completed", variant: "outline", icon: CheckCircle2 },
  FAILED: { label: "Failed", variant: "destructive", icon: XCircle },
  CANCELLED: { label: "Cancelled", variant: "secondary", icon: Ban },
};

export function ScanStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.QUEUED;
  const Icon = config.icon;

  return (
    <Badge variant={config.variant} className="gap-1">
      <Icon className={`h-3 w-3 ${status === "RUNNING" ? "animate-spin" : ""}`} />
      {config.label}
    </Badge>
  );
}

export function GateResultBadge({ result }: { result: string }) {
  if (result === "PASSED") {
    return (
      <Badge variant="outline" className="gap-1 border-green-500 text-green-600">
        <CheckCircle2 className="h-3 w-3" />
        Gate Passed
      </Badge>
    );
  }
  if (result === "FAILED") {
    return (
      <Badge variant="destructive" className="gap-1">
        <XCircle className="h-3 w-3" />
        Gate Failed
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="gap-1">
      <Clock className="h-3 w-3" />
      Pending
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
    CRITICAL: "destructive",
    HIGH: "destructive",
    MEDIUM: "default",
    LOW: "secondary",
    INFO: "outline",
  };

  return (
    <Badge variant={variants[severity] || "outline"} className="text-xs">
      {severity}
    </Badge>
  );
}
