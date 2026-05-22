"use client";

import { Badge } from "@/components/ui/badge";
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Ban,
  Pause,
  Square,
} from "lucide-react";

const statusConfig: Record<
  string,
  {
    label: string;
    variant: "default" | "secondary" | "destructive" | "outline";
    icon: React.ElementType;
  }
> = {
  QUEUED: { label: "Queued", variant: "secondary", icon: Clock },
  RUNNING: { label: "Running", variant: "default", icon: Loader2 },
  PAUSED: { label: "Paused", variant: "secondary", icon: Pause },
  STOPPED: { label: "Stopped", variant: "outline", icon: Square },
  COMPLETED: { label: "Completed", variant: "outline", icon: CheckCircle2 },
  FAILED: { label: "Failed", variant: "destructive", icon: XCircle },
  CANCELLED: { label: "Cancelled", variant: "secondary", icon: Ban },
};

export function ScanStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.QUEUED;
  const Icon = config.icon;

  return (
    <Badge variant={config.variant} className="gap-1">
      <Icon
        className={`h-3 w-3 ${status === "RUNNING" ? "animate-spin" : ""}`}
      />
      {config.label}
    </Badge>
  );
}

export function GateResultBadge({ result }: { result: string }) {
  if (result === "PASSED") {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-green-500 text-green-600"
      >
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

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL:
    "border-red-600/40 bg-red-600 text-white shadow-sm hover:bg-red-700 dark:bg-red-600 dark:hover:bg-red-500",
  HIGH:
    "border-orange-500/40 bg-orange-500 text-white shadow-sm hover:bg-orange-600 dark:bg-orange-600 dark:hover:bg-orange-500",
  MEDIUM:
    "border-amber-500/40 bg-amber-500/90 text-amber-950 shadow-sm hover:bg-amber-500 dark:bg-amber-600 dark:text-amber-950 dark:hover:bg-amber-500",
  LOW:
    "border-sky-500/40 bg-sky-500/15 text-sky-800 hover:bg-sky-500/25 dark:bg-sky-500/20 dark:text-sky-300 dark:hover:bg-sky-500/30",
  INFO:
    "border-border bg-muted text-muted-foreground hover:bg-muted/80",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.INFO;

  return (
    <Badge
      variant="outline"
      className={`text-xs font-semibold transition-colors duration-200 ${style}`}
    >
      {severity}
    </Badge>
  );
}
