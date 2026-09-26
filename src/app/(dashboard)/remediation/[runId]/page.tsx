"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { RemediationRunView } from "@/components/remediation/remediation-run-view";
import type { RemediationRunSnapshot } from "@/lib/remediation/types";

export default function RemediationRunPage() {
  const { runId } = useParams<{ runId: string }>();
  const [run, setRun] = useState<RemediationRunSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/remediation/runs/${runId}`)
      .then(async (res) => {
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || "Could not load the run");
        if (!cancelled) setRun(body as RemediationRunSnapshot);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not load the run");
      });
    return () => {
      cancelled = true;
    };
  }, [runId]);

  return (
    <div className="mx-auto w-full max-w-7xl">
      <PageBreadcrumb
        items={[
          { label: "Scans", href: "/scans" },
          ...(run ? [{ label: "Scan", href: `/scans/${run.scanId}` }] : []),
          { label: "AI remediation" },
        ]}
      />
      {error ? (
        <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
      ) : run ? (
        <RemediationRunView initial={run} />
      ) : (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Loading run…
        </div>
      )}
    </div>
  );
}
