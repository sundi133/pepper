"use client";

import { useParams } from "next/navigation";
import useSWR from "swr";
import Link from "next/link";
import { ArrowLeft, FileText, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AssessmentReportDocument } from "@/components/scans/assessment-report-document";
import { toast } from "sonner";
import { useState } from "react";

type AssessmentGet = {
  markdown: string | null;
  generatedAt: string | null;
  model: string | null;
  scanStatus: string;
};

const fetcher = (url: string) =>
  fetch(url).then((res) => {
    if (!res.ok) throw new Error("Failed to load report");
    return res.json();
  });

export default function ScanHtmlReportPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const [generating, setGenerating] = useState(false);

  const { data, error, isLoading, mutate } = useSWR<AssessmentGet>(
    `/api/scans/${scanId}/assessment-report`,
    fetcher,
  );

  async function generateReport(regenerate: boolean) {
    setGenerating(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/assessment-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regenerate }),
      });
      const payload = (await res.json()) as {
        markdown?: string;
        error?: string;
        cached?: boolean;
      };
      if (!res.ok) {
        throw new Error(payload.error || "Generation failed");
      }
      if (payload.markdown) {
        toast.success(
          payload.cached ? "Loaded cached assessment report" : "Assessment report generated",
        );
        await mutate();
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Generation failed");
    } finally {
      setGenerating(false);
    }
  }

  if (isLoading) {
    return (
      <p className="py-16 text-center text-muted-foreground">
        Loading report…
      </p>
    );
  }

  if (error || !data) {
    return (
      <div className="py-16 text-center">
        <p className="text-destructive">Could not load this report.</p>
        <Button asChild variant="outline" className="mt-4">
          <Link href={`/scans/${scanId}`}>Back to scan</Link>
        </Button>
      </div>
    );
  }

  const hasReport = Boolean(data.markdown?.trim());
  const completed = data.scanStatus === "COMPLETED";

  return (
    <div className="min-h-screen bg-[#f7f6f3]">
      <div className="sticky top-0 z-10 border-b bg-[#f7f6f3]/95 px-4 py-3 backdrop-blur-sm">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" asChild>
              <Link href={`/scans/${scanId}`}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to scan
              </Link>
            </Button>
            <span className="text-sm text-muted-foreground">
              Security assessment report
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {completed && (
              <>
                <Button
                  size="sm"
                  disabled={generating}
                  onClick={() => generateReport(false)}
                >
                  {generating ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <FileText className="mr-2 h-4 w-4" />
                  )}
                  {hasReport ? "Refresh from scan" : "Generate report"}
                </Button>
                {hasReport && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={generating}
                    onClick={() => generateReport(true)}
                  >
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Regenerate
                  </Button>
                )}
              </>
            )}
          </div>
        </div>
        {data.generatedAt && (
          <p className="mx-auto max-w-4xl px-4 pb-2 text-xs text-muted-foreground">
            {hasReport ? "Generated" : "Last generated"}:{" "}
            {new Date(data.generatedAt).toLocaleString()}
            {data.model ? ` · Model: ${data.model}` : ""}
          </p>
        )}
      </div>

      {!completed && (
        <p className="mx-auto max-w-4xl px-4 py-8 text-center text-muted-foreground">
          Complete the scan to generate the assessment report.
        </p>
      )}

      {completed && !hasReport && !generating && (
        <div className="mx-auto max-w-4xl px-4 py-12 text-center">
          <p className="text-stone-700">
            Generate a single professional Markdown report (18 standard sections) from
            your scan findings using your organization&apos;s LLM settings.
          </p>
          <Button className="mt-4" onClick={() => generateReport(false)}>
            <FileText className="mr-2 h-4 w-4" />
            Generate assessment report
          </Button>
        </div>
      )}

      {generating && (
        <p className="py-8 text-center text-sm text-muted-foreground">
          Generating report… this may take several minutes.
        </p>
      )}

      {hasReport && data.markdown && (
        <AssessmentReportDocument markdown={data.markdown} />
      )}
    </div>
  );
}
