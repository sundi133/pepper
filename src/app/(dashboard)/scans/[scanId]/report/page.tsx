"use client";

import { useParams } from "next/navigation";
import useSWR from "swr";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  PentestReportWidget,
  type PentestReportPayload,
} from "@/components/scans/pentest-report-widget";

const fetcher = (url: string) =>
  fetch(url).then((res) => {
    if (!res.ok) throw new Error("Failed to load report");
    return res.json();
  });

export default function ScanHtmlReportPage() {
  const params = useParams();
  const scanId = params.scanId as string;

  const { data, error, isLoading } = useSWR<PentestReportPayload>(
    `/api/scans/${scanId}/report-data`,
    fetcher,
  );

  if (isLoading) {
    return (
      <p className="py-16 text-center text-muted-foreground">
        Loading report…
      </p>
    );
  }

  if (error || !data?.report) {
    return (
      <div className="py-16 text-center">
        <p className="text-destructive">Could not load this report.</p>
        <Button asChild variant="outline" className="mt-4">
          <Link href={`/scans/${scanId}`}>Back to scan</Link>
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="sticky top-0 z-10 border-b bg-[#f7f6f3]/95 px-4 py-3 backdrop-blur-sm">
        <div className="mx-auto flex max-w-5xl items-center gap-3">
          <Button variant="ghost" size="sm" asChild>
            <Link href={`/scans/${scanId}`}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to scan
            </Link>
          </Button>
          <span className="text-sm text-muted-foreground">
            HTML assessment report
          </span>
        </div>
      </div>
      <PentestReportWidget data={data} />
    </div>
  );
}
