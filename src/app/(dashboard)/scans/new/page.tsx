"use client";

import { Suspense } from "react";
import { ScanHub } from "@/components/scan-hub/scan-hub";
import { Loader2 } from "lucide-react";

function ScanHubFallback() {
  return (
    <div className="flex items-center justify-center gap-2 py-24 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" />
      Loading scan hub…
    </div>
  );
}

export default function NewScanPage() {
  return (
    <Suspense fallback={<ScanHubFallback />}>
      <ScanHub />
    </Suspense>
  );
}
