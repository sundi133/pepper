"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

function RepositoriesRedirectInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const q = searchParams.toString();
    router.replace(`/scans/new${q ? `?${q}` : ""}`);
  }, [router, searchParams]);

  return (
    <div className="flex items-center justify-center gap-2 py-24 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" />
      Redirecting to Scan…
    </div>
  );
}

/** Repositories merged into Scan hub — preserve query params (e.g. GitHub OAuth). */
export default function RepositoriesRedirectPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center gap-2 py-24 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
        </div>
      }
    >
      <RepositoriesRedirectInner />
    </Suspense>
  );
}
