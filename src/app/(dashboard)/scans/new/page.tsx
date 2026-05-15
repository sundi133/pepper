"use client";

import { NewSecurityScanForm } from "@/components/scans/new-security-scan-form";
import { useProjects } from "@/hooks/use-scan-polling";

export default function NewScanPage() {
  const { projects } = useProjects();

  return (
    <div className="w-full py-6">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          New scan
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Git repository, SVN checkout, or file upload.
        </p>
      </header>
      <NewSecurityScanForm projects={projects} />
    </div>
  );
}
