"use client";

import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function DocumentationSettingsPage() {
  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col gap-4">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Documentation" },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-border/60 bg-background shadow-sm">
        <iframe
          title="Pepper documentation"
          src="/docs/index.html"
          className="h-full w-full border-0"
        />
      </div>
    </div>
  );
}
