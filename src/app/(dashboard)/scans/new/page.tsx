"use client";

import Link from "next/link";
import { useProjects } from "@/hooks/use-scan-polling";
import { NewSecurityScanForm } from "@/components/scans/new-security-scan-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

export default function NewScanPage() {
  const { projects, isLoading } = useProjects();

  return (
    <div className="relative mx-auto w-full max-w-6xl space-y-6 pb-8">
      <div
        className="pointer-events-none absolute inset-0 -z-10 opacity-[0.35]"
        style={{
          backgroundImage: `linear-gradient(to right, oklch(1 0 0 / 0.04) 1px, transparent 1px),
            linear-gradient(to bottom, oklch(1 0 0 / 0.04) 1px, transparent 1px)`,
          backgroundSize: "24px 24px",
        }}
        aria-hidden
      />

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <Button variant="ghost" size="sm" className="w-fit gap-2 px-0 text-muted-foreground hover:text-foreground" asChild>
          <Link href="/scans">
            <ArrowLeft className="h-4 w-4" />
            Back to scans
          </Link>
        </Button>
      </div>

      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
          New security scan
        </h1>
        <p className="max-w-2xl text-sm text-muted-foreground sm:text-base">
          Analyze your source code for vulnerabilities, secrets, and security
          issues.
        </p>
      </header>

      {isLoading ? (
        <p className="py-12 text-center text-sm text-muted-foreground">
          Loading projects…
        </p>
      ) : projects.length === 0 ? (
        <p className="rounded-xl border border-dashed border-border/60 bg-card/40 px-4 py-10 text-center text-sm text-muted-foreground">
          Create a project first, then return here to start a scan.{" "}
          <Link href="/projects/new" className="font-medium text-primary hover:underline">
            New project
          </Link>
        </p>
      ) : (
        <NewSecurityScanForm projects={projects} />
      )}
    </div>
  );
}
