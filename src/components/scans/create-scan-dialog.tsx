"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Plus } from "lucide-react";
import {
  NewSecurityScanForm,
} from "@/components/scans/new-security-scan-form";
import type { ScanProject } from "@/components/scans/types";

export type { ScanProject } from "@/components/scans/types";

export function CreateScanDialog({
  projects,
  triggerLabel = "New scan",
  triggerVariant = "default",
  triggerClassName,
  onScanCreated,
}: {
  projects: ScanProject[];
  triggerLabel?: string;
  triggerVariant?: "default" | "outline" | "ghost" | "secondary" | "link";
  triggerClassName?: string;
  onScanCreated?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [formKey, setFormKey] = useState(0);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) setFormKey((k) => k + 1);
      }}
    >
      <DialogTrigger asChild>
        <Button variant={triggerVariant} className={triggerClassName}>
          <Plus className="mr-2 h-4 w-4" />
          {triggerLabel}
        </Button>
      </DialogTrigger>
      <DialogContent className="flex max-h-[min(92vh,880px)] w-[min(96vw,56rem)] max-w-none flex-col gap-0 overflow-hidden p-0 sm:max-w-none">
        <DialogHeader className="shrink-0 space-y-1 border-b border-border/60 bg-card/50 px-6 py-4 pr-14">
          <DialogTitle className="text-xl">New security scan</DialogTitle>
          <DialogDescription>
            Analyze your source code for vulnerabilities, secrets, and security
            issues.
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6 sm:py-6">
          <NewSecurityScanForm
            key={formKey}
            projects={projects}
            embedded
            onCancel={() => setOpen(false)}
            onCreated={() => {
              setOpen(false);
              onScanCreated?.();
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
