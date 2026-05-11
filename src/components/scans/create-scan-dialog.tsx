"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Upload } from "lucide-react";
import { toast } from "sonner";
import {
  validateCreateScanFields,
  type CreateScanFieldErrors,
} from "@/lib/create-scan-validation";

export interface ScanProject {
  id: string;
  name: string;
  repoUrl?: string | null;
  defaultBranch?: string | null;
}

interface CreateScanFormProps {
  projects: ScanProject[];
  onCancel?: () => void;
  onCreated?: () => void;
}

export function CreateScanForm({
  projects,
  onCancel,
  onCreated,
}: CreateScanFormProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [projectId, setProjectId] = useState("");
  const [scanType, setScanType] = useState("FULL");
  const [sourceMode, setSourceMode] = useState<"upload" | "git" | "svn">(
    "git",
  );
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [svnUrl, setSvnUrl] = useState("");
  const [svnRevision, setSvnRevision] = useState("");
  const [svnUsername, setSvnUsername] = useState("");
  const [svnPassword, setSvnPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<CreateScanFieldErrors>({});
  const [touched, setTouched] = useState<{
    project?: boolean;
    source?: boolean;
  }>({});
  const [submitAttempted, setSubmitAttempted] = useState(false);

  useEffect(() => {
    if (!projectId) return;
    const p = projects.find((x) => x.id === projectId);
    if (p?.repoUrl) {
      setRepoUrl(p.repoUrl);
      setBranch(p.defaultBranch || "");
    } else {
      setRepoUrl("");
      setBranch("");
    }
  }, [projectId, projects]);

  function runValidation(): CreateScanFieldErrors {
    return validateCreateScanFields({
      projectId,
      sourceMode,
      file,
      repoUrl,
      svnUrl,
    });
  }

  function showProjectError() {
    return Boolean(
      fieldErrors.project && (touched.project || submitAttempted),
    );
  }

  function showSourceError() {
    return Boolean(
      fieldErrors.source && (touched.source || submitAttempted),
    );
  }

  async function handleSubmit() {
    setSubmitAttempted(true);
    const errors = runValidation();
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      if (errors.project) toast.error(errors.project);
      else if (errors.source) toast.error(errors.source);
      return;
    }

    setLoading(true);

    try {
      const formData = new FormData();
      const data = {
        projectId,
        scanType,
        repoUrl: sourceMode === "git" ? repoUrl : undefined,
        branch: sourceMode === "git" ? branch : undefined,
        svnUrl: sourceMode === "svn" ? svnUrl : undefined,
        svnRevision:
          sourceMode === "svn" ? svnRevision || undefined : undefined,
        svnUsername:
          sourceMode === "svn" ? svnUsername || undefined : undefined,
        svnPassword:
          sourceMode === "svn" ? svnPassword || undefined : undefined,
      };
      formData.append("data", JSON.stringify(data));
      if (sourceMode === "upload" && file) formData.append("file", file);

      const res = await fetch("/api/scans", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to create scan");
      }

      const result = await res.json();
      toast.success("Scan created successfully");
      onCreated?.();
      router.push(`/scans/${result.scanId}`);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to create scan",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="create-scan-project">Project *</Label>
          <Select
            value={projectId}
            onValueChange={(v) => {
              setProjectId(v);
              setTouched((t) => ({ ...t, project: true }));
              setFieldErrors(
                validateCreateScanFields({
                  projectId: v,
                  sourceMode,
                  file,
                  repoUrl,
                  svnUrl,
                }),
              );
            }}
          >
            <SelectTrigger id="create-scan-project" aria-invalid={showProjectError()}>
              <SelectValue placeholder="Select a project" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {showProjectError() && (
            <p className="text-sm text-destructive" role="alert">
              {fieldErrors.project}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label>Scan Type</Label>
          <Select value={scanType} onValueChange={setScanType}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="FULL">Full Scan</SelectItem>
              <SelectItem value="SAST_ONLY">SAST Only</SelectItem>
              <SelectItem value="SCA_ONLY">SCA Only</SelectItem>
              <SelectItem value="SECRETS_ONLY">Secrets Only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label>Source Code *</Label>
          <div className="flex gap-1 rounded-md border p-1">
            {(["upload", "git", "svn"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => {
                  setSourceMode(mode);
                  setFieldErrors((e) => ({ ...e, source: undefined }));
                }}
                className={`flex-1 rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                  sourceMode === mode
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {mode === "upload" ? "ZIP / TAR" : mode === "git" ? "Git" : "SVN"}
              </button>
            ))}
          </div>
        </div>

        {sourceMode === "upload" && (
          <div className="space-y-2">
            <Label htmlFor="create-scan-archive">Archive file *</Label>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                id="create-scan-archive"
                type="file"
                accept=".zip,.tar,.tar.gz,.tgz"
                aria-invalid={showSourceError()}
                onBlur={() => {
                  setTouched((t) => ({ ...t, source: true }));
                  setFieldErrors(
                    validateCreateScanFields({
                      projectId,
                      sourceMode,
                      file,
                      repoUrl,
                      svnUrl,
                    }),
                  );
                }}
                onChange={(e) => {
                  setFile(e.target.files?.[0] || null);
                  setFieldErrors((err) => ({ ...err, source: undefined }));
                }}
              />
              {file && (
                <span className="text-sm text-muted-foreground">
                  {(file.size / 1024 / 1024).toFixed(1)} MB
                </span>
              )}
            </div>
            {showSourceError() && fieldErrors.source && (
              <p className="text-sm text-destructive" role="alert">
                {fieldErrors.source}
              </p>
            )}
          </div>
        )}

        {sourceMode === "git" && (
          <>
            <div className="space-y-2">
              <Label htmlFor="create-scan-repo">Repository URL *</Label>
              <Input
                id="create-scan-repo"
                placeholder="https://github.com/org/repo.git"
                value={repoUrl}
                aria-invalid={showSourceError()}
                onBlur={() => {
                  setTouched((t) => ({ ...t, source: true }));
                  setFieldErrors(
                    validateCreateScanFields({
                      projectId,
                      sourceMode,
                      file,
                      repoUrl,
                      svnUrl,
                    }),
                  );
                }}
                onChange={(e) => {
                  setRepoUrl(e.target.value);
                  setFieldErrors((err) => ({ ...err, source: undefined }));
                }}
              />
              {showSourceError() && fieldErrors.source && (
                <p className="text-sm text-destructive" role="alert">
                  {fieldErrors.source}
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-scan-branch">Branch (optional)</Label>
              <Input
                id="create-scan-branch"
                placeholder="Leave blank to use repository default"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
              />
            </div>
          </>
        )}

        {sourceMode === "svn" && (
          <>
            <div className="space-y-2">
              <Label htmlFor="create-scan-svn">SVN Repository URL *</Label>
              <Input
                id="create-scan-svn"
                placeholder="https://svn.riouxsvn.com/my-repo/trunk"
                value={svnUrl}
                aria-invalid={showSourceError()}
                onBlur={() => {
                  setTouched((t) => ({ ...t, source: true }));
                  setFieldErrors(
                    validateCreateScanFields({
                      projectId,
                      sourceMode,
                      file,
                      repoUrl,
                      svnUrl,
                    }),
                  );
                }}
                onChange={(e) => {
                  setSvnUrl(e.target.value);
                  setFieldErrors((err) => ({ ...err, source: undefined }));
                }}
              />
              <p className="text-xs text-muted-foreground">
                Full URL to the SVN path you want to scan (e.g. repo root,
                /trunk, or a specific branch).
              </p>
              {showSourceError() && fieldErrors.source && (
                <p className="text-sm text-destructive" role="alert">
                  {fieldErrors.source}
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-scan-svn-rev">Revision (optional)</Label>
              <Input
                id="create-scan-svn-rev"
                placeholder="HEAD (latest)"
                value={svnRevision}
                onChange={(e) => setSvnRevision(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                A revision number (e.g. 42) or leave blank for HEAD.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-2">
                <Label htmlFor="create-scan-svn-user">Username (optional)</Label>
                <Input
                  id="create-scan-svn-user"
                  placeholder="svn-user"
                  value={svnUsername}
                  onChange={(e) => setSvnUsername(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-scan-svn-pass">Password (optional)</Label>
                <Input
                  id="create-scan-svn-pass"
                  type="password"
                  placeholder="password"
                  value={svnPassword}
                  onChange={(e) => setSvnPassword(e.target.value)}
                />
              </div>
            </div>
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              <p>
                Requires <code>svn</code> CLI on the worker. The worker runs{" "}
                <code>svn export</code> to fetch the code without .svn metadata,
                then scans it like any other source.
              </p>
            </div>
          </>
        )}
      </div>

      <div className="mt-6 flex justify-end gap-2">
        {onCancel && (
          <Button variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        )}
        <Button onClick={handleSubmit} disabled={loading}>
          {loading ? (
            "Creating..."
          ) : (
            <>
              <Upload className="mr-2 h-4 w-4" />
              Start Scan
            </>
          )}
        </Button>
      </div>
    </>
  );
}

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
      <DialogContent className="flex max-h-[min(90vh,720px)] flex-col gap-0 overflow-hidden p-0 sm:max-w-lg">
        <DialogHeader className="shrink-0 space-y-1 border-b px-6 py-4 pr-14">
          <DialogTitle>New scan</DialogTitle>
          <DialogDescription>
            Choose project, scan type, and source (Git, upload, or SVN). You
            will be taken to the scan page when it is queued.
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          <CreateScanForm
            key={formKey}
            projects={projects}
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
